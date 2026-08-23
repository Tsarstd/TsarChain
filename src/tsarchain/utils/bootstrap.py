# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: libsecp256k1

from __future__ import annotations

import os
import time
import json
import shutil
import hashlib
import tempfile
import tarfile
import zipfile

import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional
from ecdsa import SECP256k1, VerifyingKey

# ---------------- Local Project ----------------
from . import config as CFG
from ..storage.kv import iter_prefix
from ..core.block import Block

from .tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.utils.bootstrap")

ProgressCallback = Optional[Callable[[str], None]]


@dataclass(frozen=True)
class SnapshotBootstrapResult:
    status: str
    reason: Optional[str] = None
    bytes_written: int = 0
    height: Optional[int] = None
    source: Optional[str] = None
    duration_s: float = 0.0


def maybe_bootstrap_snapshot(progress_cb: ProgressCallback = None) -> SnapshotBootstrapResult:
    """
    Download and install a pre-packaged snapshot containing the 5 LMDB environments
    (chain, utxo, state, graffiti, mempool) for fast blockchain synchronization.
    """
    start_time = time.time()
    node_dir = os.path.abspath(CFG.NODE_DATA_DIR)
    meta_path = CFG.SNAPSHOT_META_PATH or os.path.join(node_dir, "snapshot.meta.json")

    def _emit(message: str) -> None:
        if progress_cb:
            progress_cb(message)
        log.info("[bootstrap] %s", message)

    if not CFG.SNAPSHOT_BOOTSTRAP_ENABLED:
        return SnapshotBootstrapResult(status="skipped", reason="disabled")

    if CFG.BACKUP_SNAPSHOT and CFG.SNAPSHOT_BACKUP_DIR:
        try:
            os.makedirs(CFG.SNAPSHOT_BACKUP_DIR, exist_ok=True)
        except Exception:
            pass

    manifest = _fetch_manifest()
    expected_sha = _safe_lower(manifest, "sha256")
    snapshot_url = (
        (manifest or {}).get("snapshot_url")
        or (manifest or {}).get("url")
        or CFG.SNAPSHOT_FILE_URL
    )
    height = _safe_int(manifest, "height")
    generated_at = _safe_int(manifest, "generated_at")

    if manifest:
        if CFG.SNAPSHOT_REQUIRE_SIGNATURE and not manifest.get("signature"):
            return SnapshotBootstrapResult(status="failed", reason="missing_signature")
        if not _verify_manifest_signature(manifest):
            return SnapshotBootstrapResult(status="failed", reason="signature_invalid")
        if CFG.SNAPSHOT_MAX_AGE_SECONDS and generated_at:
            age = max(0, int(time.time()) - generated_at)
            if age > CFG.SNAPSHOT_MAX_AGE_SECONDS:
                log.warning("[bootstrap] Manifest age (%ss) exceeds max tolerated (%ss)", age, CFG.SNAPSHOT_MAX_AGE_SECONDS)

    if not snapshot_url:
        return SnapshotBootstrapResult(status="skipped", reason="no_snapshot_url")

    # Check if local chain is already ahead of the snapshot
    local_height = _get_local_chain_height()
    if local_height is not None and height and local_height >= height:
        _emit(f"Local chain height ({local_height}) >= snapshot height ({height}); skipping bootstrap.")
        return SnapshotBootstrapResult(status="skipped", reason="local_chain_ahead", height=height)

    tmp_dl_path = None
    staging_dir = None
    backup_path = None
    replaced = False

    try:
        # 1. Download snapshot archive/file to temporary path
        _emit(f"Fetching snapshot from {snapshot_url}...")
        tmp_fd, tmp_dl_path = tempfile.mkstemp(prefix="tsar_snapshot_dl_", suffix=".tmp")
        os.close(tmp_fd)

        final_size = _download_with_progress(snapshot_url, tmp_dl_path, expected_sha, _emit)

        if final_size < CFG.SNAPSHOT_MIN_SIZE_BYTES:
            raise ValueError(f"snapshot too small ({final_size} bytes)")

        # 2. Extract into staging directory
        staging_dir = f"{node_dir}.bootstrap_staging_{int(time.time())}"
        if os.path.exists(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)
        os.makedirs(staging_dir, exist_ok=True)

        _extract_snapshot_payload(tmp_dl_path, staging_dir, _emit)

        # 3. Atomic swap: backup existing node directory, replace with staging
        if os.path.exists(node_dir):
            backup_path = f"{node_dir}.bak_{int(time.time())}"
            shutil.move(node_dir, backup_path)

        os.replace(staging_dir, node_dir)
        replaced = True

        # 4. Resolve installed chain height (from manifest or extracted chain DB)
        installed_height = height if (height is not None and height > 0) else _get_local_chain_height()

        # 5. Write metadata
        meta = {
            "sha256": expected_sha or _hash_file(tmp_dl_path),
            "size": final_size,
            "height": installed_height,
            "source": snapshot_url,
            "generated_at": generated_at or int(time.time()),
            "applied_at": int(time.time()),
        }
        _write_meta(meta_path, meta)

        # 6. Validate chain integrity
        valid, validate_reason = _validate_snapshot_chain()
        if not valid:
            raise ValueError(validate_reason or "snapshot chain validation failed")

        # 7. Cleanup backup directory on success
        if backup_path and os.path.exists(backup_path):
            shutil.rmtree(backup_path, ignore_errors=True)

        duration = time.time() - start_time
        _emit(f"Snapshot successfully installed at height {installed_height or 0} ({final_size / 1_048_576:.2f} MB in {duration:.1f}s)")

        return SnapshotBootstrapResult(
            status="installed",
            bytes_written=final_size,
            height=installed_height,
            source=snapshot_url,
            duration_s=duration,
        )

    except Exception as exc:
        log.exception("[bootstrap] Snapshot bootstrap failed")
        _emit(f"Snapshot bootstrap failed: {exc}")

        # Rollback: remove partially installed node directory and restore backup
        if replaced and os.path.exists(node_dir):
            shutil.rmtree(node_dir, ignore_errors=True)
        if backup_path and os.path.exists(backup_path):
            try:
                os.replace(backup_path, node_dir)
                _emit("Restored previous node database from backup.")
            except Exception as rb_exc:
                log.exception("[bootstrap] Rollback failed: %s", rb_exc)

        return SnapshotBootstrapResult(status="failed", reason=str(exc))
    finally:
        if tmp_dl_path and os.path.exists(tmp_dl_path):
            try:
                os.remove(tmp_dl_path)
            except Exception:
                pass
        if staging_dir and os.path.exists(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)


def _download_with_progress(
    url: str,
    dest_path: str,
    expected_sha: Optional[str],
    emit_cb: Callable[[str], None],
) -> int:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": CFG.SNAPSHOT_USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=CFG.SNAPSHOT_HTTP_TIMEOUT) as resp, open(dest_path, "wb") as out:
        total_header = resp.headers.get("Content-Length")
        total_bytes = int(total_header) if total_header and total_header.isdigit() else 0

        chunk_size = max(64 * 1024, int(CFG.SNAPSHOT_CHUNK_BYTES))
        hasher = hashlib.sha256()
        downloaded = 0
        last_emit = time.time()
        start_dl = time.time()

        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)
            hasher.update(chunk)
            downloaded += len(chunk)

            now = time.time()
            if now - last_emit >= 0.5 or (total_bytes and downloaded == total_bytes):
                last_emit = now
                elapsed = max(0.001, now - start_dl)
                speed_mb = (downloaded / (1024 * 1024)) / elapsed
                if total_bytes > 0:
                    pct = (downloaded / total_bytes) * 100.0
                    emit_cb(f"Downloading snapshot: {pct:.1f}% ({downloaded / (1024 * 1024):.1f}/{total_bytes / (1024 * 1024):.1f} MB, {speed_mb:.2f} MB/s)")
                else:
                    emit_cb(f"Downloading snapshot: {downloaded / (1024 * 1024):.1f} MB ({speed_mb:.2f} MB/s)")

    if total_bytes > 0 and downloaded < total_bytes:
        raise ValueError(f"Download incomplete: {downloaded}/{total_bytes} bytes")

    if expected_sha:
        computed_sha = hasher.hexdigest().lower()
        if computed_sha != expected_sha.lower():
            raise ValueError(f"Snapshot SHA256 mismatch: expected {expected_sha}, got {computed_sha}")

    return downloaded


def _extract_snapshot_payload(src_file: str, dest_dir: str, emit_cb: Callable[[str], None]) -> None:
    """
    Extract a downloaded snapshot file into dest_dir.
    Supports .tar.gz, .tgz, .tar, .zip, or raw .mdb file fallback.
    """
    is_tar = False
    is_zip = False

    try:
        is_tar = tarfile.is_tarfile(src_file)
    except Exception:
        pass

    if not is_tar:
        try:
            is_zip = zipfile.is_zipfile(src_file)
        except Exception:
            pass

    if is_tar:
        emit_cb("Extracting tar snapshot archive...")
        with tarfile.open(src_file, "r:*") as tar:
            try:
                tar.extractall(dest_dir, filter="data")
            except TypeError:
                tar.extractall(dest_dir)
    elif is_zip:
        emit_cb("Extracting zip snapshot archive...")
        with zipfile.ZipFile(src_file, "r") as zf:
            zf.extractall(dest_dir)
    else:
        # Raw .mdb fallback (legacy mode: place in chain directory)
        emit_cb("Copying raw LMDB file into chain storage...")
        chain_dest = os.path.join(dest_dir, "chain")
        os.makedirs(chain_dest, exist_ok=True)
        shutil.copy2(src_file, os.path.join(chain_dest, "data.mdb"))
        return

    # Normalize nested directory (e.g. if archive contains top-level 'node/' or 'data/node/')
    _normalize_extracted_structure(dest_dir)


def _normalize_extracted_structure(dest_dir: str) -> None:
    """
    Ensure the 5 sub-databases exist directly under dest_dir.
    If archive wrapped them inside a folder (e.g., node/), hoist them up.
    """
    entries = os.listdir(dest_dir)
    if "chain" in entries:
        return

    for entry in entries:
        sub = os.path.join(dest_dir, entry)
        if os.path.isdir(sub) and os.path.exists(os.path.join(sub, "chain")):
            for item in os.listdir(sub):
                shutil.move(os.path.join(sub, item), os.path.join(dest_dir, item))
            shutil.rmtree(sub, ignore_errors=True)
            break


def _fetch_manifest() -> Optional[dict]:
    url = CFG.SNAPSHOT_MANIFEST_URL.strip() if CFG.SNAPSHOT_MANIFEST_URL else ""
    if not url:
        return None
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": CFG.SNAPSHOT_USER_AGENT,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=CFG.SNAPSHOT_HTTP_TIMEOUT) as resp:
            raw = resp.read()
        manifest = json.loads(raw.decode("utf-8"))
        return manifest
    except Exception as exc:
        log.warning("[_fetch_manifest] Failed fetching manifest from %s: %s", url, exc)
        return None


def _verify_manifest_signature(manifest: dict | None) -> bool:
    if not manifest:
        return True

    signature_hex = (manifest.get("signature") or "").strip()
    if not signature_hex:
        return not CFG.SNAPSHOT_REQUIRE_SIGNATURE

    pubkey_hex = (CFG.SNAPSHOT_PUBKEY_HEX or "").strip()
    if not pubkey_hex:
        return not CFG.SNAPSHOT_REQUIRE_SIGNATURE

    try:
        payload_dict = dict(manifest)
        payload_dict.pop("signature", None)
        payload = json.dumps(payload_dict, sort_keys=True, separators=CFG.CANONICAL_SEP).encode("utf-8")
        vk = VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=SECP256k1)
        vk.verify(bytes.fromhex(signature_hex), payload, hashfunc=hashlib.sha256)
        return True
    except Exception as exc:
        log.warning("[_verify_manifest_signature] Signature verification failed: %s", exc)
        return False


def _get_local_chain_height() -> Optional[int]:
    meta_path = CFG.SNAPSHOT_META_PATH
    if meta_path and os.path.exists(meta_path):
        try:
            meta = _load_meta(meta_path)
            h = meta.get("height")
            if isinstance(h, int) and h >= 0:
                return h
        except Exception:
            pass

    chain_dir = CFG.LMDB_CHAIN_DIR
    if chain_dir and os.path.exists(os.path.join(chain_dir, "data.mdb")):
        try:
            items = list(iter_prefix("chain", b"h:"))
            if items:
                items.sort(key=lambda kv: kv[0])
                _, last_val = items[-1]
                if len(last_val) >= 108 and not last_val.startswith(b"{"):
                    blk = Block.from_storage_bytes(last_val)
                    return int(blk.height)
                else:
                    d = json.loads(last_val.decode("utf-8"))
                    return int(d.get("height", -1))
        except Exception:
            pass
    return None


def _hash_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_meta(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_meta(path: str, data: dict) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp_path = os.path.join(parent, f"{os.path.basename(path)}.tmp")

    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)

    os.replace(tmp_path, path)


def _safe_lower(source: Optional[dict], key: str) -> str:
    if not source:
        return ""
    val = source.get(key)
    if isinstance(val, str):
        return val.strip().lower()
    return ""


def _safe_int(source: Optional[dict], key: str) -> int:
    if not source:
        return 0
    return int(source.get(key, 0))


def annotate_local_snapshot_meta(height: Optional[int], tip_timestamp: Optional[int] = None) -> Optional[dict]:
    meta_path = CFG.SNAPSHOT_META_PATH
    if not meta_path:
        return None

    if os.path.exists(meta_path):
        meta = _load_meta(meta_path)
    else:
        meta = {}
    updated = False

    # ---- height ----
    if height is not None and height >= 0:
        h = int(height)
        if meta.get("height") != h:
            meta["height"] = h
            updated = True

    # ---- generated_at ----
    if tip_timestamp:
        ts = int(tip_timestamp)
        if ts > 0 and meta.get("generated_at") != ts:
            meta["generated_at"] = ts
            updated = True

    if not updated and os.path.exists(meta_path):
        return meta

    if not meta.get("applied_at"):
        meta["applied_at"] = int(time.time())

    _write_meta(meta_path, meta)
    return meta


def _validate_snapshot_chain() -> tuple[bool, Optional[str]]:
    chain_dir = CFG.LMDB_CHAIN_DIR
    if not chain_dir or not os.path.exists(chain_dir):
        return False, "Chain DB directory missing"

    try:
        items = list(iter_prefix("chain", b"h:"))
    except Exception as exc:
        return False, f"Failed to access chain DB: {exc}"

    if not items:
        return False, "empty chain db"

    items.sort(key=lambda kv: kv[0])
    _, first_val = items[0]

    entry_block = None
    if len(first_val) >= 108 and not first_val.startswith(b"{"):
        try:
            entry_block = Block.from_storage_bytes(first_val)
        except Exception as exc:
            log.warning("[_validate_snapshot_chain] from_storage_bytes failed: %s", exc)

    if entry_block is None:
        try:
            entry_dict = json.loads(first_val.decode("utf-8"))
            if isinstance(entry_dict, dict):
                try:
                    entry_block = Block.from_dict(entry_dict)
                except Exception:
                    # Fallback to dictionary field checks for mock/legacy snapshots
                    h = int(entry_dict.get("height", -1))
                    if h != 0:
                        return False, f"genesis block not included in snapshot (first height {h})"
                    prev = (entry_dict.get("prev_block_hash") or "").strip().lower()
                    zero_hex = CFG.ZERO_HASH.hex() if isinstance(CFG.ZERO_HASH, (bytes, bytearray)) else bytes(CFG.ZERO_HASH).hex()
                    if prev != zero_hex:
                        return False, "prev_block_hash genesis mismatch"
                    expected_genesis = CFG.GENESIS_HASH_HEX
                    if expected_genesis.startswith("0x"):
                        expected_genesis = expected_genesis[2:]
                    if expected_genesis:
                        entry_h = (entry_dict.get("hash") or "").strip().lower()
                        if entry_h != expected_genesis:
                            return False, f"genesis hash snapshot ({entry_h}) does not match expected ({expected_genesis})"
                    return True, None
        except Exception as exc:
            return False, f"chain entry invalid: {exc}"

    if entry_block is None:
        return False, "chain genesis block missing or invalid"

    height = int(getattr(entry_block, "height", -1))
    if height != 0:
        return False, f"genesis block not included in snapshot (first height {height})"

    prev = getattr(entry_block, "prev_block_hash", b"")
    if isinstance(prev, (bytes, bytearray)):
        prev_hex = bytes(prev).hex()
    else:
        prev_hex = str(prev or "").strip().lower()

    zero_hex = CFG.ZERO_HASH.hex() if isinstance(CFG.ZERO_HASH, (bytes, bytearray)) else bytes(CFG.ZERO_HASH).hex()
    if prev_hex != zero_hex:
        return False, "prev_block_hash genesis mismatch"

    expected_genesis = CFG.GENESIS_HASH_HEX
    if expected_genesis.startswith("0x"):
        expected_genesis = expected_genesis[2:]

    if expected_genesis:
        entry_hash = entry_block.hash().hex().lower()
        if entry_hash != expected_genesis:
            return False, f"genesis hash snapshot ({entry_hash}) does not match expected ({expected_genesis})"

    return True, None


__all__ = ["maybe_bootstrap_snapshot", "SnapshotBootstrapResult", "annotate_local_snapshot_meta"]
