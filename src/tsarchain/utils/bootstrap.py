# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

from __future__ import annotations

import os, json, shutil, hashlib, tempfile, time
import lmdb
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional
from ecdsa import BadSignatureError, SECP256k1, VerifyingKey

# ---------------- Local Project ----------------
from . import config as CFG
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


def maybe_bootstrap_snapshot(context: str = "default", progress_cb: ProgressCallback = None) -> SnapshotBootstrapResult:
    ctx = (context or "default").lower()
    start_time = time.time()
    target_file = CFG.LMDB_DATA_FILE
    meta_path = CFG.SNAPSHOT_META_PATH
    os.makedirs(os.path.dirname(target_file), exist_ok=True)

    if not CFG.SNAPSHOT_BOOTSTRAP_ENABLED:
        return SnapshotBootstrapResult(status="skipped", reason="disabled")

    if ctx == "gui" and not CFG.SNAPSHOT_BOOTSTRAP_FOR_GUI:
        return SnapshotBootstrapResult(status="skipped", reason="gui_disabled")
    if ctx.startswith("cli") and not CFG.SNAPSHOT_BOOTSTRAP_FOR_CLI:
        return SnapshotBootstrapResult(status="skipped", reason="cli_disabled")

    manifest = _fetch_manifest()
    if manifest is None and not CFG.SNAPSHOT_FILE_URL:
        return SnapshotBootstrapResult(status="skipped", reason="no_source")

    expected_sha = _safe_lower(manifest, "sha256")
    expected_size = _safe_int(manifest, "size")
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
                log.warning("[bootstrap] Manifest too old (%ss)", age)

    if not snapshot_url:
        return SnapshotBootstrapResult(status="skipped", reason="no_snapshot_url")

    local_meta = _load_meta(meta_path)
    have_local = os.path.exists(target_file)
    actual_sha = None
    if expected_sha and have_local:
        try:
            actual_sha = _hash_file(target_file)
        except Exception as exc:
            log.warning("[bootstrap.%s] Failed hashing local snapshot: %s", ctx, exc)
            actual_sha = None
    if expected_sha and local_meta.get("sha256") == expected_sha and have_local:
        if actual_sha == expected_sha:
            return SnapshotBootstrapResult(
                status="skipped",
                reason="already_current",
                height=local_meta.get("height"),
            )
        log.warning(
            "[bootstrap.%s] Local snapshot hash mismatch (expected %s, got %s); forcing re-download",
            ctx,
            expected_sha,
            actual_sha or "unknown",
        )

    if os.path.exists(target_file) and not expected_sha and os.path.getsize(target_file) >= CFG.SNAPSHOT_MIN_SIZE_BYTES:
        return SnapshotBootstrapResult(status="skipped", reason="no_manifest_hash")

    def _emit(message: str) -> None:
        if progress_cb:
            try:
                progress_cb(message)
            except Exception:
                pass
        log.info("[bootstrap.%s] %s", ctx, message)

    tmp_path = None
    bytes_written = 0
    backup_path: Optional[str] = None
    replaced = False
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="tsar_snapshot_", suffix=".mdb")
        os.close(tmp_fd)

        bytes_written = _download_snapshot(snapshot_url, tmp_path, expected_size, _emit)
        actual_sha = _hash_file(tmp_path)
        if expected_sha and actual_sha != expected_sha:
            raise ValueError(f"sha256 mismatch (expected {expected_sha}, got {actual_sha})")

        final_size = os.path.getsize(tmp_path)
        if final_size < CFG.SNAPSHOT_MIN_SIZE_BYTES:
            raise ValueError(f"snapshot too small ({final_size} bytes)")

        if os.path.exists(target_file):
            backup_path = f"{target_file}.bak"
            try:
                shutil.move(target_file, backup_path)
            except Exception:
                backup_path = None
        os.replace(tmp_path, target_file)
        replaced = True

        meta = {
            "sha256": actual_sha,
            "size": final_size,
            "height": height,
            "source": snapshot_url,
            "generated_at": generated_at,
            "applied_at": int(time.time()),
        }
        _write_meta(meta_path, meta)
        valid, validate_reason = _validate_snapshot_chain()
        if not valid:
            raise ValueError(validate_reason or "snapshot validation failed")
        if backup_path and os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except Exception:
                pass
        duration = time.time() - start_time
        _emit(f"Snapshot applied ({final_size/1_048_576:.2f} MB in {duration:.1f}s)")

        return SnapshotBootstrapResult(
            status="installed",
            bytes_written=final_size,
            height=height,
            source=snapshot_url,
            duration_s=duration,
        )

    except Exception as exc:
        _emit(f"Snapshot bootstrap failed: {exc}")
        if replaced and os.path.exists(target_file):
            try:
                os.remove(target_file)
            except Exception:
                pass
        if backup_path and os.path.exists(backup_path):
            try:
                os.replace(backup_path, target_file)
            except Exception:
                pass
        return SnapshotBootstrapResult(status="failed", reason=str(exc))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


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
    except urllib.error.URLError as exc:
        log.warning("[bootstrap] manifest fetch failed: %s", exc)
        return None
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except Exception:
        log.warning("[bootstrap] manifest decode failed")
        return None
    return manifest


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
        payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        vk = VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=SECP256k1)
        vk.verify(bytes.fromhex(signature_hex), payload, hashfunc=hashlib.sha256)
        return True
    
    except (BadSignatureError, ValueError) as exc:
        log.warning("[bootstrap] manifest signature invalid: %s", exc)
        return False


def _download_snapshot(url: str, dest: str, expected_size: int, emit: Callable[[str], None]) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": CFG.SNAPSHOT_USER_AGENT})
    bytes_written = 0
    next_report = 0
    expected = max(0, int(expected_size or 0))
    with urllib.request.urlopen(req, timeout=CFG.SNAPSHOT_HTTP_TIMEOUT) as resp, open(dest, "wb") as handle:
        while True:
            chunk = resp.read(CFG.SNAPSHOT_CHUNK_BYTES)
            if not chunk:
                break
            
            handle.write(chunk)
            bytes_written += len(chunk)
            if expected:
                progress = bytes_written / expected
                if bytes_written >= next_report:
                    emit(f"Mengunduh snapshot {progress:.0%} ({bytes_written/1_048_576:.1f} MB)")
                    next_report = bytes_written + max(CFG.SNAPSHOT_CHUNK_BYTES * 4, expected // 10 or CFG.SNAPSHOT_CHUNK_BYTES * 4)
            else:
                if bytes_written >= next_report:
                    emit(f"Mengunduh snapshot {bytes_written/1_048_576:.1f} MB")
                    next_report = bytes_written + CFG.SNAPSHOT_CHUNK_BYTES * 4
    if expected and bytes_written < expected:
        emit(f"Snapshot download smaller than expected ({bytes_written} < {expected})")
    return bytes_written


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
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def _write_meta(path: str, data: dict) -> None:
    tmp_path = f"{path}.tmp"
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
    try:
        return int(source.get(key, 0))
    except Exception:
        return 0


def annotate_local_snapshot_meta(height: Optional[int], tip_timestamp: Optional[int] = None) -> Optional[dict]:
    meta_path = CFG.SNAPSHOT_META_PATH
    data_file = CFG.LMDB_DATA_FILE
    if not meta_path or not os.path.exists(meta_path):
        return None
    meta = _load_meta(meta_path)
    updated = False

    if height is not None and height >= 0:
        h = int(height)
        if meta.get("height") != h:
            meta["height"] = h
            updated = True

    if tip_timestamp:
        ts = int(tip_timestamp)
        if ts > 0 and meta.get("generated_at") != ts:
            meta["generated_at"] = ts
            updated = True

    file_size = None
    digest = None
    if data_file and os.path.exists(data_file):
        try:
            stat = os.stat(data_file)
            file_size = int(stat.st_size)
            if meta.get("size") != file_size:
                meta["size"] = file_size
                updated = True
        except Exception:
            pass
        try:
            digest = _hash_file(data_file)
            if meta.get("sha256") != digest:
                meta["sha256"] = digest
                updated = True
        except Exception:
            pass

    if not updated:
        return meta

    if not meta.get("applied_at"):
        meta["applied_at"] = int(time.time())
    _write_meta(meta_path, meta)
    return meta


__all__ = ["maybe_bootstrap_snapshot", "SnapshotBootstrapResult", "annotate_local_snapshot_meta"]


def _validate_snapshot_chain() -> tuple[bool, Optional[str]]:
    db_dir = getattr(CFG, "DB_DIR", "")
    if not db_dir or not os.path.exists(db_dir):
        return False, "DB directory missing"
    try:
        env = lmdb.open(db_dir, readonly=True, max_dbs=16, lock=False)
    except Exception as exc:
        return False, f"cannot open LMDB: {exc}"
    entry: Optional[dict] = None
    try:
        try:
            chain_db = env.open_db(b"chain")
        except Exception as exc:
            return False, f"chain db open failed: {exc}"
        with env.begin(db=chain_db, write=False) as txn:
            cur = txn.cursor()
            if not cur.first():
                return False, "chain db kosong"
            try:
                entry = json.loads(cur.value().decode("utf-8"))
            except Exception as exc:
                return False, f"chain entry invalid: {exc}"
    finally:
        try:
            env.close()
        except Exception:
            pass

    if not entry:
        return False, "chain entry missing"

    height = int(entry.get("height", -1))
    if height != 0:
        return False, f"snapshot tidak memuat genesis (height pertama {height})"
    prev = (entry.get("prev_block_hash") or "").strip().lower()
    zero_hex = getattr(CFG.ZERO_HASH, "hex", lambda: bytes(CFG.ZERO_HASH).hex())()
    if prev != zero_hex:
        return False, "prev_block_hash genesis tidak sesuai"
    return True, None
