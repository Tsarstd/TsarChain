# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: libsecp256k1

from __future__ import annotations

import os, json, shutil, hashlib, tempfile, time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional
from ecdsa import BadSignatureError, SECP256k1, VerifyingKey

# ---------------- Local Project ----------------
from . import config as CFG
from ..storage.kv import iter_prefix, kv_enabled

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

    if CFG.BACKUP_SNAPSHOT and CFG.SNAPSHOT_BACKUP_DIR:
        try:
            os.makedirs(CFG.SNAPSHOT_BACKUP_DIR, exist_ok=True)
        except Exception:
            pass

    if not CFG.SNAPSHOT_BOOTSTRAP_ENABLED:
        return SnapshotBootstrapResult(status="skipped", reason="disabled")

    if ctx == "gui" and not CFG.SNAPSHOT_BOOTSTRAP_FOR_GUI:
        return SnapshotBootstrapResult(status="skipped", reason="gui_disabled")
    if ctx.startswith("cli") and not CFG.SNAPSHOT_BOOTSTRAP_FOR_CLI:
        return SnapshotBootstrapResult(status="skipped", reason="cli_disabled")

    manifest = _fetch_manifest()
    expected_sha = _safe_lower(manifest, "sha256")
    snapshot_url = (
        (manifest or {}).get("snapshot_url")
        or (manifest or {}).get("url")
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
        actual_sha = _hash_file(target_file)
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
            progress_cb(message)
        log.info("[bootstrap.%s] %s", ctx, message)

    tmp_path = None
    backup_path: Optional[str] = None
    replaced = False
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="tsar_snapshot_", suffix=".mdb")
        os.close(tmp_fd)

        actual_sha = _hash_file(tmp_path)
        if expected_sha and actual_sha != expected_sha:
            raise ValueError(f"sha256 mismatch (expected {expected_sha}, got {actual_sha})")

        final_size = os.path.getsize(tmp_path)
        if final_size < CFG.SNAPSHOT_MIN_SIZE_BYTES:
            raise ValueError(f"snapshot too small ({final_size} bytes)")

        if os.path.exists(target_file):
            backup_path = f"{target_file}.bak"
            shutil.move(target_file, backup_path)
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
            os.remove(backup_path)
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
        log.exception("[bootstrap.%s] Snapshot bootstrap failed", ctx)
        _emit(f"Snapshot bootstrap failed: {exc}")
        if replaced and os.path.exists(target_file):
            os.remove(target_file)
        if backup_path and os.path.exists(backup_path):
            os.replace(backup_path, target_file)
        return SnapshotBootstrapResult(status="failed", reason=str(exc))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


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
    with urllib.request.urlopen(req, timeout=CFG.SNAPSHOT_HTTP_TIMEOUT) as resp:
        raw = resp.read()
        return None
    manifest = json.loads(raw.decode("utf-8"))
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
    
    payload_dict = dict(manifest)
    payload_dict.pop("signature", None)
    payload = json.dumps(payload_dict, sort_keys=True, separators=CFG.CANONICAL_SEP).encode("utf-8")
    vk = VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=SECP256k1)
    vk.verify(bytes.fromhex(signature_hex), payload, hashfunc=hashlib.sha256)
    return True
    

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
    return int(source.get(key, 0))

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
        stat = os.stat(data_file)
        file_size = int(stat.st_size)
        if meta.get("size") != file_size:
            meta["size"] = file_size
            updated = True
            
        digest = _hash_file(data_file)
        if meta.get("sha256") != digest:
            meta["sha256"] = digest
            updated = True

    if not updated:
        return meta

    if not meta.get("applied_at"):
        meta["applied_at"] = int(time.time())
    _write_meta(meta_path, meta)
    return meta


__all__ = ["maybe_bootstrap_snapshot", "SnapshotBootstrapResult", "annotate_local_snapshot_meta"]


def _validate_snapshot_chain() -> tuple[bool, Optional[str]]:
    if not kv_enabled():
        return False, "KV backend disabled"
    db_dir = CFG.LMDB_DATA_FILE
    if not db_dir or not os.path.exists(db_dir):
        return False, "DB directory missing"

    items = list(iter_prefix("chain", b"h:"))
    if not items:
        return False, "empty chain db"

    items.sort(key=lambda kv: kv[0])
    _, first_val = items[0]
    try:
        entry = json.loads(first_val.decode("utf-8"))
    except Exception as exc:
        return False, f"chain entry invalid: {exc}"

    if not entry:
        return False, "chain entry missing"

    height = int(entry.get("height", -1))
    if height != 0:
        return False, f"genesis block not include in snapshot (first height {height})"

    prev = (entry.get("prev_block_hash") or "").strip().lower()
    zero_hex = CFG.ZERO_HASH.hex()
    if prev != zero_hex:
        return False, "prev_block_hash genesis missmatch"

    expected_genesis = CFG.GENESIS_HASH_HEX
    if expected_genesis:
        entry_hash = (entry.get("hash") or "").strip().lower()
        if not entry_hash:
            return False, "genesis hash not available in snapshot"
        if entry_hash != expected_genesis:
            return False, "genesis hash snapshot was not same in tsarchain network"

    return True, None
