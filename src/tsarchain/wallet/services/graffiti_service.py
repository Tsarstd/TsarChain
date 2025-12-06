# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173

from __future__ import annotations

import base64, json, os, socket, time, hashlib, mimetypes, tempfile
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from tsarchain.network.protocol import send_message, recv_message
from tsarchain.utils import config as CFG
from tsarchain.contracts.graffiti import validate_graffiti_file
from tsarchain.utils.tsar_logging import get_ctx_logger

log = get_ctx_logger("tsarchain.wallet.graffiti_service")


def _pick_endpoint(meta: Dict[str, Any]) -> Optional[Tuple[str, int]]:
    host = str(meta.get("ip") or "").strip()
    port = int(meta.get("port") or 0)
    if host and port > 0:
        return host, port

    url = str(meta.get("url") or "").strip()
    if url:
        parsed = urlparse(url if "://" in url else f"tcp://{url}")
        netloc = parsed.netloc or parsed.path
        if netloc:
            if ":" in netloc:
                host_part, port_part = netloc.split(":", 1)
                try:
                    port = int(port_part)
                except Exception:
                    port = 0
            else:
                host_part = netloc
            host_part = host_part.strip()
            if host_part:
                if port <= 0:
                    port = CFG.STORAGE_PORT_START or CFG.PORT_START
                if port <= 0:
                    return None
                return host_part, port
    return None


def _send_storage_request(host: str, port: int, payload: Dict[str, Any], timeout: float | None = None, max_len: int | None = None) -> Dict[str, Any]:
    timeout = timeout or CFG.RPC_TIMEOUT
    if max_len is None:
        max_len = int(CFG.GRAFFITI_MAX_MSG_BYTES, CFG.MAX_MSG)
    resp: Dict[str, Any] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))
            raw = json.dumps(payload).encode("utf-8")
            send_message(s, raw, max_len=max_len)
            data = recv_message(s, timeout, max_len=max_len)
            if not data:
                return {"status": "error", "reason": "no_response"}
            obj = json.loads(data.decode("utf-8"))
            if isinstance(obj, dict):
                resp = obj
            else:
                resp = {"status": "error", "reason": "bad_response"}
    except Exception as e:
        resp = {"status": "error", "reason": str(e)}
    return resp


def fetch_storers(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]], limit: Optional[int] = None) -> list[Dict[str, Any]]:
    resp = rpc_call({"type": "STOR_LIST"}) or {}
    storers = resp.get("storers") or resp.get("items") or []
    valid: list[Dict[str, Any]] = []
    for meta in storers:
        try:
            port = int(meta.get("port") or 0)
        except Exception:
            port = 0
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        if not addr or port <= 0:
            continue
        valid.append(meta)
    valid.sort(key=lambda m: int(m.get("last_seen", 0)), reverse=True)
    if limit is not None and limit > 0:
        return valid[:limit]
    return valid


def _sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(chunk), b""):
            if not part:
                break
            h.update(part)
    return h.hexdigest()


def upload_graffiti(
    storer_meta: Dict[str, Any],
    file_path: str,
    *,
    graffiti_id: Optional[str] = None,
    sha256_hex: Optional[str] = None,
    art_id: Optional[str] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """
    Upload a file to a storage node discovered from the TsarChain node RPC.

    rpc_call    : callable yang menerima dict dan mengembalikan response RPC node (sinkron).
    storer_addr : bech32 address storage target.
    file_path   : path file yang akan diunggah.
    graffiti_id : optional id unik (default = sha256_hex).
    sha256_hex  : optional file hash (akan dihitung jika None).
    progress_cb : optional callback(sent_bytes, total_bytes).
    """
    if not os.path.isfile(file_path):
        return {"status": "error", "reason": "file_not_found"}

    total_size = os.path.getsize(file_path)
    mime_guess, _ = mimetypes.guess_type(file_path)
    try:
        mime_norm = validate_graffiti_file(total_size, mime_guess, os.path.basename(file_path))
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}
    sha_hex = (sha256_hex or _sha256_file(file_path)).lower()
    gid = graffiti_id or sha_hex
    meta = dict(storer_meta or {})
    endpoint = _pick_endpoint(meta)
    if not endpoint:
        return {"status": "error", "reason": "storer_no_endpoint"}
    host, port = endpoint

    init_payload = {
        "type": "STOR_INIT",
        "graffiti_id": gid,
        "size_bytes": int(total_size),
        "sha256": sha_hex,
        "filename": os.path.basename(file_path) or "blob.bin",
        "mime": mime_norm,
    }
    if art_id:
        init_payload["art_id"] = str(art_id).strip().lower()
    init_resp = _send_storage_request(host, port, init_payload)
    if init_resp.get("status") not in ("ok", "accepted"):
        return {"status": "error", "stage": "init", "resp": init_resp}

    chunk_size = int(init_resp.get("chunk_size") or CFG.STORAGE_UPLOAD_CHUNK)
    sent = 0
    with open(file_path, "rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            put_payload = {
                "type": "STOR_PUT",
                "graffiti_id": gid,
                "data": base64.b64encode(buf).decode("ascii"),
            }
            put_resp = _send_storage_request(host, port, put_payload)
            if put_resp.get("status") not in ("ok", "accepted"):
                return {"status": "error", "stage": "put", "resp": put_resp}
            sent += len(buf)
            if progress_cb:
                try:
                    progress_cb(sent, total_size)
                except Exception:
                    pass

    commit_payload = {"type": "STOR_COMMIT", "graffiti_id": gid}
    commit_resp = _send_storage_request(host, port, commit_payload)
    if commit_resp.get("status") not in ("ok", "accepted"):
        return {"status": "error", "stage": "commit", "resp": commit_resp}

    receipt = commit_resp.get("receipt") or {"graffiti_id": gid, "sha256": sha_hex, "size_bytes": total_size}
    receipt.setdefault("id", receipt.get("receipt_id") or f"rcpt_{gid}_{int(time.time())}")
    return {
        "status": "ok",
        "graffiti_id": gid,
        "receipt": receipt,
        "storer": meta,
        "size_bytes": total_size,
        "sha256": sha_hex,
    }


def fetch_graffiti_file(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    art_id: str,
    *,
    storer_addr: Optional[str] = None,
    cache_dir: Optional[str] = None,
    max_bytes: int = CFG.GRAFFITI_MAX_SIZE_BYTES,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Ambil file graffiti dari storage node berdasarkan art_id.
    - rpc_call: fungsi sinkron ke node (mis. NodeClient.send)
    - storer_addr: preferensi alamat storage (bech32) bila tersedia
    - cache_dir: lokasi cache lokal (default data_user/graffiti_cache)
    Return: {"status": "ok", "bytes": b"...", "meta": {...}, "cache_path": "..."} atau {"status": "error", "reason": "..."}
    """
    art_norm = (art_id or "").strip().lower()
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

    try:
        max_bytes = int(max_bytes)
    except Exception:
        max_bytes = int(CFG.GRAFFITI_MAX_SIZE_BYTES)
    # Clamp by graffiti msg limit to avoid hitting generic MAX_MSG
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = int(msg_cap * 3 // 4)  # guard for base64/json overhead
    max_bytes = max(32 * 1024, min(max_bytes, int(CFG.GRAFFITI_MAX_SIZE_BYTES), data_cap))

    try:
        storers = fetch_storers(rpc_call)  # type: ignore[arg-type]
    except Exception as e:
        log.warning("[fetch] storers_unavailable art=%s err=%s", art_norm[:16], e)
        return {"status": "error", "reason": f"storers_unavailable:{e}"}

    if not storers:
        log.warning("[fetch] no_storers art=%s", art_norm[:16])
        return {"status": "error", "reason": "no_storers"}

    preferred, others = [], []
    storer_target = (storer_addr or "").strip().lower()
    for meta in storers:
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        (preferred if storer_target and addr == storer_target else others).append(meta)
    candidates = preferred + others

    cache_root = cache_dir or os.path.join("data_user", "graffiti_cache")
    os.makedirs(cache_root, exist_ok=True)

    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = int(msg_cap * 3 // 4)  # approximate base64 overhead guard

    last_error = None
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint
        payload = {"type": "STOR_GET_BY_ART", "art_id": art_norm, "include_data": True, "max_bytes": min(max_bytes, data_cap)}
        resp = _send_storage_request(host, port, payload, timeout=timeout, max_len=msg_cap)
        if not isinstance(resp, dict):
            last_error = "bad_response"
            log.warning("[fetch] bad_response art=%s host=%s port=%s meta=%s", art_norm[:16], host, port, meta)
            continue
        if not resp.get("found"):
            last_error = resp.get("reason") or "not_found"
            log.info("[fetch] not_found art=%s host=%s port=%s reason=%s meta=%s", art_norm[:16], host, port, last_error, meta)
            continue
        if resp.get("status") == "error":
            last_error = resp.get("reason") or "error"
            log.warning("[fetch] storage_error art=%s host=%s port=%s reason=%s meta=%s", art_norm[:16], host, port, last_error, meta)
            continue
        data_b64 = resp.get("data_b64")
        meta_resp = resp.get("meta") or {}
        if not data_b64:
            last_error = "no_data"
            log.warning("[fetch] no_data art=%s host=%s port=%s", art_norm[:16], host, port)
            continue
        try:
            raw = base64.b64decode(data_b64)
        except Exception:
            last_error = "decode_failed"
            log.warning("[fetch] decode_failed art=%s host=%s port=%s", art_norm[:16], host, port)
            continue
        fname = meta_resp.get("filename") or f"{art_norm}.bin"
        ext = ".jpg" if str(meta_resp.get("mime") or "").startswith("image/") else os.path.splitext(fname)[1] or ".bin"
        cache_path = os.path.join(cache_root, f"{art_norm}{ext}")
        try:
            with open(cache_path, "wb") as fh:
                fh.write(raw)
        except Exception:
            log.warning("[fetch] cache_write_failed art=%s path=%s", art_norm[:16], cache_path)
            cache_path = ""
            try:
                fd, tmp_path = tempfile.mkstemp(prefix=f"{art_norm}_", suffix=ext, dir=cache_root)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(raw)
                cache_path = tmp_path
            except Exception as exc:
                log.error("[fetch] cache_write_retry_failed art=%s err=%s", art_norm[:16], exc)
                cache_path = ""
        log.info("[fetch] ok art=%s host=%s size=%s cache=%s", art_norm[:16], host, len(raw), bool(cache_path))
        return {"status": "ok", "bytes": raw, "meta": meta_resp, "cache_path": cache_path}

    return {"status": "error", "reason": last_error or "unavailable"}


__all__ = ["fetch_storers", "upload_graffiti"]
