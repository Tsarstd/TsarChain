# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse


from tsarcore_native import open_storage as _native_open_storage
from tsarchain.utils import config as CFG
from tsarchain.network.protocol import send_message, recv_message
from tsarchain.network.pow_token import solve_pow

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.database_web")


WEB_CACHE_DB = "web_cache"
WEB_MEDIA_DB = "web_media"
WEB_CACHE_TTL_SEC = 60  # TTL default cache web untuk data realtime (detik)
WEB_CACHE_ERROR_TTL_SHORT = 8  # TTL singkat untuk error sementara (detik)
WEB_STOR_LIST_TTL_SEC = 120  # TTL cache STOR_LIST (detik)

_store = None
_store_lock = threading.RLock()
_native_warned = False


def _open_store():
    global _store
    global _native_warned
    if _store is not None:
        return _store
    with _store_lock:
        if _store is not None:
            return _store
        if _native_open_storage is None:
            if not _native_warned:
                log.warning("[webdb] tsarcore_native unavailable; cache disabled")
                _native_warned = True
            return None
        try:
            _store = _native_open_storage(
                "lmdb",
                (CFG.WEB_DATABASE_PATH),
                map_size_init=int(CFG.LMDB_WEB_SIZE_INIT),
                map_size_max=int(CFG.LMDB_WEB_SIZE_MAX),
                pretty_json=False,
            )
        except Exception as exc:
            log.warning("[webdb] lmdb disabled: %s", exc)
            _store = None
    return _store


def _json_dumps(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=True, default=str, separators=(",", ":")).encode("utf-8")


def _json_loads(raw: bytes) -> Optional[dict]:
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _is_expired(entry: dict, now_ts: Optional[int] = None) -> bool:
    now_ts = int(now_ts or time.time())
    ts = int(entry.get("ts") or 0)
    ttl_raw = entry.get("ttl")
    if ttl_raw is None:
        ttl = int(WEB_CACHE_TTL_SEC)
    else:
        ttl = int(ttl_raw)
    if ttl <= 0:
        return False
    return ts <= 0 or now_ts - ts > ttl


def make_cache_key(prefix: str, *parts: object) -> str:
    items = []
    for part in (prefix, *parts):
        if part is None:
            continue
        txt = str(part).strip().lower()
        if not txt:
            continue
        items.append(txt)
    return ":".join(items)


def should_cache_error(reason: object) -> bool:
    txt = str(reason or "").strip().lower()
    if not txt:
        return False
    if txt == "not_found" or txt == "height_out_of_range":
        return True
    return "not found" in txt


def cache_ttl_for_error(reason: object) -> Optional[int]:
    txt = str(reason or "").strip().lower()
    if not txt:
        return None
    if txt in ("pow_required", "rate_limited", "timeout", "rpc_timeout", "rpc_exception", "no_response"):
        return WEB_CACHE_ERROR_TTL_SHORT
    if "timeout" in txt or "rate limit" in txt or "pow_required" in txt:
        return WEB_CACHE_ERROR_TTL_SHORT
    if should_cache_error(txt):
        return WEB_CACHE_TTL_SEC
    return None


def cache_get_json(key: str, refresh_ttl: bool = False) -> Optional[object]:
    store = _open_store()
    if store is None:
        return None
    k = key.encode("utf-8")
    try:
        raw = store.get_bytes(WEB_CACHE_DB, k)
    except Exception:
        log.warning("[webdb] cache_get failed key=%s", key)
        return None
    if raw is None:
        return None
    
    entry = _json_loads(bytes(raw))
    if not entry:
        return None
    
    # PERUBAHAN: Refresh TTL jika diminta
    if refresh_ttl and not _is_expired(entry):
        # Perbarui timestamp, perpanjang usia cache
        entry["ts"] = int(time.time())
        try:
            store.put_bytes(WEB_CACHE_DB, k, _json_dumps(entry))
        except Exception:
            pass  # Jangan gagal hanya karena refresh gagal
    
    if _is_expired(entry):
        try:
            store.delete(WEB_CACHE_DB, k)
        except Exception:
            pass
        return None
    
    return entry.get("payload")


def cache_set_json(key: str, payload: object, ttl_sec: int = WEB_CACHE_TTL_SEC) -> None:
    log.debug("cache_set_json. key=%s ttl=%s", key, ttl_sec)
    store = _open_store()
    if store is None:
        return
    entry = {
        "ts": int(time.time()),
        "ttl": int(ttl_sec),
        "payload": payload,
    }
    try:
        store.put_bytes(WEB_CACHE_DB, key.encode("utf-8"), _json_dumps(entry))
    except Exception:
        log.warning("[webdb] cache_set failed key=%s", key)


def _media_meta_key(art_id: str) -> bytes:
    return f"meta:{art_id}".encode("utf-8")


def _media_data_key(art_id: str) -> bytes:
    return f"data:{art_id}".encode("utf-8")


def _cache_media_error(art_id: str, reason: str, ttl_sec: int = WEB_CACHE_TTL_SEC) -> None:
    store = _open_store()
    if store is None:
        return
    entry = {
        "ts": int(time.time()),
        "ttl": int(ttl_sec),
        "status": "error",
        "reason": str(reason or "error"),
    }
    try:
        store.put_bytes(WEB_MEDIA_DB, _media_meta_key(art_id), _json_dumps(entry))
        store.delete(WEB_MEDIA_DB, _media_data_key(art_id))
    except Exception:
        log.warning("[webdb] media_error cache failed art=%s", art_id[:16])

def _cache_media_ok_path(art_id: str, meta: dict, cache_path: str, size: int, ttl_sec: int = 0) -> None:
    """Cache media metadata + disk path (preferred for large blobs)."""
    store = _open_store()
    if store is None:
        return
    entry = {
        "ts": int(time.time()),
        "ttl": int(ttl_sec),
        "status": "ok",
        "meta": meta or {},
        "size": int(size or 0),
        "cache_path": str(cache_path or ""),
    }
    try:
        store.put_bytes(WEB_MEDIA_DB, _media_meta_key(art_id), _json_dumps(entry))
        store.delete(WEB_MEDIA_DB, _media_data_key(art_id))
    except Exception:
        log.warning("[webdb] media_ok_path cache failed art=%s", art_id[:16])


def _load_media_entry(art_id: str) -> Optional[dict]:
    store = _open_store()
    if store is None:
        return None
    raw = store.get_bytes(WEB_MEDIA_DB, _media_meta_key(art_id))
    if raw is None:
        return None
    entry = _json_loads(bytes(raw))
    if not entry or _is_expired(entry):
        try:
            store.delete(WEB_MEDIA_DB, _media_meta_key(art_id))
            store.delete(WEB_MEDIA_DB, _media_data_key(art_id))
        except Exception:
            pass
        return None
    return entry


def _guess_media_ext(meta: dict, art_id: str) -> str:
    fname = str(meta.get("filename") or f"{art_id}.bin")
    ext = os.path.splitext(fname)[1] or ""
    mime = str(meta.get("mime") or "")
    if mime.startswith("image/"):
        if ext.lower() in (".jpg", ".jpeg"):
            return ext
        return ".jpg"
    if mime.startswith("video/"):
        return ".mp4" if ext.lower() != ".mp4" else ext
    return ext or ".bin"


def _write_cache_file(cache_root: str, art_id: str, meta: dict, data: bytes) -> str:
    os.makedirs(cache_root, exist_ok=True)
    ext = _guess_media_ext(meta, art_id)
    cache_path = os.path.join(cache_root, f"{art_id}{ext}")
    try:
        if not os.path.exists(cache_path) or os.path.getsize(cache_path) != len(data):
            with open(cache_path, "wb") as fh:
                fh.write(data)
    except Exception:
        log.warning("[webdb] cache write failed art=%s", art_id[:16])
    return cache_path


def _get_cached_graffiti_file(art_id: str, cache_dir: Optional[str]) -> Optional[dict]:
    store = _open_store()
    if store is None:
        return None
    entry = _load_media_entry(art_id)
    if not entry:
        return None
    if entry.get("status") != "ok":
        return {"status": "error", "reason": entry.get("reason") or "not_found"}
    data_raw = store.get_bytes(WEB_MEDIA_DB, _media_data_key(art_id))
    if data_raw is None:
        return None
    cache_root = cache_dir or os.path.join("data_user", "graffiti_cache")
    cache_path = _write_cache_file(cache_root, art_id, entry.get("meta") or {}, bytes(data_raw))
    return {"status": "ok", "meta": entry.get("meta") or {}, "cache_path": cache_path}


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
                port = int(port_part)
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


def _send_storage_request(
    host: str,
    port: int,
    payload: Dict[str, Any],
    timeout: Optional[float] = None,
    max_len: Optional[int] = None,
    identity_hint: Optional[str] = None,
    max_pow_retry: int = 1,
) -> Dict[str, Any]:
    
    timeout = timeout or CFG.RPC_TIMEOUT
    if max_len is None:
        max_len = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    base_payload = dict(payload)
    identity_norm = (identity_hint or base_payload.get("wallet_addr") or base_payload.get("creator_addr") or "").strip().lower()
    resp: Dict[str, Any] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        raw = json.dumps(base_payload).encode("utf-8")
        send_message(sock, raw, max_len=max_len)
        data = recv_message(sock, timeout, max_len=max_len)
        if not data:
            return {"status": "error", "reason": "no_response"}
        obj = json.loads(data.decode("utf-8"))
        if isinstance(obj, dict):
            resp = obj
        else:
            resp = {"status": "error", "reason": "bad_response"}
    pow_challenge = resp.get("pow_challenge") if isinstance(resp, dict) else None
    need_pow = resp.get("reason") in ("pow_required", "rate_limited") if isinstance(resp, dict) else False
    if max_pow_retry > 0 and pow_challenge:
        identity_for_pow = identity_norm or str(pow_challenge.get("identity") or "")
        solution = solve_pow(pow_challenge, identity=identity_for_pow or "anon")
        if solution:
            retry_payload = dict(base_payload)
            retry_payload["pow"] = solution
            return _send_storage_request(
                host,
                port,
                retry_payload,
                timeout=timeout,
                max_len=max_len,
                identity_hint=identity_for_pow,
                max_pow_retry=max_pow_retry - 1,
            )
        if need_pow and "reason" not in resp:
            resp["reason"] = "pow_required"
    return resp


def fetch_storers(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    limit: Optional[int] = None,
    *,
    cache_scope: Optional[str] = None,
    ttl_sec: Optional[int] = None,
) -> list[Dict[str, Any]]:
    ttl_sec = int(ttl_sec or WEB_STOR_LIST_TTL_SEC)
    cache_key = make_cache_key("web", cache_scope, "stor_list")
    cached = cache_get_json(cache_key)
    if isinstance(cached, list):
        return cached[:limit] if limit is not None and limit > 0 else cached

    resp = rpc_call({"type": "STOR_LIST"}) or {}
    if isinstance(resp, dict) and resp.get("error"):
        ttl_err = cache_ttl_for_error(resp.get("error"))
        if ttl_err is not None:
            cache_set_json(cache_key, [], ttl_sec=ttl_err)
        return []

    storers = resp.get("storers") or resp.get("items") or []
    valid: list[Dict[str, Any]] = []
    for meta in storers:
        port = int(meta.get("port") or 0)
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        if not addr or port <= 0:
            continue
        valid.append(meta)
    valid.sort(key=lambda m: int(m.get("last_seen", 0)), reverse=True)
    if ttl_sec > 0:
        cache_set_json(cache_key, valid, ttl_sec=ttl_sec)
    if limit is not None and limit > 0:
        return valid[:limit]
    return valid


def fetch_graffiti_file(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    art_id: str,
    *,
    storer_addr: Optional[str] = None,
    cache_dir: Optional[str] = None,
    cache_scope: Optional[str] = None,
    stor_list_ttl_sec: Optional[int] = None,
    max_bytes: int = CFG.GRAFFITI_MAX_SIZE_BYTES,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    art_norm = (art_id or "").strip().lower()
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

    # Cache first
    cached = _get_cached_graffiti_file(art_norm, cache_dir)
    if cached is not None:
        return cached

    max_bytes = max(32 * 1024, min(int(max_bytes), int(CFG.GRAFFITI_MAX_SIZE_BYTES)))
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = int(msg_cap * 3 // 4)

    storers = fetch_storers(rpc_call, cache_scope=cache_scope, ttl_sec=stor_list_ttl_sec)
    if not storers:
        return {"status": "error", "reason": "no_storers"}

    preferred, others = [], []
    storer_target = (storer_addr or "").strip().lower()
    for meta in storers:
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        (preferred if storer_target and addr == storer_target else others).append(meta)
    candidates = preferred + others

    cache_root = cache_dir or os.path.join("data_user", "graffiti_cache")
    os.makedirs(cache_root, exist_ok=True)

    last_error = None
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint

        # 1) Fetch metadata only (fast/small)
        meta_payload = {"type": "STOR_GET_BY_ART", "art_id": art_norm, "include_data": False}
        meta_resp = _send_storage_request(host, port, meta_payload, timeout=max(float(timeout), 8.0), max_len=msg_cap)

        if not isinstance(meta_resp, dict):
            last_error = "bad_response"
            continue
        if not meta_resp.get("found"):
            last_error = meta_resp.get("reason") or "not_found"
            continue
        if meta_resp.get("status") == "error":
            last_error = meta_resp.get("reason") or "error"
            continue

        gid = str(meta_resp.get("graffiti_id") or "").strip()
        meta_info = meta_resp.get("meta") or {}

        # Determine total file size from meta (preferred). Fallback to 0 (unknown).
        try:
            total_size = int(meta_info.get("size_bytes") or meta_info.get("size") or meta_info.get("bytes") or 0)
        except Exception:
            total_size = 0

        # If size is unknown, attempt a one-shot bounded fetch (may still fail with file_too_large).
        if total_size <= 0:
            payload = {
                "type": "STOR_GET_BY_ART",
                "art_id": art_norm,
                "include_data": True,
                "max_bytes": int(min(max_bytes, data_cap)),
            }
            resp = _send_storage_request(host, port, payload, timeout=max(float(timeout), 12.0), max_len=msg_cap)
            if not isinstance(resp, dict):
                last_error = "bad_response"
                continue
            if not resp.get("found"):
                last_error = resp.get("reason") or "not_found"
                continue
            if resp.get("status") == "error":
                last_error = resp.get("reason") or "error"
                continue
            data_b64 = resp.get("data_b64")
            if not data_b64:
                last_error = "no_data"
                continue
            raw = base64.b64decode(data_b64)
            meta_out = resp.get("meta") or meta_info
            cache_path = _write_cache_file(cache_root, art_norm, meta_out, raw)
            _cache_media_ok_path(art_norm, meta_out, cache_path, len(raw), ttl_sec=0)
            log.info("[webdb] ok(oneshot_unknown) art=%s host=%s bytes=%s cache=%s", art_norm[:16], host, len(raw), True)
            return {"status": "ok", "meta": meta_out, "cache_path": cache_path}

        if total_size > max_bytes:
            last_error = "file_too_large"
            continue

        ext = _guess_media_ext(meta_info, art_norm)
        cache_path = os.path.join(cache_root, f"{art_norm}{ext}")
        tmp_path = cache_path + ".part"

        # If the file already exists on disk and matches size, use it.
        try:
            if os.path.isfile(cache_path) and os.path.getsize(cache_path) == int(total_size):
                _cache_media_ok_path(art_norm, meta_info, cache_path, int(total_size), ttl_sec=0)
                log.info("[webdb] ok(disk_hit) art=%s host=%s size=%s cache=%s", art_norm[:16], host, total_size, True)
                return {"status": "ok", "meta": meta_info, "cache_path": cache_path}
        except Exception:
            pass

        # 2) Small file: one-shot is fine
        one_shot_limit = int(min(int(data_cap), 8 * 1024 * 1024))
        if int(total_size) <= one_shot_limit:
            payload = {
                "type": "STOR_GET_BY_ART",
                "art_id": art_norm,
                "include_data": True,
                "max_bytes": int(min(int(total_size), int(data_cap))),
            }
            resp = _send_storage_request(host, port, payload, timeout=max(float(timeout), 12.0), max_len=msg_cap)
            if not isinstance(resp, dict):
                last_error = "bad_response"
                continue
            if not resp.get("found"):
                last_error = resp.get("reason") or "not_found"
                continue
            if resp.get("status") == "error":
                last_error = resp.get("reason") or "error"
                continue
            data_b64 = resp.get("data_b64")
            if not data_b64:
                last_error = "no_data"
                continue
            raw = base64.b64decode(data_b64)
            meta_out = resp.get("meta") or meta_info
            cache_path = _write_cache_file(cache_root, art_norm, meta_out, raw)
            _cache_media_ok_path(art_norm, meta_out, cache_path, len(raw), ttl_sec=0)
            log.info("[webdb] ok(oneshot) art=%s host=%s bytes=%s cache=%s", art_norm[:16], host, len(raw), True)
            return {"status": "ok", "meta": meta_out, "cache_path": cache_path}

        # 3) Large file: chunked download (like wallet upload)
        burst = int(CFG.STOR_GET_RL_IP_BURST)
        # keep calls modest to reduce overhead and avoid rate limiting
        target_calls = max(2, min(8, max(2, burst - 2)))
        chunk_raw = (int(total_size) + int(target_calls) - 1) // int(target_calls)
        chunk_raw = max(1024 * 1024, int(chunk_raw))
        chunk_raw = min(int(chunk_raw), int(min(int(data_cap), 64 * 1024 * 1024)))

        dl_timeout = max(float(timeout), 20.0)

        offset = 0
        calls = 0
        start_ts = time.time()
        ok = True

        try:
            with open(tmp_path, "wb") as out:
                while offset < int(total_size):
                    want = min(int(chunk_raw), int(total_size) - int(offset))
                    chunk_payload = {
                        "type": "STOR_GET_BY_ART",
                        "art_id": art_norm,
                        "include_data": True,
                        "offset": int(offset),
                        "length": int(want),
                        "max_bytes": int(want),
                    }
                    if gid:
                        chunk_payload["graffiti_id"] = gid

                    resp = _send_storage_request(host, port, chunk_payload, timeout=dl_timeout, max_len=msg_cap)
                    calls += 1

                    if not isinstance(resp, dict):
                        last_error = "bad_response"
                        ok = False
                        break
                    if not resp.get("found"):
                        last_error = resp.get("reason") or "not_found"
                        ok = False
                        break
                    if resp.get("status") == "error":
                        last_error = resp.get("reason") or "error"
                        ok = False
                        break

                    data_b64 = resp.get("data_b64") or ""
                    if not data_b64:
                        last_error = "no_data"
                        ok = False
                        break
                    chunk = base64.b64decode(data_b64)
                    if not chunk:
                        last_error = "no_data"
                        ok = False
                        break
                    out.write(chunk)
                    offset += len(chunk)

                    # Safety: if server returns less than requested and no progress -> bail
                    if len(chunk) == 0:
                        last_error = "no_progress"
                        ok = False
                        break

            if not ok:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
                continue

            os.replace(tmp_path, cache_path)

        except Exception:
            last_error = "io_error"
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            continue

        elapsed = max(0.001, time.time() - start_ts)
        mbps = (float(total_size) / (1024 * 1024)) / elapsed
        _cache_media_ok_path(art_norm, meta_info, cache_path, int(total_size), ttl_sec=0)
        log.info(
            "[webdb] ok(chunked) art=%s host=%s size=%s chunk=%s calls~%s speed=%.2fMB/s cache=%s",
            art_norm[:16],
            host,
            int(total_size),
            int(chunk_raw),
            int(calls),
            float(mbps),
            True,
        )
        return {"status": "ok", "meta": meta_info, "cache_path": cache_path}

    reason = last_error or "unavailable"
    ttl_err = cache_ttl_for_error(reason)
    if ttl_err is not None:
        _cache_media_error(art_norm, reason, ttl_sec=ttl_err)
    return {"status": "error", "reason": reason}



__all__ = [
    "WEB_CACHE_TTL_SEC",
    "WEB_CACHE_ERROR_TTL_SHORT",
    "WEB_STOR_LIST_TTL_SEC",
    "cache_get_json",
    "cache_set_json",
    "cache_ttl_for_error",
    "fetch_graffiti_file",
    "fetch_storers",
    "make_cache_key",
    "should_cache_error",
]
