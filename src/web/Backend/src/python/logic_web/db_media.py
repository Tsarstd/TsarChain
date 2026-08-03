# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import os
import time
import base64
from typing import Any, Callable, Dict, Optional

from tsarchain.utils import config as CFG
from tsarchain.utils.benchmarks import benchmark
from kremlin.services.graffiti_service import _pick_endpoint, _send_storage_request

from tsarchain.utils.tsar_logging import get_ctx_logger
from web.Backend.src.python.logic_web import db_cache

log = get_ctx_logger("tsarchain.web.logic_web.db_media")


def _media_meta_key(art_id: str) -> bytes:
    return f"meta:{art_id}".encode("utf-8")


def _media_data_key(art_id: str) -> bytes:
    return f"data:{art_id}".encode("utf-8")


def _cache_media_error(art_id: str, reason: str, ttl_sec: int = db_cache.WEB_CACHE_TTL_SEC) -> None:
    store = db_cache._open_store()
    if store is None:
        return
    entry = {
        "ts": int(time.time()),
        "ttl": int(ttl_sec),
        "status": "error",
        "reason": str(reason or "error"),
    }
    try:
        store.put_bytes(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id), db_cache._serialize_payload(entry))
        store.delete(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
    except Exception:
        log.warning("[webdb] media_error cache failed art=%s", art_id[:16])


def _cache_media_success(art_id: str, meta: dict, cache_path: str, size: int, ttl_sec: int = 0) -> None:
    store = db_cache._open_store()
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
        store.put_bytes(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id), db_cache._serialize_payload(entry))
        store.delete(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
    except Exception:
        log.warning("[webdb] media_ok_path cache failed art=%s", art_id[:16])


def _load_media_entry(art_id: str) -> Optional[dict]:
    store = db_cache._open_store()
    if store is None:
        return None
    raw = store.get_bytes(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id))
    if raw is None:
        return None
    entry = db_cache._deserialize_payload(bytes(raw))
    if not entry or db_cache._is_expired(entry):
        try:
            store.delete(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id))
            store.delete(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
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
    ext = _guess_media_ext(meta, art_id)
    log.info("mime=%s", ext)
    cache_path = os.path.join(cache_root, f"{art_id}{ext}")
    try:
        os.makedirs(cache_root, exist_ok=True)
        if not os.path.exists(cache_path) or os.path.getsize(cache_path) != len(data):
            with open(cache_path, "wb") as fh:
                fh.write(data)
    except Exception:
        log.warning("[webdb] cache write failed art=%s", art_id[:16])
    return cache_path


def _get_cached_graffiti_file(art_id: str, cache_dir: Optional[str]) -> Optional[dict]:
    store = db_cache._open_store()
    if store is None:
        return None
    entry = _load_media_entry(art_id)
    if not entry:
        return None
    if entry.get("status") != "ok":
        return {"status": "error", "reason": entry.get("reason") or "not_found"}
    
    cache_path = entry.get("cache_path")
    expected_size = entry.get("size")
    if cache_path and expected_size is not None:
        if os.path.isfile(cache_path) and os.path.getsize(cache_path) == expected_size:
            log.info("[webdb] ok(cache_disk_hit) art=%s path=%s", art_id[:16], cache_path)
            return {"status": "ok", "meta": entry.get("meta") or {}, "cache_path": cache_path}
            
    data_raw = store.get_bytes(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
    if data_raw is None:
        return None
    cache_root = cache_dir or os.path.join("data", "web", "graffiti_cache")
    cache_path = _write_cache_file(cache_root, art_id, entry.get("meta") or {}, bytes(data_raw))
    return {"status": "ok", "meta": entry.get("meta") or {}, "cache_path": cache_path}


def fetch_storers(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    limit: Optional[int] = None,
    *,
    cache_scope: Optional[str] = None,
    ttl_sec: Optional[int] = None,
) -> list[Dict[str, Any]]:
    
    ttl_sec = int(ttl_sec or db_cache.WEB_STOR_LIST_TTL_SEC)
    cache_key = db_cache.make_cache_key("web", cache_scope, "stor_list")
    cached = db_cache.cache_get(cache_key)
    if isinstance(cached, list):
        return cached[:limit] if limit is not None and limit > 0 else cached

    resp = rpc_call({"type": "STOR_LIST"}) or {}
    if isinstance(resp, dict) and resp.get("error"):
        ttl_err = db_cache.get_error_cache_ttl(resp.get("error"))
        if ttl_err is not None:
            db_cache.cache_set(cache_key, [], ttl_sec=ttl_err)
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
        db_cache.cache_set(cache_key, valid, ttl_sec=ttl_sec)
    if limit is not None and limit > 0:
        return valid[:limit]
    return valid


def _do_oneshot_fetch(
    host: str,
    port: int,
    msg_cap: int,
    log_tag: str,
    art_norm: str,
    payload: dict,
    timeout: float,
    cache_root: str,
    meta_info: dict,
) -> object:
    
    resp = _send_storage_request(host, port, payload, timeout=max(float(timeout), 12.0), max_len=msg_cap)
    if not isinstance(resp, dict):
        return "bad_response"
    if not resp.get("found"):
        return resp.get("reason") or "not_found"
    if resp.get("status") == "error":
        return resp.get("reason") or "error"
    data_b64 = resp.get("data_b64")
    if not data_b64:
        return "no_data"
    raw = base64.b64decode(data_b64)
    meta_out = resp.get("meta") or meta_info
    cache_path = _write_cache_file(cache_root, art_norm, meta_out, raw)
    _cache_media_success(art_norm, meta_out, cache_path, len(raw), ttl_sec=0)
    log.info("[webdb] ok(%s) art=%s host=%s bytes=%s cache=%s", log_tag, art_norm[:16], host, len(raw), True)
    return {"status": "ok", "meta": meta_out, "cache_path": cache_path}


@benchmark(label="fetch_graffiti_file", threshold_ms=15.0)
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
    art_norm = os.path.basename(art_norm).replace("..", "").replace("/", "").replace("\\", "")
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

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

    cache_root = cache_dir or os.path.join("data", "web", "graffiti_cache")
    os.makedirs(cache_root, exist_ok=True)

    last_error = None
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint

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

        try:
            total_size = int(meta_info.get("size_bytes") or meta_info.get("size") or meta_info.get("bytes") or 0)
        except Exception:
            total_size = 0

        if total_size <= 0:
            payload = {
                "type": "STOR_GET_BY_ART",
                "art_id": art_norm,
                "include_data": True,
                "max_bytes": int(min(max_bytes, data_cap)),
            }
            res = _do_oneshot_fetch(
                host=host, port=port, payload=payload, timeout=timeout, msg_cap=msg_cap,
                art_norm=art_norm, meta_info=meta_info, cache_root=cache_root, log_tag="oneshot_unknown"
            )
            if isinstance(res, str):
                last_error = res
                continue
            return res

        if total_size > max_bytes:
            last_error = "file_too_large"
            continue

        ext = _guess_media_ext(meta_info, art_norm)
        cache_path = os.path.join(cache_root, f"{art_norm}{ext}")
        tmp_path = cache_path + ".part"

        try:
            if os.path.isfile(cache_path) and os.path.getsize(cache_path) == int(total_size):
                _cache_media_success(art_norm, meta_info, cache_path, int(total_size), ttl_sec=0)
                log.info("[webdb] ok(disk_hit) art=%s host=%s size=%s cache=%s", art_norm[:16], host, total_size, True)
                return {"status": "ok", "meta": meta_info, "cache_path": cache_path}
        except Exception:
            pass

        one_shot_limit = int(min(int(data_cap), 8 * 1024 * 1024))
        if int(total_size) <= one_shot_limit:
            payload = {
                "type": "STOR_GET_BY_ART",
                "art_id": art_norm,
                "include_data": True,
                "max_bytes": int(min(int(total_size), int(data_cap))),
            }
            res = _do_oneshot_fetch(
                host=host, port=port, payload=payload, timeout=timeout, msg_cap=msg_cap,
                art_norm=art_norm, meta_info=meta_info, cache_root=cache_root, log_tag="oneshot"
            )
            if isinstance(res, str):
                last_error = res
                continue
            return res

        burst = int(CFG.STOR_GET_RL_IP_BURST)
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
        _cache_media_success(art_norm, meta_info, cache_path, int(total_size), ttl_sec=0)
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
    ttl_err = db_cache.get_error_cache_ttl(reason)
    if ttl_err is not None:
        _cache_media_error(art_norm, reason, ttl_sec=ttl_err)
    return {"status": "error", "reason": reason}
