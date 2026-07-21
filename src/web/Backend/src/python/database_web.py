# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import os
import json
import time
import base64
import threading

from typing import Any, Callable, Dict, Optional

from tsarchain.utils import config as CFG
from tsarchain.utils.benchmarks import benchmark
from tsarcore_native import open_storage as _native_open_storage
from kremlin.services.graffiti_service import _pick_endpoint, _send_storage_request

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.database_web")


WEB_CACHE_DB = "web_cache"
WEB_MEDIA_DB = "web_media"
WEB_CACHE_TTL_SEC = 60
WEB_CACHE_ERROR_TTL_SHORT = 8
WEB_STOR_LIST_TTL_SEC = 120

WEB_BLOCKS_DB = "web_blocks"
BLOCK_RANGE_LIMIT = 200
PREFETCH_INTERVAL = 30

_store = None
_store_lock = threading.RLock()
_native_warned = False

_prefetch_thread = None
_prefetch_running = False


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

# ============= RECEIPT CACHE HELPER ==============

def get_receipt_file(txid: str) -> str:
    txid_norm = str(txid or "").strip().lower()
    txid_safe = os.path.basename(txid_norm).replace("..", "").replace("/", "").replace("\\", "")
    if not txid_safe:
        return ""
    output_dir = "data/web/receipts"
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, f"{txid_safe[:64]}.jpg")

def is_receipt_fresh(file_path: str, max_age_seconds: int) -> bool:
    if not os.path.exists(file_path):
        return False
    
    try:
        file_age = time.time() - os.path.getmtime(file_path)
        return file_age <= max_age_seconds
    except Exception:
        return False

def read_receipt_file(file_path: str, txid: str) -> dict:
    with open(file_path, "rb") as f:
        image_bytes = f.read()
    
    base64_image = base64.b64encode(image_bytes).decode('utf-8')
    return {
        "status": "success",
        "message": "Receipt generated successfully (from cache)",
        "data_url": f"data:image/jpeg;base64,{base64_image}",
        "filename": f"{txid[:64]}.jpg",
        "size_bytes": len(image_bytes)
    }

def schedule_receipt_deletion(txid: str, delay_seconds: int):
    def delete_file():
        file_path = get_receipt_file(txid)
        if os.path.exists(file_path):
            os.remove(file_path)
            log.debug(f"Auto-deleted receipt file after {delay_seconds}s: {file_path}")
    
    timer = threading.Timer(delay_seconds, delete_file)
    timer.daemon = True
    timer.start()

def cleanup_receipt_files(max_age_seconds: int):
    output_dir = "data/web/receipts"
    if not os.path.exists(output_dir):
        return
    
    current_time = time.time()
    for filename in os.listdir(output_dir):
        if filename.endswith('.jpg'):
            file_path = os.path.join(output_dir, filename)
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > max_age_seconds:
                os.remove(file_path)
                log.debug(f"Cleaned up stale receipt file: {filename} (age: {file_age:.1f}s)")

# ============= RECEIPT CACHE END ==============

# ============= HISTORY BOOK CACHE HELPER ==============

def get_history_book_file(address: str) -> str:
    addr_norm = str(address or "").strip().lower()
    addr_safe = os.path.basename(addr_norm).replace("..", "").replace("/", "").replace("\\", "")
    if not addr_safe:
        return ""
    output_dir = "data/web/history_books"
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, f"history_{addr_safe[:16]}.pdf")

def is_history_book_fresh(file_path: str, max_age_seconds: int) -> bool:
    if not os.path.exists(file_path):
        return False
    
    try:
        file_age = time.time() - os.path.getmtime(file_path)
        return file_age <= max_age_seconds
    except Exception:
        return False

def read_history_book_file(file_path: str, address: str) -> dict:
    with open(file_path, "rb") as f:
        pdf_bytes = f.read()
    
    base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
    return {
        "status": "success",
        "message": "History Book generated successfully (from cache)",
        "data_url": f"data:application/pdf;base64,{base64_pdf}",
        "filename": f"history_{address}.pdf",
        "size_bytes": len(pdf_bytes)
    }

def schedule_history_book_deletion(address: str, delay_seconds: int):
    def delete_file():
        file_path = get_history_book_file(address)
        if os.path.exists(file_path):
            os.remove(file_path)
            log.debug(f"Auto-deleted history book file after {delay_seconds}s: {file_path}")
    
    timer = threading.Timer(delay_seconds, delete_file)
    timer.daemon = True
    timer.start()

def cleanup_history_book_files(max_age_seconds: int):
    output_dir = "data/web/history_books"
    if not os.path.exists(output_dir):
        return
    
    current_time = time.time()
    for filename in os.listdir(output_dir):
        if filename.endswith('.pdf'):
            file_path = os.path.join(output_dir, filename)
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > max_age_seconds:
                os.remove(file_path)
                log.debug(f"Cleaned up stale history book file: {filename} (age: {file_age:.1f}s)")

# ============= HISTORY BOOK CACHE END ==============

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
    
    if refresh_ttl and not _is_expired(entry):
        # Perbarui timestamp, perpanjang usia cache
        entry["ts"] = int(time.time())
        try:
            store.put_bytes(WEB_CACHE_DB, k, _json_dumps(entry))
        except Exception:
            pass
    
    if _is_expired(entry):
        try:
            store.delete(WEB_CACHE_DB, k)
        except Exception:
            pass
        return None
    
    return entry.get("payload")

def cache_set(key: str, payload: object, ttl_sec: int = WEB_CACHE_TTL_SEC) -> None:
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


# ==================== BLOCK RANGE PREFETCH SYSTEM ====================

def _block_key(height: int) -> bytes:
    return f"block:{height:08d}".encode("utf-8")

def save_blocks_permanent(blocks: list) -> None:
    store = _open_store()
    if store is None:
        return
    
    if not isinstance(blocks, list):
        return
    
    for block in blocks:
        if not isinstance(block, dict):
            continue
            
        height = block.get("height")
        if height is None:
            continue
            
        try:
            store.put_bytes(WEB_BLOCKS_DB, _block_key(int(height)), _json_dumps(block))
        except Exception:
            log.warning("[webdb] Failed to save block %s", height)

def get_block_from_storage(height: int) -> Optional[dict]:
    store = _open_store()
    if store is None:
        return None
    
    try:
        raw = store.get_bytes(WEB_BLOCKS_DB, _block_key(height))
        if raw:
            return _json_loads(bytes(raw))
    except Exception:
        log.exception("get_block_from_storage, fail")
    
    return None

def get_block_range_from_storage(start: int, limit: int) -> dict:
    store = _open_store()
    if store is None:
        return {"items": [], "has_more": True}
    
    items = []
    for offset in range(limit):
        height = start + offset
        block = get_block_from_storage(height)
        if block:
            items.append(block)
        else:
            break
    
    has_more = len(items) == limit
    
    return {
        "items": items,
        "start_height": start,
        "limit": limit,
        "has_more": has_more,
        "next_height": start + len(items) if has_more else None,
        "tip_height": None,
    }


def get_last_stored_height() -> int:
    store = _open_store()
    if store is None:
        return -1
    
    max_height = -1
    try:
        prefix = b"block:"
        for key_bytes, _ in store.iter_prefix(WEB_BLOCKS_DB, prefix):
            try:
                key_str = key_bytes.decode('utf-8')
                if key_str.startswith("block:"):
                    height_str = key_str[6:].lstrip('0')
                    if height_str == '':
                        height = 0
                    else:
                        height = int(height_str)
                    
                    if height > max_height:
                        max_height = height
            except (ValueError, IndexError) as e:
                log.debug("[webdb] Error parsing key %s: %s", key_bytes, e)
                continue
        
        
    except Exception as e:
        log.warning("[webdb] Error in get_last_stored_height: %s", e)
        return -1
    
    return max_height

def _store_initial_height_key() -> bytes:
    return b"prefetch:last_height"

def get_prefetch_last_height() -> int:
    store = _open_store()
    if store is None:
        return -1
    try:
        raw = store.get_bytes(WEB_CACHE_DB, _store_initial_height_key())
        if raw:
            return int(raw.decode("utf-8"))
    except Exception:
        pass
    return -1

def set_prefetch_last_height(height: int) -> None:
    store = _open_store()
    if store is None:
        return
    try:
        store.put_bytes(WEB_CACHE_DB, _store_initial_height_key(), 
                       str(height).encode("utf-8"))
    except Exception:
        log.warning("[webdb] Failed to save prefetch last height")

def prefetch_blocks(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]) -> bool:
    store = _open_store()
    if store is None:
        log.warning("[webdb] No storage available for prefetch")
        return False
    
    last_stored = get_prefetch_last_height()
    if last_stored == -1:
        last_stored = get_last_stored_height()
    
    try:
        network_info = rpc_call({"type": "GET_NETWORK_INFO"}) or {}
        tip_height = network_info.get("height") or network_info.get("tip_height")
        if tip_height is None:
            range_resp = rpc_call({"type": "GET_BLOCK_RANGE", "limit": 1}) or {}
            tip_height = range_resp.get("tip_height")
    except Exception as exc:
        log.warning("[webdb] Failed to get tip height: %s", exc)
        return False
    
    if tip_height is None or tip_height <= last_stored:
        return False
    
    blocks_to_fetch = min(tip_height - last_stored, BLOCK_RANGE_LIMIT)
    if blocks_to_fetch <= 0:
        return False
    
    log.info("[webdb] Prefetching %d blocks from height %d to %d", 
             blocks_to_fetch, last_stored + 1, tip_height)
    
    has_more = (tip_height - last_stored) > blocks_to_fetch
    
    try:
        start_height = last_stored + 1
        resp = rpc_call({
            "type": "GET_BLOCK_RANGE",
            "start_height": start_height,
            "limit": blocks_to_fetch
        }) or {}
        
        if isinstance(resp, dict) and resp.get("error"):
            log.warning("[webdb] Prefetch failed: %s", resp.get("error"))
            return False
        
        items = resp.get("items") or []
        if not items:
            log.info("[webdb] No new blocks to prefetch (empty response)")
            return False
        
        new_items = []
        for item in items:
            height = item.get("height")
            if height is None:
                continue
            
            existing = get_block_from_storage(height)
            if existing is None:
                new_items.append(item)
            else:
                log.debug("[webdb] Block %d already exists, skipping", height)
        
        if new_items:
            save_blocks_permanent(new_items)
            log.info("[webdb] Prefetched %d new blocks (height %d to %d)", 
                    len(new_items), new_items[0].get("height", 0), 
                    new_items[-1].get("height", 0))
            
            highest_new = max(item.get("height", 0) for item in new_items)
            set_prefetch_last_height(highest_new)
        else:
            log.info("[webdb] All blocks already exist in storage")
            # If all blocks already exist, update the prefetch height to the maximum height in items
            # to make progress and prevent scanning the same range in the next iterations
            valid_heights = [item.get("height") for item in items if item.get("height") is not None]
            if valid_heights:
                set_prefetch_last_height(max(valid_heights))
            
        return has_more
            
    except Exception as exc:
        log.warning("[webdb] Prefetch exception: %s", exc)
        return False

# ==================== BLOCK RANGE PREFETCH SEND ====================


def start_prefetch_thread(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]) -> None:
    global _prefetch_thread, _prefetch_running
    
    if _prefetch_running:
        return
    
    _prefetch_running = True
    
    def prefetch_worker():
        while _prefetch_running:
            try:
                has_more = prefetch_blocks(rpc_call)
            except Exception as exc:
                log.warning("[webdb] Prefetch worker exception: %s", exc)
                has_more = False
            
            if has_more and _prefetch_running:
                # Sleep briefly to prevent high CPU utilization during rapid catch-up
                time.sleep(0.1)
                continue
            
            for _ in range(PREFETCH_INTERVAL * 10):
                if not _prefetch_running:
                    break
                time.sleep(0.1)
    
    _prefetch_thread = threading.Thread(target=prefetch_worker, daemon=True)
    _prefetch_thread.name = "block-prefetch-worker"
    _prefetch_thread.start()
    
    log.info("[webdb] Block prefetch thread started (interval=%ds)", PREFETCH_INTERVAL)

def stop_prefetch_thread() -> None:
    global _prefetch_running
    _prefetch_running = False

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
    store = _open_store()
    if store is None:
        return None
    entry = _load_media_entry(art_id)
    if not entry:
        return None
    if entry.get("status") != "ok":
        return {"status": "error", "reason": entry.get("reason") or "not_found"}
    
    # Check if the cache file already exists on disk with correct size
    cache_path = entry.get("cache_path")
    expected_size = entry.get("size")
    if cache_path and expected_size is not None:
        if os.path.isfile(cache_path) and os.path.getsize(cache_path) == expected_size:
            log.info("[webdb] ok(cache_disk_hit) art=%s path=%s", art_id[:16], cache_path)
            return {"status": "ok", "meta": entry.get("meta") or {}, "cache_path": cache_path}
            
    data_raw = store.get_bytes(WEB_MEDIA_DB, _media_data_key(art_id))
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
    
    ttl_sec = int(ttl_sec or WEB_STOR_LIST_TTL_SEC)
    cache_key = make_cache_key("web", cache_scope, "stor_list")
    cached = cache_get_json(cache_key)
    if isinstance(cached, list):
        return cached[:limit] if limit is not None and limit > 0 else cached

    resp = rpc_call({"type": "STOR_LIST"}) or {}
    if isinstance(resp, dict) and resp.get("error"):
        ttl_err = cache_ttl_for_error(resp.get("error"))
        if ttl_err is not None:
            cache_set(cache_key, [], ttl_sec=ttl_err)
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
        cache_set(cache_key, valid, ttl_sec=ttl_sec)
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
    _cache_media_ok_path(art_norm, meta_out, cache_path, len(raw), ttl_sec=0)
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

    cache_root = cache_dir or os.path.join("data", "web", "graffiti_cache")
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
            res = _do_oneshot_fetch(
                host=host, port=port, payload=payload, timeout=timeout, msg_cap=msg_cap,
                art_norm=art_norm, meta_info=meta_info, cache_root=cache_root, log_tag="oneshot"
            )
            if isinstance(res, str):
                last_error = res
                continue
            return res

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
    "cache_set",
    "cache_ttl_for_error",
    "fetch_graffiti_file",
    "fetch_storers",
    "make_cache_key",
    "should_cache_error",
    "save_blocks_permanent",
    "get_block_from_storage",
    "get_block_range_from_storage",
    "get_last_stored_height",
    "prefetch_blocks",
    "start_prefetch_thread",
    "stop_prefetch_thread",
    "cleanup_receipt_files",
    "schedule_receipt_deletion",
    "read_receipt_file",
    "is_receipt_fresh",
    "get_receipt_file"
]