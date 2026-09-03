# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import time
import threading
from typing import Any, Callable, Dict, Optional

from web.Backend.src.core.logic_web import db_cache

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.Backend.src.core.logic_web.db_blocks")

WEB_BLOCKS_DB = "web_blocks"
BLOCK_RANGE_LIMIT = 200
PREFETCH_INTERVAL = 30

_prefetch_thread = None
_prefetch_running = False
_prefetch_stop_event = threading.Event()


def save_blocks_to_storage(blocks: list) -> None:
    store = db_cache.open_web_store()
    if store is None or not blocks:
        return
    
    max_h = -1
    for block in blocks:
        if not block or type(block) is not dict:
            continue
        height = block.get("height")
        if height is None:
            continue
            
        try:
            h_int = int(height)
            store.put_bytes(WEB_BLOCKS_DB, _block_key(h_int), db_cache._serialize_payload(block))
            if h_int > max_h:
                max_h = h_int
        except Exception as exc:
            log.warning("[webdb] Failed to save block %s: %s", height, exc)

    if max_h >= 0:
        prev_max = get_last_stored_height()
        if max_h > prev_max:
            store.put_bytes(WEB_BLOCKS_DB, _meta_max_height_key(), str(max_h).encode("utf-8"))


def get_block_from_storage(height: int) -> Optional[dict]:
    store = db_cache.open_web_store()
    if store is None:
        return None
    
    try:
        raw = store.get_bytes(WEB_BLOCKS_DB, _block_key(height))
        if raw:
            return db_cache._deserialize_payload(bytes(raw))
    except Exception:
        log.exception("get_block_from_storage, fail")
    
    return None


def get_block_range_from_storage(start: int, limit: int) -> dict:
    store = db_cache.open_web_store()
    if store is None:
        return {"items": [], "has_more": True}
    
    items = []
    for offset in range(limit):
        height = start - offset
        if height < 0:
            break
        block = get_block_from_storage(height)
        if block:
            items.append(block)
        else:
            break
    
    next_h = start - len(items)
    has_more = next_h >= 0 and len(items) == limit
    
    tip_h = get_last_stored_height()
    if (tip_h is None or tip_h < 0) and items:
        tip_h = items[0].get("height")

    return {
        "items": items,
        "start_height": start,
        "limit": limit,
        "has_more": has_more,
        "next_height": next_h if has_more else -1,
        "tip_height": tip_h if tip_h is not None and tip_h >= 0 else None,
    }


def get_last_stored_height() -> int:
    store = db_cache.open_web_store()
    if store is None:
        return -1

    try:
        meta_raw = store.get_bytes(WEB_BLOCKS_DB, _meta_max_height_key())
        if meta_raw:
            return int(meta_raw.decode("utf-8"))
    except Exception:
        pass

    max_height = -1
    try:
        for key_bytes, _ in store.iter_prefix(WEB_BLOCKS_DB, b"block:"):
            try:
                key_str = key_bytes.decode('utf-8')
                if key_str.startswith("block:"):
                    h_str = key_str[6:].lstrip('0')
                    height = int(h_str) if h_str else 0
                    if height > max_height:
                        max_height = height
            except (ValueError, IndexError) as e:
                log.exception("[webdb] Error parsing key %s: %s", key_bytes, e)
                continue
    except Exception as e:
        log.warning("[webdb] Error in get_last_stored_height: %s", e)
        return -1
    
    if max_height >= 0:
        try:
            store.put_bytes(WEB_BLOCKS_DB, _meta_max_height_key(), str(max_height).encode("utf-8"))
        except Exception:
            pass

    return max_height


def get_prefetch_last_height() -> int:
    store = db_cache.open_web_store()
    if store is None:
        return -1
    try:
        raw = store.get_bytes(db_cache.WEB_CACHE_DB, _prefetch_last_height_key())
        if raw:
            return int(raw.decode("utf-8"))
    except Exception:
        pass
    return -1


def set_prefetch_last_height(height: int) -> None:
    store = db_cache.open_web_store()
    if store is None:
        return
    try:
        store.put_bytes(db_cache.WEB_CACHE_DB, _prefetch_last_height_key(), str(height).encode("utf-8"))
    except Exception:
        log.warning("[webdb] Failed to save prefetch last height")


def prefetch_blocks(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]) -> bool:
    store = db_cache.open_web_store()
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
    
    start_height = min(tip_height, last_stored + blocks_to_fetch)
    
    has_more = tip_height > start_height
    
    try:
        resp = rpc_call({
            "type": "GET_BLOCK_RANGE",
            "start_height": start_height,
            "limit": blocks_to_fetch
        }) or {}
        
        if resp.get("error"):
            log.warning("[webdb] Prefetch failed: %s", resp.get("error"))
            return False
        
        items = resp.get("items") or []
        if not items:
            log.info("[webdb] No new blocks to prefetch (empty response)")
            return False
        
        new_items = []
        for item in items:
            if not item:
                continue
            height = item.get("height")
            if height is not None and get_block_from_storage(height) is None:
                new_items.append(item)
        
        if new_items:
            save_blocks_to_storage(new_items)
            
            highest_new = max(item.get("height", 0) for item in new_items)
            set_prefetch_last_height(max(highest_new, start_height))
        else:
            log.info("[webdb] All blocks already exist in storage")
            valid_heights = [item.get("height") for item in items if item and item.get("height") is not None]
            if valid_heights:
                set_prefetch_last_height(max(max(valid_heights), start_height))
            else:
                set_prefetch_last_height(start_height)
            
        return has_more
            
    except Exception as exc:
        log.warning("[webdb] Prefetch exception: %s", exc)
        return False


def start_prefetch_thread(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]) -> None:
    global _prefetch_thread, _prefetch_running, _prefetch_stop_event
    
    if _prefetch_running:
        return
    
    _prefetch_running = True
    _prefetch_stop_event.clear()
    
    def prefetch_worker():
        while _prefetch_running and not _prefetch_stop_event.is_set():
            try:
                has_more = prefetch_blocks(rpc_call)
            except Exception as exc:
                log.warning("[webdb] Prefetch worker exception: %s", exc)
                has_more = False
            
            if has_more and _prefetch_running and not _prefetch_stop_event.is_set():
                time.sleep(0.1)
                continue
            
            _prefetch_stop_event.wait(timeout=PREFETCH_INTERVAL)
    
    _prefetch_thread = threading.Thread(target=prefetch_worker, daemon=True)
    _prefetch_thread.name = "block-prefetch-worker"
    _prefetch_thread.start()
    
    log.info("[webdb] Block prefetch thread started (interval=%ds)", PREFETCH_INTERVAL)


def stop_prefetch_thread() -> None:
    global _prefetch_running, _prefetch_stop_event
    _prefetch_running = False
    _prefetch_stop_event.set()


# =============================================================================
# INTERNAL METHOD
# =============================================================================

def _block_key(height: int) -> bytes:
    return f"block:{height:08d}".encode("utf-8")


def _meta_max_height_key() -> bytes:
    return b"meta:max_block_height"


def _prefetch_last_height_key() -> bytes:
    return b"prefetch:last_height"
