# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import time
import threading
from typing import Any, Callable, Dict, Optional

from tsarchain.utils.tsar_logging import get_ctx_logger
from web.Backend.src.python.logic_web import db_cache

log = get_ctx_logger("tsarchain.web.logic_web.db_blocks")

WEB_BLOCKS_DB = "web_blocks"
BLOCK_RANGE_LIMIT = 200
PREFETCH_INTERVAL = 30

_prefetch_thread = None
_prefetch_running = False


def _block_key(height: int) -> bytes:
    return f"block:{height:08d}".encode("utf-8")


def save_blocks_permanent(blocks: list) -> None:
    store = db_cache._open_store()
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
            store.put_bytes(WEB_BLOCKS_DB, _block_key(int(height)), db_cache._json_dumps(block))
        except Exception:
            log.warning("[webdb] Failed to save block %s", height)


def get_block_from_storage(height: int) -> Optional[dict]:
    store = db_cache._open_store()
    if store is None:
        return None
    
    try:
        raw = store.get_bytes(WEB_BLOCKS_DB, _block_key(height))
        if raw:
            return db_cache._json_loads(bytes(raw))
    except Exception:
        log.exception("get_block_from_storage, fail")
    
    return None


def get_block_range_from_storage(start: int, limit: int) -> dict:
    store = db_cache._open_store()
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
    store = db_cache._open_store()
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
                log.exception("[webdb] Error parsing key %s: %s", key_bytes, e)
                continue
    except Exception as e:
        log.warning("[webdb] Error in get_last_stored_height: %s", e)
        return -1
    
    return max_height


def _store_initial_height_key() -> bytes:
    return b"prefetch:last_height"


def get_prefetch_last_height() -> int:
    store = db_cache._open_store()
    if store is None:
        return -1
    try:
        raw = store.get_bytes(db_cache.WEB_CACHE_DB, _store_initial_height_key())
        if raw:
            return int(raw.decode("utf-8"))
    except Exception:
        pass
    return -1


def set_prefetch_last_height(height: int) -> None:
    store = db_cache._open_store()
    if store is None:
        return
    try:
        store.put_bytes(db_cache.WEB_CACHE_DB, _store_initial_height_key(), 
                       str(height).encode("utf-8"))
    except Exception:
        log.warning("[webdb] Failed to save prefetch last height")


def prefetch_blocks(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]) -> bool:
    store = db_cache._open_store()
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
        
        if new_items:
            save_blocks_permanent(new_items)
            log.info("[webdb] Prefetched %d new blocks (height %d to %d)", 
                    len(new_items), new_items[0].get("height", 0), 
                    new_items[-1].get("height", 0))
            
            highest_new = max(item.get("height", 0) for item in new_items)
            set_prefetch_last_height(highest_new)
        else:
            log.info("[webdb] All blocks already exist in storage")
            valid_heights = [item.get("height") for item in items if item.get("height") is not None]
            if valid_heights:
                set_prefetch_last_height(max(valid_heights))
            
        return has_more
            
    except Exception as exc:
        log.warning("[webdb] Prefetch exception: %s", exc)
        return False


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
