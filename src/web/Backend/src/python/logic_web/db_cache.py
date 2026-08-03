# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import os
import json
import time
import threading
from typing import Optional

from tsarchain.utils import config as CFG
from tsarcore_native import open_storage as _native_open_storage

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.logic_web.db_cache")


WEB_CACHE_DB = "web_cache"
WEB_MEDIA_DB = "web_media"
WEB_CACHE_TTL_SEC = 60
WEB_CACHE_ERROR_TTL_SHORT = 8
WEB_STOR_LIST_TTL_SEC = 120

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
            drive_override = os.getenv("TSAR_STORAGE_DRIVE_TYPE")
            _store = _native_open_storage(
                "lmdb",
                (CFG.WEB_DATABASE_PATH),
                map_size_init=int(CFG.LMDB_WEB_SIZE_INIT),
                map_size_max=int(CFG.LMDB_WEB_SIZE_MAX),
                pretty_json=False,
                drive_type=drive_override,
            )
            dt = getattr(_store, "drive_type", "unknown")
            log.info("[webdb] Web cache LMDB initialized at '%s' [Drive Profile: %s]", CFG.WEB_DATABASE_PATH, dt.upper())
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
    
    if refresh_ttl and not _is_expired(entry):
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
