# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import json
import time
import threading
from typing import Optional

from tsarchain.utils import config as CFG
from tsarcore_native import open_storage as _native_open_storage

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.Backend.src.core.logic_web.db_cache")

WEB_CACHE_DB = "web_cache"
WEB_MEDIA_DB = "web_media"
WEB_CACHE_TTL_SEC = 60
WEB_CACHE_ERROR_TTL_SHORT = 8
WEB_STOR_LIST_TTL_SEC = 120

_store = None
_store_lock = threading.RLock()
_native_warned = False


def make_cache_key(prefix: str, *parts: object) -> str:
    items = []
    for part in (prefix, *parts):
        if part is not None:
            txt = str(part).strip().lower()
            if txt:
                items.append(txt)
    return ":".join(items)


def is_not_found_error(reason: object) -> bool:
    txt = str(reason or "").strip().lower()
    return bool(txt and (txt in ("not_found", "height_out_of_range") or "not found" in txt))


def get_error_cache_ttl(reason: object) -> Optional[int]:
    txt = str(reason or "").strip().lower()
    if not txt:
        return None
    if any(k in txt for k in ("pow_required", "rate_limited", "rate limit", "timeout", "rpc_timeout", "rpc_exception", "no_response")):
        return WEB_CACHE_ERROR_TTL_SHORT
    if is_not_found_error(txt):
        return WEB_CACHE_TTL_SEC
    return None


def cache_get(key: str, refresh_ttl: bool = False) -> Optional[object]:
    store = open_web_store()
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
    
    entry = _deserialize_payload(bytes(raw))
    if not entry:
        return None
    
    if refresh_ttl and not _is_expired(entry):
        entry["ts"] = int(time.time())
        try:
            store.put_bytes(WEB_CACHE_DB, k, _serialize_payload(entry))
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
    store = open_web_store()
    if store is None:
        return
    entry = {
        "ts": int(time.time()),
        "ttl": int(ttl_sec),
        "payload": payload,
    }
    try:
        store.put_bytes(WEB_CACHE_DB, key.encode("utf-8"), _serialize_payload(entry))
    except Exception:
        log.warning("[webdb] cache_set failed key=%s", key)


def open_web_store():
    global _store, _native_warned
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
                CFG.WEB_DATABASE_PATH,
                map_size_init=int(CFG.LMDB_WEB_SIZE_INIT),
                map_size_max=int(CFG.LMDB_WEB_SIZE_MAX),
                pretty_json=False,
                drive_type=CFG.STORAGE_DRIVE_TYPE,
            )
            log.info("[webdb] Web cache LMDB initialized at '%s'", CFG.WEB_DATABASE_PATH)
        except Exception as exc:
            log.warning("[webdb] lmdb disabled: %s", exc)
            _store = None
    return _store


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _serialize_payload(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=True, default=str, separators=(",", ":")).encode("utf-8")


def _deserialize_payload(raw: bytes) -> Optional[dict]:
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _is_expired(entry: dict, now_ts: Optional[int] = None) -> bool:
    ttl_raw = entry.get("ttl")
    ttl = int(ttl_raw) if ttl_raw is not None else WEB_CACHE_TTL_SEC
    if ttl <= 0:
        return False
    ts = int(entry.get("ts") or 0)
    current_time = int(now_ts or time.time())
    return ts <= 0 or (current_time - ts) > ttl
