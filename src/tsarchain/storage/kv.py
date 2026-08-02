# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import os
import threading
from contextlib import contextmanager
from typing import Iterator, Tuple, Optional

from ..utils import config as CFG
from tsarcore_native import open_storage as _native_open_storage

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.storage.kv')


_native_store = None
_native_stores = {}
_init_lock = threading.RLock()

DB_PATH_MAP = {
    "node_secrets": CFG.LMDB_KEYS_DIR,
    "chain": CFG.LMDB_CHAIN_DIR,
    "utxo": CFG.LMDB_UTXO_DIR,
    "state": CFG.LMDB_STATE_DIR,
    "graffiti": CFG.LMDB_GRAFFITI_DIR,
    "mempool": CFG.LMDB_MEMPOOL_DIR,
}

def get_db_path(name: str) -> str:
    return DB_PATH_MAP.get(name, CFG.LMDB_DATA_FILE)

def _init_native_store(name: str = "chain"):
    global _native_store
    path = get_db_path(name)
    if path in _native_stores:
        _native_store = _native_stores[path]
        return _native_store
    with _init_lock:
        if path in _native_stores:
            _native_store = _native_stores[path]
            return _native_store
        
        drive_override = os.getenv("TSAR_STORAGE_DRIVE_TYPE")
        store = _native_open_storage(
            "lmdb",
            path,
            map_size_init=int(CFG.LMDB_MAP_SIZE_INIT),
            map_size_max=int(CFG.LMDB_MAP_SIZE_MAX),
            pretty_json=False,
            drive_type=drive_override,
        )
        if store is not None:
            _native_stores[path] = store
            _native_store = store
            dt = getattr(store, "drive_type", "unknown")
            log.info(f"Native LMDB storage initialized at '{path}' for '{name}' [Drive Profile: {dt.upper()}]")
        return store

def sync(force: bool = False) -> None:
    store = _ensure_env("chain")
    if store is not None and hasattr(store, "sync"):
        store.sync(force)
    with _init_lock:
        for s in (_native_stores.values()):
            if s is not store and hasattr(s, "sync"):
                s.sync(force)

def _ensure_env(name: str = "chain"):
    path = get_db_path(name)
    if path in _native_stores:
        return _native_stores[path]
    store = _init_native_store(name)
    if store is not None:
        return store
    raise RuntimeError("Native storage required but not initialized; install/build tsarcore_native")

def get(name: str, key: bytes) -> Optional[bytes]:
    store = _ensure_env(name)
    val = store.get_bytes(name, key)
    return bytes(val) if val is not None else None

def put(name: str, key: bytes, val: bytes) -> None:
    store = _ensure_env(name)
    store.put_bytes(name, key, val)

def delete(name: str, key: bytes) -> None:
    store = _ensure_env(name)
    store.delete(name, key)

def clear_db(name: str) -> int:
    store = _ensure_env(name)
    return int(store.clear_db(name))

def iter_prefix(name: str, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
    store = _ensure_env(name)
    def _generator():
        start_after: Optional[bytes] = None
        while True:
            chunk = store.iter_prefix_chunk(name, prefix, limit=CFG.KV_ITER_CHUNK, start_after=start_after) or []
            if not chunk:
                break
            for k, v in chunk:
                yield bytes(k), bytes(v)
                start_after = bytes(k)
            if len(chunk) < CFG.KV_ITER_CHUNK:
                break
    return _generator()


@contextmanager
def batch(name: str):
    store = _ensure_env(name)

    class _NativeBatch:
        def __init__(self, native_store, db_name):
            self.store = native_store; self.db_name = db_name; self._ops = []
        def put(self, key: bytes, val: bytes) -> None:
            self._ops.append((bytes(key), bytes(val)))
        def delete(self, key: bytes) -> None:
            self._ops.append((bytes(key), None))

    nb = _NativeBatch(store, name)
    try:
        yield nb
    finally:
        if nb._ops:
            store.put_batch(name, nb._ops)


# Convenience single-put with auto-grow
# (Duplicate convenience put removed; handled above)
