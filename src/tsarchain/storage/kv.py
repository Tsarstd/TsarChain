# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from contextlib import contextmanager
from typing import Iterator, Tuple, Optional
import threading

from tsarcore_native import open_storage as _native_open_storage
from ..utils import config as CFG

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.storage.kv')


def kv_enabled() -> bool:
    return CFG.KV_BACKEND == "lmdb"


_native_store = None
_init_lock = threading.RLock()

def _init_native_store():
    global _native_store
    if _native_store is not None:
        return _native_store
    if not kv_enabled():
        return None
    with _init_lock:
        if _native_store is not None:
            return _native_store
        _native_store = _native_open_storage(
            "lmdb",
            CFG.LMDB_DATA_FILE,
            map_size_init=int(CFG.LMDB_MAP_SIZE_INIT),
            map_size_max=int(CFG.LMDB_MAP_SIZE_MAX),
            pretty_json=False,
        )
    return _native_store

def _ensure_env():
    if _native_store is None and kv_enabled():
        _init_native_store()
    if _native_store is not None:
        return _native_store
    if kv_enabled():
        raise RuntimeError("Native storage required but not initialized; install/build tsarcore_native")
    return None

def get(name: str, key: bytes) -> Optional[bytes]:
    store = _ensure_env()
    if store is None:
        return None
    val = store.get_bytes(name, key)
    return bytes(val) if val is not None else None

def put(name: str, key: bytes, val: bytes) -> None:
    store = _ensure_env()
    if store is None:
        raise RuntimeError("KV not enabled")
    store.put_bytes(name, key, val)

def delete(name: str, key: bytes) -> None:
    store = _ensure_env()
    if store is None:
        return
    store.delete(name, key)

def clear_db(name: str) -> int:
    store = _ensure_env()
    if store is None:
        return 0
    return int(store.clear_db(name))

def iter_prefix(name: str, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
    store = _ensure_env()
    if store is None:
        return iter(())
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


class WriteBatch:
    def __init__(self, env, db):
        self.env = env; self.db = db
        self.txn = None

    def __enter__(self):
        self.txn = self.env.begin(db=self.db, write=True)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.txn is None:
            return
        if exc_type:
            self.txn.abort()
        else:
            self.txn.commit()
        self.txn = None


@contextmanager
def batch(name: str):
    store = _ensure_env()
    if store is None:
        raise RuntimeError("KV not enabled")

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
