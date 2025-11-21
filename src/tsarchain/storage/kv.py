# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os, lmdb
from contextlib import contextmanager
from typing import Iterator, Tuple, Optional

from tsarcore_native import open_storage as _native_open_storage
from ..utils import config as CFG

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.storage.kv')


def kv_enabled() -> bool:
    return CFG.KV_BACKEND == "lmdb"


_env = None
_db_handles = {}
_native_store = None
_env_logged = False


def _init_native_store():
    global _native_store
    if _native_store is not None:
        return _native_store
    if not kv_enabled():
        return None
    try:
        _native_store = _native_open_storage(
            "lmdb",
            CFG.LMDB_DATA_FILE,
            map_size_init=int(CFG.LMDB_MAP_SIZE_INIT),
            map_size_max=int(CFG.LMDB_MAP_SIZE_MAX),
            pretty_json=False,
        )
        log.debug("[kv] using native storage backend (lmdb)")
    except Exception as e:
        log.warning("[kv] native storage init failed, fallback to python lmdb: %s", e)
        _native_store = None
    return _native_store


def _ensure_env():
    if _native_store is None and kv_enabled():
        _init_native_store()
    if _native_store is not None:
        return _native_store
    global _env
    if _env is not None:
        return _env
    if not kv_enabled():
        return None
    os.makedirs(CFG.LMDB_DATA_FILE, exist_ok=True)
    _env = lmdb.open(CFG.LMDB_DATA_FILE, map_size=int(CFG.LMDB_MAP_SIZE_INIT), max_dbs=16, create=True, lock=True, subdir=True)
    global _env_logged
    if not _env_logged:
        log.info("[kv] using python lmdb backend at %s", CFG.LMDB_DATA_FILE)
        _env_logged = True
    return _env

def _grow_env_map(min_target: int | None = None) -> int:
    env = _ensure_env()
    if env is None or _native_store is not None:
        return 0
    info = env.info()
    cur = int(info.get('map_size', 0) or 0)
    # Double, or at least accommodate min_target, capped by MAX
    new = max(cur * 2, cur + (cur // 2))
    if min_target and min_target > new:
        new = min_target
    if new > int(CFG.LMDB_MAP_SIZE_MAX):
        new = int(CFG.LMDB_MAP_SIZE_MAX)
        log.warning("LMDB map size reached maximum: %s bytes", new)
    if new <= cur:
        if cur >= int(CFG.LMDB_MAP_SIZE_MAX):
            log.error("[_grow_env_map] Cannot grow further! Operations may fail!")
        return cur
    env.set_mapsize(new)
    return new


def _get_db(name: str):
    env = _ensure_env()
    if env is None:
        return None
    if _native_store is not None:
        return name  # native backend routes by name internally
    db = _db_handles.get(name)
    if db is None:
        db = env.open_db(name.encode("utf-8"), create=True)
        _db_handles[name] = db
    return db


def get(name: str, key: bytes) -> Optional[bytes]:
    if _native_store is not None:
        try:
            val = _native_store.get_bytes(name, key)
            return bytes(val) if val is not None else None
        except Exception as e:
            log.warning("[kv] native get failed, fallback: %s", e)
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None or _native_store is not None:
        return None
    with env.begin(db=db, write=False) as txn:
        return txn.get(key)


def put(name: str, key: bytes, val: bytes) -> None:
    if _native_store is not None:
        try:
            _native_store.put_bytes(name, key, val)
            return
        except Exception as e:
            log.warning("[kv] native put failed, fallback: %s", e)
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None or _native_store is not None:
        raise RuntimeError("KV not enabled")
    try:
        with env.begin(db=db, write=True) as txn:
            txn.put(key, val)
    except Exception as e:
        if lmdb and hasattr(lmdb, 'MapFullError') and isinstance(e, lmdb.MapFullError):
            _grow_env_map()
            with env.begin(db=db, write=True) as txn:
                txn.put(key, val)
        else:
            raise


def delete(name: str, key: bytes) -> None:
    if _native_store is not None:
        try:
            _native_store.delete(name, key)
            return
        except Exception as e:
            log.warning("[kv] native delete failed, fallback: %s", e)
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None or _native_store is not None:
        return
    try:
        with env.begin(db=db, write=True) as txn:
            txn.delete(key)
    except Exception as e:
        if lmdb and hasattr(lmdb, 'MapFullError') and isinstance(e, lmdb.MapFullError):
            _grow_env_map()
            with env.begin(db=db, write=True) as txn:
                txn.delete(key)
        else:
            raise


def clear_db(name: str) -> int:
    if _native_store is not None:
        try:
            return int(_native_store.clear_db(name))
        except Exception as e:
            log.warning("[kv] native clear_db failed, fallback: %s", e)
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None or _native_store is not None:
        return 0
    with env.begin(db=db, write=True) as txn:
        try:
            stats = txn.stat(db)
        except Exception:
            stats = {}
        try:
            txn.drop(db, delete=False)
        except Exception:
            # Fallback: manual delete (older behaviour)
            removed = 0
            try:
                with txn.cursor() as cur:
                    if cur.first():
                        while True:
                            try:
                                cur.delete()
                                removed += 1
                            except Exception:
                                pass
                            if not cur.next():
                                break
            except Exception:
                pass
            return removed
    return int(stats.get("entries", 0) or 0)


def iter_prefix(name: str, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
    if _native_store is not None:
        try:
            items = _native_store.iter_prefix(name, prefix) or []
            def _iter_native():
                for k, v in items:
                    yield bytes(k), bytes(v)
            return _iter_native()
        except Exception as e:
            log.warning("[kv] native iter_prefix failed, fallback: %s", e)
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None or _native_store is not None:
        return iter(())
    def _iter():
        with env.begin(db=db, write=False) as txn:
            with txn.cursor() as cur:
                if not cur.set_range(prefix):
                    return
                while True:
                    k = cur.key()
                    if not k or not k.startswith(prefix):
                        break
                    yield k, cur.value()
                    if not cur.next():
                        break
    return _iter()


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
            try:
                self.txn.abort()
            except Exception:
                pass
        else:
            try:
                self.txn.commit()
            except Exception:
                pass
        self.txn = None


@contextmanager
def batch(name: str):
    # Native path: simple wrapper (ops are already atomic per call)
    if _native_store is not None:
        class _NativeBatch:
            def __init__(self, store, db_name):
                self.store = store; self.db_name = db_name
            def put(self, key: bytes, val: bytes) -> None:
                self.store.put_bytes(self.db_name, key, val)
            def delete(self, key: bytes) -> None:
                self.store.delete(self.db_name, key)
        nb = _NativeBatch(_native_store, name)
        try:
            yield nb
        finally:
            pass
        return

    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None:
        raise RuntimeError("KV not enabled")
    wb = WriteBatch(env, db)
    try:
        yield wb.__enter__()
    finally:
        wb.__exit__(None, None, None)


# Convenience single-put with auto-grow
# (Duplicate convenience put removed; handled above)
