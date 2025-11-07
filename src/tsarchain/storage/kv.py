# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
import os, lmdb
from contextlib import contextmanager
from typing import Iterator, Tuple, Optional

from ..utils import config as CFG


def kv_enabled() -> bool:
    return CFG.KV_BACKEND == "lmdb"


_env = None
_db_handles = {}


def _ensure_env():
    global _env
    if _env is not None:
        return _env
    if not kv_enabled():
        return None
    os.makedirs(CFG.DB_DIR, exist_ok=True)
    _env = lmdb.open(CFG.DB_DIR, map_size=int(CFG.LMDB_MAP_SIZE_INIT), max_dbs=16, create=True, lock=True, subdir=True)
    return _env


def _grow_env_map(min_target: int | None = None) -> int:
    env = _ensure_env()
    if env is None:
        return 0
    info = env.info()
    cur = int(info.get('map_size', 0) or 0)
    # Double, or at least accommodate min_target, capped by MAX
    new = max(cur * 2, cur + (cur // 2))
    if min_target and min_target > new:
        new = min_target
    if new > int(CFG.LMDB_MAP_SIZE_MAX):
        new = int(CFG.LMDB_MAP_SIZE_MAX)
    if new <= cur:
        return cur
    env.set_mapsize(new)
    return new


def _get_db(name: str):
    env = _ensure_env()
    if env is None:
        return None
    db = _db_handles.get(name)
    if db is None:
        db = env.open_db(name.encode("utf-8"), create=True)
        _db_handles[name] = db
    return db


def get(name: str, key: bytes) -> Optional[bytes]:
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None:
        return None
    with env.begin(db=db, write=False) as txn:
        return txn.get(key)


def put(name: str, key: bytes, val: bytes) -> None:
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None:
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
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None:
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
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None:
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
    env = _ensure_env(); db = _get_db(name)
    if env is None or db is None:
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

    def put(self, key: bytes, val: bytes) -> None:
        try:
            self.txn.put(key, val)
        except Exception as e:
            # Auto-grow on map full, then retry once
            if lmdb and hasattr(lmdb, 'MapFullError') and isinstance(e, lmdb.MapFullError):
                try:
                    self.txn.abort()
                except Exception:
                    pass
                _grow_env_map()
                self.txn = self.env.begin(db=self.db, write=True)
                self.txn.put(key, val)
            else:
                raise

    def delete(self, key: bytes) -> None:
        try:
            self.txn.delete(key)
        except Exception as e:
            if lmdb and hasattr(lmdb, 'MapFullError') and isinstance(e, lmdb.MapFullError):
                try:
                    self.txn.abort()
                except Exception:
                    pass
                _grow_env_map()
                self.txn = self.env.begin(db=self.db, write=True)
                self.txn.delete(key)
            else:
                raise


@contextmanager
def batch(name: str):
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
