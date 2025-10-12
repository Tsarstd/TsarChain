# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import json, lmdb, os, threading, time
from pathlib import Path
from typing import Dict, Optional

from ..utils import config as CFG

_ENV = None
_DB = None
_LOCK = threading.RLock()

_RECORD_PATHS = {
    "node_key": Path(CFG.NODE_KEY_PATH),
    "peer_keys": Path(CFG.PEER_KEYS_PATH),
}
_LEGACY_PATHS = {
    "node_key": Path(getattr(CFG, "LEGACY_NODE_KEY_PATH", CFG.NODE_KEY_PATH)),
    "peer_keys": Path(getattr(CFG, "LEGACY_PEER_KEYS_PATH", CFG.PEER_KEYS_PATH)),
}


def _lmdb_enabled() -> bool:
    backend = str(getattr(CFG, "KV_BACKEND", "json")).lower()
    return backend == "lmdb" and lmdb is not None


def _env_path() -> str:
    return os.path.join(CFG.NODE_DATA_DIR, "kv")


def _ensure_env():
    global _ENV, _DB
    if not _lmdb_enabled():
        return None, None
    with _LOCK:
        if _ENV is None:
            path = _env_path()
            os.makedirs(path, exist_ok=True)
            size = int(getattr(CFG, "LMDB_MAP_SIZE_INIT", 64 * 1024 * 1024))
            _ENV = lmdb.open(
                path,
                map_size=size,
                max_dbs=4,
                subdir=True,
                create=True,
                lock=True,
            )
            _DB = _ENV.open_db(b"node_secrets")
        return _ENV, _DB


def _load_record(name: str) -> Optional[Dict]:
    env, db = _ensure_env()
    if env and db:
        with env.begin(write=False, db=db) as txn:
            raw = txn.get(name.encode("utf-8"))
        if raw:
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return None

    # JSON fallback / legacy migration
    paths = [
        _RECORD_PATHS.get(name),
        _LEGACY_PATHS.get(name),
    ]
    for path in paths:
        if not path:
            continue
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
            if env and db:
                _store_record(name, data)
            elif path == _LEGACY_PATHS.get(name) and path != _RECORD_PATHS.get(name):
                # migrate legacy file into new location when operating in JSON mode
                _store_record(name, data)
            return data
    return None


def _store_record(name: str, data: Dict) -> None:
    env, db = _ensure_env()
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")

    if env and db:
        with _LOCK:
            with env.begin(write=True, db=db) as txn:
                txn.put(name.encode("utf-8"), payload)
        # remove residual files once persisted to LMDB
        for path in (_RECORD_PATHS.get(name), _LEGACY_PATHS.get(name)):
            if path and path.exists():
                try:
                    path.unlink()
                except Exception:
                    pass
        return

    # JSON fallback
    path = _RECORD_PATHS.get(name)
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    legacy = _LEGACY_PATHS.get(name)
    if legacy and legacy != path and legacy.exists():
        try:
            legacy.unlink()
        except Exception:
            pass


def load_node_key() -> Optional[Dict]:
    return _load_record("node_key")


def save_node_key(record: Dict) -> None:
    data = dict(record)
    data.setdefault("updated", int(time.time()))
    _store_record("node_key", data)


def load_peer_keys() -> Dict[str, str]:
    rec = _load_record("peer_keys")
    if isinstance(rec, dict):
        return {str(k): str(v) for k, v in rec.items()}
    return {}


def save_peer_keys(keys: Dict[str, str]) -> None:
    # normalise and persist
    serialised = {str(k): str(v) for k, v in keys.items()}
    _store_record("peer_keys", serialised)
