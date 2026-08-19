# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import time
import json
from typing import Dict, Optional

from ..utils import config as CFG
from ..storage.kv import get, put

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.peers_storage")

KEYS_DB_NAME = "node_secrets"


def save_node_key(path: str, record: Dict) -> None:
    data = dict(record)
    data.setdefault("updated", int(time.time()))
    _store_record(path, data)


def load_node_key(path: str) -> Optional[Dict]:
    return _load_record(path)


def save_peer_keys(keys: Dict[str, str]) -> None:
    serialised = {str(k): str(v) for k, v in keys.items()}
    _store_record("peer_keys", serialised)


def load_peer_keys() -> Dict[str, str]:
    rec = _load_record("peer_keys")
    if isinstance(rec, dict):
        return {str(k): str(v) for k, v in rec.items()}
    return {}


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _resolve_key_and_path(name_or_path: str) -> tuple[str, Optional[str]]:
    record_paths = {
        "node_key": CFG.NODE_KEY_PATH,
        "archivist_key": CFG.ARCHIVIST_KEY_PATH,
        "peer_keys": CFG.PEER_KEYS_PATH,
        "user_key": CFG.USER_KEY_PATH,
    }
    if name_or_path in record_paths:
        return name_or_path, record_paths[name_or_path]

    for key, path in record_paths.items():
        if path and (name_or_path == path or os.path.normpath(name_or_path) == os.path.normpath(path)):
            return key, path

    return name_or_path, name_or_path


def _load_record(name: str) -> Optional[Dict]:
    db_key, _ = _resolve_key_and_path(name)
    raw = get(KEYS_DB_NAME, db_key.encode("utf-8"))
    if raw is not None:
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log.warning(f"Failed to decode KV record for {db_key}: {e}")
    return None


def _store_record(name: str, data: Dict) -> None:
    db_key, _ = _resolve_key_and_path(name)
    payload = json.dumps(data, separators=CFG.CANONICAL_SEP).encode("utf-8")
    put(KEYS_DB_NAME, db_key.encode("utf-8"), payload)
