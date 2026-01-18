# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import json, time
from typing import Dict, Optional

from ..utils import config as CFG
from ..storage.kv import get, put, kv_enabled

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.peers_storage")

KEYS_DB_NAME = "node_secrets"

def _load_record(name: str) -> Optional[Dict]:
    if kv_enabled():
        raw = get(KEYS_DB_NAME, name.encode("utf-8"))
        if raw is not None:
            try:
                return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                log.warning(f"Failed to decode KV record for {name}: {e}")
                # Fallback to JSON file
    
    # JSON fallback / legacy migration
    record_paths = {
        "node_key": CFG.NODE_KEY_PATH,
        "archivist_key": CFG.ARCHIVIST_KEY_PATH,
        "peer_keys": CFG.PEER_KEYS_PATH,
    }
    
    path = record_paths.get(name)
    if path:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Migrate to KV if enabled
                if kv_enabled():
                    _store_record(name, data)
                return data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log.debug(f"No JSON file found for {name}: {e}")
    
    return None


def _store_record(name: str, data: Dict) -> None:
    payload = json.dumps(data, separators=CFG.CANONICAL_SEP).encode("utf-8")
    
    # Store in KV (primary storage)
    if kv_enabled():
        put(KEYS_DB_NAME, name.encode("utf-8"), payload)
        log.debug(f"Stored record '{name}' to KV storage")
    else:
        log.debug("KV storage not enabled, using JSON fallback only")
    
    # JSON fallback for backward compatibility
    record_paths = {
        "node_key": CFG.NODE_KEY_PATH,
        "archivist_key": CFG.ARCHIVIST_KEY_PATH,
        "peer_keys": CFG.PEER_KEYS_PATH,
    }
    
    path = record_paths.get(name)
    if path:
        try:
            import os
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            log.debug(f"Stored record '{name}' to JSON fallback at {path}")
        except (IOError, OSError) as e:
            log.error(f"Failed to write JSON fallback for {name}: {e}")


# ======== SAVE & LOAD KEYS ==============

def load_node_key(path: str) -> Optional[Dict]:
    return _load_record(path)

def save_node_key(path: str, record: Dict) -> None:
    data = dict(record)
    data.setdefault("updated", int(time.time()))
    _store_record(path, data)

def load_peer_keys() -> Dict[str, str]:
    rec = _load_record("peer_keys")
    if isinstance(rec, dict):
        return {str(k): str(v) for k, v in rec.items()}
    return {}

def save_peer_keys(keys: Dict[str, str]) -> None:
    serialised = {str(k): str(v) for k, v in keys.items()}
    _store_record("peer_keys", serialised)