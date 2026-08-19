# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import threading
from typing import Tuple

from tsarchain.utils import config as CFG
CFG.WALLET_RPC_MIN_INTERVAL = 0.0  # Bypass RPC pacing

from kremlin.services.rpc_kremlin import NodeClient
from tsarchain.network.protocol import load_or_create_keypair_at

from tsarchain.utils.tsar_logging import get_ctx_logger
from web.Backend.src.python.logic_web import db_cache

log = get_ctx_logger("tsarchain.web.logic_web.rpc_client")

_CLIENT_CACHE = {}
_CLIENT_LOCK = threading.RLock()
_CACHE_SCOPE = "default"
RPC_SOURCE = "web_backend"


def _mk_client(host: str, port: int):
    user_id, user_pub, user_priv = load_or_create_keypair_at(CFG.USER_KEY_PATH)
    user_ctx = {"net_id": CFG.DEFAULT_NET_ID, "node_id": user_id, "pubkey": user_pub, "privkey": user_priv}
    return NodeClient(CFG, user_ctx=user_ctx, manual_bootstrap=(host, port))


def _rpc_send(client, payload: dict):
    if RPC_SOURCE and isinstance(payload, dict) and "rpc_source" not in payload:
        payload = dict(payload)
        payload["rpc_source"] = RPC_SOURCE
    return client.send(payload)


def _get_client(host: str, port: int):
    key = f"{host}:{port}"
    with _CLIENT_LOCK:
        client = _CLIENT_CACHE.get(key)
        if client is None:
            client = _mk_client(host, port)
            _CLIENT_CACHE[key] = client
        return client


def _drop_client(host: str, port: int) -> None:
    key = f"{host}:{port}"
    with _CLIENT_LOCK:
        _CLIENT_CACHE.pop(key, None)


def _payload_has_error(payload: object) -> bool:
    return isinstance(payload, dict) and bool(payload.get("error"))


def _set_cache_scope(host: str, port: int) -> None:
    global _CACHE_SCOPE
    _CACHE_SCOPE = f"{host}:{port}"


def _cache_key(kind: str, *parts: object) -> str:
    return db_cache.make_cache_key("web", _CACHE_SCOPE, kind, *parts)


def _determine_cache_policy(payload: object) -> Tuple[bool, int | None]:
    if not payload:
        return False, None
    if isinstance(payload, dict):
        if payload.get("error"):
            ttl = db_cache.get_error_cache_ttl(payload.get("error") or payload.get("detail") or payload.get("reason"))
            return ttl is not None, ttl
        if payload.get("status") == "error":
            ttl = db_cache.get_error_cache_ttl(payload.get("reason"))
            return ttl is not None, ttl
        if len(payload) == 0:
            return False, None
    return True, None


def _cache_get(key: str, refresh_ttl: bool = False):
    return db_cache.cache_get(key, refresh_ttl=refresh_ttl)


def _cache_set(key: str, payload: object, ttl_sec: int | None = None) -> None:
    if ttl_sec is None:
        db_cache.cache_set(key, payload)
    else:
        db_cache.cache_set(key, payload, ttl_sec=ttl_sec)


def _get_or_fetch_cached(key: str, fetch_fn):
    cached = _cache_get(key)
    if cached is not None:
        return cached
    payload = fetch_fn()
    cache_ok, ttl_sec = _determine_cache_policy(payload)
    if cache_ok:
        _cache_set(key, payload, ttl_sec)
    return payload
