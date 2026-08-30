# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import json

from web.Backend.src.core.logic_web import db_blocks
from web.Backend.src.core.logic_web.rpc_client import (
    get_client,
    set_cache_scope,
    rpc_send,
)
from web.Backend.src.core.logic_web import rpc_handlers

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.web.Backend.core.main_web')

_prefetch_started = False
_prefetch_host_port = None


def dispatch_rpc(op: str, param: object | None, host: str, port: int):
    global _prefetch_started, _prefetch_host_port
    set_cache_scope(host, port)
    client = get_client(host, port)
    param_norm = _normalize_param(param)
    
    if not _prefetch_started or _prefetch_host_port != f"{host}:{port}":
        try:
            db_blocks.start_prefetch_thread(lambda payload: rpc_send(get_client(host, port), payload))
            _prefetch_started = True
            _prefetch_host_port = f"{host}:{port}"
            log.info("[dispatch_rpc] Started auto-prefetch thread for %s:%s", host, port)
        except Exception:
            log.exception("[dispatch_rpc] Failed to start prefetch")
    
    if op == "receipt":
        return rpc_handlers.rpc_receipt(client, param_norm)
    if op == "history_book":
        return rpc_handlers.rpc_history_book(client, param_norm)
    if op == "network":
        return rpc_handlers.rpc_network(client)
    if op == "block":
        return rpc_handlers.rpc_block(client, param_norm)
    if op == "block_range":
        opts = param_norm if type(param_norm) is dict else _parse_block_range_opts(param_norm)
        return rpc_handlers.rpc_block_range(client, opts)
    if op == "tx":
        return rpc_handlers.rpc_tx(client, param_norm)
    if op == "address":
        return rpc_handlers.rpc_address(client, param_norm)
    if op == "graffiti":
        return rpc_handlers.rpc_graffiti(client, param_norm)
    if op == "graffiti_posts":
        opts = param_norm if type(param_norm) is dict else _parse_opts(param_norm)
        return rpc_handlers.rpc_graffiti_posts(client, opts)
    if op == "graffiti_file":
        opts = param_norm if type(param_norm) is dict else _parse_opts(param_norm)
        fallback = param_norm if type(param_norm) is str else None
        return rpc_handlers.rpc_graffiti_file(client, opts, fallback)
    if op == "graffiti_media_meta":
        opts = param_norm if type(param_norm) is dict else _parse_opts(param_norm)
        fallback = param_norm if type(param_norm) is str else None
        return rpc_handlers.rpc_graffiti_media_meta(client, opts, fallback)
    if op == "graffiti_chunk":
        opts = param_norm if type(param_norm) is dict else _parse_opts(param_norm)
        return rpc_handlers.rpc_graffiti_chunk(client, opts)
    if op == "prefetch_blocks":
        try:
            db_blocks.prefetch_blocks(lambda payload: rpc_send(get_client(host, port), payload))
            return {"status": "ok", "message": "Prefetch started"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
    
    return {"error": "unknown_op"}


# =============================================================================
# INTERNAL METHOD
# =============================================================================

def _parse_opts(param: str | None) -> dict:
    if not param:
        return {}
    raw = str(param).strip()
    if not raw:
        return {}
    if raw.startswith("{") and raw.endswith("}"):
        try:
            obj = json.loads(raw)
            return obj if type(obj) is dict else {}
        except Exception:
            return {}

    parts = [p.strip() for p in raw.split(",") if p.strip()]
    opts = {}
    if parts and parts[0].isdigit():
        opts["limit"] = int(parts[0])
    if len(parts) > 1 and parts[1].isdigit():
        opts["offset"] = int(parts[1])
    return opts


def _parse_block_range_opts(param: str | None) -> dict:
    if not param:
        return {}
    raw = str(param).strip()
    if not raw:
        return {}
    if raw.startswith("{") and raw.endswith("}"):
        try:
            obj = json.loads(raw)
            return obj if type(obj) is dict else {}
        except Exception:
            return {}
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    opts = {}
    if parts and parts[0].lstrip("-").isdigit():
        opts["start_height"] = int(parts[0])
    if len(parts) > 1 and parts[1].isdigit():
        opts["limit"] = int(parts[1])
    return opts


def _normalize_param(param: object | None):
    if param is None or type(param) in (dict, list):
        return param
    return str(param)