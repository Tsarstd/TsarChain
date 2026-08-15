# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import sys
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from web.Backend.src.python.logic_web import db_blocks, db_files
from web.Backend.src.python.logic_web.rpc_client import (
    _get_client,
    _drop_client,
    _set_cache_scope,
    _rpc_send,
)
from web.Backend.src.python.logic_web import rpc_handlers

from tsarchain.utils.tsar_logging import get_ctx_logger, setup_logging
log = get_ctx_logger('tsarchain.web.Backend.main_web')

_prefetch_started = False
_prefetch_host_port = None
_last_cleanup = 0


def _emit(out: object) -> None:
    try:
        sys.stdout.write(json.dumps(out, ensure_ascii=True, default=str))
    except Exception:
        sys.stdout.write('{"error":"json_encode_failed"}')
    sys.stdout.flush()


def _parse_opts(param: str | None) -> dict:
    if not param:
        return {}
    raw = str(param).strip()
    if not raw:
        return {}
    if raw.startswith("{") and raw.endswith("}"):
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        return {}
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
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    opts = {}
    if parts and parts[0].lstrip("-").isdigit():
        opts["start_height"] = int(parts[0])
    if len(parts) > 1 and parts[1].isdigit():
        opts["limit"] = int(parts[1])
    return opts


def _parse_host_port(host_in: object | None, port_in: object | None) -> tuple[str, int]:
    host_raw = host_in or os.environ.get("TSAR_NODE_HOST") or "127.0.0.1"
    host = str(host_raw)
    try:
        port = int(port_in or os.environ.get("TSAR_NODE_PORT") or 19000)
    except Exception:
        port = 19000
        log.exception("[main_exception] port: %s", port)
    return host, port


def _normalize_param(param: object | None):
    if param is None:
        return None
    if isinstance(param, (dict, list)):
        return param
    return str(param)


def _dispatch_rpc(op: str, param: object | None, host: str, port: int):
    global _prefetch_started, _prefetch_host_port
    _set_cache_scope(host, port)
    client = _get_client(host, port)
    param_norm = _normalize_param(param)
    
    if not _prefetch_started or _prefetch_host_port != f"{host}:{port}":
        try:
            def prefetch_rpc_call(payload):
                return _rpc_send(client, payload)
            
            db_blocks.start_prefetch_thread(prefetch_rpc_call)
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
        opts = param_norm if isinstance(param_norm, dict) else _parse_block_range_opts(param_norm)
        return rpc_handlers.rpc_block_range(client, opts)
    if op == "tx":
        return rpc_handlers.rpc_tx(client, param_norm)
    if op == "address":
        return rpc_handlers.rpc_address(client, param_norm)
    if op == "graffiti":
        return rpc_handlers.rpc_graffiti(client, param_norm)
    if op == "graffiti_posts":
        opts = param_norm if isinstance(param_norm, dict) else _parse_opts(param_norm)
        return rpc_handlers.rpc_graffiti_posts(client, opts)
    if op == "graffiti_file":
        opts = param_norm if isinstance(param_norm, dict) else _parse_opts(param_norm)
        fallback = param_norm if isinstance(param_norm, str) else None
        return rpc_handlers.rpc_graffiti_file(client, opts, fallback)
    if op == "graffiti_media_meta":
        opts = param_norm if isinstance(param_norm, dict) else _parse_opts(param_norm)
        fallback = param_norm if isinstance(param_norm, str) else None
        return rpc_handlers.rpc_graffiti_media_meta(client, opts, fallback)
    if op == "graffiti_chunk":
        opts = param_norm if isinstance(param_norm, dict) else _parse_opts(param_norm)
        return rpc_handlers.rpc_graffiti_chunk(client, opts)
    if op == "prefetch_blocks":
        try:
            db_blocks.prefetch_blocks(lambda payload: _rpc_send(client, payload))
            return {"status": "ok", "message": "Prefetch started"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
    
    return {"error": "unknown_op"}


_stdout_lock = threading.Lock()


def _emit_worker(req_id: object, payload: object) -> None:
    with _stdout_lock:
        try:
            sys.stdout.write(json.dumps({"id": req_id, "payload": payload}, ensure_ascii=True, default=str) + "\n")
        except Exception:
            sys.stdout.write('{"id":null,"payload":{"error":"json_encode_failed"}}\n')
        sys.stdout.flush()


def _worker_loop() -> None:
    global _last_cleanup
    _last_cleanup = 0
    
    def _handle_request(req_id: object, op: str, param: object, host: str, port: int) -> None:
        try:
            out = _dispatch_rpc(str(op), param, host, port)
        except Exception as exc:
            _drop_client(host, port)
            log.exception("[worker_exception]")
            detail = str(exc) or exc.__class__.__name__
            out = {"error": "rpc_exception", "detail": detail}
        _emit_worker(req_id, out)

    with ThreadPoolExecutor(max_workers=8, thread_name_prefix="rpc_worker") as executor:
        for line in sys.stdin:
            raw = (line or "").strip()
            if not raw:
                continue
            
            try:
                req = json.loads(raw)
            except Exception:
                log.exception("[worker] bad_json")
                continue
            
            if not isinstance(req, dict):
                log.warning("[worker] bad_request")
                continue
            
            req_id = req.get("id")
            op = req.get("op")
            if req_id is None or not op:
                _emit_worker(req_id, {"error": "missing_op"})
                continue
            
            current_time = time.time()
            if current_time - _last_cleanup > 60:
                db_files.cleanup_receipt_files(35)
                db_files.cleanup_history_book_files(35)
                _last_cleanup = current_time
            
            host, port = _parse_host_port(req.get("host"), req.get("port"))
            executor.submit(_handle_request, req_id, str(op), req.get("param"), host, port)


def main():
    out = None
    if len(sys.argv) < 2:
        log.error("[main] argv: %s", len(sys.argv))
        out = {"error": "missing_op"}
        _emit(out)
        return

    op = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) >= 3 else None
    if op == "worker":
        _worker_loop()
        return

    host_arg = sys.argv[3] if len(sys.argv) >= 4 else None
    port_arg = sys.argv[4] if len(sys.argv) >= 5 else None
    host, port = _parse_host_port(host_arg, port_arg)

    try:
        out = _dispatch_rpc(str(op), param, host, port)
    except Exception as exc:
        _drop_client(host, port)
        log.exception("[main_gateway_exception]")
        detail = str(exc) or exc.__class__.__name__
        out = {"error": "rpc_exception", "detail": detail}
    if out is None:
        out = {"error": "empty_response"}
    _emit(out)


if __name__ == "__main__":
    setup_logging("logging/web.log", force=True)
    main()
