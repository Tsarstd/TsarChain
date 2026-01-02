# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import json
import os
import sys
import threading
from pathlib import Path

# Ensure project root + src + local backend src on path
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_SRC = Path(__file__).resolve().parents[3]
PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(ROOT_SRC))
sys.path.insert(0, str(PROJECT_ROOT))

from tsarchain.wallet.services.rpc_client import NodeClient
from tsarchain.network.protocol import load_or_create_keypair_at
from tsarchain.utils import config as CFG
from src.web.Backend.src import database_web as webdb

from tsarchain.utils.tsar_logging import get_ctx_logger, setup_logging
log = get_ctx_logger('tsarchain.web.Backend.py_rpc_client')

_CLIENT_CACHE = {}
_CLIENT_LOCK = threading.RLock()
_CACHE_SCOPE = "default"
_prefetch_started = False
_prefetch_host_port = None
RPC_SOURCE = os.environ.get("TSAR_RPC_SOURCE") or "web_backend"

def _emit(out: object) -> None:
    try:
        sys.stdout.write(json.dumps(out, ensure_ascii=True, default=str))
    except Exception:
        sys.stdout.write('{"error":"json_encode_failed"}')
    sys.stdout.flush()

def _mk_client(host: str, port: int):
    user_id, user_pub, user_priv = load_or_create_keypair_at(CFG.USER_KEY_PATH)
    user_ctx = {"net_id": CFG.DEFAULT_NET_ID, "node_id": user_id, "pubkey": user_pub, "privkey": user_priv}
    return NodeClient(CFG, user_ctx=user_ctx, manual_bootstrap=(host, port))

def _rpc_send(client, payload: dict):
    if RPC_SOURCE and isinstance(payload, dict) and "rpc_source" not in payload:
        payload = dict(payload)
        payload["rpc_source"] = RPC_SOURCE
    resp = client.send(payload)
    return resp

def _get_client(host: str, port: int):
    global _prefetch_started
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

def _set_cache_scope(host: str, port: int) -> None:
    global _CACHE_SCOPE
    _CACHE_SCOPE = f"{host}:{port}"

def _cache_key(kind: str, *parts: object) -> str:
    return webdb.make_cache_key("web", _CACHE_SCOPE, kind, *parts)

def _payload_has_error(payload: object) -> bool:
    return isinstance(payload, dict) and bool(payload.get("error"))

def _cache_policy(payload: object) -> tuple[bool, int | None]:
    if payload is None:
        return False, None
    if isinstance(payload, dict):
        if payload.get("error"):
            ttl = webdb.cache_ttl_for_error(payload.get("error") or payload.get("detail") or payload.get("reason"))
            return ttl is not None, ttl
        if payload.get("status") == "error":
            ttl = webdb.cache_ttl_for_error(payload.get("reason"))
            return ttl is not None, ttl
    return True, None

def _cache_get(key: str, refresh_ttl: bool = False):
    return webdb.cache_get_json(key, refresh_ttl=refresh_ttl)

def _cache_set(key: str, payload: object, ttl_sec: int | None = None) -> None:
    if ttl_sec is None:
        webdb.cache_set_json(key, payload)
    else:
        webdb.cache_set_json(key, payload, ttl_sec=ttl_sec)

def _cache_fetch(key: str, fetch_fn):
    cached = _cache_get(key)
    if cached is not None:
        return cached
    payload = fetch_fn()
    cache_ok, ttl_sec = _cache_policy(payload)
    if cache_ok:
        _cache_set(key, payload, ttl_sec)
    return payload

def rpc_network(client):
    key = _cache_key("network")
    def _fetch():
        info = _rpc_send(client, {"type": "GET_NETWORK_INFO"}) or {}
        peers = _rpc_send(client, {"type": "GET_PEERS"}) or {}
        if isinstance(peers, dict) and "peers" in peers:
            info["peers"] = peers.get("peers")
        if isinstance(info, dict) and info.get("type") == "NETWORK_INFO":
            return info.get("data") or info
        return info
    return _cache_fetch(key, _fetch)

def rpc_block(client, val: str):
    if str(val).isdigit():
        key = _cache_key("block", "h", str(val))
        payload = {"type": "GET_BLOCK", "height": int(val)}
    else:
        key = _cache_key("block", "hash", str(val).lower())
        payload = {"type": "GET_BLOCK", "hash": str(val)}
    cached = _cache_get(key)
    if cached is not None:
        return cached
    resp = _rpc_send(client, payload)
    if _payload_has_error(resp):
        ttl_err = webdb.cache_ttl_for_error(resp.get("error") if isinstance(resp, dict) else None)
        if ttl_err is not None:
            _cache_set(key, resp, ttl_err)
        return resp
    webdb.cache_set_json(key, resp, ttl_sec=0)
    return resp

def rpc_block_range(client, opts: dict):
    global _prefetch_started
    
    start_height = None
    if isinstance(opts, dict):
        start_height = opts.get("start_height") or opts.get("start") or opts.get("height")
    
    limit = int(opts.get("limit", 200) or 200) if isinstance(opts, dict) else 200
    if start_height is None or start_height == "latest":
        key = _cache_key("block_range", "latest", limit)
        cached = _cache_get(key)
        if cached is not None:
            log.debug("[rpc_block_range] Using latest blocks from volatile cache")
            return cached
    
    if start_height is not None and start_height != "latest":
        try:
            start_height_int = int(start_height)
            storage_result = webdb.get_block_range_from_storage(start_height_int, limit)
            
            if len(storage_result["items"]) >= limit:
                log.debug("[rpc_block_range] Using %d blocks from permanent storage", 
                         len(storage_result["items"]))
                return storage_result
            
            missing_count = limit - len(storage_result["items"])
            if missing_count > 0:
                next_start = start_height_int + len(storage_result["items"])
                rpc_resp = _rpc_send(client, {
                    "type": "GET_BLOCK_RANGE", 
                    "start_height": next_start, 
                    "limit": missing_count
                })
                
                if isinstance(rpc_resp, dict) and "items" in rpc_resp:
                    new_items = rpc_resp.get("items", [])
                    webdb.save_blocks_permanent(new_items)
                    storage_result["items"].extend(new_items)
                    storage_result["has_more"] = rpc_resp.get("has_more", False)
                    storage_result["next_height"] = rpc_resp.get("next_height")
                return storage_result   
            
        except ValueError:
            pass
    
    log.debug("[rpc_block_range] Fetching from RPC (height=%s, limit=%d)", start_height, limit)
    resp = _rpc_send(client, {
        "type": "GET_BLOCK_RANGE", 
        "limit": limit, 
        "start_height": start_height
    })
    
    if not _payload_has_error(resp) and isinstance(resp, dict) and "items" in resp:
        webdb.save_blocks_permanent(resp["items"])
        
        if start_height is None or start_height == "latest":
            cache_key = _cache_key("block_range", "latest", limit)
            _cache_set(cache_key, resp, ttl_sec=30)
    
    return resp

def rpc_tx(client, txid: str):
    txid_norm = str(txid).lower()
    key = _cache_key("tx", txid_norm)
    return _cache_fetch(key, lambda: _rpc_send(client, {"type": "GET_TX_DETAIL", "txid": txid_norm}))

def rpc_address(client, addr: str):
    addr_norm = str(addr or "").strip()
    key = _cache_key("address", addr_norm.lower())
    cached = _cache_get(key)
    if cached is not None:
        return cached

    balances = _rpc_send(client, {"type": "GET_BALANCES", "addresses": [addr_norm]}) or {}
    utxos = _rpc_send(client, {"type": "GET_UTXOS", "address": addr_norm}) or {}
    history = _rpc_send(client, {"type": "GET_TX_HISTORY", "address": addr_norm, "limit": 200}) or {}
    history_list = []
    if isinstance(history, dict):
        history_list = history.get("items") or []
        if not history_list:
            for key in ["history", "transactions", "txs", "data"]:
                if key in history and isinstance(history[key], list):
                    history_list = history[key]
                    break
                
    if not isinstance(history_list, list):
        history_list = []
        
    had_error = _payload_has_error(balances) or _payload_has_error(utxos) or _payload_has_error(history)
    error_ttl = None
    if had_error:
        for resp in (balances, utxos, history):
            if not _payload_has_error(resp):
                continue
            ttl = webdb.cache_ttl_for_error(resp.get("error") if isinstance(resp, dict) else None)
            if ttl is None:
                error_ttl = None
                break
            if error_ttl is None or ttl > error_ttl:
                error_ttl = ttl

    if not isinstance(balances, dict):
        balances = {}
    if not isinstance(utxos, (dict, list)):
        utxos = {}
    if not isinstance(history, (dict, list)):
        history = {}

    spendable = immature = 0
    items = balances.get("items") or balances.get("balances") or balances.get("map") or {}
    entry = {}
    if isinstance(items, dict):
        entry = items.get(addr_norm) or next(iter(items.values()), {}) or {}
    elif isinstance(items, list):
        entry = items[0] if items else {}
    if isinstance(entry, dict):
        spendable = int(entry.get("spendable") or 0)
        immature = int(entry.get("immature") or 0)
        outgoing = int(entry.get("pending_outgoing") or 0)
        incoming = int(entry.get("pending_incoming") or 0)

    utxo_list = []
    if isinstance(utxos, dict):
        raw = utxos.get("utxos") or utxos.get("items")
        if isinstance(raw, dict):
            for utxo_key, val in raw.items():
                txid = utxo_key
                idx = 0
                if isinstance(utxo_key, str) and ":" in utxo_key:
                    txid, idx_s = utxo_key.rsplit(":", 1)
                    try:
                        idx = int(idx_s)
                    except Exception:
                        idx = 0
                if isinstance(val, dict):
                    amount = val.get("amount") or val.get("value") or val.get("tx_out", {}).get("amount", 0)
                    height = val.get("block_height") or val.get("height")
                    confirmations = val.get("confirmations")
                else:
                    amount = val
                    height = None
                    confirmations = None
                utxo_list.append({
                    "txid": txid,
                    "vout": idx,
                    "amount": amount or 0,
                    "height": height,
                    "confirmations": confirmations,
                })
        elif isinstance(raw, list):
            utxo_list = [u for u in raw if isinstance(u, dict)]
        else:
            # fallback: utxos dict may already be outpoint map
            if utxos and all(isinstance(v, dict) for v in utxos.values()):
                for utxo_key, val in utxos.items():
                    txid = utxo_key
                    idx = 0
                    if isinstance(utxo_key, str) and ":" in utxo_key:
                        txid, idx_s = utxo_key.rsplit(":", 1)
                        try:
                            idx = int(idx_s)
                        except Exception:
                            idx = 0
                    amount = val.get("amount") or val.get("value") or val.get("tx_out", {}).get("amount", 0)
                    utxo_list.append({
                        "txid": txid,
                        "vout": idx,
                        "amount": amount or 0,
                        "height": val.get("block_height") or val.get("height"),
                        "confirmations": val.get("confirmations"),
                    })
    elif isinstance(utxos, list):
        utxo_list = [u for u in utxos if isinstance(u, dict)]

    balance = sum(int(u.get("amount", 0) or 0) for u in utxo_list if isinstance(u, dict))

    out = {
        "address": addr_norm,
        "spendable": spendable,
        "immature": immature,
        "outgoing": outgoing,
        "incoming": incoming,
        "balance": balance,
        "utxos": utxo_list or [],
        "history": history_list,
        "height": history.get("height") if isinstance(history, dict) else None,
    }
    if not had_error:
        _cache_set(key, out)
    elif error_ttl is not None:
        _cache_set(key, out, error_ttl)
    return out


def rpc_graffiti(client, art_id: str):
    art_norm = str(art_id or "").strip()
    key = _cache_key("graffiti", art_norm.lower()) if art_norm else None
    if key:
        cached = _cache_get(key)
        if cached is not None:
            return cached

    post_resp = _rpc_send(client, {"type": "GRAFFITI_GET_ART", "art_id": art_norm}) or {}
    comments_resp = _rpc_send(client, {"type": "GRAFFITI_GET_COMMENTS", "art_id": art_norm}) or {}
    cache_ok = True
    error_ttl = None
    for resp in (post_resp, comments_resp):
        if not _payload_has_error(resp):
            continue
        ttl = webdb.cache_ttl_for_error(resp.get("error") if isinstance(resp, dict) else None)
        if ttl is None:
            cache_ok = False
            break
        if error_ttl is None or ttl > error_ttl:
            error_ttl = ttl

    post = None
    if isinstance(post_resp, dict):
        post = post_resp.get("post") or post_resp
    comments = comments_resp.get("comments") if isinstance(comments_resp, dict) else None
    out = {"post": post, "comments": comments}
    if key and cache_ok:
        _cache_set(key, out, error_ttl)
    return out

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

def rpc_graffiti_posts(client, opts: dict):
    limit = int(opts.get("limit", 50) or 50)
    offset = int(opts.get("offset", 0) or 0)
    key = _cache_key("graffiti_posts", limit, offset)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    payload = {"type": "GRAFFITI_GET_POSTS", "limit": limit, "offset": offset}
    resp = _rpc_send(client, payload)
    cache_ok = True
    error_ttl = None
    if _payload_has_error(resp):
        error_ttl = webdb.cache_ttl_for_error(resp.get("error") if isinstance(resp, dict) else None)
        cache_ok = error_ttl is not None
    if isinstance(resp, dict) and resp.get("type") == "GRAFFITI_GET_POSTS":
        out = {"posts": resp.get("posts") or [], "limit": limit, "offset": offset}
    else:
        out = {"posts": [], "limit": limit, "offset": offset}
    if cache_ok:
        _cache_set(key, out, error_ttl)
    return out

def rpc_graffiti_file(client, opts: dict, fallback_art_id: str | None):
    art_id = (opts.get("art_id") or fallback_art_id or "").strip()
    storer = (opts.get("storer_addr") or opts.get("storer") or "").strip()
    cache_dir = (opts.get("cache_dir") or opts.get("cache") or "").strip() or None
    try:
        max_bytes = int(opts.get("max_bytes") or 0) or int(CFG.GRAFFITI_MAX_SIZE_BYTES)
    except Exception:
        max_bytes = int(CFG.GRAFFITI_MAX_SIZE_BYTES)
    try:
        timeout = float(opts.get("timeout") or 0) or 5.0
    except Exception:
        timeout = 5.0

    if not art_id:
        return {"status": "error", "reason": "missing_art_id"}

    resp = webdb.fetch_graffiti_file(
        lambda payload: _rpc_send(client, payload),
        art_id,
        storer_addr=storer,
        cache_dir=cache_dir,
        cache_scope=_CACHE_SCOPE,
        max_bytes=max_bytes,
        timeout=timeout,
    )
    if not isinstance(resp, dict):
        return {"status": "error", "reason": "bad_response"}
    out = {
        "status": resp.get("status") or "error",
        "reason": resp.get("reason"),
        "meta": resp.get("meta") or {},
        "cache_path": resp.get("cache_path"),
    }
    return out


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
            
            webdb.start_prefetch_thread(prefetch_rpc_call)
            _prefetch_started = True
            _prefetch_host_port = f"{host}:{port}"
            log.info("[dispatch_rpc] Started auto-prefetch thread for %s:%s", host, port)
        except Exception as exc:
            log.warning("[dispatch_rpc] Failed to start prefetch: %s", exc)
    
    if op == "network":
        return rpc_network(client)
    if op == "block":
        return rpc_block(client, param_norm)
    if op == "block_range":
        opts = param_norm if isinstance(param_norm, dict) else _parse_block_range_opts(param_norm)
        return rpc_block_range(client, opts)
    if op == "tx":
        return rpc_tx(client, param_norm)
    if op == "address":
        return rpc_address(client, param_norm)
    if op == "graffiti":
        return rpc_graffiti(client, param_norm)
    if op == "graffiti_posts":
        opts = param_norm if isinstance(param_norm, dict) else _parse_opts(param_norm)
        return rpc_graffiti_posts(client, opts)
    if op == "graffiti_file":
        opts = param_norm if isinstance(param_norm, dict) else _parse_opts(param_norm)
        fallback = param_norm if isinstance(param_norm, str) else None
        return rpc_graffiti_file(client, opts, fallback)
    if op == "prefetch_blocks":
        try:
            webdb.prefetch_blocks(lambda payload: _rpc_send(client, payload))
            return {"status": "ok", "message": "Prefetch started"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
    
    return {"error": "unknown_op"}


def _emit_worker(req_id: object, payload: object) -> None:
    try:
        sys.stdout.write(json.dumps({"id": req_id, "payload": payload}, ensure_ascii=True, default=str) + "\n")
    except Exception:
        sys.stdout.write('{"id":null,"payload":{"error":"json_encode_failed"}}\n')
    sys.stdout.flush()


def _worker_loop() -> None:
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
        host, port = _parse_host_port(req.get("host"), req.get("port"))
        try:
            out = _dispatch_rpc(str(op), req.get("param"), host, port)
        except Exception as exc:
            _drop_client(host, port)
            log.exception("[worker_exception]")
            detail = str(exc) or exc.__class__.__name__
            out = {"error": "rpc_exception", "detail": detail}
        _emit_worker(req_id, out)


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
    setup_logging(force=True)
    main()
