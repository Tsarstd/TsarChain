# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import json
import os
import sys
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
    resp = client.send(payload)
    return resp

_CACHE_SCOPE = "default"

def _set_cache_scope(host: str, port: int) -> None:
    global _CACHE_SCOPE
    _CACHE_SCOPE = f"{host}:{port}"

def _cache_key(kind: str, *parts: object) -> str:
    return webdb.make_cache_key("web", _CACHE_SCOPE, kind, *parts)

def _payload_has_error(payload: object) -> bool:
    return isinstance(payload, dict) and bool(payload.get("error"))

def _should_cache_payload(payload: object) -> bool:
    if payload is None:
        return False
    if isinstance(payload, dict) and payload.get("error"):
        return webdb.should_cache_error(payload.get("error"))
    return True

def _cache_get(key: str):
    return webdb.cache_get_json(key)

def _cache_set(key: str, payload: object) -> None:
    webdb.cache_set_json(key, payload)

def _cache_fetch(key: str, fetch_fn):
    cached = _cache_get(key)
    if cached is not None:
        log.debug("[webcache] hit key=%s", key[:96])
        return cached
    log.debug("[webcache] miss_rpc key=%s", key[:96])
    payload = fetch_fn()
    if _should_cache_payload(payload):
        _cache_set(key, payload)
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
        log.debug("[webcache] hit key=%s", key[:96])
        return cached
    log.debug("[webcache] miss_rpc key=%s", key[:96])
    resp = _rpc_send(client, payload)
    if _payload_has_error(resp):
        if webdb.should_cache_error(resp.get("error") if isinstance(resp, dict) else None):
            _cache_set(key, resp)
        return resp
    webdb.cache_set_json(key, resp, ttl_sec=0)
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
    history = _rpc_send(client, {"type": "GET_TX_HISTORY", "address": addr_norm, "limit": 50}) or {}
    had_error = _payload_has_error(balances) or _payload_has_error(utxos) or _payload_has_error(history)

    if not isinstance(balances, dict):
        balances = {}
    if not isinstance(utxos, (dict, list)):
        utxos = {}
    if not isinstance(history, (dict, list)):
        history = {}

    spendable = immature = pending = 0
    items = balances.get("items") or balances.get("balances") or balances.get("map") or {}
    entry = {}
    if isinstance(items, dict):
        entry = items.get(addr_norm) or next(iter(items.values()), {}) or {}
    elif isinstance(items, list):
        entry = items[0] if items else {}
    if isinstance(entry, dict):
        spendable = int(entry.get("spendable") or entry.get("confirmed") or entry.get("balance_spendable") or 0)
        immature = int(entry.get("immature") or entry.get("balance_immature") or 0)
        pending = int(entry.get("pending") or entry.get("unconfirmed") or entry.get("balance_pending") or 0)

    utxo_list = []
    if isinstance(utxos, dict):
        raw = utxos.get("utxos") or utxos.get("items")
        if isinstance(raw, dict):
            for key, val in raw.items():
                txid = key
                idx = 0
                if isinstance(key, str) and ":" in key:
                    txid, idx_s = key.rsplit(":", 1)
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
                for key, val in utxos.items():
                    txid = key
                    idx = 0
                    if isinstance(key, str) and ":" in key:
                        txid, idx_s = key.rsplit(":", 1)
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
        "pending": pending,
        "balance": balance,
        "utxos": utxo_list or [],
        "history": history.get("txs") if isinstance(history, dict) else history,
        "height": history.get("height") if isinstance(history, dict) else None,
    }
    if not had_error:
        _cache_set(key, out)
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
    if _payload_has_error(post_resp) and not webdb.should_cache_error(post_resp.get("error")):
        cache_ok = False
    if _payload_has_error(comments_resp) and not webdb.should_cache_error(comments_resp.get("error")):
        cache_ok = False

    post = None
    if isinstance(post_resp, dict):
        post = post_resp.get("post") or post_resp
    comments = comments_resp.get("comments") if isinstance(comments_resp, dict) else None
    out = {"post": post, "comments": comments}
    if key and cache_ok and _should_cache_payload(out):
        _cache_set(key, out)
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

def rpc_graffiti_posts(client, opts: dict):
    limit = int(opts.get("limit", 50) or 50)
    offset = int(opts.get("offset", 0) or 0)
    key = _cache_key("graffiti_posts", limit, offset)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    payload = {"type": "GRAFFITI_GET_POSTS", "limit": limit, "offset": offset}
    resp = _rpc_send(client, payload)
    cache_ok = not _payload_has_error(resp)
    if isinstance(resp, dict) and resp.get("type") == "GRAFFITI_GET_POSTS":
        out = {"posts": resp.get("posts") or [], "limit": limit, "offset": offset}
    else:
        out = {"posts": [], "limit": limit, "offset": offset}
    if cache_ok and _should_cache_payload(out):
        _cache_set(key, out)
    return out

def rpc_graffiti_file(client, opts: dict, fallback_art_id: str | None):
    art_id = (opts.get("art_id") or fallback_art_id or "").strip()
    storer = (opts.get("storer_addr") or opts.get("storer") or "").strip()
    if not art_id:
        return {"status": "error", "reason": "missing_art_id"}
    resp = webdb.fetch_graffiti_file(lambda payload: _rpc_send(client, payload), art_id, storer_addr=storer)
    if not isinstance(resp, dict):
        return {"status": "error", "reason": "bad_response"}
    out = {
        "status": resp.get("status") or "error",
        "reason": resp.get("reason"),
        "meta": resp.get("meta") or {},
        "cache_path": resp.get("cache_path"),
    }
    return out


def main():
    out = None
    if len(sys.argv) < 2:
        log.error("[main] argv: %s", len(sys.argv))
        out = {"error": "missing_op"}
        _emit(out)
        return

    op = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) >= 3 else None

    host = os.environ.get("TSAR_NODE_HOST") or (sys.argv[3] if len(sys.argv) >= 4 else "127.0.0.1")
    try:
        port = int(os.environ.get("TSAR_NODE_PORT") or (sys.argv[4] if len(sys.argv) >= 5 else 19000))
    except Exception:
        port = 19000
        log.exception("[main_exception] port: %s", port)

    try:
        _set_cache_scope(host, port)
        client = _mk_client(host, port)
        if op == "network":
            out = rpc_network(client)
        elif op == "block":
            out = rpc_block(client, param)
        elif op == "tx":
            out = rpc_tx(client, param)
        elif op == "address":
            out = rpc_address(client, param)
        elif op == "graffiti":
            out = rpc_graffiti(client, param)
        elif op == "graffiti_posts":
            opts = _parse_opts(param)
            out = rpc_graffiti_posts(client, opts)
        elif op == "graffiti_file":
            opts = _parse_opts(param)
            out = rpc_graffiti_file(client, opts, param)
        else:
            out = {"error": "unknown_op"}
    except Exception as exc:
        log.exception("[main_gateway_exception]")
        detail = str(exc) or exc.__class__.__name__
        out = {"error": "rpc_exception", "detail": detail}
    if out is None:
        out = {"error": "empty_response"}
    _emit(out)


if __name__ == "__main__":
    setup_logging(force=True)
    main()
