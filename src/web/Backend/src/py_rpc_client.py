import json
import os
import sys
from pathlib import Path

# Ensure project src on path
ROOT_SRC = Path(__file__).resolve().parents[3]  # .../ProjectV0.2/src
sys.path.insert(0, str(ROOT_SRC))

from tsarchain.wallet.services.rpc_client import NodeClient  # type: ignore
from tsarchain.wallet.services.graffiti_service import fetch_graffiti_file  # type: ignore
from tsarchain.network.protocol import load_or_create_keypair_at  # type: ignore
from tsarchain.utils import config as CFG  # type: ignore


def _mk_client(host: str, port: int):
    user_id, user_pub, user_priv = load_or_create_keypair_at(CFG.USER_KEY_PATH)
    user_ctx = {"net_id": CFG.DEFAULT_NET_ID, "node_id": user_id, "pubkey": user_pub, "privkey": user_priv}
    return NodeClient(CFG, user_ctx=user_ctx, manual_bootstrap=(host, port))


def _rpc_send(client, payload: dict):
    resp = client.send(payload)
    return resp


def rpc_network(client):
    info = _rpc_send(client, {"type": "GET_NETWORK_INFO"}) or {}
    peers = _rpc_send(client, {"type": "GET_PEERS"}) or {}
    if isinstance(peers, dict) and "peers" in peers:
        info["peers"] = peers.get("peers")
    if isinstance(info, dict) and info.get("type") == "NETWORK_INFO":
        return info.get("data") or info
    return info


def rpc_block(client, val: str):
    if str(val).isdigit():
        payload = {"type": "GET_BLOCK", "height": int(val)}
    else:
        payload = {"type": "GET_BLOCK", "hash": str(val)}
    resp = _rpc_send(client, payload)
    return resp


def rpc_tx(client, txid: str):
    resp = _rpc_send(client, {"type": "GET_TX_DETAIL", "txid": str(txid).lower()})
    if isinstance(resp, dict) and not resp.get("error"):
        return resp
    # fallback
    for pay in (
        {"type": "GET_TX", "txid": str(txid).lower()},
        {"type": "GET_TRANSACTION", "txid": str(txid).lower()},
        {"type": "TX_GET", "txid": str(txid).lower()},
    ):
        rr = _rpc_send(client, pay)
        if isinstance(rr, dict) and not rr.get("error"):
            return rr
    return resp


def rpc_address(client, addr: str):
    balances = _rpc_send(client, {"type": "GET_BALANCES", "addresses": [addr]}) or {}
    utxos = _rpc_send(client, {"type": "GET_UTXOS", "address": addr}) or {}
    history = _rpc_send(client, {"type": "GET_TX_HISTORY", "address": addr, "limit": 50}) or {}

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
        entry = items.get(addr) or next(iter(items.values()), {}) or {}
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

    return {
        "address": addr,
        "spendable": spendable,
        "immature": immature,
        "pending": pending,
        "balance": balance,
        "utxos": utxo_list or [],
        "history": history.get("txs") if isinstance(history, dict) else history,
        "height": history.get("height") if isinstance(history, dict) else None,
    }


def rpc_graffiti(client, art_id: str):
    post_resp = _rpc_send(client, {"type": "GRAFFITI_GET_ART", "art_id": art_id}) or {}
    comments_resp = _rpc_send(client, {"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id}) or {}
    post = None
    if isinstance(post_resp, dict):
        post = post_resp.get("post") or post_resp
    comments = comments_resp.get("comments") if isinstance(comments_resp, dict) else None
    return {"post": post, "comments": comments}

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
    payload = {"type": "GRAFFITI_GET_POSTS", "limit": limit, "offset": offset}
    resp = _rpc_send(client, payload)
    if isinstance(resp, dict) and resp.get("type") == "GRAFFITI_GET_POSTS":
        return {"posts": resp.get("posts") or [], "limit": limit, "offset": offset}
    return {"posts": [], "limit": limit, "offset": offset}

def rpc_graffiti_file(client, opts: dict, fallback_art_id: str | None):
    art_id = (opts.get("art_id") or fallback_art_id or "").strip()
    storer = (opts.get("storer_addr") or opts.get("storer") or "").strip()
    if not art_id:
        return {"status": "error", "reason": "missing_art_id"}
    resp = fetch_graffiti_file(lambda payload: _rpc_send(client, payload), art_id, storer_addr=storer)
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
    if len(sys.argv) < 2:
        print(json.dumps({"error": "missing_op"}))
        return

    op = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) >= 3 else None

    host = os.environ.get("TSAR_NODE_HOST") or (sys.argv[3] if len(sys.argv) >= 4 else "127.0.0.1")
    try:
        port = int(os.environ.get("TSAR_NODE_PORT") or (sys.argv[4] if len(sys.argv) >= 5 else 19000))
    except Exception:
        port = 19000

    try:
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
        print(json.dumps(out))
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))


if __name__ == "__main__":
    main()
