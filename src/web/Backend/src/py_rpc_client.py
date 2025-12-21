import json
import os
import sys
from pathlib import Path

# Ensure project src on path
ROOT_SRC = Path(__file__).resolve().parents[3]  # .../ProjectV0.2/src
sys.path.insert(0, str(ROOT_SRC))

from tsarchain.wallet.services.rpc_client import NodeClient  # type: ignore
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

    spendable = immature = pending = 0
    items = []
    try:
        items = balances.get("items") or []
    except Exception:
        items = []
    for it in items:
        spendable += int(it.get("spendable", 0) or 0)
        immature += int(it.get("immature", 0) or 0)
        pending += int(it.get("pending", 0) or 0)

    utxo_list = utxos.get("utxos") if isinstance(utxos, dict) else None
    if utxo_list is None and isinstance(utxos, list):
        utxo_list = utxos
    balance = sum(int(u.get("amount", 0) or 0) for u in (utxo_list or []))

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
        else:
            out = {"error": "unknown_op"}
        print(json.dumps(out))
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))


if __name__ == "__main__":
    main()
