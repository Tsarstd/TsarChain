# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Dict, Optional

from tsarchain.network.protocol import load_or_create_keypair_at
from tsarchain.wallet.services.rpc_client import NodeClient
from tsarchain.wallet.services.graffiti_service import fetch_graffiti_file as fetch_graffiti_blob
from tsarchain.utils import config as CFG

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("web.Backend.rpc_gateway")

BASE_DIR = "data_web"

def _pick(d: Dict[str, Any], *keys: str) -> Any:
    log.debug("_pick keys=%s", keys)
    if not isinstance(d, dict):
        log.warning("_pick expected dict, got %s", type(d).__name__)
        return None
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None

def _pick_nested(d: Dict[str, Any], *paths: tuple[str, ...]) -> Any:
    log.debug("_pick_nested paths=%s", paths)
    if not isinstance(d, dict):
        log.warning("_pick_nested expected dict, got %s", type(d).__name__)
        return None
    for path in paths:
        cur: Any = d
        ok = True
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                ok = False
                break
            cur = cur[key]
        if ok and cur not in (None, ""):
            return cur
    return None

class ExplorerGateway:
    def __init__(self, manual_bootstrap: Optional[tuple[str, int]] = None) -> None:
        log.debug("init gateway manual_bootstrap=%s", manual_bootstrap)
        self.base_dir = str(BASE_DIR)
        user_key_path = os.path.join(self.base_dir, CFG.USER_KEY_PATH)
        os.makedirs(os.path.dirname(user_key_path), exist_ok=True)
        user_id, user_pub, user_priv = load_or_create_keypair_at(user_key_path)
        self.cache_dir = os.path.join(self.base_dir, "data_user", "graffiti_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        user_ctx = {
            "net_id": CFG.DEFAULT_NET_ID,
            "node_id": user_id,
            "pubkey": user_pub,
            "privkey": user_priv,
        }
        self.rpc = NodeClient(
            cfg_module=None,
            user_ctx=user_ctx,
            root=None,
            manual_bootstrap=manual_bootstrap,
        )
        self._info_cache: Optional[Dict[str, Any]] = None
        self._info_cache_ts = 0.0
        self._info_cache_ttl = 30.0
        self._info_lock = threading.Lock()
        self._info_snapshot_cache: Optional[Dict[str, Any]] = None
        self._info_snapshot_ts = 0.0
        self._info_snapshot_lock = threading.Lock()

    def _rpc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        log.debug("rpc send type=%s", payload.get("type") if isinstance(payload, dict) else None)
        resp = self.rpc.send(payload)
        if not isinstance(resp, dict):
            log.warning(
                "rpc bad response type=%s for payload type=%s",
                type(resp).__name__,
                payload.get("type") if isinstance(payload, dict) else None,
            )
            return {"error": "bad_response"}
        if resp.get("error"):
            log.warning("rpc error for type=%s: %s", payload.get("type"), resp.get("error"))
        return resp

    def get_info(self) -> Dict[str, Any]:
        log.debug("get_info")
        now = time.time()
        with self._info_lock:
            if self._info_cache and (now - self._info_cache_ts) < self._info_cache_ttl:
                return dict(self._info_cache)
        r = self._rpc({"type": "GET_NETWORK_INFO"})
        if not isinstance(r, dict) or r.get("error"):
            log.warning("get_info rpc error: %s", r.get("error") if isinstance(r, dict) else "bad_response")
            if isinstance(r, dict) and r.get("error") == "rate_limited":
                with self._info_lock:
                    if self._info_cache:
                        return dict(self._info_cache)
            return {"error": r.get("error") if isinstance(r, dict) else "bad_response"}

        body = r.get("data") if r.get("type") == "NETWORK_INFO" and isinstance(r.get("data"), dict) else r

        network = _pick(body, "net_id", "network_id") or _pick_nested(body, ("identity", "network_id")) or CFG.DEFAULT_NET_ID
        height = _pick(body, "height", "tip_height") or _pick_nested(body, ("chain", "tip_height"))
        difficulty = _pick(body, "difficulty", "tip_difficulty") or _pick_nested(body, ("chain", "tip_difficulty"))
        target = _pick(body, "target", "tip_target") or _pick_nested(body, ("chain", "tip_target_hex"))
        tip = _pick(body, "tip", "tip_hash", "best_hash") or _pick_nested(body, ("chain", "tip_hash"))
        hashrate = _pick(body, "hashrate", "network_hashrate") or _pick_nested(body, ("chain", "est_network_hashrate_hps_window"))
        genesis = _pick(body, "genesis_hash", "genesis") or _pick_nested(body, ("chain", "genesis_hash"))

        peers = body.get("peers")
        if isinstance(peers, dict):
            peers_count = peers.get("count") or peers.get("total") or len(peers.get("items") or [])
        elif isinstance(peers, list):
            peers_count = len(peers)
        else:
            peers_count = None

        mempool = _pick(body, "mempool_count", "txpool_size", "mempool") or _pick_nested(body, ("transactions", "mempool_txs"))
        mempool_bytes = _pick_nested(body, ("transactions", "mempool_bytes_estimate"))
        supply = body.get("supply") if isinstance(body.get("supply"), dict) else {}
        chain = body.get("chain") if isinstance(body.get("chain"), dict) else {}
        transactions = body.get("transactions") if isinstance(body.get("transactions"), dict) else {}

        info = {
            "network": network,
            "height": height,
            "difficulty": difficulty,
            "target": target,
            "tip": tip,
            "hashrate": hashrate,
            "genesis": genesis,
            "peers": peers_count,
            "mempool": mempool,
            "mempool_bytes": mempool_bytes,
            "supply": supply,
            "chain": chain,
            "transactions": transactions,
        }
        with self._info_lock:
            self._info_cache = dict(info)
            self._info_cache_ts = time.time()
        return info

    def _decode_comment(self, c: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize comment payload so UI can show plain text (no hex).
        """
        if not isinstance(c, dict):
            return {}
        text = c.get("comment_text")
        if not text:
            raw_hex = c.get("comment_hex") or c.get("comment")
            if isinstance(raw_hex, str):
                try:
                    text = bytes.fromhex(raw_hex).decode("utf-8", errors="replace")
                except Exception:
                    text = raw_hex
        out = dict(c)
        if text:
            out["comment_text"] = text
        return out

    def get_info_snapshot(self) -> Dict[str, Any]:
        """
        Return full network snapshot (identity/chain/supply/txs/utxo/graffiti/miners/peers).
        """
        log.debug("get_info_snapshot")
        now = time.time()
        with self._info_snapshot_lock:
            if self._info_snapshot_cache and (now - self._info_snapshot_ts) < self._info_cache_ttl:
                return dict(self._info_snapshot_cache)

        snap_raw = self._rpc({"type": "GET_NETWORK_INFO"})
        if not isinstance(snap_raw, dict) or snap_raw.get("error"):
            log.warning("get_info_snapshot rpc error: %s", snap_raw.get("error") if isinstance(snap_raw, dict) else "bad_response")
            with self._info_snapshot_lock:
                if isinstance(snap_raw, dict) and snap_raw.get("error") == "rate_limited" and self._info_snapshot_cache:
                    return dict(self._info_snapshot_cache)
            return {"error": snap_raw.get("error") if isinstance(snap_raw, dict) else "bad_response"}

        snap = snap_raw.get("data") if snap_raw.get("type") == "NETWORK_INFO" and isinstance(snap_raw.get("data"), dict) else snap_raw

        # Attach peers count when absent
        peers_count = None
        peers_section = snap.get("peers")
        if isinstance(peers_section, dict):
            peers_count = peers_section.get("count") or peers_section.get("total")
        elif isinstance(peers_section, list):
            peers_count = len(peers_section)

        if peers_count is None:
            peers_resp = self._rpc({"type": "GET_PEERS"})
            if isinstance(peers_resp, dict):
                peers = peers_resp.get("peers")
                if isinstance(peers, list):
                    peers_count = len(peers)
                    snap["peers"] = {"count": peers_count, "items": peers}
                elif isinstance(peers_resp.get("count"), int):
                    peers_count = peers_resp.get("count")
                    snap["peers"] = {"count": peers_count}
        snap.setdefault("peers_count", peers_count)

        with self._info_snapshot_lock:
            self._info_snapshot_cache = dict(snap)
            self._info_snapshot_ts = time.time()
        return snap

    def get_block(self, idx: str) -> Dict[str, Any]:
        log.debug("get_block idx=%s", idx)
        s = str(idx or "").strip()
        if re.fullmatch(r"\d+", s):
            h = int(s)
            blk = self._rpc({"type": "GET_BLOCK", "height": h})
            if isinstance(blk, dict) and blk and not blk.get("error"):
                blk.setdefault("height", h)
                return blk
            log.warning(
                "block not found by height=%s error=%s",
                h,
                blk.get("error") if isinstance(blk, dict) else "not_found",
            )
            return {"error": (blk.get("error") if isinstance(blk, dict) else "not_found")}

        if re.fullmatch(r"[0-9a-fA-F]{64}", s):
            blk = self._rpc({"type": "GET_BLOCK", "hash": s.lower()})
            if isinstance(blk, dict) and blk and not blk.get("error"):
                blk.setdefault("hash", s.lower())
                return blk
            log.warning(
                "block not found by hash=%s error=%s",
                s.lower(),
                blk.get("error") if isinstance(blk, dict) else "not_found",
            )
            return {"error": (blk.get("error") if isinstance(blk, dict) else "not_found")}

        log.warning("invalid block id: %s", s)
        return {"error": "invalid_block_id"}

    def _normalize_tx(self, t: Dict[str, Any], txid_hint: str) -> Dict[str, Any]:
        log.debug("normalize_tx txid_hint=%s", txid_hint)
        tx = t.get("tx") if isinstance(t.get("tx"), dict) else t.get("transaction") if isinstance(t.get("transaction"), dict) else t
        if not isinstance(tx, dict):
            log.warning("normalize_tx bad shape for txid_hint=%s", txid_hint)
            return {"error": "tx_bad_shape"}

        txid = tx.get("txid") or tx.get("id") or tx.get("hash") or txid_hint
        tx["txid"] = txid

        if "inputs" not in tx and "vin" in tx:
            tx["inputs"] = tx.get("vin") or []
        if "outputs" not in tx and "vout" in tx:
            tx["outputs"] = tx.get("vout") or []

        if "is_coinbase" not in tx:
            vin = tx.get("inputs") or []
            if isinstance(vin, list) and vin:
                prev = (vin[0].get("txid") or vin[0].get("prev_txid") or "")
                tx["is_coinbase"] = (prev == "0" * 64) or bool(vin[0].get("coinbase"))

        return tx

    def get_tx(self, txid: str) -> Dict[str, Any]:
        log.debug("get_tx txid=%s", txid)
        tid = str(txid or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", tid):
            log.warning("invalid txid: %s", tid)
            return {"error": "invalid_txid"}

        r = self._rpc({"type": "GET_TX_DETAIL", "txid": tid})
        if not isinstance(r, dict) or r.get("error"):
            for pay in (
                {"type": "GET_TX", "txid": tid},
                {"type": "GET_TRANSACTION", "txid": tid},
                {"type": "TX_GET", "txid": tid},
            ):
                rr = self._rpc(pay)
                if isinstance(rr, dict) and not rr.get("error"):
                    r = rr
                    break
            else:
                log.warning("tx not found for txid=%s", tid)
                return {"error": "not_found"}

        return self._normalize_tx(r, tid)

    def get_address(
        self,
        addr: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        direction: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        log.debug(
            "get_address addr=%s limit=%s offset=%s direction=%s status=%s",
            addr,
            limit,
            offset,
            direction,
            status,
        )
        address = str(addr or "").strip().lower()
        if not address:
            log.warning("invalid address: %s", addr)
            return {"error": "invalid_address"}

        bals = self._rpc({"type": "GET_BALANCES", "addresses": [address]})
        utx = self._rpc({"type": "GET_UTXOS", "address": address})

        hist_payload: Dict[str, Any] = {"type": "GET_TX_HISTORY", "address": address}
        if limit is not None:
            hist_payload["limit"] = int(limit)
        if offset is not None:
            hist_payload["offset"] = int(offset)
        if direction in ("in", "out"):
            hist_payload["direction"] = direction
        if status in ("confirmed", "unconfirmed"):
            hist_payload["status"] = status
        his = self._rpc(hist_payload)

        res = {"address": address, "spendable": 0, "immature": 0, "pending": 0, "utxos": [], "history": []}

        def _pick_entry(d: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            if not isinstance(d, dict):
                return None
            if any(k in d for k in ("spendable", "confirmed", "pending", "immature")):
                return d
            for key in ("balances", "items", "map"):
                m = d.get(key)
                if isinstance(m, dict):
                    return m.get(address) or (list(m.values())[0] if m else {})
            if isinstance(d.get("balance"), dict):
                return d.get("balance")
            return None

        be = _pick_entry(bals) or {}
        if isinstance(be, dict):
            res["spendable"] = int(be.get("spendable") or be.get("confirmed") or be.get("balance_spendable") or 0)
            res["immature"] = int(be.get("immature") or be.get("balance_immature") or 0)
            res["pending"] = int(be.get("pending") or be.get("unconfirmed") or be.get("balance_pending") or 0)

        utxo_list = []
        if isinstance(utx, dict):
            raw = utx.get("utxos") or utx.get("items") or []
            if isinstance(raw, dict):
                for k, v in raw.items():
                    txid, idx = k.rsplit(":", 1)
                    utxo_list.append(
                        {
                            "txid": txid,
                            "index": int(idx),
                            "amount": v.get("amount") or v.get("value") or 0,
                            "height": v.get("block_height") or v.get("height"),
                            "confirmations": v.get("confirmations"),
                        }
                    )
            elif isinstance(raw, list):
                utxo_list = raw
        elif isinstance(utx, list):
            utxo_list = utx
        res["utxos"] = utxo_list

        if isinstance(his, list):
            res["history"] = his
        elif isinstance(his, dict):
            res["history"] = his.get("history") or his.get("items") or []

        if (res["spendable"] == 0 and res["pending"] == 0 and res["immature"] == 0) and res["utxos"]:
            res["spendable"] = int(sum(int(u.get("amount") or 0) for u in res["utxos"]))

        return res

    def get_graffiti(self, art_id: str) -> Dict[str, Any]:
        log.debug("get_graffiti art_id=%s", art_id)
        aid = str(art_id or "").strip().lower()
        if not aid:
            log.warning("invalid art_id: %s", art_id)
            return {"error": "invalid_art_id"}
        resp = self._rpc({"type": "GRAFFITI_GET_ART", "art_id": aid})
        if isinstance(resp, dict) and resp.get("error"):
            log.warning("graffiti get error art_id=%s error=%s", aid, resp.get("error"))
        if isinstance(resp, dict):
            post = resp.get("post") if isinstance(resp.get("post"), dict) else resp
            if isinstance(post, dict) and isinstance(post.get("comments"), list):
                post["comments"] = [self._decode_comment(c) for c in post.get("comments")]
            return resp
        return {"error": "bad_response"}

    def get_graffiti_comments(self, art_id: str, *, limit: Optional[int] = None) -> Dict[str, Any]:
        log.debug("get_graffiti_comments art_id=%s limit=%s", art_id, limit)
        aid = str(art_id or "").strip().lower()
        if not aid:
            log.warning("invalid art_id for comments: %s", art_id)
            return {"error": "invalid_art_id"}
        payload: Dict[str, Any] = {"type": "GRAFFITI_GET_COMMENTS", "art_id": aid}
        if limit is not None:
            payload["limit"] = int(limit)
        resp = self._rpc(payload)
        if isinstance(resp, dict) and resp.get("error"):
            log.warning("graffiti comments error art_id=%s error=%s", aid, resp.get("error"))
        if isinstance(resp, dict):
            if isinstance(resp.get("comments"), list):
                resp["comments"] = [self._decode_comment(c) for c in resp.get("comments")]
            return resp
        return {"error": "bad_response"}

    def fetch_graffiti_file(self, art_id: str, *, post: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        log.debug("fetch_graffiti_file art_id=%s has_post=%s", art_id, bool(post))
        aid = str(art_id or "").strip().lower()
        if not aid:
            log.warning("invalid art_id for fetch: %s", art_id)
            return {"status": "error", "reason": "invalid_art_id"}
        storer_addr = (post or {}).get("storer") or (post or {}).get("storage")
        result = fetch_graffiti_blob(self._rpc, aid, storer_addr=storer_addr, cache_dir=self.cache_dir)
        if isinstance(result, dict) and result.get("status") not in (None, "ok"):
            log.warning("graffiti fetch error art_id=%s status=%s", aid, result.get("status"))
        return result
