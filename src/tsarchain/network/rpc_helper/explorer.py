# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import time
import threading
import collections

# ---------------- Local Project ----------------
from ...utils import config as CFG
from .base import NetworkHandlerProxy
from ...contracts import graffiti as GRAFF
from ...utils.benchmarks import benchmark
from ...utils.helpers import estimate_block_size_bytes, spkhex_to_address

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.user_rpc_helper.explorer")


class ExplorerHandler(NetworkHandlerProxy):
    def __init__(self, network):
        super().__init__(network)
        self._block_hash_cache = collections.OrderedDict()
        self._block_hash_cache_lock = threading.RLock()

    @benchmark(label="GET_TX_DETAIL", threshold_ms=15.0)
    def process_tx_lookup(self, txid_hex: str, src_tag: str | None = None) -> dict:
        txid_hex = str(txid_hex or "").strip().lower()
        where, tx, height, timestamp, conf, chain, _, _ = self.find_tx_and_meta(txid_hex)
        if tx is None:
            return {"error": "tx not found", "txid": txid_hex}

        is_coinbase = self.is_coinbase_tx(tx)
        opmap = {} if is_coinbase else self.build_outpoint_map(chain)

        vin, total_in = ([], 0) if is_coinbase else self._build_tx_inputs(tx, opmap)
        vout, total_out = self._build_tx_outputs(tx)

        fee = None
        if not is_coinbase and vin and total_in >= total_out:
            fee = total_in - total_out
            
        bonus = self._calculate_block_bonus(height, chain, opmap) if where == "chain" else None
            
        return {
            "type": "TX_DETAIL",
            "txid": txid_hex,
            "status": "unconfirmed" if where == "mempool" else "confirmed",
            "confirmations": conf,
            "height": height,
            "timestamp": timestamp,
            "is_coinbase": is_coinbase,
            "inputs": vin,
            "outputs": vout,
            "total_in": None if is_coinbase else total_in,
            "total_out": total_out,
            "fee": fee,
            "bonus": bonus,
        }


    @benchmark(label="GET_BLOCK_HASH", threshold_ms=5.0)
    def handle_get_block_hash(self, height: int) -> dict:

        cache = self._block_hash_cache
        cache_lock = self._block_hash_cache_lock
        if cache is None or cache_lock is None:
            cache = self._block_hash_cache = collections.OrderedDict()
            cache_lock = self._block_hash_cache_lock = threading.RLock()

        now = time.time()
        h_hex = None
        cache_hit = False
        cache_ttl = 5.0
        max_cache = max(1, int(CFG.HASH_CACHE_MAX))

        with cache_lock:
            entry = cache.get(height)
            if entry:
                cached_hash, ts = entry
                if now - ts <= cache_ttl:
                    h_hex = cached_hash
                    cache_hit = True
                    cache.move_to_end(height)
                else:
                    cache.pop(height, None)

        if not cache_hit:
            try:
                h_hex = self.broadcast.blockchain.get_block_hash(int(height))
            except Exception:
                log.exception("handle_get_block_hash")
                h_hex = None
            if h_hex:
                with cache_lock:
                    cache[height] = (h_hex, now)
                    while len(cache) > max_cache:
                        cache.popitem(last=False)

        if h_hex is None:
            return {"type": "BLOCK_HASH", "error": "height_out_of_range", "cache_hit": cache_hit}
            
        return {"type": "BLOCK_HASH", "height": height, "hash": h_hex or "", "cache_hit": cache_hit}


    def serialize_block(self, b) -> dict:
        txs, graffiti_posts, graffiti_comments, graffiti_payouts = self._process_block_all_tx(b)

        return {
            "type": "BLOCK",
            "block_id": self._extract_block_id_from_block(b),
            "hash": self.bhash_hex(b),
            "prev_hash": self._prevhash_hex(b),
            "height": b.height,
            "time": b.timestamp,
            "nonce": b.nonce,
            "difficulty": b.difficulty,
            "version": b.version,
            "bits": b.bits,
            "chainwork": b.chainwork,
            "size_bytes": estimate_block_size_bytes(b),
            "merkle_root": self._to_hex_helper(b.merkle_root),
            "total_fee": int(b.total_fee or 0),
            "tx": txs,
            "tx_count": len(txs),
            "graffiti": graffiti_posts,
            "comments": graffiti_comments,
            "payouts": graffiti_payouts,
            "payout_count": len(graffiti_payouts),
            "graffiti_on_mempool": self._get_mempool_graffiti_count(),
        }


    def bhash_hex(self, b) -> str:
        h = b.hash
        if callable(h):
            v = h()
            if type(v) in (bytes, bytearray):
                return v.hex()
            if type(v) is str and len(v) >= 64:
                return v
        elif type(h) in (bytes, bytearray):
            return h.hex()
        elif type(h) is str and len(h) >= 64:
            return h
        return ""


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _build_tx_inputs(self, tx, opmap: dict) -> tuple[list, int]:
        vin = []
        total_in = 0
        inputs = tx.inputs or []
        for tin in inputs:
            key = self.txin_prevkey(tin)
            amt, spk_hex = opmap.get(key, (None, None))
            if amt is not None:
                total_in += int(amt)
            prev_txid = key.split(":")[0]
            prev_index = int(key.split(":")[1]) if ":" in key else 0
            addr_prev = spkhex_to_address(spk_hex) if spk_hex else None
            vin.append({
                "prev_txid": prev_txid,
                "prev_index": prev_index,
                "amount": None if amt is None else int(amt),
                "address": addr_prev
            })
        return vin, total_in

    def _build_tx_outputs(self, tx) -> tuple[list, int]:
        vout = []
        total_out = 0
        outputs = tx.outputs or []
        for n, o in enumerate(outputs):
            amt = int(o.amount or 0)
            total_out += amt
            event_info = None
            spk = o.script_pubkey
            if spk is not None:
                meta = GRAFF.parse_from_script(spk)
                if meta:
                    ev = str(meta.get("event", "")).upper()
                    if ev in ("POST", "COMMENT", "PAYOUT"):
                        event_info = ev
            
            vout.append({
                "index": n,
                "amount": amt,
                "address": self.txout_to_address(o),
                "event": event_info
            })
        return vout, total_out


    def _calculate_block_bonus(self, height: int, chain: list, opmap: dict = None) -> int | None:
        if 0 <= height < len(chain):
            b = chain[height]
            if int(b.height or 0) == height:
                return int(b.total_fee or 0)
        block = next((b for b in reversed(chain) if int(b.height or 0) == height), None)
        if not block:
            return None
        return int(block.total_fee or 0)


    def _extract_block_id_from_block(self, b) -> str | None:
        txs = b.transactions or []
        if not txs:
            return None
        cb = txs[0] if txs[0].is_coinbase else next((t for t in txs if t.is_coinbase), None)
        if cb and cb.block_id:
            return str(cb.block_id)
        return None


    def _prevhash_hex(self, b) -> str:
        v = b.prev_block_hash
        if type(v) in (bytes, bytearray):
            return v.hex()
        if type(v) is str:
            return v
        return ""


    def _serialize_tx_basic(self, tx) -> dict:
        txid = ""
        tid = tx.txid
        if type(tid) in (bytes, bytearray): txid = tid.hex()
        elif type(tid) is str: txid = tid
        inputs = tx.inputs or []
        n_in = len(inputs)
        vout_list = []
        outputs = tx.outputs or []
        for idx, o in enumerate(outputs):
            amt = int(o.amount or 0)
            addr = self.txout_to_address(o) or ""
            vout_list.append({"index": idx, "amount": amt, "address": addr})
        d = {
            "txid": txid,
            "vin": [{} for _ in range(n_in)],
            "vout": vout_list,
            "is_coinbase": bool(tx.is_coinbase),
        }
        if not tx.is_coinbase:
            d["fee"] = tx.fee
        else:
            d["reward"] = tx.reward
        return d


    def _to_hex_helper(self, x):
        if type(x) in (bytes, bytearray):
            return x.hex()
        if type(x) is str:
            return x
        return None


    def _process_block_all_tx(self, b) -> tuple[list, list, list, list]:
        txs, posts, comments, payouts = [], [], [], []
        
        b_txs = b.transactions or []
        for tx in b_txs:
            txs.append(self._serialize_tx_basic(tx))
            t_txid = tx.txid
            txid_hex = self._to_hex_helper(t_txid)
            
            outputs = tx.outputs or []
            for tx_out in outputs:
                spk = tx_out.script_pubkey
                if not spk:
                    continue
                if not (meta := GRAFF.parse_from_script(spk)):
                    continue
                    
                ev = str(meta.get("event", "")).upper()
                if ev == "POST":
                    posts.append({
                        "txid": txid_hex,
                        "sha256": meta.get("sha256"),
                        "size": meta.get("size"),
                        "mime": meta.get("mime"),
                        "creator": meta.get("creator"),
                    })
                elif ev == "COMMENT":
                    comments.append({
                        "txid": txid_hex,
                        "art_id": meta.get("art_id"),
                        "comment_len": meta.get("comment_len"),
                        "commenter": meta.get("commenter"),
                    })
                elif ev == "PAYOUT":
                    recipients = meta.get("recipients", [])
                    payouts.append({
                        "txid": txid_hex,
                        "art_id": meta.get("art_id"),
                        "epoch": meta.get("epoch"),
                        "recipients": recipients if type(recipients) is list else [],
                    })
        return txs, posts, comments, payouts


    def _get_mempool_graffiti_count(self) -> int:
        count = 0
        mem = self.broadcast.mempool if self.broadcast else None
        if mem:
            for tx in mem.get_all_txs():
                outputs = tx.outputs or []
                def _has_graff(tx_out):
                    spk = tx_out.script_pubkey
                    return bool(GRAFF.parse_from_script(spk)) if spk else False
                if any(_has_graff(tx_out) for tx_out in outputs):
                    count += 1
        return count