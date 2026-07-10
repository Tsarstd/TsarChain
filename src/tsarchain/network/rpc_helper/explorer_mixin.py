# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import time
import threading
import collections

# ---------------- Local Project ----------------
from ...utils import config as CFG
from ...contracts import graffiti as GRAFF
from ...utils.benchmarks import benchmark
from ...utils.helpers import last_pushdata, estimate_block_size_bytes, spkhex_to_address

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.user_rpc_helper.explorer_mixin")

class ExplorerMixin:
    def _build_tx_inputs(self, tx, opmap: dict) -> tuple[list, int]:
        vin = []
        total_in = 0
        for tin in (getattr(tx, "inputs", []) or []):
            key = self._txin_prevkey(tin)
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
        for n, o in enumerate(getattr(tx, "outputs", []) or []):
            amt = int(getattr(o, "amount", 0))
            total_out += amt
            event_info = None
            spk = getattr(o, "script_pubkey", None)
            if spk is not None:
                meta = GRAFF.parse_from_script(spk)
                if meta:
                    ev = str(meta.get("event", "")).upper()
                    if ev in ("POST", "COMMENT", "PAYOUT"):
                        event_info = ev
            
            vout.append({
                "index": n,
                "amount": amt,
                "address": self._txout_to_address(o),
                "event": event_info
            })
        return vout, total_out

    def _calculate_block_bonus(self, height: int, chain: list, opmap: dict) -> int | None:
        block = next((b for b in chain if int(getattr(b, "height", 0)) == height), None)
        if not block:
            return None
            
        total_block_fee = 0
        for tx_in_block in getattr(block, "transactions", []) or []:
            if self._is_coinbase_tx(tx_in_block):
                continue
                
            tx_total_in = sum(int(opmap.get(self._txin_prevkey(tin), (0, None))[0] or 0)
                              for tin in getattr(tx_in_block, "inputs", []) or [])
            tx_total_out = sum(int(getattr(o, "amount", 0))
                               for o in getattr(tx_in_block, "outputs", []) or [])
            
            tx_fee = tx_total_in - tx_total_out
            if tx_fee > 0:
                total_block_fee += tx_fee
                
        return total_block_fee

    @benchmark(label="GET_TX_DETAIL", threshold_ms=15.0)
    def _get_tx_detail(self, txid_hex: str, src_tag: str | None = None) -> dict:
        where, tx, height, timestamp, conf, chain, _, _ = self._find_tx_and_meta(txid_hex)
        if tx is None:
            return {"error": "tx not found", "txid": txid_hex}

        opmap = self._build_outpoint_map(chain)
        is_coinbase = self._is_coinbase_tx(tx)

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

    # ----------------------- Helpers For Block -------------------------

    def _bhash_hex(self, b) -> str:
        h = getattr(b, "hash", None)
        if callable(h):
            v = h()
            if isinstance(v, (bytes, bytearray)):
                return v.hex()
            if isinstance(v, str) and len(v) >= 64:
                return v
        elif isinstance(h, (bytes, bytearray)):
            return h.hex()
        elif isinstance(h, str) and len(h) >= 64:
            return h
        return ""

    def _extract_block_id_from_block(self, b) -> str | None:
        txs = getattr(b, "transactions", None) or []
        if not txs:
            return None

        cb = txs[0]
        if not getattr(cb, "is_coinbase", False):
            for t in txs:
                if getattr(t, "is_coinbase", False):
                    cb = t
                    break
            else:
                return None

        if not getattr(cb, "inputs", None):
            return None
        vin0 = cb.inputs[0]

        if hasattr(vin0.script_sig, "serialize"):
            raw = vin0.script_sig.serialize()
        elif isinstance(vin0.script_sig, (bytes, bytearray)):
            raw = bytes(vin0.script_sig)
        else:
            return None

        data = last_pushdata(raw)
        if not data:
            return None
        return data.decode("utf-8", errors="ignore") or data.hex()

    @benchmark(label="GET_BLOCK_HASH", threshold_ms=15.0)
    def _handle_get_block_hash(self, height: int) -> dict:

        cache = getattr(self, "_block_hash_cache", None)
        cache_lock = getattr(self, "_block_hash_cache_lock", None)
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
                log.exception("_handle_get_block_hash")
                h_hex = None
            if h_hex:
                with cache_lock:
                    cache[height] = (h_hex, now)
                    while len(cache) > max_cache:
                        cache.popitem(last=False)

        if h_hex is None:
            return {"type": "BLOCK_HASH", "error": "height_out_of_range", "cache_hit": cache_hit}
            
        return {"type": "BLOCK_HASH", "height": height, "hash": h_hex or "", "cache_hit": cache_hit}

    def _prevhash_hex(self, b) -> str:
        v = getattr(b, "prev_block_hash", None)
        if isinstance(v, (bytes, bytearray)):
            return v.hex()
        if isinstance(v, str):
            return v
        return ""

    def _serialize_tx_basic(self, tx) -> dict:
        txid = ""
        tid = getattr(tx, "txid", None)
        if isinstance(tid, (bytes, bytearray)): txid = tid.hex()
        elif isinstance(tid, str): txid = tid
        n_in  = len(getattr(tx, "inputs", []) or [])
        vout_list = []
        for idx, o in enumerate(getattr(tx, "outputs", []) or []):
            amt = int(getattr(o, "amount", 0))
            addr = self._txout_to_address(o) or ""
            vout_list.append({"index": idx, "amount": amt, "address": addr})
        
        return {"txid": txid, "vin": [{} for _ in range(n_in)], "vout": vout_list}

    def _to_hex_helper(self, x):
        if isinstance(x, (bytes, bytearray)):
            return x.hex()
        if isinstance(x, str):
            return x
        return None

    def _process_block_txs(self, b) -> tuple[list, list, list, list]:
        txs, posts, comments, payouts = [], [], [], []
        
        for tx in getattr(b, "transactions", []) or []:
            txs.append(self._serialize_tx_basic(tx))
            txid_hex = self._to_hex_helper(getattr(tx, "txid"))
            
            for tx_out in getattr(tx, "outputs", []) or []:
                if not (spk := getattr(tx_out, "script_pubkey", None)):
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
                        "recipients": recipients if isinstance(recipients, list) else [],
                    })
        return txs, posts, comments, payouts

    def _get_mempool_graffiti_count(self) -> int:
        count = 0
        if mem := getattr(self, "mempool", None):
            for tx in mem.get_all_txs():
                if any(GRAFF.parse_from_script(getattr(tx_out, "script_pubkey", None)) 
                       for tx_out in getattr(tx, "outputs", []) or []):
                    count += 1
        return count

    def _serialize_block(self, b) -> dict:
        txs, graffiti_posts, graffiti_comments, graffiti_payouts = self._process_block_txs(b)

        return {
            "type": "BLOCK",
            "block_id": self._extract_block_id_from_block(b),
            "hash": self._bhash_hex(b),
            "prev_hash": self._prevhash_hex(b),
            "height": getattr(b, "height"),
            "time": getattr(b, "timestamp"),
            "nonce": getattr(b, "nonce"),
            "difficulty": getattr(b, "difficulty", None),
            "version": getattr(b, "version"),
            "bits": getattr(b, "bits"),
            "chainwork": getattr(b, "chainwork", None),
            "size_bytes": estimate_block_size_bytes(b),
            "merkle_root": self._to_hex_helper(getattr(b, "merkle_root")),
            "tx": txs,
            "tx_count": len(txs),
            "graffiti": graffiti_posts,
            "comments": graffiti_comments,
            "payouts": graffiti_payouts,
            "payout_count": len(graffiti_payouts),
            "graffiti_on_mempool": self._get_mempool_graffiti_count(),
        }