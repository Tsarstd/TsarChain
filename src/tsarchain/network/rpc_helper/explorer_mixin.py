# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import time
import threading
import collections

# ---------------- Local Project ----------------
from ...utils import config as CFG
from ...contracts import graffiti as GRAFF
from ...utils.helpers import last_pushdata, _estimate_block_size_bytes

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.user_rpc_helper.explorer_mixin")

class ExplorerMixin:
    def _get_tx_detail(self, txid_hex: str, src_tag: str | None = None) -> dict:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        
        where, tx, height, timestamp, conf, chain, mem, tip_height = self._find_tx_and_meta(txid_hex)
        if tx is None:
            return {"error": "tx not found", "txid": txid_hex}

        opmap = self._build_outpoint_map(chain)
        vin = []
        total_in = 0
        is_coinbase = self._is_coinbase_tx(tx)

        if not is_coinbase:
            for tin in (getattr(tx, "inputs", []) or []):
                key = self._txin_prevkey(tin)
                amt, spk_hex = opmap.get(key, (None, None))
                if amt is not None:
                    total_in += int(amt)
                prev_txid = key.split(":")[0]
                prev_index = int(key.split(":")[1]) if ":" in key else 0
                addr_prev = self._spkhex_to_address(spk_hex) if spk_hex else None
                vin.append({
                    "prev_txid": prev_txid,
                    "prev_index": prev_index,
                    "amount": None if amt is None else int(amt),
                    "address": addr_prev
                })

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
                    if ev == "POST":
                        event_info = "POST"
                    elif ev == "COMMENT":
                        event_info = "COMMENT"
                    elif ev == "PAYOUT":
                        recipients = meta.get("recipients")
                        if not isinstance(recipients, list):
                            recipients = []
                        event_info = "PAYOUT"
            
            vout.append({
                "index": n,
                "amount": amt,
                "address": self._txout_to_address(o),
                "event": event_info
            })

        fee = None
        if not is_coinbase and vin and total_in >= total_out:
            fee = total_in - total_out
            
        # ===== BONUS CALCULATED =====
        # 'bonus' is an additional mining reward from transaction fees
        bonus = None
        if where == "chain":  # Only for confirmed transactions
            block = None
            for b in chain:
                if int(getattr(b, "height", 0)) == height:
                    block = b
                    break
            
            if block:
                total_block_fee = 0
                for tx_in_block in getattr(block, "transactions", []) or []:
                    if self._is_coinbase_tx(tx_in_block):
                        continue

                    tx_total_in = 0
                    tx_total_out = 0
                    
                    # Inputs
                    for tin_block in getattr(tx_in_block, "inputs", []) or []:
                        key = self._txin_prevkey(tin_block)
                        amt, _ = opmap.get(key, (0, None))
                        tx_total_in += int(amt) if amt is not None else 0
                    
                    # Outputs
                    for o_block in getattr(tx_in_block, "outputs", []) or []:
                        tx_total_out += int(getattr(o_block, "amount", 0))
                    
                    # Fee = total input - total output
                    tx_fee = tx_total_in - tx_total_out
                    if tx_fee > 0:
                        total_block_fee += tx_fee
                
                bonus = total_block_fee
                
        # ===== END BONUS =====
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            tag = src_tag or "-"
            if result > 15.0:
                log.warning("[GET_TX_DETAIL] Benchmark : %.3f ms src=%s", result, tag)
            
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

    def _handle_get_block_hash(self, height: int) -> dict:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()

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
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 15.0:
                log.warning(
                    "[_handle_get_block_hash] Benchmark : %.3f ms cache_hit=%s height=%s",
                    result,
                    cache_hit,
                    height,
                )
            
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
        n_out = len(getattr(tx, "outputs", []) or [])
        vout_list = []
        for idx, o in enumerate(getattr(tx, "outputs", []) or []):
            amt = int(getattr(o, "amount", 0))
            addr = self._txout_to_address(o) or ""
            vout_list.append({"index": idx, "amount": amt, "address": addr})
        
        return {"txid": txid, "vin": [{} for _ in range(n_in)], "vout": vout_list}

    def _serialize_block(self, b) -> dict:
        def _to_hex(x):
            if isinstance(x, (bytes, bytearray)):
                return x.hex()
            if isinstance(x, str):
                return x
            return None

        # block
        height = getattr(b, "height")
        hash = self._bhash_hex(b)
        prev_hash = self._prevhash_hex(b)
        timestamp = getattr(b, "timestamp")
        version = getattr(b, "version")
        block_id = self._extract_block_id_from_block(b)
        
        # Nonce
        nonce = getattr(b, "nonce")

        # Merkle root
        mroot = getattr(b, "merkle_root")
        mroot_hex = _to_hex(mroot)
        
        # Bits
        bits = getattr(b, "bits")
        
        # Chainwork & Difficulty
        chainwork = getattr(b, "chainwork", None)
        diff = getattr(b, "difficulty", None)

        # Size estimation
        size_bytes = _estimate_block_size_bytes(b)
        
        # Transactions processing
        txs = []
        graffiti_posts, graffiti_comments, graffiti_payouts = [], [], []
        
        for tx in getattr(b, "transactions", []) or []:
            txs.append(self._serialize_tx_basic(tx))
            txid_hex = _to_hex(getattr(tx, "txid"))
            
            for tx_out in getattr(tx, "outputs", []) or []:
                if not (spk := getattr(tx_out, "script_pubkey", None)):
                    continue
                
                meta = GRAFF.parse_from_script(spk) 
                if not meta:
                    continue
                    
                ev = str(meta.get("event", "")).upper()
                if ev == "POST":
                    graffiti_posts.append({
                        "txid": txid_hex,
                        "sha256": meta.get("sha256"),
                        "size": meta.get("size"),
                        "mime": meta.get("mime"),
                        "creator": meta.get("creator"),
                    })
                elif ev == "COMMENT":
                    graffiti_comments.append({
                        "txid": txid_hex,
                        "art_id": meta.get("art_id"),
                        "comment_len": meta.get("comment_len"),
                        "commenter": meta.get("commenter"),
                    })
                elif ev == "PAYOUT":
                    recipients = meta.get("recipients", [])
                    graffiti_payouts.append({
                        "txid": txid_hex,
                        "art_id": meta.get("art_id"),
                        "epoch": meta.get("epoch"),
                        "recipients": recipients if isinstance(recipients, list) else [],
                    })

        # Graffiti in mempool count
        graffiti_on_mempool = 0
        if (mem := getattr(self, "mempool", None)):
            for tx in mem.get_all_txs():
                if any(GRAFF.parse_from_script(getattr(tx_out, "script_pubkey", None)) 
                    for tx_out in getattr(tx, "outputs", []) or []):
                    graffiti_on_mempool += 1

        return {
            "type": "BLOCK",
            "block_id": block_id,
            "hash": hash,
            "prev_hash": prev_hash,
            "height": height,
            "time": timestamp,
            "nonce": nonce,
            "difficulty": diff,
            "version": version,
            "bits": bits,
            "chainwork": chainwork,
            "size_bytes": size_bytes,
            "merkle_root": mroot_hex,
            "tx": txs,
            "tx_count": len(txs),
            "graffiti": graffiti_posts,
            "comments": graffiti_comments,
            "payouts": graffiti_payouts,
            "payout_count": len(graffiti_payouts),
            "graffiti_on_mempool": graffiti_on_mempool,
        }