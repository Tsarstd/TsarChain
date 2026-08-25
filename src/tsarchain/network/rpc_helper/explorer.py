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
from ...utils.helpers import last_pushdata, estimate_block_size_bytes, spkhex_to_address

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.user_rpc_helper.explorer")


class ExplorerHandler(NetworkHandlerProxy):

    @benchmark(label="GET_TX_DETAIL", threshold_ms=15.0)
    def process_tx_lookup(self, txid_hex: str, src_tag: str | None = None) -> dict:
        txid_hex = str(txid_hex or "").strip().lower()
        where, tx, height, timestamp, conf, chain, _, _ = self.find_tx_and_meta(txid_hex)
        if tx is None:
            return {"error": "tx not found", "txid": txid_hex}

        opmap = self.build_outpoint_map(chain)
        is_coinbase = self.is_coinbase_tx(tx)

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


    @benchmark(label="GET_BLOCK_HASH", threshold_ms=15.0)
    def handle_get_block_hash(self, height: int) -> dict:

        try:
            cache = self._block_hash_cache
        except AttributeError:
            cache = None
        try:
            cache_lock = self._block_hash_cache_lock
        except AttributeError:
            cache_lock = None
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

        try:
            b_height = b.height
        except AttributeError:
            b_height = 0
        try:
            b_time = b.timestamp
        except AttributeError:
            b_time = 0
        try:
            b_nonce = b.nonce
        except AttributeError:
            b_nonce = 0
        try:
            b_difficulty = b.difficulty
        except AttributeError:
            b_difficulty = None
        try:
            b_version = b.version
        except AttributeError:
            b_version = 0
        try:
            b_bits = b.bits
        except AttributeError:
            b_bits = 0
        try:
            b_chainwork = b.chainwork
        except AttributeError:
            b_chainwork = None
        try:
            b_merkle = self._to_hex_helper(b.merkle_root)
        except AttributeError:
            b_merkle = None

        return {
            "type": "BLOCK",
            "block_id": self._extract_block_id_from_block(b),
            "hash": self.bhash_hex(b),
            "prev_hash": self._prevhash_hex(b),
            "height": b_height,
            "time": b_time,
            "nonce": b_nonce,
            "difficulty": b_difficulty,
            "version": b_version,
            "bits": b_bits,
            "chainwork": b_chainwork,
            "size_bytes": estimate_block_size_bytes(b),
            "merkle_root": b_merkle,
            "tx": txs,
            "tx_count": len(txs),
            "graffiti": graffiti_posts,
            "comments": graffiti_comments,
            "payouts": graffiti_payouts,
            "payout_count": len(graffiti_payouts),
            "graffiti_on_mempool": self._get_mempool_graffiti_count(),
        }


    def bhash_hex(self, b) -> str:
        try:
            h = b.hash
        except AttributeError:
            h = None
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
        try:
            inputs = tx.inputs or []
        except AttributeError:
            inputs = []
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
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        for n, o in enumerate(outputs):
            try:
                amt = int(o.amount or 0)
            except (AttributeError, TypeError):
                amt = 0
            total_out += amt
            event_info = None
            try:
                spk = o.script_pubkey
            except AttributeError:
                spk = None
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


    def _calculate_block_bonus(self, height: int, chain: list, opmap: dict) -> int | None:
        def _get_h(b):
            try:
                return int(b.height or 0)
            except (AttributeError, TypeError, ValueError):
                return 0
        block = next((b for b in chain if _get_h(b) == height), None)
        if not block:
            return None
            
        total_block_fee = 0
        try:
            txs = block.transactions or []
        except AttributeError:
            txs = []
        for tx_in_block in txs:
            if self.is_coinbase_tx(tx_in_block):
                continue
            try:
                inputs = tx_in_block.inputs or []
            except AttributeError:
                inputs = []
            try:
                outputs = tx_in_block.outputs or []
            except AttributeError:
                outputs = []
                
            tx_total_in = sum(int(opmap.get(self.txin_prevkey(tin), (0, None))[0] or 0)
                              for tin in inputs)
            def _get_amt(o):
                try:
                    return int(o.amount or 0)
                except (AttributeError, TypeError):
                    return 0
            tx_total_out = sum(_get_amt(o) for o in outputs)
            
            tx_fee = tx_total_in - tx_total_out
            if tx_fee > 0:
                total_block_fee += tx_fee
                
        return total_block_fee


    def _extract_block_id_from_block(self, b) -> str | None:
        try:
            txs = b.transactions or []
        except AttributeError:
            txs = []
        if not txs:
            return None

        cb = txs[0]
        try:
            is_cb = cb.is_coinbase
        except AttributeError:
            is_cb = False
        if not is_cb:
            for t in txs:
                try:
                    t_is_cb = t.is_coinbase
                except AttributeError:
                    t_is_cb = False
                if t_is_cb:
                    cb = t
                    break
            else:
                return None

        try:
            inputs = cb.inputs
        except AttributeError:
            inputs = None
        if not inputs:
            return None
        vin0 = inputs[0]

        try:
            sig = vin0.script_sig
        except AttributeError:
            sig = None
        try:
            ser = sig.serialize
            raw = ser() if callable(ser) else None
        except AttributeError:
            if type(sig) in (bytes, bytearray):
                raw = bytes(sig)
            else:
                return None

        if not raw:
            return None

        data = last_pushdata(raw)
        if not data:
            return None
        return data.decode("utf-8", errors="ignore") or data.hex()


    def _prevhash_hex(self, b) -> str:
        try:
            v = b.prev_block_hash
        except AttributeError:
            v = None
        if type(v) in (bytes, bytearray):
            return v.hex()
        if type(v) is str:
            return v
        return ""


    def _serialize_tx_basic(self, tx) -> dict:
        txid = ""
        try:
            tid = tx.txid
        except AttributeError:
            tid = None
        if type(tid) in (bytes, bytearray): txid = tid.hex()
        elif type(tid) is str: txid = tid
        try:
            inputs = tx.inputs or []
        except AttributeError:
            inputs = []
        n_in = len(inputs)
        vout_list = []
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        for idx, o in enumerate(outputs):
            try:
                amt = int(o.amount or 0)
            except (AttributeError, TypeError):
                amt = 0
            addr = self.txout_to_address(o) or ""
            vout_list.append({"index": idx, "amount": amt, "address": addr})
        
        return {"txid": txid, "vin": [{} for _ in range(n_in)], "vout": vout_list}


    def _to_hex_helper(self, x):
        if type(x) in (bytes, bytearray):
            return x.hex()
        if type(x) is str:
            return x
        return None


    def _process_block_all_tx(self, b) -> tuple[list, list, list, list]:
        txs, posts, comments, payouts = [], [], [], []
        
        try:
            b_txs = b.transactions or []
        except AttributeError:
            b_txs = []
        for tx in b_txs:
            txs.append(self._serialize_tx_basic(tx))
            try:
                t_txid = tx.txid
            except AttributeError:
                t_txid = None
            txid_hex = self._to_hex_helper(t_txid)
            
            try:
                outputs = tx.outputs or []
            except AttributeError:
                outputs = []
            for tx_out in outputs:
                try:
                    spk = tx_out.script_pubkey
                except AttributeError:
                    spk = None
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
        try:
            mem = self.mempool
        except AttributeError:
            mem = None
        if mem:
            for tx in mem.get_all_txs():
                try:
                    outputs = tx.outputs or []
                except AttributeError:
                    outputs = []
                def _has_graff(tx_out):
                    try:
                        spk = tx_out.script_pubkey
                    except AttributeError:
                        spk = None
                    return bool(GRAFF.parse_from_script(spk)) if spk else False
                if any(_has_graff(tx_out) for tx_out in outputs):
                    count += 1
        return count