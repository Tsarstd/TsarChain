# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import time
import threading
import collections

from bech32 import convertbits, bech32_encode, bech32_decode

from ...utils import config as CFG

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc_helper.history_mixin")


class HistoryMixin:
    def _txin_prevkey(self, tin) -> str:
        txid = getattr(tin, "txid", None)
        if isinstance(txid, (bytes, bytearray)):
            ptx = txid.hex()
        elif isinstance(txid, str) and len(txid) >= 64:
            ptx = txid
        else:
            p0 = getattr(tin, "prev_tx", b"")
            if isinstance(p0, (bytes, bytearray)):
                ptx = p0.hex()
            else:
                ptx = str(p0 or "")
        idx = getattr(tin, "vout", getattr(tin, "prev_index", 0))
        idx = int(idx)
        return f"{ptx}:{idx}"

    def _is_coinbase_tx(self, tx) -> bool:
        ins = getattr(tx, "inputs", []) or []
        if len(ins) == 0:
            return True
        first = ins[0]
        p0 = getattr(first, "txid", None)
        if isinstance(p0, (bytes, bytearray)):
            b = p0
        elif isinstance(p0, str) and len(p0) == 64:
            b = bytes.fromhex(p0)
        else:
            b = getattr(first, "prev_tx", b"")
            if not isinstance(b, (bytes, bytearray)):
                b = b""
        return b == b"\x00" * 32

    def _spkhex_to_address(self, spk_hex: str) -> str | None:
        if isinstance(spk_hex, bytes):
            spk_hex = spk_hex.hex()
        spk_hex = spk_hex.lower()
        if spk_hex.startswith("0014") and len(spk_hex) == 44:
            prog = bytes.fromhex(spk_hex[4:])
            data = [0] + convertbits(list(prog), 8, 5, True)
            return bech32_encode(CFG.ADDRESS_PREFIX, data)
        if spk_hex.startswith("0020") and len(spk_hex) == 68:
            prog = bytes.fromhex(spk_hex[4:])
            data = [0] + convertbits(list(prog), 8, 5, True)
            return bech32_encode(CFG.ADDRESS_PREFIX, data)
        return None

    def _txout_to_spk_hex(self, txout) -> str | None:
        spk = getattr(txout, "script_pubkey", None)
        if spk is None:
            return None
        if hasattr(spk, "serialize"):
            return spk.serialize().hex()
        if isinstance(spk, (bytes, bytearray)):
            return bytes(spk).hex()
        if isinstance(spk, str):
            return spk.lower()
        return None

    def _txout_to_address(self, txout) -> str | None:
        spk_hex = self._txout_to_spk_hex(txout)
        if not spk_hex:
            return None
        return self._spkhex_to_address(spk_hex)

    def _normalize_spk_hex(self, addr: str) -> str | None:
        def _is_hex(s: str) -> bool:
            try:
                bytes.fromhex(s)
                return True
            except Exception:
                return False

        addr = (addr or "").strip().lower()
        if not addr:
            return None
        if addr.startswith(CFG.ADDRESS_PREFIX + "1"):
            try:
                spk = self._addr_to_spk(addr)
                return spk.serialize().hex()
            except Exception:
                return None
        if addr.startswith("0014") and len(addr) == 44:
            return addr if _is_hex(addr) else None
        if addr.startswith("0020") and len(addr) == 68:
            return addr if _is_hex(addr) else None
        if addr.startswith("00") and len(addr) in (42, 66):
            if not _is_hex(addr):
                return None
            if len(addr) == 42:
                return "0014" + addr[2:]
            return "0020" + addr[2:]
        return None

    def _build_outpoint_map(self, chain, mem=None):
        chain_map: dict[str, tuple[int, str]] = {}
        for b in chain:
            txs = getattr(b, "transactions", []) or []
            for tx in txs:
                txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
                for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                    amount = int(getattr(o, "amount", 0))
                    spk_hex = self._txout_to_spk_hex(o) or ""
                    chain_map[f"{txid}:{idx}"] = (amount, spk_hex)
        if mem is None:
            return chain_map
        mem_map: dict[str, tuple[int, str]] = {}
        for tx in mem:
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                amount = int(getattr(o, "amount", 0))
                spk_hex = self._txout_to_spk_hex(o) or ""
                mem_map[f"{txid}:{idx}"] = (amount, spk_hex)
        return chain_map, mem_map

    def _find_tx_and_meta(self, txid_hex: str):
        with self.broadcast.lock:
            chain = list(self.broadcast.blockchain.chain)
            tip_height = int(self.broadcast.blockchain.height)
            mem = self.broadcast.mempool.get_all_txs()
        for tx in mem:
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            if txid == txid_hex:
                return ("mempool", tx, None, 0, None, chain, mem, tip_height)
        for b in chain:
            h = int(getattr(b, "height", 0))
            timestamp = int(getattr(b, "timestamp", 0))
            for tx in getattr(b, "transactions", []) or []:
                txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
                if txid == txid_hex:
                    conf = max(0, tip_height - h + 1)
                    return ("chain", tx, h, timestamp, conf, chain, mem, tip_height)

        return (None, None, None, 0, 0, chain, mem, tip_height)

    def _get_tx_history(self, address: str, limit: int = 50, offset: int = 0, direction: str | None = None, status: str | None = None) -> dict:
        start = time.perf_counter()
        
        if not isinstance(address, str):
            return {"items": [], "total": 0, "limit": limit, "offset": offset}

        addr = (address or "").strip().lower()
        if not addr:
            return {"items": [], "total": 0, "limit": limit, "offset": offset}
        max_addr_len = int(CFG.MAX_UTXO_ADDR_LEN)
        if len(addr) > max_addr_len:
            return {"items": [], "total": 0, "limit": limit, "offset": offset, "error": "address too long"}

        target_spk_hex = self._normalize_spk_hex(addr)
        if not target_spk_hex:
            return {"items": [], "total": 0, "limit": limit, "offset": offset, "error": "invalid address"}

        cache = getattr(self, "_tx_history_cache", None)
        cache_lock = getattr(self, "_tx_history_cache_lock", None)
        if cache is None or cache_lock is None:
            cache = self._tx_history_cache = collections.OrderedDict()
            cache_lock = self._tx_history_cache_lock = threading.RLock()

        cache_ttl = 10.0
        max_cache = max(16, int(CFG.MAX_HISTORY_LIMIT))
        max_cache_items = max(200, int(CFG.MAX_HISTORY_LIMIT) * 10)

        mempool = getattr(self.broadcast, "mempool", None)
        mem_seq = getattr(mempool, "change_seq", 0)

        with self.broadcast.lock:
            chain_ref = self.broadcast.blockchain.chain
            tip_height = int(self.broadcast.blockchain.height)
            tip_hash = self._bhash_hex(chain_ref[-1]) if chain_ref else ""

        def _slice_items(items: list[dict]) -> dict:
            filtered = items
            if direction in ("in", "out"):
                filtered = [it for it in filtered if it["direction"] == direction]
            if status in ("confirmed", "unconfirmed"):
                filtered = [it for it in filtered if it["status"] == status]
            
            optimized_items = []
            for item in filtered:
                optimized = dict(item)
                if optimized["direction"] == "in":
                    optimized.pop("to", None)
                elif optimized["direction"] == "out":
                    optimized.pop("from", None)
                optimized_items.append(optimized)
            
            total = len(optimized_items)
            start_idx = max(0, int(offset))
            end_idx   = max(start_idx, int(start_idx + max(0, int(limit))))
            return {"items": optimized_items[start_idx:end_idx], "total": total, "limit": int(limit), "offset": int(offset)}

        now = time.time()
        with cache_lock:
            entry = cache.get(target_spk_hex)
            if entry:
                if (now - entry.get("ts", 0)) <= cache_ttl and entry.get("tip_height") == tip_height and entry.get("tip_hash") == tip_hash and entry.get("mem_seq") == mem_seq:
                    cache.move_to_end(target_spk_hex)
                    return _slice_items(entry.get("items") or [])
                cache.pop(target_spk_hex, None)

        with self.broadcast.lock:
            chain = list(self.broadcast.blockchain.chain)
            tip_height = int(self.broadcast.blockchain.height)
            mem = self.broadcast.mempool.get_all_txs()

        tip_hash = self._bhash_hex(chain[-1]) if chain else ""
        mem_seq = getattr(mempool, "change_seq", mem_seq)

        opmap_chain, opmap_mem = self._build_outpoint_map(chain, mem)
        items = []

        def _append_item(tx, where, h_or_none, timestamp):
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            is_cb = self._is_coinbase_tx(tx)
            conf = 0
            height = None
            if where == "chain":
                height = int(h_or_none or 0)
                conf = max(0, tip_height - height + 1)

            received_to_addr = 0
            main_recipient_spk, max_rec_amt = None, -1
            for o in getattr(tx, "outputs", []) or []:
                amt = int(getattr(o, "amount", 0))
                spk_hex = self._txout_to_spk_hex(o) or ""
                if spk_hex == target_spk_hex:
                    received_to_addr += amt
                else:
                    if amt > max_rec_amt:
                        max_rec_amt = amt
                        main_recipient_spk = spk_hex

            spent_from_addr = 0
            sources = set()
            for tin in getattr(tx, "inputs", []) or []:
                key = self._txin_prevkey(tin)
                if where == "mempool":
                    amt_spk = opmap_mem.get(key) or opmap_chain.get(key)
                else:
                    amt_spk = opmap_chain.get(key)
                if not amt_spk:
                    continue
                amt_prev, spk_prev = amt_spk
                if spk_prev == target_spk_hex:
                    spent_from_addr += int(amt_prev)
                elif spk_prev:
                    sources.add(spk_prev)

            if spent_from_addr > 0:
                net_amt = spent_from_addr - received_to_addr
                if net_amt < 0:
                    net_amt = 0
                dirn = "out"
                frm = addr
                to = self._spkhex_to_address(main_recipient_spk) if main_recipient_spk else None
                if to == addr:
                    to = None
            elif received_to_addr > 0:
                dirn = "in"
                net_amt = received_to_addr
                frm = "coinbase"
                if not is_cb and sources:
                    src_spk = next(iter(sources))
                    frm = self._spkhex_to_address(src_spk)
                to  = addr
            else:
                return

            st = "unconfirmed" if where == "mempool" else "confirmed"
            items.append({
                "txid": txid,
                "direction": dirn,
                "amount": int(net_amt),
                "status": st,
                "confirmations": conf,
                "height": height,
                "from": frm,
                "to": to,
                "timestamp": timestamp,
            })

        for tx in mem:
            _append_item(tx, "mempool", None, int(time.time()))

        for b in chain:
            h = int(getattr(b, "height", 0))
            block_timestamp = int(getattr(b, "timestamp", 0))
            for tx in getattr(b, "transactions", []) or []:
                _append_item(tx, "chain", h, block_timestamp)
                
        by_id = {}
        for it in items:
            tid = it.get("txid")
            if not tid:
                continue
            prev = by_id.get(tid)
            if prev is None:
                by_id[tid] = it
                continue
            rank_prev = (prev.get("status") == "confirmed", int(prev.get("height") or -1))
            rank_new  = (it.get("status") == "confirmed", int(it.get("height") or -1))
            if rank_new > rank_prev:
                by_id[tid] = it
        items = list(by_id.values())

        def _key(it):
            st = 0 if it["status"] == "unconfirmed" else 1
            h  = it["height"] if it["height"] is not None else -1
            return (st, -h)
        items.sort(key=_key)

        # cache
        if len(items) <= max_cache_items:
            now = time.time()
            with cache_lock:
                cache[target_spk_hex] = {
                    "ts": now,
                    "tip_height": tip_height,
                    "tip_hash": tip_hash,
                    "mem_seq": mem_seq,
                    "items": items,
                }
                cache.move_to_end(target_spk_hex)
                while len(cache) > max_cache:
                    cache.popitem(last=False)
                    
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        if result > 25.0:
            log.warning("[_get_tx_history] Benchmark : %.3f ms", result)
        
        return _slice_items(items)