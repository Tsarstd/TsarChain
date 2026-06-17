# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; Merkle; Signal-X3DH

import socket, threading, json, time, collections
from collections import deque
from bech32 import convertbits, bech32_decode, bech32_encode

# ---------------- Local Project ----------------
from ..core.tx import Tx, TxIn, TxOut
from ..utils.helpers import Script, OP_RETURN, last_pushdata, compute_tx_weight_vsize, _estimate_block_size_bytes
from ..contracts import graffiti as GRAFFITI
from .protocol import send_message, recv_message,build_envelope, SecureChannel
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.client_helper")


# ------------------------------ Guard ------------------------------
def _tb_now(self):
    return time.time()

def _tb_allow(self, table, key, rate_per_window, window_s, burst, backoff_key=None):
    now = self._tb_now()
    if not hasattr(self, "backoff_until"):
        self.backoff_until = {}
    tokens, last = table.get(key, (burst, now))
    # refill
    if now > last:
        refill = (now - last) * (rate_per_window / float(window_s))
        tokens = min(burst, tokens + refill)
    # backoff?
    if backoff_key and self.backoff_until.get(backoff_key, 0) > now:
        log.warning("[ratelimit] backoff active key=%s until=%.3f now=%.3f", backoff_key, self.backoff_until.get(backoff_key, 0), now)
        return False
    if tokens >= 1.0:
        table[key] = (tokens - 1.0, now)
        return True
    log.warning("[ratelimit] denied key=%s rate=%s/%ss burst=%s", backoff_key or key, rate_per_window, window_s, burst)
    return False

def _backoff(self, key, secs):
    self.backoff_until[key] = max(self._tb_now() + secs, self.backoff_until.get(key, 0))
    log.warning("[ratelimit] backoff set key=%s for %.2fs", key, secs)

def _nonce_guard(self, scope: str, sender_key: str, nonce: str, ts: int, window: int) -> bool:
    if not (scope and sender_key and nonce and isinstance(ts, int)):
        return False
    now = time.time()
    if abs(now - ts) > window:
        log.warning("[nonce_guard] ts window violation scope=%s sender=%s", scope, sender_key)
        return False
    
    max_entries = max(1, int(CFG.NONCE_PER_SENDER_MAX))
    bucket_key = f"{scope}:{sender_key}"
    guard_lock = getattr(self, "_nonce_guard_lock", threading.RLock())
    with guard_lock:
        table = getattr(self, "_nonce_guard_table", None)
        bucket = table.setdefault(bucket_key, {})
        # prune expired
        for n, t in list(bucket.items()):
            if now - t > window:
                bucket.pop(n, None)
        if nonce in bucket:
            log.warning("[nonce_guard] replay scope=%s sender=%s nonce=%s", scope, sender_key, nonce[:16])
            return False
        bucket[nonce] = now
        # enforce size
        if len(bucket) > max_entries:
            for n, _t in sorted(bucket.items(), key=lambda it: it[1])[: len(bucket) - max_entries]:
                bucket.pop(n, None)
    return True

# ------------------------------ P2P Chat ------------------------------
def _send_to_peer(self, peer: tuple[str,int], payload: dict) -> None:
    if not isinstance(peer, tuple) or len(peer) != 2:
        raise ValueError("bad peer")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.5)
        s.connect(peer)
        env = build_envelope(payload, self.node_ctx, extra={"pubkey": self.pubkey})
        if CFG.ENFORCE_HELLO_PUBKEY or CFG.ENVELOPE_REQUIRED:
            env["pubkey"] = self.pubkey
        raw = json.dumps(env).encode("utf-8")
        if CFG.P2P_ENC_REQUIRED:
            chan = SecureChannel(
                s, role="client",
                node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                get_pinned=self._get_pinned, set_pinned=self._set_pinned,
            )
            chan.handshake()
            chan.send(raw)
            _ = chan.recv(1)
        else:
            send_message(s, raw)
            _ = recv_message(s, timeout=1)

def _chat_enqueue_locked(self, to_addr: str, msg: dict) -> None:
    mb = self.chat_mailboxes.get(to_addr)
    if mb is None:
        mb = deque(maxlen=50)       # batas 50 per inbox
        self.chat_mailboxes[to_addr] = mb
    mb.append(msg)

def _chat_seen_add_locked(self, msg_id: str) -> bool:
    if msg_id in self.chat_seen_ids: return False
    self.chat_seen_ids.add(msg_id)
    self.chat_seen_order.append(msg_id)
    if len(self.chat_seen_ids) > 5000 and self.chat_seen_order:
        old = self.chat_seen_order.popleft()
        self.chat_seen_ids.discard(old)
    return True

def _chat_rl_ok_locked(self, from_addr: str, now: float) -> bool:
    start, cnt = self.chat_rate.get(from_addr, (0.0, 0))
    if now - start > self.chat_window_sec:
        self.chat_rate[from_addr] = (now, 1); return True
    cnt += 1
    self.chat_rate[from_addr] = (start, cnt)
    return cnt <= self.chat_burst_max

def _relay_chat(self, msg: dict, exclude=None) -> None:
    hops = int(msg.get("hops", 0))
    if hops >= 2: return
    msg2 = dict(msg); msg2["hops"] = hops + 1
    self.broadcast._broadcast(self.peers, {"type": "CHAT_RELAY", "data": msg2}, exclude=exclude)

def _relay_chat_async(self, msg: dict, exclude=None) -> None:
    threading.Thread(target=self._relay_chat, args=(msg, exclude), daemon=True).start()
    
def _relay_presence(self, pres: dict, exclude=None) -> None:
    hops = int(pres.get("hops", 0))
    if hops >= 2:
        return
    pres2 = dict(pres); pres2["hops"] = hops + 1
    msg = {"type": "CHAT_PRESENCE", **pres2}
    self.broadcast._broadcast(self.peers, msg, exclude=exclude)

def _relay_presence_async(self, pres: dict, exclude=None) -> None:
    threading.Thread(target=self._relay_presence, args=(pres, exclude), daemon=True).start()

def _mailbox_put(self, addr, item, ttl_s, per_addr_max, global_max):
    now = time.time()
    exp = now + ttl_s
    with self.chat_lock:
        dq = self.chat_mailbox.get(addr)
        if dq is None:
            dq = collections.deque()
            self.chat_mailbox[addr] = dq
        # lazy GC per addr
        while dq and dq[0][0] <= now:
            dq.popleft(); self.chat_global_count -= 1
        if len(dq) >= per_addr_max or self.chat_global_count >= global_max:
            return False  # mailbox full
        dq.append((exp, item))
        self.chat_global_count += 1
        return True
    
def _enqueue_rcpt(self, to_addr, kind, mid, frm, to, ts):
    item = {
        "type": "CHAT_RCPT",
        "rcpt": kind,
        "msg_id": mid,
        "from": frm,
        "to": to,
        "ts": int(ts),
    }
    self._mailbox_put(to_addr, item, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)

def _mailbox_pull(self, addr, nmax):
    now = time.time()
    out = []
    with self.chat_lock:
        dq = self.chat_mailbox.get(addr)
        if not dq:
            return out
        # prune expired entries first
        while dq and dq[0][0] <= now:
            dq.popleft(); self.chat_global_count -= 1
        while dq and len(out) < nmax:
            exp, it = dq.popleft()
            self.chat_global_count -= 1
            if exp > now:
                out.append(it)
    return out

def _dedup_mid(self, from_addr, msg_id):
    if msg_id is None: 
        return False
    rec = self.chat_seen_mid.get(from_addr)
    if rec is None:
        dq = collections.deque(maxlen=self.chat_seen_max)
        st = set()
        self.chat_seen_mid[from_addr] = (dq, st)
    else:
        dq, st = rec
    if msg_id in st:
        return True
    # tambah
    dq, st = self.chat_seen_mid[from_addr]
    if len(dq) == dq.maxlen:
        old = dq.popleft(); st.discard(old)
    dq.append(msg_id); st.add(msg_id)
    return False

def _gc_mailboxes(self):
    now = time.time()
    if now - self.chat_gc_last < 30:
        return
    with self.chat_lock:
        for addr, dq in list(self.chat_mailbox.items()):
            changed = False
            while dq and dq[0][0] <= now:
                dq.popleft(); self.chat_global_count -= 1; changed = True
            if not dq and changed:
                self.chat_mailbox.pop(addr, None)
        # bersihkan backoff kadaluarsa
        for k, until in list(self.backoff_until.items()):
            if until <= now:
                self.backoff_until.pop(k, None)
    self.chat_gc_last = now
# ------------------------------ END OF P2P Chat ------------------------------


# ------------- HISTORY HELPERS (script <-> address, scan chain) -------------
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

# ------------- END OF HISTORY HELPERS -------------


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
            meta = GRAFFITI.parse_from_script(spk)
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
            
            meta = GRAFFITI.parse_from_script(spk) 
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
            if any(GRAFFITI.parse_from_script(getattr(tx_out, "script_pubkey", None)) 
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


# ----------------------- TX template (wallet) -------------------------

def _addr_to_spk(self, addr: str) -> Script:
    addr = (addr or "").strip()
    hrp, data = bech32_decode(addr)
    if data is None:
        raise ValueError("invalid bech32 address")
    if (hrp or "").lower() != CFG.ADDRESS_PREFIX:
        raise ValueError(f"Address HRP must be {CFG.ADDRESS_PREFIX}, got '{hrp}'")
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None:
        raise ValueError("decode bech32 failed")
    return Script([0, bytes(decoded)])

def _estimate_tx_size(self, n_inputs, n_outputs, segwit=True):
    return CFG.TX_BASE_VBYTES + n_inputs * CFG.SEGWIT_INPUT_VBYTES + n_outputs * CFG.SEGWIT_OUTPUT_VBYTES

def _check_tx_limits(self, tx_obj: Tx, ctx: str = "rpc_create"):
    weight, vsize, base_size, total_size = compute_tx_weight_vsize(tx_obj)
    vin = len(getattr(tx_obj, "inputs", []) or [])
    vout = len(getattr(tx_obj, "outputs", []) or [])

    if vsize > int(CFG.MAX_TX_VSIZE):
        raise ValueError("tx_vsize_exceeds_limit")
    if vsize < int(CFG.MIN_TX_VSIZE):
        raise ValueError("tx_vsize_below_min")
    if weight > int(CFG.MAX_TX_WEIGHT):
        raise ValueError("tx_weight_exceeds_limit")
    if weight < int(CFG.MIN_TX_WEIGHT):
        raise ValueError("tx_weight_below_min")
    if vin > int(CFG.MAX_TX_INPUTS):
        raise ValueError("tx_inputs_exceed_limit")
    if vout > int(CFG.MAX_TX_OUTPUTS):
        raise ValueError("tx_outputs_exceed_limit")

def _select_utxos_for(self, utxos: list[dict], target_amount_sat: int, fee_rate: int):
    utxos_dict = {}
    for u in utxos:
        k = f"{u['txid']}:{u['index']}"
        utxos_dict[k] = {
            "amount": int(u.get("amount", 0)),
            "script_pubkey": u.get("scriptPubKey", b"").hex(),
        }

    candidates = []
    for key, v in utxos_dict.items():
        txid_hex, idx = key.split(":")
        candidates.append({
            "txid": txid_hex,
            "index": int(idx),
            "amount": int(v["amount"]),
            "scriptPubKey": bytes.fromhex(v["script_pubkey"])
        })
    candidates.sort(key=lambda x: x["amount"])

    selected, acc = [], 0
    n_outputs = 2
    est_fee = 0
    for c in candidates:
        selected.append(c)
        acc += c["amount"]
        est_size = self._estimate_tx_size(len(selected), n_outputs, True)
        est_fee  = fee_rate * est_size
        if acc >= target_amount_sat + est_fee:
            change = acc - target_amount_sat - est_fee
            if change < CFG.DUST_THRESHOLD_SAT:
                n_outputs = 1
                est_fee  = fee_rate * self._estimate_tx_size(len(selected), n_outputs, True)
                if acc < target_amount_sat + est_fee:
                    continue
                change = 0
            return selected, est_fee, change

    raise ValueError(f"insufficient funds: have={acc}, need={target_amount_sat + est_fee}")

def _handle_create_tx(self, from_addr, to_addr, amount, fee_rate):
    if not isinstance(from_addr, str) or not isinstance(to_addr, str):
        raise ValueError("from/to address must be string")

    amt_sat = int(amount * CFG.TSAR) if isinstance(amount, float) else int(amount)
    # Ensure latest UTXO view from disk before building
    self.broadcast.utxodb._load()
    utxos_map = self.broadcast.utxodb.get(from_addr) or {}

    tip_height = self.broadcast.blockchain.height
    utxos_list = []
    for k, v in utxos_map.items():
        txid_hex, idx_str = k.split(":")
        is_cb = bool(v.get("is_coinbase", False))
        born  = int(v.get("block_height", 0))
        if is_cb:
            confirmations = max(0, (int(tip_height) - born) + 1)
            if confirmations < CFG.COINBASE_MATURITY:
                continue
        utxos_list.append({
            "txid": txid_hex,
            "index": int(idx_str),
            "amount": int(v.get("amount", 0)),
            "scriptPubKey": bytes.fromhex(v.get("script_pubkey", "")),
            "height": born,
            "is_coinbase": is_cb,
        })

    if not utxos_list:
        raise ValueError("no spendable utxos")

    from_spk = self._addr_to_spk(from_addr)
    to_spk   = self._addr_to_spk(to_addr)

    selected, fee, change = self._select_utxos_for(utxos_list, amt_sat, fee_rate)

    ins  = [TxIn(bytes.fromhex(u["txid"]), u["index"], amount=int(u["amount"])) for u in selected]
    outs = [TxOut(amt_sat, to_spk)]
    if change >= CFG.DUST_THRESHOLD_SAT:
        outs.append(TxOut(change, from_spk))
    tx = Tx(version=1, inputs=ins, outputs=outs, locktime=0, is_coinbase=False)
    _check_tx_limits(self, tx, ctx="create_single")

    input_meta = [{
        "txid": u["txid"],
        "index": u["index"],
        "amount": int(u["amount"]),
        "script_pubkey": u["scriptPubKey"].hex(),
    } for u in selected]
    return {
        "tx": tx.to_dict(),
        "inputs": input_meta,
        "fee": fee,
        "change": change,
        "from": from_addr,
        "to": to_addr,
        "amount_sat": amt_sat
    }

def _deserialize_spk_hex(self, spk_hex: str) -> Script:
    b = bytes.fromhex((spk_hex or "").strip())
    return Script.deserialize(b)


# ----------------------- GRAFFITI template (wallet) -------------------------
def _guard_graffiti_output(self, spk: Script) -> None:
    """
    Validate graffiti OP_RETURN payload against node-side limits.
    Only triggers when payload starts with GRAFFITI_MAGIC.
    """
    try:
        raw = spk.serialize()
    except Exception:
        return
    data = last_pushdata(raw)
    if not data:
        return
    if not data.startswith(CFG.GRAFFITI_MAGIC):
        return
    if len(data) > int(CFG.MAX_GRAFFITI_OPRET):
        raise ValueError("graffiti_opreturn_too_large")

    meta = GRAFFITI.parse_payload(data)
    if not meta:
        raise ValueError("graffiti_payload_invalid")

    event = str(meta.get("event", "")).upper()
    if event == "POST":
        size_val = int(meta.get("size", 0))
        if size_val <= 0:
            raise ValueError("graffiti_size_invalid")
        if size_val > int(CFG.GRAFFITI_MAX_SIZE_BYTES):
            raise ValueError("graffiti_size_exceeds_limit")
        
    elif event == "COMMENT":
        comment_len = int(meta.get("comment_len", 0))
        if comment_len <= 0:
            raise ValueError("graffiti_comment_empty")
        if comment_len > int(CFG.GRAFFITI_COMMENT_MAX_BYTES):
            raise ValueError("graffiti_comment_too_large")
        amount = int(meta.get("amount", 0))
        if amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
            raise ValueError("graffiti_comment_fee_too_low")
        tip = int(meta.get("tip", 0))
        if tip < 0:
            raise ValueError("graffiti_comment_tip_negative")

def _handle_create_tx_multi(self, from_addr: str, outputs: list, fee_rate: int, force_inputs: list[str] | None = None):
    if not isinstance(from_addr, str):
        raise ValueError("from must be string")
    if not isinstance(outputs, list) or not outputs:
        raise ValueError("outputs must be non-empty list")

    fee_rate = int(max(CFG.MIN_FEE_RATE_SATVB, min(fee_rate, CFG.MAX_FEE_RATE_SATVB)))
    self.broadcast.utxodb._load()
    utxos_map = self.broadcast.utxodb.get(from_addr) or {}
    tip_height = self.broadcast.blockchain.height
    utxos_list = []
    for k, v in (utxos_map.items() if isinstance(utxos_map, dict) else []):
        txid_hex, idx_str = k.split(":")
        is_cb = bool(v.get("is_coinbase", False))
        born  = int(v.get("block_height", 0))
        if is_cb:
            confirmations = max(0, (int(tip_height) - born) + 1)
            if confirmations < CFG.COINBASE_MATURITY:
                continue
            
        utxos_list.append({
            "txid": txid_hex,
            "index": int(idx_str),
            "amount": int(v.get("amount", 0)),
            "scriptPubKey": bytes.fromhex(v.get("script_pubkey", "")),
            "height": born,
            "is_coinbase": is_cb,
        })
    
    fixed_outs: list[tuple[int, Script]] = []
    total_target = 0
    for item in outputs:
        if not isinstance(item, dict):
            raise ValueError("output item must be dict")
        amt = int(item.get("amount", 0))
        if "spk_hex" in item:
            spk = self._deserialize_spk_hex(item["spk_hex"])
        elif "opret_hex" in item:
            data = bytes.fromhex(item["opret_hex"])
            spk = Script([OP_RETURN, data])
        elif "address" in item:
            spk = self._addr_to_spk(str(item["address"]))
        else:
            raise ValueError("output item must have spk_hex/opret_hex/address")
        self._guard_graffiti_output(spk)
        fixed_outs.append((amt, spk))
        total_target += max(0, amt)

    preselected = []
    pre_acc = 0
    forced_keys = set(force_inputs or [])
    utxo_by_key = {f"{u['txid']}:{u['index']}": u for u in utxos_list}
    for key in forced_keys:
        u = utxo_by_key.get(key)
        if u:
            preselected.append(u)
            pre_acc += int(u["amount"])
            
    if force_inputs:
        missing = [k for k in forced_keys if k not in utxo_by_key]
        if missing:
            # Global UTXO map stores entries as {"tx_out": TxOut, "is_coinbase": bool, "block_height": int}
            global_utxos = getattr(self.broadcast.utxodb, "utxos", {})
            for key in list(missing):
                txid_hex, idx_str = key.split(":")
                entry = global_utxos.get(key)
                if not entry:
                    continue
                tx_out = entry.get("tx_out")
                amt = int(getattr(tx_out, "amount", 0))
                spk = getattr(tx_out, "script_pubkey", None)
                spk_bytes = spk.serialize() if hasattr(spk, "serialize") else (spk if isinstance(spk, (bytes, bytearray)) else b"")
                is_cb = bool(entry.get("is_coinbase", False))
                born  = int(entry.get("block_height", 0))
                u = {
                    "txid": txid_hex,
                    "index": int(idx_str),
                    "amount": amt,
                    "scriptPubKey": spk_bytes,
                    "height": born,
                    "is_coinbase": is_cb,
                }
                utxos_list.append(u)
                utxo_by_key[key] = u
                preselected.append(u)
                pre_acc += amt
                missing.remove(key)
                
        if missing:
            locks = {}
            sender_spk = self._addr_to_spk(from_addr)
            sender_spk_bytes = sender_spk.serialize()
            for key in list(missing):
                meta = locks.get(key)
                if not isinstance(meta, dict):
                    continue
                if str(meta.get("owner", "")).strip().lower() != str(from_addr).strip().lower():
                    continue
                amt = int(meta.get("amount", 0))
                if amt <= 0 or not sender_spk_bytes:
                    continue
                txid_hex, idx_str = key.split(":")
                u = {
                    "txid": txid_hex,
                    "index": int(idx_str),
                    "amount": amt,
                    "scriptPubKey": sender_spk_bytes,
                    "height": 0,
                    "is_coinbase": False,
                }
                utxos_list.append(u)
                utxo_by_key[key] = u
                preselected.append(u)
                pre_acc += amt
                missing.remove(key)
        if any(k not in utxo_by_key for k in forced_keys):
            raise ValueError("forced_input_missing")

    if not utxos_list and not preselected:
        raise ValueError("no spendable utxos")
    candidates = [u for u in utxos_list if f"{u['txid']}:{u['index']}" not in forced_keys]
    candidates.sort(key=lambda x: x["amount"])

    selected = list(preselected)
    acc = pre_acc
    need = total_target
    change = 0
    fee_est = 0
    def _est_fee(n_in: int, n_out: int) -> int:
        return fee_rate * self._estimate_tx_size(n_in, n_out, True)

    # Greedy accumulate
    while True:
        fee_est = _est_fee(len(selected), len(fixed_outs) + 1)
        if acc >= need + fee_est:
            change = acc - need - fee_est
            if change < CFG.DUST_THRESHOLD_SAT:
                fee_est2 = _est_fee(len(selected), len(fixed_outs))
                if acc >= need + fee_est2:
                    change = 0
                    fee_est = fee_est2
                else:
                    pass
            if acc >= need + fee_est:
                break

        if not candidates:
            raise ValueError(f"insufficient funds: have={acc}, need={need + fee_est}")
        selected.append(candidates.pop(0))
        acc += int(selected[-1]["amount"])

    from_spk = self._addr_to_spk(from_addr)
    ins  = [TxIn(bytes.fromhex(u["txid"]), u["index"], amount=int(u["amount"])) for u in selected]
    non_opret, opret_outs = [], []
    for amt, spk in fixed_outs:
        is_opret = (isinstance(spk, Script) and getattr(spk, "cmds", None) and spk.cmds and spk.cmds[0] == OP_RETURN)
        (opret_outs if is_opret else non_opret).append(TxOut(amt, spk))
    outs = non_opret
    if change >= CFG.DUST_THRESHOLD_SAT:
        outs.append(TxOut(change, from_spk))
    outs.extend(opret_outs)

    tx = Tx(version=1, inputs=ins, outputs=outs, locktime=0, is_coinbase=False)
    _check_tx_limits(self, tx, ctx="create_multi")
    input_meta = [{
        "txid": u["txid"],
        "index": u["index"],
        "amount": int(u["amount"]),
        "script_pubkey": u["scriptPubKey"].hex(),
    } for u in selected]

    return {
        "tx": tx.to_dict(),
        "inputs": input_meta,
        "fee": fee_est,
        "change": change,
        "from": from_addr,
        "outputs": [
            {
                "amount": int(amt),
                "script_pubkey": spk.serialize().hex(),
            } for (amt, spk) in fixed_outs
        ]
    }

_CLIENT_HELPER = {
    "_send_to_peer": _send_to_peer,
    "_chat_enqueue_locked": _chat_enqueue_locked,
    "_chat_seen_add_locked": _chat_seen_add_locked,
    "_chat_rl_ok_locked": _chat_rl_ok_locked,
    "_relay_chat": _relay_chat,
    "_relay_chat_async": _relay_chat_async,
    "_relay_presence": _relay_presence,
    "_relay_presence_async": _relay_presence_async,
    "_tb_now": _tb_now,
    "_tb_allow": _tb_allow,
    "_backoff": _backoff,
    "_nonce_guard": _nonce_guard,
    "_mailbox_put": _mailbox_put,
    "_enqueue_rcpt": _enqueue_rcpt,
    "_mailbox_pull": _mailbox_pull,
    "_dedup_mid": _dedup_mid,
    "_gc_mailboxes": _gc_mailboxes,
    "_txin_prevkey": _txin_prevkey,
    "_is_coinbase_tx": _is_coinbase_tx,
    "_spkhex_to_address": _spkhex_to_address,
    "_txout_to_spk_hex": _txout_to_spk_hex,
    "_txout_to_address": _txout_to_address,
    "_normalize_spk_hex": _normalize_spk_hex,
    "_build_outpoint_map": _build_outpoint_map,
    "_find_tx_and_meta": _find_tx_and_meta,
    "_get_tx_history": _get_tx_history,
    "_get_tx_detail": _get_tx_detail,
    "_bhash_hex": _bhash_hex,
    "_extract_block_id_from_block": _extract_block_id_from_block,
    "_handle_get_block_hash": _handle_get_block_hash,
    "_prevhash_hex": _prevhash_hex,
    "_serialize_tx_basic": _serialize_tx_basic,
    "_serialize_block": _serialize_block,
    "_addr_to_spk": _addr_to_spk,
    "_estimate_tx_size": _estimate_tx_size,
    "_select_utxos_for": _select_utxos_for,
    "_handle_create_tx": _handle_create_tx,
    "_deserialize_spk_hex": _deserialize_spk_hex,
    "_guard_graffiti_output": _guard_graffiti_output,
    "_handle_create_tx_multi": _handle_create_tx_multi,
}

def install_client_helper(target_cls) -> None:
    for name, func in _CLIENT_HELPER.items():
        setattr(target_cls, name, func)

__all__ = ("install_client_helper",)
