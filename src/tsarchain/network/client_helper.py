# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; Merkle; Signal-X3DH

import socket, threading, json, time, collections, hashlib
from collections import deque
from bech32 import convertbits, bech32_decode, bech32_encode

# ---------------- Local Project ----------------
from ..core.tx import Tx, TxIn, TxOut
from ..utils.helpers import Script, OP_RETURN, last_pushdata
from ..contracts import graffiti as GRAFFITI
from .protocol import send_message, recv_message,build_envelope, SecureChannel
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.client_helper")


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
        mb = deque(maxlen=500)       # batas 500 per inbox
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

def _txout_to_address(self, txout) -> str | None:
    spk = getattr(txout, "script_pubkey", None)
    if spk is None:
        return None
    if hasattr(spk, "serialize"):
        spk_hex = spk.serialize().hex()
    elif isinstance(spk, (bytes, bytearray)):
        spk_hex = bytes(spk).hex()
    elif isinstance(spk, str):
        spk_hex = spk
    else:
        return None
    return self._spkhex_to_address(spk_hex)

def _build_outpoint_map_chain(self, chain) -> dict:
    m: dict[str, tuple[int, str]] = {}
    for b in chain:
        txs = getattr(b, "transactions", []) or []
        for tx in txs:
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                amount = int(getattr(o, "amount", 0))
                addr = self._txout_to_address(o) or ""
                m[f"{txid}:{idx}"] = (amount, addr)
    return m

def _build_outpoint_map(self, chain, mem) -> dict:
    m: dict[str, tuple[int, str]] = {}
    for b in chain:
        txs = getattr(b, "transactions", []) or []
        for tx in txs:
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                amount = int(getattr(o, "amount", 0))
                addr = self._txout_to_address(o) or ""
                m[f"{txid}:{idx}"] = (amount, addr)
    for tx in mem:
        txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
        for idx, o in enumerate(getattr(tx, "outputs", []) or []):
            amount = int(getattr(o, "amount", 0))
            addr = self._txout_to_address(o) or ""
            m[f"{txid}:{idx}"] = (amount, addr)
    return m

def _find_tx_and_meta(self, txid_hex: str):
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
        tip_height = int(self.broadcast.blockchain.height)
        mem = self.broadcast.mempool.get_all_txs()
    for tx in mem:
        txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
        if txid == txid_hex:
            return ("mempool", tx, None, 0, chain, mem, tip_height)
    for b in chain:
        h = int(getattr(b, "height", 0))
        for tx in getattr(b, "transactions", []) or []:
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            if txid == txid_hex:
                conf = max(0, tip_height - h + 1)
                return ("chain", tx, h, conf, chain, mem, tip_height)

    return (None, None, None, 0, chain, mem, tip_height)

def _get_tx_history(self, address: str, limit: int = 50, offset: int = 0, direction: str | None = None, status: str | None = None) -> dict:
    if not isinstance(address, str):
        return {"items": [], "total": 0, "limit": limit, "offset": offset}

    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
        tip_height = int(self.broadcast.blockchain.height)
        mem = self.broadcast.mempool.get_all_txs()
        
    opmap_all   = self._build_outpoint_map(chain, mem)
    opmap_chain = self._build_outpoint_map_chain(chain)
    items = []

    def _append_item(tx, where, h_or_none):
        txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
        is_cb = self._is_coinbase_tx(tx)
        conf = 0
        height = None
        if where == "chain":
            height = int(h_or_none or 0)
            conf = max(0, tip_height - height + 1)

        received_to_addr = 0
        main_recipient, max_rec_amt = None, -1
        for o in getattr(tx, "outputs", []) or []:
            amt = int(getattr(o, "amount", 0))
            addr_o = self._txout_to_address(o)
            if addr_o == address:
                received_to_addr += amt
            else:
                if amt > max_rec_amt:
                    max_rec_amt = amt
                    main_recipient = addr_o

        spent_from_addr = 0
        sources = set()
        for tin in getattr(tx, "inputs", []) or []:
            key = self._txin_prevkey(tin)
            amt_addr = opmap_all.get(key) if where == "mempool" else opmap_chain.get(key)
            if not amt_addr:
                continue
            amt_prev, addr_prev = amt_addr
            if addr_prev == address:
                spent_from_addr += int(amt_prev)
            elif addr_prev:
                sources.add(addr_prev)

        if spent_from_addr > 0:
            net_amt = spent_from_addr - received_to_addr
            if net_amt < 0:
                net_amt = 0
            dirn = "out"
            frm = address
            to  = main_recipient if (main_recipient and main_recipient != address) else None
        elif received_to_addr > 0:
            dirn = "in"
            net_amt = received_to_addr
            frm = "coinbase" if is_cb else (next(iter(sources)) if sources else None)
            to  = address
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
        })

    for tx in mem:
        _append_item(tx, "mempool", None)
    for b in chain:
        h = int(getattr(b, "height", 0))
        for tx in getattr(b, "transactions", []) or []:
            _append_item(tx, "chain", h)
            
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
    
    if direction in ("in", "out"):
        items = [it for it in items if it["direction"] == direction]
    if status in ("confirmed", "unconfirmed"):
        items = [it for it in items if it["status"] == status]

    def _key(it):
        st = 0 if it["status"] == "unconfirmed" else 1
        h  = it["height"] if it["height"] is not None else -1
        return (st, -h)
    items.sort(key=_key)

    total = len(items)
    start = max(0, int(offset))
    end   = max(start, int(start + max(0, int(limit))))
    items = items[start:end]
    return {"items": items, "total": total, "limit": int(limit), "offset": int(offset)}


def _get_tx_detail(self, txid_hex: str) -> dict:
    where, tx, height, conf, chain, mem, tip_height = self._find_tx_and_meta(txid_hex)
    if tx is None:
        return {"error": "tx not found", "txid": txid_hex}

    opmap = self._build_outpoint_map_chain(chain)
    vin = []
    total_in = 0
    is_coinbase = self._is_coinbase_tx(tx)

    if not is_coinbase:
        for tin in (getattr(tx, "inputs", []) or []):
            key = self._txin_prevkey(tin)
            amt, a = opmap.get(key, (None, None))
            if amt is not None:
                total_in += int(amt)
            prev_txid = key.split(":")[0]
            prev_index = int(key.split(":")[1]) if ":" in key else 0
            vin.append({
                "prev_txid": prev_txid,
                "prev_index": prev_index,
                "amount": None if amt is None else int(amt),
                "address": a
            })

    vout = []
    total_out = 0
    for n, o in enumerate(getattr(tx, "outputs", []) or []):
        amt = int(getattr(o, "amount", 0))
        total_out += amt
        vout.append({
            "index": n,
            "amount": amt,
            "address": self._txout_to_address(o)
        })

    fee = None
    if not is_coinbase and vin and total_in >= total_out:
        fee = total_in - total_out

    return {
        "type": "TX_DETAIL",
        "txid": txid_hex,
        "status": "unconfirmed" if where == "mempool" else "confirmed",
        "confirmations": conf,
        "height": height,
        "is_coinbase": is_coinbase,
        "inputs": vin,
        "outputs": vout,
        "total_in": None if is_coinbase else total_in,
        "total_out": total_out,
        "fee": fee
    }

# ----------------------- Helpers For Block (wallet - explorer tab) -------------------------

def _bhash_hex(self, b) -> str:
    # 1) Method .hash()
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

    # 2) Method .header() -> bytes
    hdr_fn = getattr(b, "header", None)
    if callable(hdr_fn):
        bb = hdr_fn()
        if isinstance(bb, (bytes, bytearray)) and len(bb) > 0:
            return hashlib.sha256(hashlib.sha256(bb).digest()).hexdigest()

    # 3) Header object with serialize method(s)
    hdr_obj = getattr(b, "header", None)
    if hdr_obj is not None and not callable(hdr_obj):
        for meth in ("serialize_block", "serialize", "to_bytes", "serialize_header", "serialize_header_only"):
            fn = getattr(hdr_obj, meth, None)
            if callable(fn):
                bb = fn()
                if isinstance(bb, (bytes, bytearray)) and len(bb) > 0:
                    return hashlib.sha256(hashlib.sha256(bb).digest()).hexdigest()
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
        log.debug(
            "[_handle_get_block_hash] Benchmark : %.3f ms cache_hit=%s height=%s",
            result,
            cache_hit,
            height,
        )
        
    return {"type": "BLOCK_HASH", "height": height, "hash": h_hex or "", "cache_hit": cache_hit}

def _prevhash_hex(self, b) -> str:
    for name in ("prev_hash", "previous_hash", "prev_block_hash"):
        v = getattr(b, name, None)
        if isinstance(v, (bytes, bytearray)):
            return v.hex()
        if isinstance(v, str):
            return v
    hdr = getattr(b, "header", None)
    if hdr is not None:
        v = getattr(hdr, "prev_hash", None)
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

    # Height / time / nonce / difficulty
    height = int(getattr(b, "height", getattr(b, "index", 0)))

    ts = None
    for name in ("time", "timestamp"):
        v = getattr(b, name, None)
        if v is not None:
            ts = int(v); break

    nonce = None
    for obj in (b, getattr(b, "header", None)):
        if obj is None or callable(obj):
            continue
        v = getattr(obj, "nonce", None)
        if v is not None:
            nonce = int(v); break

    diff = None
    for obj in (b, getattr(b, "header", None)):
        if obj is None or callable(obj):
            continue
        v = getattr(obj, "difficulty", None)
        if v is not None:
            diff = v; break

    # Version / bits / merkle root
    version = getattr(b, "version", None)
    bits    = getattr(b, "bits", None)
    mroot   = getattr(b, "merkle_root", None)
    if mroot is None:
        hdr = getattr(b, "header", None)
        if hdr is not None and not callable(hdr):
            mroot = getattr(hdr, "merkle_root", None)
    mroot_hex = _to_hex(mroot)

    # Transactions (light)
    txs = []
    graffiti_posts = []
    graffiti_comments = []
    for tx in getattr(b, "transactions", []) or []:
        txs.append(self._serialize_tx_basic(tx))
        txid_hex = ""
        tid = getattr(tx, "txid", None)
        if isinstance(tid, (bytes, bytearray)):
            txid_hex = tid.hex()
        elif isinstance(tid, str):
            txid_hex = tid
        for tx_out in getattr(tx, "outputs", []) or []:
            spk = getattr(tx_out, "script_pubkey", None)
            meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
            if not meta:
                continue
            ev = str(meta.get("event", "")).upper()
            if ev == "POST":
                graffiti_posts.append({
                    "txid": txid_hex,
                    "sha256": meta.get("sha256"),
                    "size": meta.get("size"),
                    "mime": meta.get("mime"),
                    "storer": meta.get("storer"),
                    "receipt": meta.get("receipt"),
                })
            elif ev == "COMMENT":
                comment_hex = meta.get("comment") or ""
                comment_text = ""
                comment_text = bytes.fromhex(comment_hex).decode("utf-8", errors="ignore")
                graffiti_comments.append({
                    "txid": txid_hex,
                    "art_id": meta.get("art_id"),
                    "comment_hex": comment_hex,
                    "comment_text": comment_text,
                    "amount": meta.get("amount"),
                    "tip": meta.get("tip"),
                    "creator": meta.get("creator"),
                    "commenter": meta.get("commenter"),
                    "comment_len": meta.get("comment_len"),
                })

    blk_id = self._extract_block_id_from_block(b)
    block_dict = {
        "type": "BLOCK",
        "block_id": blk_id,
        "hash": self._bhash_hex(b),
        "prev_hash": self._prevhash_hex(b),
        "height": height,
        "time": ts,
        "nonce": nonce,
        "difficulty": diff,
        "version": version,
        "bits": bits,
        "merkle_root": mroot_hex,
        "tx": txs,
        "tx_count": len(txs),
        "graffiti": graffiti_posts,
        "comments": graffiti_comments,
    }
    mem = getattr(self, "mempool", None)
    if mem:
        count = 0
        for tx in mem.get_all_txs():
            for tx_out in getattr(tx, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                meta = None
                try:
                    meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                except Exception:
                    log.exception("[_serialize_block] unexpected error")
                    meta = None
                if meta and str(meta.get("event", "")).upper() == "POST":
                    count += 1
                    break
        block_dict["graffiti_on_mempool"] = count
    return block_dict


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
    "_txout_to_address": _txout_to_address,
    "_build_outpoint_map_chain": _build_outpoint_map_chain,
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
    "_handle_create_tx_multi": _handle_create_tx_multi,
}

def install_client_helper(target_cls) -> None:
    for name, func in _CLIENT_HELPER.items():
        setattr(target_cls, name, func)

__all__ = ("install_client_helper",)
