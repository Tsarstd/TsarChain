# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; libsecp256k1; Signal-X3DH; RFC7748-X25519

import hashlib
import time, secrets, json
from typing import TYPE_CHECKING, Any, Callable, Optional

from bech32 import convertbits, bech32_decode

from ...utils.helpers import hash160
from ...utils.helpers import batch_verify_der_low_s
from ...utils import config as CFG
from ...contracts import graffiti as GRAFFITI

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc")

if TYPE_CHECKING:
    from ..node import Network


def _verify_chat_signatures(tasks: list[tuple[str, str, bytes, str]]) -> dict[str, bool]:
    """
    tasks: [(label, pub_hex, payload_bytes, sig_hex), ...]
    Returns mapping label -> bool
    """
    verdict: dict[str, bool] = {}
    normalized: list[tuple[str, bytes, bytes, bytes]] = []
    for label, pub_hex, payload, sig_hex in tasks:
        verdict[label] = False
        if not (pub_hex and sig_hex and isinstance(payload, (bytes, bytearray)) and payload):
            continue
        pub_b = bytes.fromhex(pub_hex)
        sig_b = bytes.fromhex(sig_hex)
        normalized.append((label, pub_b, bytes(payload), sig_b))

    if not normalized:
        return verdict

    triples = [
        (pub_b, hashlib.sha256(payload).digest(), sig_b)
        for _, pub_b, payload, sig_b in normalized
    ]
    results = batch_verify_der_low_s(triples, enforce_low_s=True, parallel=False)

    for (label, _, _, _), ok in zip(normalized, results):
        verdict[label] = bool(ok)
    return verdict


__all__ = ["handle_user_rpc"]


def handle_user_rpc(
    self: "Network",
    message: dict[str, Any],
    addr: Optional[tuple],
    mtype: str,
    *,
    client_ip: Callable[[], str],
    is_miner_sender: Callable[[], bool],
    overlay_realtime_mempool_stats: Callable[[dict, "Network"], None],
    choose_relay_route: Callable[["Network", int], list[tuple]],
    relay_chain: Callable[["Network", list[tuple], dict, Optional[tuple]], None],
    send_chat_relay: Callable[["Network", tuple, dict], dict],
) -> dict | None:

# =============================================================================
# ---------------------------- User Activities RPC ----------------------------
# =============================================================================

    if mtype == "PING":
        return {"type": "PONG"}

#----------------------#-------------------

    elif mtype in ("GET_BALANCES"):
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        
        ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"
        rl_key = f"bal:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.BALANCE_RL_IP_BURST, CFG.BALANCE_RL_IP_WINDOW_S, CFG.BALANCE_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.BALANCE_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        addrs_raw = message.get("addresses") or []
        if not addrs_raw and message.get("address"):
            addrs_raw = [message["address"]]
        if not isinstance(addrs_raw, list) or not addrs_raw:
            return {"error": "missing addresses"}
        if len(addrs_raw) > CFG.MAX_ADDRS_PER_REQ:
            return {"error": "too many addresses (max %d)" % CFG.MAX_ADDRS_PER_REQ}

        norm = []
        for a in addrs_raw:
            if not a:
                continue
            a = str(a).strip()
            if a.lower().startswith(CFG.ADDRESS_PREFIX):
                a = a.lower()
            if len(a) > CFG.MAX_UTXO_ADDR_LEN:
                return {"error": "address too long"}
            norm.append(a)

        addrs = list(dict.fromkeys(norm))
        with self.broadcast.lock:
            chain = list(self.broadcast.blockchain.chain)
            tip_height = int(self.broadcast.blockchain.height)
            mem = self.broadcast.mempool.get_all_txs()
        self.broadcast.utxodb._load()

        opmap = self._build_outpoint_map(chain, mem)
        pending_out_map: dict[str, int] = {}
        incoming_map: dict[str, int] = {}
        for tx in mem or []:
            spent_local: dict[str, int] = {}
            recv_local: dict[str, int] = {}

            for tin in getattr(tx, "inputs", []) or []:
                key = self._txin_prevkey(tin)
                amt_owner = opmap.get(key)
                if not amt_owner:
                    continue
                amt, owner = amt_owner
                if owner and amt:
                    spent_local[owner] = spent_local.get(owner, 0) + int(amt)

            for o in getattr(tx, "outputs", []) or []:
                amt = int(getattr(o, "amount", 0) or 0)
                if amt <= 0:
                    continue
                addr_o = self._txout_to_address(o)
                if addr_o:
                    recv_local[addr_o] = recv_local.get(addr_o, 0) + amt

            # Treat change outputs (addr appears on both sides) as neutral.
            for addr, spent_amt in list(spent_local.items()):
                change_amt = min(spent_amt, recv_local.get(addr, 0))
                if change_amt > 0:
                    spent_local[addr] = spent_amt - change_amt
                    recv_local[addr] = recv_local.get(addr, 0) - change_amt

            for addr, spent_amt in spent_local.items():
                if spent_amt > 0:
                    pending_out_map[addr] = pending_out_map.get(addr, 0) + spent_amt
            for addr, recv_amt in recv_local.items():
                if recv_amt > 0:
                    incoming_map[addr] = incoming_map.get(addr, 0) + recv_amt

        items = {}
        for addr_str in addrs:
            b = self.broadcast.utxodb.get_balance(addr_str, mode="breakdown", current_height=tip_height)
            if not isinstance(b, dict):
                b = {"total": int(b or 0), "mature": int(b or 0), "immature": 0}
            pending_out = int(pending_out_map.get(addr_str, 0))
            pending_in = int(incoming_map.get(addr_str, 0))

            spendable = max(0, int(b.get("mature", 0)) - int(pending_out or 0))
            items[addr_str] = {
                "balance": int(b.get("total", 0)),
                "spendable": spendable,
                "immature": int(b.get("immature", 0)),
                "pending_outgoing": int(pending_out or 0),
                "pending_incoming": int(pending_in or 0),
                "maturity": int(CFG.COINBASE_MATURITY),
            }
            
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GET_BALANCES] Benchmark : %.3f ms", result)
            
        return {"type": "BALANCES", "height": tip_height, "items": items}

    elif mtype == "CREATE_TX":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        from_addr = (message.get("from") or "").strip().lower()
        to_addr   = (message.get("to")   or "").strip().lower()
        amount    = message.get("amount")
        fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
        fee_rate = max(CFG.MIN_FEE_RATE_SATVB, min(fee_rate, CFG.MAX_FEE_RATE_SATVB))
        tpl = self._handle_create_tx(from_addr, to_addr, amount, fee_rate)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GET_BALANCES] Benchmark : %.3f ms", result)
        
        return {"type": "TX_TEMPLATE", "data": tpl}

#----------------------#-------------------

    elif mtype == "GET_NETWORK_INFO":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        ip = client_ip()
        rl_key = f"info:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.INFO_RL_IP_BURST, CFG.INFO_RL_IP_WINDOW_S, CFG.INFO_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.INFO_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        
        snap = self.broadcast.blockchain._read_snapshot_state()
        overlay_realtime_mempool_stats(snap, self)
        with self.lock:
            peers_sane = [(ip,p) for (ip,p) in self.peers if isinstance(p,int) and p>0]
            
        snap.setdefault("peers", {})
        if isinstance(snap["peers"], dict):
            snap["peers"]["count"] = len(peers_sane)
        else:
            snap["peers"] = {"count": len(peers_sane)}
            
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GET_NETWORK_INFO] Benchmark : %.3f ms", result)
            
        return {"type": "NETWORK_INFO", "data": snap}

#----------------------#-------------------

    elif mtype == "GET_BLOCK":
        if "height" in message:
            return self._handle_get_block_at(int(message["height"]))
        hx = str(message.get("hash") or "").strip()
        if not hx:
            return {"type": "BLOCK", "error": "missing_height_or_hash"}
        return self._handle_get_block_by_hash(hx)

#----------------------#-------------------

    elif mtype == "GET_PEERS":
        if not is_miner_sender():
            return {"type": "PEERS", "peers": []}
        return {"type": "PEERS", "peers": list(self.peers)}

#----------------------#-------------------

    elif mtype == "NEW_TX":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        if CFG.ENABLE_DANDELION_PP and "phase" not in message:
            message = dict(message)
            message["phase"] = "stem"
        
        success = self.broadcast.receive_tx(message, addr, self.peers)
        if success:
            txid = (message.get("data") or {}).get("txid")
            
            if CFG.DEBUG_BENCHMARKS:
                end = time.perf_counter()
                result = round((end - start) * 1000.0, 3)
                log.debug("[NEW_TX] Benchmark : %.3f ms", result)
                
            return {"status": "ok", "txid": txid}
        else:
            reason = getattr(self.broadcast.mempool, 'last_error_reason', None)
            return {"status": "error", "reason": (reason or "invalid tx")}

#----------------------#-------------------

    elif mtype == "GET_MEMPOOL":
        mode = str(message.get("mode", "")).strip().lower()
        if mode == "snapshot":
            if CFG.DEBUG_BENCHMARKS:
                start = time.perf_counter()
                
            if not is_miner_sender():
                return {"error": "forbidden: miners-only endpoint"}
            peer_port = int(message.get("port", 0))
            target = None
            if isinstance(addr, tuple):
                if peer_port > 0:
                    target = self._normalize_peer((addr[0], peer_port))
                if not target:
                    # fall back to known peers with same IP
                    with self.lock:
                        for candidate in self.peers:
                            if candidate[0] == addr[0]:
                                target = candidate
                                break
            if not target:
                return {"error": "missing_peer_port"}
            min_iv = message.get("min_interval")
            force = bool(message.get("force"))
            pushed = self.broadcast.send_mempool_to_peer(target, min_interval_s=min_iv, force=force)
            
            if CFG.DEBUG_BENCHMARKS:
                end = time.perf_counter()
                result = round((end - start) * 1000.0, 3)
                log.debug("[GET_MEMPOOL] snapshot mode Benchmark : %.3f ms", result)
                
            return {"type": "MEMPOOL_SYNC", "count": int(pushed)}

        if mode in ("inline", "inline_full"):
            ip = client_ip()
            mp_key = f"mempool:{ip}"
            if not self._tb_allow(self.rl_ip, mp_key, CFG.MEMPOOL_INLINE_RL_BURST, CFG.MEMPOOL_INLINE_RL_WINDOW_S, CFG.MEMPOOL_INLINE_RL_BURST, backoff_key=mp_key):
                self._backoff(mp_key, CFG.MEMPOOL_INLINE_RL_BACKOFF)
                return {"error": "rate_limited"}
            all_txs = self.broadcast.mempool.get_all_txs() or []
            inline: list[dict] = []
            total = len(all_txs)
            hard_cap = max(1024, CFG.MAX_MSG) - len(CFG.NETWORK_MAGIC)
            limit = CFG.MEMPOOL_INLINE_MAX_TX
            base = {"type": "MEMPOOL", "mode": "inline_full", "total": total, "txs": []}

            for tx in all_txs:
                if len(inline) >= limit:
                    break
                if hasattr(tx, "to_dict"):
                    tx_dict = tx.to_dict(include_txid=True)
                elif isinstance(tx, dict):
                    tx_dict = dict(tx)
                else:
                    continue

                if not tx_dict.get("txid") and getattr(tx, "txid", None):
                    txid_attr = getattr(tx, "txid")
                    tx_dict["txid"] = txid_attr.hex() if isinstance(txid_attr, (bytes, bytearray)) else str(txid_attr)

                candidate = dict(base)
                candidate["txs"] = inline + [tx_dict]
                enc = json.dumps(candidate, separators=CFG.CANONICAL_SEP).encode("utf-8")

                if hard_cap > 0 and enc and len(enc) > hard_cap:
                    if inline:
                        break
                    # Single tx too large, skip it
                    continue

                inline.append(tx_dict)

            return {
                "type": "MEMPOOL",
                "mode": "inline_full",
                "total": total,
                "count": len(inline),
                "txs": inline,
            }
        txs = self.broadcast.mempool.get_all_txs()
        hexes = []
        for t in txs:
            txid = getattr(t, "txid", None)
            if isinstance(txid, (bytes, bytearray)):
                hexes.append(txid.hex())
            elif isinstance(txid, str):
                hexes.append(txid)
                
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GET_MEMPOOL] inline mode Benchmark : %.3f ms", result)
            
        return {"type": "MEMPOOL", "mode": "txids", "txs": hexes}

#----------------------#-------------------

    elif mtype == "GET_TX_HISTORY":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        ip = client_ip()
        hist_key = f"hist:{ip}"
        if not self._tb_allow(self.rl_ip, hist_key, CFG.HISTORY_RL_IP_BURST, CFG.HISTORY_RL_IP_WINDOW_S, CFG.HISTORY_RL_IP_BURST, backoff_key=hist_key):
            self._backoff(hist_key, CFG.HISTORY_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        addr_str = (message.get("address") or "").strip().lower()
        if not addr_str:
            return {"error": "missing address"}
        limit = int(message.get("limit", 50))
        offset = int(message.get("offset", 0))
        if limit > CFG.MAX_HISTORY_LIMIT:
            limit = CFG.MAX_HISTORY_LIMIT
        with self.broadcast.lock:
            tip_height = int(self.broadcast.blockchain.height)
        history = self._get_tx_history(addr_str, limit=limit, offset=offset,
                                    direction=message.get("direction"),
                                    status=message.get("status"))
        history["height"] = tip_height
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GET_TX_HISTORY] Benchmark : %.3f ms", result)
        
        return {"type": "TX_HISTORY", "address": addr_str, **history}

#----------------------#-------------------

    elif mtype == "GET_TX_DETAIL":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        ip = client_ip()
        hist_key = f"hist:{ip}"
        if not self._tb_allow(self.rl_ip, hist_key, CFG.HISTORY_RL_IP_BURST, CFG.HISTORY_RL_IP_WINDOW_S, CFG.HISTORY_RL_IP_BURST, backoff_key=hist_key):
            self._backoff(hist_key, CFG.HISTORY_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        txid_hex = message.get("txid")
        if not txid_hex:
            return {"error": "missing txid"}
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GET_TX_DETAIL] Benchmark : %.3f ms", result)
            
        return self._get_tx_detail(txid_hex)

#----------------------#-------------------

    elif mtype == "GET_UTXOS":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        ip = client_ip()
        hist_key = f"hist:{ip}"
        if not self._tb_allow(self.rl_ip, hist_key, CFG.HISTORY_RL_IP_BURST, CFG.HISTORY_RL_IP_WINDOW_S, CFG.HISTORY_RL_IP_BURST, backoff_key=hist_key):
            self._backoff(hist_key, CFG.HISTORY_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        
        address = (message.get("address") or "").strip().lower()
        if not address:
            return {"error": "missing address"}

        if len(address) > CFG.MAX_UTXO_ADDR_LEN:
            return {"error": "address too long"}
        
        utxos = self.broadcast.utxodb.get(address)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GET_UTXOS] Benchmark : %.3f ms", result)
            
        return {"type": "UTXOS", "address": address, "utxos": utxos}

# =============================================================================
# ---------------------------- P2P Chat RPC -----------------------------------
# =============================================================================

    elif mtype == "CHAT_REGISTER":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        
        ip = client_ip()
        reg_key = f"chatreg:{ip}"
        if not self._tb_allow(self.rl_ip, reg_key, CFG.CHAT_REG_RL_IP_BURST, CFG.CHAT_REG_RL_WINDOW_S, CFG.CHAT_REG_RL_IP_BURST, backoff_key=reg_key):
            self._backoff(reg_key, CFG.CHAT_REG_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        addr_s   = (message.get("address")  or "").strip().lower()
        chat_pub = ((message.get("chat_pub") or message.get("pubkey") or "").strip().lower())

        presence_sig = (message.get("presence_sig") or "").strip().lower()
        if not presence_sig:
            return {"error": "presence_sig_required"}

        spend_pk = (message.get("spend_pub") or "").strip().lower()
        reg_sig  = (message.get("reg_sig")  or "")
        ts_val   = int(message.get("ts", 0))

        if not addr_s or not chat_pub or not spend_pk or not reg_sig or not ts_val:
            return {"error": "missing fields"}

        if not addr_s.startswith(CFG.ADDRESS_PREFIX):
            return {"error": "bad address format"}

        if not (len(chat_pub) == 64 and all(c in "0123456789abcdef" for c in chat_pub)):
            return {"error": "bad chat_pub"}

        if not (len(spend_pk) == 66 and all(c in "0123456789abcdef" for c in spend_pk)):
            return {"error": "bad spend_pub"}

        # Anti replay time window (±5 minutes)
        if abs(time.time() - ts_val) > 300:
            return {"error": "stale ts"}
        hrp, data = bech32_decode(addr_s)
        if hrp != CFG.ADDRESS_PREFIX or not data:
            return {"error": "bad address hrp"}
        witver = data[0]
        prog   = bytes(convertbits(data[1:], 5, 8, False))
        if witver != 0 or len(prog) != 20:
            return {"error": "address not p2wpkh"}
        if hash160(bytes.fromhex(spend_pk)) != prog:
            return {"error": "register proof mismatch"}
        
        pres_bytes = b"|".join([
            b"CHAT_PRESENCE",
            addr_s.encode(),
            bytes.fromhex(chat_pub),
            bytes.fromhex(spend_pk),
            str(ts_val).encode()
        ])
        reg_bytes = b"|".join([
            b"CHAT_REG",
            addr_s.encode(),
            bytes.fromhex(spend_pk),
            bytes.fromhex(chat_pub),
            str(int(ts_val)).encode()
        ])

        sig_check = _verify_chat_signatures([
            ("presence", spend_pk, pres_bytes, presence_sig),
            ("register", spend_pk, reg_bytes, reg_sig),
        ])
        if not sig_check.get("presence"):
            return {"error": "bad_presence_sig"}
        if not sig_check.get("register"):
            log.debug("[process_message] CHAT_REGISTER bad reg_sig from %s", addr)
            return {"error": "bad reg_sig"}

        now = time.time()
        pid = secrets.token_hex(16)
        with self.chat_lock:
            self.chat_spend_pub[addr_s] = spend_pk
            self.chat_presence_pub[addr_s] = chat_pub
            self.chat_presence_seen.add(pid)
            b = self.chat_prekeys.get(addr_s) or {}
            if "ik" not in b: 
                b["ik"] = chat_pub
                b["ts"] = int(now)
                self.chat_prekeys[addr_s] = b

        pres = {"pid": pid, "address": addr_s, "pubkey": chat_pub, "spend_pub": spend_pk, "presence_sig": presence_sig, "ts": int(now), "hops": 0}
        self._relay_presence_async(pres, exclude=addr)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_REGISTER] Benchmark : %.3f ms", result)
            
        return {"type": "CHAT_REGISTERED", "address": addr_s, "pubkey": chat_pub}

#----------------------#-------------------

    elif mtype == "CHAT_LOOKUP_PUB":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        addr_s = (message.get("address") or "").strip().lower()
        if not addr_s:
            return {"error": "missing address"}
        pubhex = self.chat_presence_pub.get(addr_s)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_LOOKUP_PUB] Benchmark : %.3f ms", result)
            
        return {"type": "CHAT_PUBKEY", "address": addr_s, "pubkey": pubhex, "found": bool(pubhex)}

#----------------------#-------------------

    elif mtype == "CHAT_PRESENCE":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        addr_s = (message.get("address") or "").strip().lower()
        pubhex = (message.get("pubkey")  or "").strip().lower()
        spend_pk = (message.get("spend_pub") or "").strip().lower()
        presence_sig = (message.get("presence_sig") or "").strip().lower()
        hops   = int(message.get("hops") or 0)
        ts_val = int(message.get("ts")   or 0)
        ip     = addr[0] if isinstance(addr, tuple) else "0.0.0.0"

        if abs(time.time() - ts_val) > CFG.PRESENCE_TTL_S:
            log.debug("[process_message] CHAT_PRESENCE stale ts from %s", addr)
            return {"error": "presence_stale"}

        # signature presence verification
        if not (pubhex and spend_pk and presence_sig):
            return {"error": "presence_missing_fields"}
        if not (len(pubhex) == 64 and all(c in "0123456789abcdef" for c in pubhex)):
            return {"error": "presence_bad_pub"}
        if not (len(spend_pk) == 66 and all(c in "0123456789abcdef" for c in spend_pk)):
            return {"error": "presence_bad_spend_pub"}
        hrp, data = bech32_decode(addr_s)
        if hrp != CFG.ADDRESS_PREFIX or not data:
            return {"error": "presence_bad_hrp"}
        prog = bytes(convertbits(data[1:], 5, 8, False))
        if len(prog) != 20:
            return {"error": "presence_bad_prog"}
        if hash160(bytes.fromhex(spend_pk)) != prog:
            return {"error": "presence_addr_mismatch"}
        
        pres_bytes = b"|".join([b"CHAT_PRESENCE", addr_s.encode(), bytes.fromhex(pubhex), bytes.fromhex(spend_pk), str(ts_val).encode()])
        sig_ok = _verify_chat_signatures([("presence", spend_pk, pres_bytes, presence_sig)])
        if not sig_ok.get("presence"):
            return {"error": "presence_bad_sig"}

        if hops >= CFG.PRESENCE_MAX_HOPS:
            log.debug("[process_message] CHAT_PRESENCE max hops from %s", addr)
            return {"error": "presence_hops"}

        if not self._tb_allow(self.rl_ip, ip, CFG.CHAT_RL_IP_BURST, CFG.CHAT_RL_IP_WINDOWS, CFG.CHAT_RL_IP_BURST, backoff_key=ip):
            self._backoff(ip, CFG.CHAT_BACKOFF_S); return {"error": "presence_rate_ip"}

        if not self._tb_allow(self.rl_addr, addr_s, CFG.PRESENCE_RL_ADDR_BURST, CFG.PRESENCE_RL_ADDR_WINDOWS, CFG.PRESENCE_RL_ADDR_BURST, backoff_key=addr_s):
            self._backoff(addr_s, CFG.CHAT_BACKOFF_S); return {"error": "presence_rate_addr"}

        pid = message.get("pid") or secrets.token_hex(16)
        with self.chat_lock:
            self.chat_presence_pub[addr_s] = pubhex
            self.chat_spend_pub[addr_s] = spend_pk
            self.chat_presence_seen.add(pid)
            b = self.chat_prekeys.get(addr_s) or {}
            if "ik" not in b:
                b["ik"] = pubhex
                b["ts"] = int(time.time())
                self.chat_prekeys[addr_s] = b

        message["hops"] = hops + 1
        self._relay_presence_async(message, exclude=addr)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_PRESENCE] Benchmark : %.3f ms", result)
        
        return {"type": "CHAT_PRESENCE_OK"}

    # ====== PREKEY BUNDLE ======
    
    elif mtype == "CHAT_PUBLISH_PREKEYS":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        ip = client_ip()
        reg_key = f"chatreg:{ip}"
        if not self._tb_allow(self.rl_ip, reg_key, CFG.CHAT_REG_RL_IP_BURST, CFG.CHAT_REG_RL_WINDOW_S, CFG.CHAT_REG_RL_IP_BURST, backoff_key=reg_key):
            self._backoff(reg_key, CFG.CHAT_REG_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        addr_s = (message.get("address") or "").strip().lower()
        ik  = (message.get("ik")  or "").strip().lower()
        spk = (message.get("spk") or "").strip().lower()
        sig = (message.get("sig") or "").strip().lower()
        opk = (message.get("opk") or None)
        if not addr_s or not ik or not spk or not sig:
            return {"error":"missing fields"}
        # validasi: addr -> spend_pub ada? dan signature SPK ditandatangani oleh spend key
        sp = (self.chat_spend_pub.get(addr_s) or "").strip().lower()
        if not sp: return {"error":"unknown_address"}
        payload = b"TSAR-SPK|" + bytes.fromhex(spk) + b"|" + bytes.fromhex(sp)
        sig_ok = _verify_chat_signatures([("spk", sp, payload, sig)])
        if not sig_ok.get("spk"):
            return {"error":"bad_spk_sig"}
        with self.chat_lock:
            rec = self.chat_prekeys.get(addr_s) or {}
            rec.update({"ik": ik, "spk": spk, "sig": sig, "ts": int(time.time())})
            if isinstance(opk, str) and len(opk)==64:
                rec.setdefault("opk_list", []).append(opk)
            self.chat_prekeys[addr_s] = rec
            
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_PUBLISH_PREKEYS] Benchmark : %.3f ms", result)
            
        return {"type":"CHAT_PUBLISH_PREKEYS"}

#----------------------#-------------------

    elif mtype == "CHAT_GET_PREKEY":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        addr_s = (message.get("address") or "").strip().lower()
        b = self.chat_prekeys.get(addr_s) or {}
        if not b or ("ik" not in b or "spk" not in b or "sig" not in b):
            return {"error":"no_bundle"}
        # consume satu OPK jika ada
        opk = None
        with self.chat_lock:
            lst = b.get("opk_list") or []
            if lst:
                opk = lst.pop(0)
            self.chat_prekeys[addr_s] = b
        sp = self.chat_spend_pub.get(addr_s)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_GET_PREKEY] Benchmark : %.3f ms", result)
        
        return {"type":"CHAT_PREKEY_BUNDLE","bundle":{"ik": b["ik"], "spk": b["spk"], "sig": b["sig"], "opk": opk, "spend_pub": sp}}

#----------------------#-------------------

    elif mtype == "CHAT_SEND":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"
        frm = (message.get("from") or "").strip().lower()
        to  = (message.get("to")   or "").strip().lower()
        enc = message.get("enc")
        mid = message.get("msg_id")
        ts  = int(message.get("ts") or 0)
        chat_sig = (message.get("chat_sig") or "").strip().lower()
        ratchet_pn = int(message.get("ratchet_pn") or 0)
        ratchet_n = int(message.get("ratchet_n") or 0)
        max_idx = CFG.CHAT_RATCHET_INDEX_MAX
        if not (0 <= ratchet_pn <= max_idx and 0 <= ratchet_n <= max_idx):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "ratchet_index_out_of_range"}

        if not self._tb_allow(self.rl_ip, ip, CFG.CHAT_RL_IP_BURST, CFG.CHAT_RL_IP_WINDOWS, CFG.CHAT_RL_IP_BURST, backoff_key=ip):
            self._backoff(ip, CFG.CHAT_BACKOFF_S)
            return {"type": "CHAT_ACK", "status": "rate_limited", "scope": "ip"}

        if not self._tb_allow(self.rl_addr, frm, CFG.CHAT_RL_ADDR_BURST, CFG.CHAT_RL_ADDR_WINDOWS, CFG.CHAT_RL_ADDR_BURST, backoff_key=frm):
            self._backoff(frm, CFG.CHAT_BACKOFF_S)
            return {"type": "CHAT_ACK", "status": "rate_limited", "scope": "address"}

        if not (frm and to and enc and (mid is not None) and ts):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_fields"}

        now = int(time.time())
        if abs(now - ts) > CFG.CHAT_TS_DRIFT_S:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "ts_drift"}

        if self._dedup_mid(frm, mid):
            return {"type": "CHAT_ACK", "status": "duplicate"}

        # ---- Encrypted only ----
        nonce_hex = str((enc or {}).get("nonce") or "")
        ct_hex    = str((enc or {}).get("ct")    or "")
        fp_hex    = (message.get("from_pub")    or "").strip().lower()     # eph X25519
        fs_hex = (message.get("from_static") or "").strip().lower()
        exp = self.chat_presence_pub.get(frm)

        if not exp:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "no_presence"}
        if fs_hex != exp:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_static"}

        if not (len(ct_hex) // 2 <= CFG.CHAT_MAX_CT_BYTES):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "too_large"}

        if not (len(nonce_hex) == 24 and all(c in "0123456789abcdef" for c in nonce_hex)):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_nonce"}

        if not (len(fp_hex) == 64 and all(c in "0123456789abcdef" for c in fp_hex)):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_pub"}

        if not (len(fs_hex) == 64 and all(c in "0123456789abcdef" for c in fs_hex)):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_static"}

        # routing authenticity signature verification (without decryption)
        if not chat_sig:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "sig_required"}
        sp = (self.chat_spend_pub.get(frm) or "").strip().lower()
        if not sp:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "no_spend_pub"}
        
        chat_bytes = b"|".join([
            b"CHAT_SEND",
            frm.encode(), to.encode(),
            str(mid).encode(), str(ts).encode(),
            bytes.fromhex(fp_hex), bytes.fromhex(fs_hex),
            str(ratchet_pn).encode(), str(ratchet_n).encode(),
            bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex)
        ])
        chat_verify = _verify_chat_signatures([("chat_send", sp, chat_bytes, chat_sig)])
        if not chat_verify.get("chat_send"):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_sig"}

        # === Onion-lite relay (opsional) ===
        relay_hops = int(CFG.CHAT_NUM_HOPS)
        if CFG.CHAT_FORCE_RELAY and len(self.peers) >= max(1, relay_hops):
            route = choose_relay_route(self, hops=relay_hops)
            if not route:
                log.debug("[process_message] CHAT_SEND relay requested but no peers available; falling back to direct queue")
            else:
                inner = {
                    "type": "CHAT_SEND_INNER",
                    "to": to,
                    "msg": {
                        "from": frm,
                        "msg_id": mid,
                        "ts": ts,
                        "from_static": fs_hex,
                        "from_pub": (message.get("from_pub") or "").strip().lower(),
                        "enc": {"nonce": enc.get("nonce"), "ct": enc.get("ct")},
                        "used_opk": message.get("used_opk"),
                        "ratchet_pn": ratchet_pn,
                        "ratchet_n": ratchet_n,
                    },
                }
                relay_chain(self, route, inner)
                return {"type": "CHAT_ACK", "status": "relayed", "hops": len(route)}

        ok = self._mailbox_put(to, {
            "type": "CHAT_ITEM",
            "from": frm,
            "to": to,
            "enc": {"nonce": enc.get("nonce"), "ct": enc.get("ct")},
            "from_pub": (message.get("from_pub") or "").strip().lower(),
            "from_static": fs_hex,
            "used_opk": message.get("used_opk"),
            "ratchet_pn": ratchet_pn,
            "ratchet_n": ratchet_n,
            "msg_id": mid,
            "ts": ts,
        }, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)

        if not ok:
            return {"type": "CHAT_ACK", "status": "mailbox_full"}
        self._enqueue_rcpt(frm, "delivered", mid, frm, to, ts)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_SEND] Benchmark : %.3f ms", result)
            
        return {"type": "CHAT_ACK", "status": "queued"}

#----------------------#-------------------

    elif mtype == "CHAT_PULL":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        me = (message.get("address") or "").strip().lower()
        if not me:
            return {"type": "CHAT_NONE", "items": [], "error": "bad_address"}
        n_raw = message.get("n", message.get("max", 20))
        n = int(n_raw)
        if n > CFG.CHAT_PULL_MAX_ITEMS:
            n = CFG.CHAT_PULL_MAX_ITEMS
        if n < 0:
            n = 0
        ts = int(message.get("ts", 0))
        pull_sig = (message.get("pull_sig") or "").strip().lower()

        now = int(time.time())
        if abs(now - ts) > CFG.CHAT_TS_DRIFT_S:
            return {"type": "CHAT_NONE", "items": [], "error": "ts_drift"}

        spend_pk = self.chat_spend_pub.get(me)
        if not spend_pk:
            return {"type": "CHAT_NONE", "items": [], "error": "not_registered"}

        msg_bytes = b"|".join([b"CHAT_PULL", me.encode(), str(ts).encode()])
        pull_check = _verify_chat_signatures([("pull", spend_pk, msg_bytes, pull_sig)])
        if not pull_check.get("pull"):
            return {"type": "CHAT_NONE", "items": [], "error": "bad_sig"}

        items = self._mailbox_pull(me, n)
        self._gc_mailboxes()
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_PULL] Benchmark : %.3f ms", result)
            
        return {"type": "CHAT_ITEMS", "items": items}

#----------------------#-------------------

    elif mtype == "CHAT_RELAY":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        # payload: {"route": [peer1, peer2, ...], "inner": {...}}
        route = list(message.get("route") or [])
        inner = message.get("inner") or {}
        if route:
            nxt = route.pop(0)
            return send_chat_relay(self, nxt, {"type": "CHAT_RELAY", "route": route, "inner": inner})
        # last hop: deliver inner ke mailbox
        if (inner or {}).get("type") == "CHAT_SEND_INNER":
            to  = (inner.get("to") or "").strip().lower()
            msg = inner.get("msg") or {}
            ok = self._mailbox_put(to, {
                "type": "CHAT_ITEM",
                "from": msg.get("from"),
                "to": to,
                "enc": msg.get("enc"),
                "from_pub": msg.get("from_pub"),
                "from_static": msg.get("from_static"),
                "used_opk": msg.get("used_opk"),
                "ratchet_pn": msg.get("ratchet_pn"),
                "ratchet_n": msg.get("ratchet_n"),
                "msg_id": msg.get("msg_id"),
                "ts": msg.get("ts"),
            }, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)
            
            if CFG.DEBUG_BENCHMARKS:
                end = time.perf_counter()
                result = round((end - start) * 1000.0, 3)
                log.debug("[CHAT_RELAY] Benchmark : %.3f ms", result)
                
            return {"type": "CHAT_RELAY_ACK", "status": ("queued" if ok else "rejected")}
        return {"error": "bad_inner"}

#----------------------#-------------------

    elif mtype == "CHAT_READ":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        sender = (message.get("sender") or "").strip().lower()
        reader = (message.get("reader") or "").strip().lower()
        mid    = message.get("msg_id")
        ts_val = int(message.get("ts") or 0)
        read_sig = (message.get("read_sig") or "").strip().lower()

        if not sender or not reader or mid is None or ts_val <= 0:
            return {"error": "bad_fields"}
        if not read_sig:
            return {"error": "sig_required"}
        ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"

        if not self._tb_allow(self.rl_ip, ip, 8, 10, 8, backoff_key=ip):
            return {"error": "rate_limited"}

        # read receipt verification
        sp = (self.chat_spend_pub.get(reader) or "").strip().lower()
        if not sp:
            return {"error": "no_spend_pub"}
        rr = b"|".join([
            b"CHAT_READ",
            sender.encode(), reader.encode(),
            str(mid).encode(), str(ts_val).encode()
        ])
        read_check = _verify_chat_signatures([("read", sp, rr, read_sig)])
        if not read_check.get("read"):
            return {"error": "bad_sig"}

        self._enqueue_rcpt(sender, "read", mid, sender, reader, int(time.time()))
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CHAT_READ] Benchmark : %.3f ms", result)
            
        return {"type": "CHAT_READ_OK"}

# =============================================================================
# ---------------------------- GRAFFITI RPC -----------------------------------
# =============================================================================

    elif mtype == "STOR_LIST":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        by_addr = {}
        for v in self.storage_peers.values():
            k = (v.get("address") or "").lower()
            old = by_addr.get(k)
            if not old:
                by_addr[k] = dict(v)
            else:
                cand = dict(v)
                if (old.get("port") or 0) == 0 and (cand.get("port") or 0) > 0:
                    by_addr[k] = cand
                elif int(cand.get("last_seen") or 0) > int(old.get("last_seen") or 0):
                    by_addr[k] = cand

        items = []
        with self.lock:
            for (ip, p), meta in (self.storage_peers or {}).items():
                if not isinstance(meta, dict): 
                    continue
                items.append({
                    "addr": meta.get("addr"),
                    "url": meta.get("url",""),
                    "ip": ip,
                    "port": int(meta.get("port",0)),
                    "last_seen": int(meta.get("last_seen",0)),
                    "alive": bool(meta.get("alive",False)),
                })
                
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[STOR_LIST] Benchmark : %.3f ms", result)
            
        return {"type":"STOR_LIST","storers": items}

#----------------------#-------------------

    elif mtype == "GRAFFITI_GET_PAYOUTS":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        art_id = str(message.get("art_id") or "").strip().lower()
        if not art_id:
            return {"type": "GRAFFITI_GET_PAYOUTS", "payouts": []}
        limit = int(message.get("limit", 100) or 100)
        limit = max(1, min(limit, 500))
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        payouts = reg.list_payouts(art_id, limit) if reg else []
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GRAFFITI_GET_PAYOUTS] Benchmark : %.3f ms", result)
            
        return {"type": "GRAFFITI_GET_PAYOUTS", "art_id": art_id, "payouts": payouts}

#----------------------#-------------------

    elif mtype == "CREATE_TX_MULTI":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        from_addr = (message.get("from") or "").strip().lower()
        outputs   = message.get("outputs") or []
        fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
        force_inputs = message.get("force_inputs") or None
        if not from_addr or not outputs:
            return {"error": "missing from/outputs"}
        
        tpl = self._handle_create_tx_multi(from_addr, outputs, fee_rate, force_inputs)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[CREATE_TX_MULTI] Benchmark : %.3f ms", result)
            
        return {"type": "TX_TEMPLATE", "data": tpl}

#----------------------#-------------------

    elif mtype == "GRAFFITI_GET_POSTS":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        limit = int(message.get("limit", 50) or 50)
        limit = max(1, min(limit, 500))
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        posts = reg.list_posts(limit) if reg else []
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GRAFFITI_GET_POSTS] Benchmark : %.3f ms", result)
            
        return {"type": "GRAFFITI_GET_POSTS", "posts": posts}

#----------------------#-------------------

    elif mtype == "GRAFFITI_GET_COMMENTS":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        art_id = str(message.get("art_id") or "").strip().lower()
        if not art_id:
            return {"type": "GRAFFITI_GET_COMMENTS", "comments": []}
        limit = int(message.get("limit", 100) or 100)
        limit = max(1, min(limit, 500))
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        comments = reg.list_comments(art_id, limit) if reg else []
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GRAFFITI_GET_COMMENTS] Benchmark : %.3f ms", result)
            
        return {"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id, "comments": comments}

#----------------------#-------------------

    elif mtype == "GRAFFITI_GET_ART":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        art_id_raw = str(message.get("art_id") or "").strip()
        if not art_id_raw:
            return {"type": "GRAFFITI_GET_ART", "error": "missing_art_id"}
        art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        post = reg.get_post(art_id) if reg else None
        if not post:
            return {"type": "GRAFFITI_GET_ART", "art_id": art_id, "error": "not_found"}
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GRAFFITI_GET_ART] Benchmark : %.3f ms", result)
            
        return {"type": "GRAFFITI_GET_ART", "art_id": art_id, "post": post}

    return None
