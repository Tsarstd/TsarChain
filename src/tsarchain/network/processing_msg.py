# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; libsecp256k1; Signal-X3DH; RFC7748-X25519

import time, secrets, base64, random
from typing import TYPE_CHECKING, Any, Optional
from bech32 import convertbits, bech32_decode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# ---------------- Local Project ----------------
from ..utils.helpers import hash160
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network(processing_msg)")


if TYPE_CHECKING:
    from .node import Network

__all__ = ["process_message"]


def process_message(self: "Network", message: dict[str, Any], addr: Optional[tuple]=None) -> dict | None:
    if not isinstance(message, dict):
        return {"error": "invalid message: expected JSON object"}

    mtype = message.get("type")
    if not isinstance(mtype, str):
        return {"error": "missing or invalid 'type'"}
    mtype = mtype.strip().upper()

    # ----------------------------------------------------------------------------------
    # GUARDIANS: role-based gate + limits
    # ----------------------------------------------------------------------------------
    MINERS = {"HELLO", "NEW_BLOCK", "GET_FULL_SYNC", "FULL_SYNC", "CHAIN", "MEMPOOL",
              "GET_HEADERS", "HEADERS", "GET_BLOCKS", "BLOCKS"}
    
    NODE_STORAGE = {"STOR_INIT", "STOR_PUT", "STOR_COMMIT", "STOR_STATUS", "STOR_GC", "STOR_PAID"}

    USER = {
        "PING", "GET_BALANCES", "CREATE_TX", "CREATE_TX_MULTI", "GET_INFO",
        "GET_TX_HISTORY", "GET_TX_DETAIL", "NEW_TX", "GET_UTXOS", "GET_PEERS",
        "GET_NETWORK_INFO", "GET_BLOCK_AT", "GET_BLOCK", "GET_BLOCK_HASH", "STOR_LIST",

        # Chat & storage listing
        "CHAT_REGISTER", "CHAT_LOOKUP_PUB", "CHAT_PRESENCE", "CHAT_SEND", "CHAT_PULL", "CHAT_RELAY", "CHAT_READ",
        "CHAT_GET_PREKEY", "CHAT_PUBLISH_PREKEYS",

        # Mempool utilities
        "GET_MEMPOOL",
    }

    def _is_miner_sender() -> bool:
        if not isinstance(addr, tuple):
            return False
        if addr in self.peers:
            return True
        try:
            peer_port = int(message.get("port", -1))
        except Exception:
            log.exception("[_is_miner_sender] bad port in message from %s", addr)
            peer_port = -1
        return (peer_port > 0) and ((addr[0], peer_port) in self.peers)

    BOOTSTRAP_ALLOW = {"HELLO", "GET_FULL_SYNC", "FULL_SYNC", "GET_HEADERS", "HEADERS"}
    if (mtype in MINERS) and (mtype not in BOOTSTRAP_ALLOW) and (not _is_miner_sender()):
        try:
            peer_port = int(message.get("port", -1))
            if peer_port > 0 and isinstance(addr, tuple):
                self.peers.add((addr[0], peer_port))
            else:
                return {"error": "forbidden: miners-only endpoint"}
        except Exception:
            return {"error": "forbidden: miners-only endpoint"}
    
    if (mtype not in MINERS) and (mtype not in USER) and (mtype not in NODE_STORAGE):
        return {"error": "unknown type"}

    # =============== NODE MESSAGES ===============
    if mtype == "HELLO":
        return self._handle_hello(message, addr)

    elif mtype == "NEW_BLOCK":
        self.broadcast.receive_block(message, addr, self.peers)
        return {"status": "ok"}

    elif mtype == "GET_FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"type": "SYNC_REDIRECT", "reason": "full_sync_disabled"}
        return self._handle_get_full_sync(message, addr)

    elif mtype == "GET_HEADERS":
        return self._handle_get_headers(message, addr)

    elif mtype == "GET_BLOCKS":
        return self._handle_get_blocks(message, addr)

    elif mtype in ("HEADERS", "BLOCKS"):
        return {"status": "ok"}

    elif mtype == "FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"status": "ignored", "reason": "full_sync_disabled"}
        return self._handle_full_sync(message, addr)

    elif mtype == "CHAIN":
        if self._validate_incoming_chain(message):
            return {"status": "ok"}

    elif mtype == "MEMPOOL":
        self.broadcast.receive_mempool(message)
        return {"status": "mempool received"}

    # =============== USER MESSAGES ===============

    elif mtype == "PING":
        return {"type": "PONG"}

    elif mtype in ("GET_BALANCES"):
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
        try:
            self.broadcast.utxodb._load()
        except Exception:
            log.exception("[process_message] UTXO DB load error")

        opmap = self._build_outpoint_map(chain, mem)
        items = {}
        for addr_str in addrs:
            b = self.broadcast.utxodb.get_balance(addr_str, mode="breakdown", current_height=tip_height)
            if not isinstance(b, dict):
                b = {"total": int(b or 0), "mature": int(b or 0), "immature": 0}
            pending_out = 0
            try:
                for tx in mem or []:
                    for tin in getattr(tx, "inputs", []) or []:
                        key = self._txin_prevkey(tin)
                        amt, owner = opmap.get(key, (0, ""))
                        if owner == addr_str and amt:
                            pending_out += int(amt)
            except Exception:
                log.exception("[process_message] pending_out calc error")
                pass

            spendable = max(0, int(b.get("mature", 0)) - int(pending_out or 0))
            items[addr_str] = {
                "balance": int(b.get("total", 0)),
                "spendable": spendable,
                "immature": int(b.get("immature", 0)),
                "pending_outgoing": int(pending_out or 0),
                "maturity": int(CFG.COINBASE_MATURITY),
            }
        return {"type": "BALANCES", "height": tip_height, "items": items}

    elif mtype == "CREATE_TX":
        from_addr = (message.get("from") or "").strip().lower()
        to_addr   = (message.get("to")   or "").strip().lower()
        amount    = message.get("amount")
        try:
            fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
        except Exception:
            fee_rate = CFG.DEFAULT_FEE_RATE_SATVB
        fee_rate = max(CFG.MIN_FEE_RATE_SATVB, min(fee_rate, CFG.MAX_FEE_RATE_SATVB))
        try:
            tpl = self._handle_create_tx(from_addr, to_addr, amount, fee_rate)
            return {"type": "TX_TEMPLATE", "data": tpl}
        except Exception:
            log.exception("[process_message] CREATE_TX error")

    elif mtype == "GET_INFO":
        info = {
            "type": "INFO",
            "height": self.broadcast.blockchain.height,
            "blocks": len(self.broadcast.blockchain.chain),
            "mempool": len(self.broadcast.mempool.get_all_txs()),
            "utxos": len(self.broadcast.utxodb.utxos),
        }
        try:
            with self.lock:
                peers_sane = [(ip,p) for (ip,p) in self.peers if isinstance(p,int) and p>0]
            info["peers"] = len(peers_sane)
        except Exception:
            log.exception("[process_message] GET_INFO peers count error")
            info["peers"] = 0
        if self.storage_service:
            idx = self.storage_service.index()
            files = idx.get("files", {}) if isinstance(idx, dict) else {}
            info["storage_address"] = self.storage_address
            info["storage_files"] = len(files)
            info["storage_bytes_used"] = int(idx.get("bytes_used", 0)) if isinstance(idx, dict) else 0
        else:
            info["storage_address"] = self.storage_address
            info["storage_files"] = 0
            info["storage_bytes_used"] = 0
        return info

    elif mtype == "GET_NETWORK_INFO":
        try:
            snap = self.broadcast.blockchain._compute_state_snapshot()
            try:
                with self.lock:
                    peers_sane = [(ip,p) for (ip,p) in self.peers if isinstance(p,int) and p>0]
                snap.setdefault("peers", {})
                if isinstance(snap["peers"], dict):
                    snap["peers"]["count"] = len(peers_sane)
                else:
                    snap["peers"] = {"count": len(peers_sane)}
            except Exception:
                log.exception("[process_message] GET_NETWORK_INFO peers count error")
            return {"type": "NETWORK_INFO", "data": snap}
        except Exception:
            log.exception("[process_message] GET_NETWORK_INFO error")
        
    elif mtype == "GET_BLOCK_AT":
        try:
            h = int(message.get("height"))
        except Exception:
            log.debug("[process_message] GET_BLOCK_AT invalid height from %s", addr)
        return self._handle_get_block_at(h)
    
    elif mtype == "GET_BLOCK_HASH":
        try:
            h = int(message.get("height"))
        except Exception:
            log.debug("[process_message] GET_BLOCK_HASH invalid height from %s", addr)
        return self._handle_get_block_hash(h)

    elif mtype == "GET_BLOCK":
        if "height" in message:
            try:
                return self._handle_get_block_at(int(message["height"]))
            except Exception:
                log.exception("[process_message] GET_BLOCK invalid height from %s", addr)
        hx = str(message.get("hash") or "").strip()
        if not hx:
            return {"type": "BLOCK", "error": "missing_height_or_hash"}
        return self._handle_get_block_by_hash(hx)

    elif mtype == "GET_PEERS":
        if not _is_miner_sender():
            return {"type": "PEERS", "peers": []}
        return {"type": "PEERS", "peers": list(self.peers)}

    elif mtype == "NEW_TX":
        success = self.broadcast.receive_tx(message, addr, self.peers)
        if success:
            txid = (message.get("data") or {}).get("txid")
            return {"status": "ok", "txid": txid}
        else:
            # Surface mempool reason if available for better UX
            reason = getattr(self.broadcast.mempool, 'last_error_reason', None)
            return {"status": "error", "reason": (reason or "invalid tx")}

    elif mtype == "GET_MEMPOOL":
        try:
            txs = self.broadcast.mempool.get_all_txs()
            return {"type": "MEMPOOL", "txs": [getattr(t, "txid", b"").hex() for t in txs]}
        except Exception:
            log.exception("[process_message] GET_MEMPOOL error")

    elif mtype == "GET_TX_HISTORY":
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
        return {"type": "TX_HISTORY", "address": addr_str, **history}

    elif mtype == "GET_TX_DETAIL":
        txid_hex = message.get("txid")
        if not txid_hex:
            return {"error": "missing txid"}
        return self._get_tx_detail(txid_hex)

    elif mtype == "GET_UTXOS":
        address = (message.get("address") or "").strip().lower()
        if not address:
            return {"error": "missing address"}
        
        if len(address) > CFG.MAX_UTXO_ADDR_LEN:
            return {"error": "address too long"}
        
        utxos = self.broadcast.utxodb.get(address)
        return {"type": "UTXOS", "address": address, "utxos": utxos}
    
    # ========= P2P CHAT =========
    
    elif mtype == "CHAT_REGISTER":
        addr_s   = (message.get("address")  or "").strip().lower()
        chat_pub = ((message.get("chat_pub") or message.get("pubkey") or "").strip().lower())
        
        presence_sig = (message.get("presence_sig") or "").strip().lower()
        if not presence_sig:
            return {"error": "presence_sig_required"}
        
        spend_pk = (message.get("spend_pub") or "").strip().lower()
        reg_sig  = (message.get("reg_sig")  or "")
        ts_val   = int(message.get("ts", 0))

        if not addr_s or not chat_pub or not spend_pk or not reg_sig or not ts_val:
            log.debug("[process_message] CHAT_REGISTER missing fields from %s", addr)
            return {"error": "missing fields"}
        
        if not addr_s.startswith(CFG.ADDRESS_PREFIX):
            log.debug("[process_message] CHAT_REGISTER bad address format from %s", addr)
            return {"error": "bad address format"}
        
        if not (len(chat_pub) == 64 and all(c in "0123456789abcdef" for c in chat_pub)):
            log.debug("[process_message] CHAT_REGISTER bad chat_pub from %s", addr)
            return {"error": "bad chat_pub"}
        
        if not (len(spend_pk) == 66 and all(c in "0123456789abcdef" for c in spend_pk)):
            log.debug("[process_message] CHAT_REGISTER bad spend_pub from %s", addr)
            return {"error": "bad spend_pub"}
        
        # Anti replay time window (±5 minutes)
        if abs(time.time() - ts_val) > 300:
            log.debug("[process_message] CHAT_REGISTER stale ts from %s", addr)
            return {"error": "stale ts"}
        try:
            hrp, data = bech32_decode(addr_s)
            if hrp != CFG.ADDRESS_PREFIX or not data:
                return {"error": "bad address hrp"}
            witver = data[0]
            prog   = bytes(convertbits(data[1:], 5, 8, False))
            if witver != 0 or len(prog) != 20:
                return {"error": "address not p2wpkh"}
            if hash160(bytes.fromhex(spend_pk)) != prog:
                return {"error": "register proof mismatch"}
        except Exception:
            log.exception("[process_message] CHAT_REGISTER addr decode failed from %s", addr)
            return {"error": "addr decode failed"}
        try:
            pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(spend_pk))
            # signature presence verification
            pres_bytes = b"|".join([
                b"CHAT_PRESENCE",
                addr_s.encode(),
                bytes.fromhex(chat_pub),
                bytes.fromhex(spend_pk),
                str(ts_val).encode()
            ])
            try:
                pub_obj.verify(bytes.fromhex(presence_sig), pres_bytes, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                return {"error": "bad_presence_sig"}
            except Exception:
                return {"error": "presence_sig_verify_failed"}
            
            reg_bytes = b"|".join([
                b"CHAT_REG",
                addr_s.encode(),
                bytes.fromhex(spend_pk),
                bytes.fromhex(chat_pub),
                str(int(ts_val)).encode()
            ])
            pub_obj.verify(bytes.fromhex(reg_sig), reg_bytes, ec.ECDSA(hashes.SHA256()))
            
        except Exception:
            log.exception("[process_message] CHAT_REGISTER bad reg_sig from %s", addr)
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
        try:
            self._relay_presence_async(pres, exclude=addr)
        except Exception:
            log.exception("[process_message] CHAT_REGISTER relay error from %s", addr)
            pass
        return {"type": "CHAT_REGISTERED", "address": addr_s, "pubkey": chat_pub}

    elif mtype == "CHAT_LOOKUP_PUB":
        addr_s = (message.get("address") or "").strip().lower()
        if not addr_s:
            return {"error": "missing address"}
        pubhex = self.chat_presence_pub.get(addr_s)
        log.debug("[process_message] CHAT_LOOKUP_PUB for %s from %s", addr_s, addr)
        return {"type": "CHAT_PUBKEY", "address": addr_s, "pubkey": pubhex, "found": bool(pubhex)}
    
    elif mtype == "CHAT_PRESENCE":
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
        try:
            hrp, data = bech32_decode(addr_s)
            if hrp != CFG.ADDRESS_PREFIX or not data:
                return {"error": "presence_bad_hrp"}
            prog = bytes(convertbits(data[1:], 5, 8, False))
            if len(prog) != 20:
                return {"error": "presence_bad_prog"}
            if hash160(bytes.fromhex(spend_pk)) != prog:
                return {"error": "presence_addr_mismatch"}
        except Exception:
            return {"error": "presence_addr_decode_failed"}
        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(spend_pk))
            pres_bytes = b"|".join([b"CHAT_PRESENCE", addr_s.encode(), bytes.fromhex(pubhex), bytes.fromhex(spend_pk), str(ts_val).encode()])
            vk.verify(bytes.fromhex(presence_sig), pres_bytes, ec.ECDSA(hashes.SHA256()))
        except Exception:
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
        try:
            self._relay_presence_async(message, exclude=addr)
        except Exception:
            log.exception("[process_message] CHAT_PRESENCE relay error from %s", addr)
            pass
        return {"type": "CHAT_PRESENCE_OK"}

    # ====== PREKEY BUNDLE ======
    elif mtype == "CHAT_PUBLISH_PREKEYS":
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
        try:
            pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(sp))
            payload = b"TSAR-SPK|" + bytes.fromhex(spk) + b"|" + bytes.fromhex(sp)
            pub_obj.verify(bytes.fromhex(sig), payload, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return {"error":"bad_spk_sig"}
        with self.chat_lock:
            rec = self.chat_prekeys.get(addr_s) or {}
            rec.update({"ik": ik, "spk": spk, "sig": sig, "ts": int(time.time())})
            if isinstance(opk, str) and len(opk)==64:
                rec.setdefault("opk_list", []).append(opk)
            self.chat_prekeys[addr_s] = rec
        return {"type":"CHAT_PUBLISHED"}

    elif mtype == "CHAT_GET_PREKEY":
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
        return {"type":"CHAT_PREKEY_BUNDLE","bundle":{"ik": b["ik"], "spk": b["spk"], "sig": b["sig"], "opk": opk, "spend_pub": sp}}

    elif mtype == "CHAT_SEND":
        ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"
        frm = (message.get("from") or "").strip().lower()
        to  = (message.get("to")   or "").strip().lower()
        enc = message.get("enc")
        mid = message.get("msg_id")
        ts  = int(message.get("ts") or 0)
        chat_sig = (message.get("chat_sig") or "").strip().lower()
        try:
            ratchet_pn = int(message.get("ratchet_pn") or 0)
            ratchet_n = int(message.get("ratchet_n") or 0)
        except Exception:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_ratchet_index"}
        max_idx = getattr(CFG, "CHAT_RATCHET_INDEX_MAX", 1_000_000)
        if not (0 <= ratchet_pn <= max_idx and 0 <= ratchet_n <= max_idx):
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "ratchet_index_out_of_range"}

        if not self._tb_allow(self.rl_ip, ip, CFG.CHAT_RL_IP_BURST, CFG.CHAT_RL_IP_WINDOWS, CFG.CHAT_RL_IP_BURST, backoff_key=ip):
            self._backoff(ip, CFG.CHAT_BACKOFF_S)
            return {"type": "CHAT_ACK", "status": "rate_limited", "scope": "ip"}
        
        if not self._tb_allow(self.rl_addr, frm, CFG.CHAT_RL_ADDR_BURST, CFG.CHAT_RL_ADDR_WINDOWS, CFG.CHAT_RL_ADDR_BURST, backoff_key=frm):
            self._backoff(frm, CFG.CHAT_BACKOFF_S)
            return {"type": "CHAT_ACK", "status": "rate_limited", "scope": "address"}

        if not (frm and to and enc and (mid is not None) and ts):
            log.debug("[process_message] CHAT_SEND reject bad_fields from %s -> %s mid=%s", frm, to, mid)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_fields"}

        now = int(time.time())
        if abs(now - ts) > CFG.CHAT_TS_DRIFT_S:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "ts_drift"}

        if self._dedup_mid(frm, mid):
            log.debug("[process_message] CHAT_SEND duplicate drop frm=%s mid=%s", frm, mid)
            return {"type": "CHAT_ACK", "status": "duplicate"}

        # ---- Encrypted only ----
        try:
            nonce_hex = str((enc or {}).get("nonce") or "")
            ct_hex    = str((enc or {}).get("ct")    or "")
            fp_hex    = (message.get("from_pub")    or "").strip().lower()     # eph X25519
            fs_hex = (message.get("from_static") or "").strip().lower()
            exp = self.chat_presence_pub.get(frm)
            
            if not exp:
                log.debug("[process_message] CHAT_SEND reject no_presence frm=%s mid=%s", frm, mid)
                return {"type": "CHAT_ACK", "status": "rejected", "reason": "no_presence"}
            if fs_hex != exp:
                log.debug("[process_message] CHAT_SEND reject bad_from_static frm=%s mid=%s exp=%s got=%s", frm, mid, exp[:12], fs_hex[:12])
                return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_static"}
            
        except Exception:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_enc"}

        if not (len(ct_hex) // 2 <= CFG.CHAT_MAX_CT_BYTES):
            log.debug("[process_message] CHAT_SEND reject too_large frm=%s mid=%s size=%d", frm, mid, len(ct_hex)//2)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "too_large"}
        
        if not (len(nonce_hex) == 24 and all(c in "0123456789abcdef" for c in nonce_hex)):
            log.debug("[process_message] CHAT_SEND reject bad_nonce frm=%s mid=%s", frm, mid)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_nonce"}
        
        if not (len(fp_hex) == 64 and all(c in "0123456789abcdef" for c in fp_hex)):
            log.debug("[process_message] CHAT_SEND reject bad_from_pub frm=%s mid=%s", frm, mid)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_pub"}
        
        if not (len(fs_hex) == 64 and all(c in "0123456789abcdef" for c in fs_hex)):
            log.debug("[process_message] CHAT_SEND reject bad_from_static_len frm=%s mid=%s", frm, mid)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_static"}
        
        # routing authenticity signature verification (without decryption)
        if not chat_sig:
            log.debug("[process_message] CHAT_SEND reject sig_required frm=%s mid=%s", frm, mid)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "sig_required"}
        sp = (self.chat_spend_pub.get(frm) or "").strip().lower()
        if not sp:
            log.debug("[process_message] CHAT_SEND reject no_spend_pub frm=%s mid=%s", frm, mid)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "no_spend_pub"}
        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(sp))
            chat_bytes = b"|".join([
                b"CHAT_SEND",
                frm.encode(), to.encode(),
                str(mid).encode(), str(ts).encode(),
                bytes.fromhex(fp_hex), bytes.fromhex(fs_hex),
                str(ratchet_pn).encode(), str(ratchet_n).encode(),
                bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex)
            ])
            vk.verify(bytes.fromhex(chat_sig), chat_bytes, ec.ECDSA(hashes.SHA256()))
        except Exception:
            log.debug("[process_message] CHAT_SEND reject bad_sig frm=%s mid=%s", frm, mid)
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_sig"}

        # === Onion-lite relay (opsional) ===
        relay_hops = int(getattr(CFG, "CHAT_NUM_HOPS", 2))
        if getattr(CFG, "CHAT_FORCE_RELAY", False) and len(self.peers) >= max(1, relay_hops):
            route = _choose_relay_route(self, hops=relay_hops)
            if not route:
                log.debug("[process_message] CHAT_SEND relay requested but no peers available; falling back to direct queue")
            else:
                log.debug("[process_message] CHAT_SEND relay route=%s used_opk=%s", route, "yes" if message.get("used_opk") else "no")
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
                _relay_chain(self, route, inner)
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
            log.debug("[process_message] CHAT_SEND reject mailbox_full frm=%s -> %s mid=%s", frm, to, mid)
            return {"type": "CHAT_ACK", "status": "mailbox_full"}
        try:
            self._enqueue_rcpt(frm, "delivered", mid, frm, to, ts)
        except Exception:
            log.exception("[process_message] CHAT_SEND enqueue_rcpt error from %s", addr)
            pass

        log.debug("[process_message] CHAT_SEND queued frm=%s -> %s mid=%s used_opk=%s", frm, to, mid, "yes" if message.get("used_opk") else "no")
        return {"type": "CHAT_ACK", "status": "queued"}

    elif mtype == "CHAT_PULL":
        me = (message.get("address") or "").strip().lower()
        if not me:
            return {"type": "CHAT_NONE", "items": [], "error": "bad_address"}
        n_raw = message.get("n", message.get("max", 20))
        try:
            n = int(n_raw)
        except Exception:
            n = 20
        if n > CFG.CHAT_PULL_MAX_ITEMS:
            n = CFG.CHAT_PULL_MAX_ITEMS
        if n < 0:
            n = 0
        try:
            ts = int(message.get("ts", 0))
        except Exception:
            ts = 0
        pull_sig = (message.get("pull_sig") or "").strip().lower()

        now = int(time.time())
        if abs(now - ts) > CFG.CHAT_TS_DRIFT_S:
            log.debug("[process_message] CHAT_PULL reject ts_drift addr=%s now=%s ts=%s", me, now, ts)
            return {"type": "CHAT_NONE", "items": [], "error": "ts_drift"}

        spend_pk = self.chat_spend_pub.get(me)
        if not spend_pk:
            return {"type": "CHAT_NONE", "items": [], "error": "not_registered"}

        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), bytes.fromhex(spend_pk))
            msg_bytes = b"|".join([b"CHAT_PULL", me.encode(), str(ts).encode()])
            vk.verify(bytes.fromhex(pull_sig), msg_bytes, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return {"type": "CHAT_NONE", "items": [], "error": "bad_sig"}

        items = self._mailbox_pull(me, n)
        self._gc_mailboxes()
        return {"type": "CHAT_ITEMS", "items": items}

    elif mtype == "CHAT_RELAY":
        # payload: {"route": [peer1, peer2, ...], "inner": {...}}
        route = list(message.get("route") or [])
        inner = message.get("inner") or {}
        if route:
            nxt = route.pop(0)
            return _send_chat_relay(self, nxt, {"type": "CHAT_RELAY", "route": route, "inner": inner})
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
            return {"type": "CHAT_RELAY_ACK", "status": ("queued" if ok else "rejected")}
        return {"error": "bad_inner"}
    
    elif mtype == "CHAT_READ":
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
        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(sp))
            rr = b"|".join([
                b"CHAT_READ",
                sender.encode(), reader.encode(),
                str(mid).encode(), str(ts_val).encode()
            ])
            vk.verify(bytes.fromhex(read_sig), rr, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return {"error": "bad_sig"}
        except Exception:
            return {"error": "sig_verify_failed"}
        
        try:
            self._enqueue_rcpt(sender, "read", mid, sender, reader, int(time.time()))
        except Exception:
            log.exception("[process_message] CHAT_READ enqueue_rcpt error from %s", addr)
            pass
        return {"type": "CHAT_READ_OK"}
    
    # -------------- [NEW] GRAFFITI ---------- #
        
    elif mtype == "STOR_LIST":
        now = time.time()
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
        return {"type":"STOR_LIST","storers": items}
        
    elif mtype == "CREATE_TX_MULTI":
        from_addr = (message.get("from") or "").strip().lower()
        outputs   = message.get("outputs") or []
        try:
            fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
        except Exception:
            log.debug("[process_message] CREATE_TX_MULTI bad fee_rate from %s", addr)
            fee_rate = CFG.DEFAULT_FEE_RATE_SATVB
        force_inputs = message.get("force_inputs") or None
        
        if not from_addr or not outputs:
            return {"error": "missing from/outputs"}
        try:
            tpl = self._handle_create_tx_multi(from_addr, outputs, fee_rate, force_inputs)
            return {"type": "TX_TEMPLATE", "data": tpl}
        except Exception:
            log.exception("[process_message] CREATE_TX_MULTI error from %s", addr)
            return {"error": "CREATE_TX_MULTI failed"}
        
        
    # =============== STORAGE RPC (ROLE: NODE_STORAGE) ===============

    elif mtype == "STOR_PUT":
        upid = message.get("upload_id")
        
        if "b64" in message or "chunk_index" in message:
            idx = int(message.get("chunk_index") or 0)
            b64 = message.get("b64") or ""
        else:
            hexdata = (message.get("data") or "")
            try:
                raw = bytes.fromhex(hexdata)
                b64 = base64.b64encode(raw).decode("ascii")
                idx = 0
            except Exception:
                log.exception("[process_message] STOR_PUT bad hex data from %s", addr)
                return {"type": "STOR_ACK", "status":"rejected", "reason":"bad_hex"}

        resp = self.storage_service.put_chunk(upid, int(idx), b64)
        return {"type":"STOR_ACK", **resp}

    elif mtype == "STOR_COMMIT":
        upid = message.get("upload_id")
        resp = self.storage_service.commit_upload(upid)
        return {"type":"STOR_ACK", **resp}

    elif mtype == "STOR_STATUS":
        gid = message.get("graffiti_id")
        resp = self.storage_service.status(gid)
        return {"type":"STOR_ACK", **resp}

    elif mtype == "STOR_INDEX":
        resp = self.storage_service.index()
        return {"type":"STOR_ACK", **resp}

    elif mtype == "STOR_GC":
        if not self.storage_service:
            return {"type":"STOR_ACK","status":"rejected","reason":"storage_disabled"}
        tip = int(message.get("tip_height") or 0)
        resp = self.storage_service.gc(tip)
        return {"type":"STOR_ACK", **resp}

    elif mtype == "STOR_PAID":
        gid  = message.get("graffiti_id")
        txid = message.get("txid")
        resp = self.storage_service.mark_paid(gid, txid)
        return {"type":"STOR_ACK", **resp}

    else:
        log.debug("[process_message] unknown type '%s' from %s", mtype, addr)
        return {"error": "Unknown message type"}
    
    # -------- helpers: relay ----------
def _choose_relay_route(self, hops: int = 2) -> list[tuple]:
    try:
        with self.lock:
            pool = list(self.peers)
        random.shuffle(pool)
        return pool[:max(1,hops)]
    except Exception:
        return []

def _relay_chain(self, route: list[tuple], inner: dict, src_addr=None):
    if not route:
        return
    first = route[0]
    payload = {"type":"CHAT_RELAY","route": route[1:], "inner": inner}
    self._send_chat_relay(first, payload)

def _send_chat_relay(self, peer: tuple, payload: dict):
    try:
        self._send_to_peer(peer, payload)
        return {"status":"ok"}
    except Exception:
        log.exception("[_send_chat_relay] send error to %s", peer)
        return {"status":"error"}
