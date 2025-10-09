# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; libsecp256k1

import time, secrets, base64
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

def _mask_addr(s: str) -> str:
    s = (s or "").strip().lower()
    return s if len(s) < 14 else f"{s[:6]}…{s[-6:]}"

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
    MINERS = {"HELLO", "NEW_BLOCK", "GET_FULL_SYNC", "FULL_SYNC", "CHAIN", "MEMPOOL"}
    NODE_STORAGE = {"STOR_INIT", "STOR_PUT", "STOR_COMMIT", "STOR_STATUS", "STOR_GC", "STOR_PAID"}
    
    USER = {
        "PING", "GET_BALANCE", "GET_BALANCES", "CREATE_TX", "CREATE_TX_MULTI", "GET_INFO",
        "GET_TX_HISTORY", "GET_TX_DETAIL", "NEW_TX", "GET_UTXOS", "GET_PEERS",
        "GET_NETWORK_INFO", "GET_BLOCK_AT", "GET_BLOCK", "GET_BLOCK_HASH",
        
        # Chat & storage listing
        "CHAT_REGISTER", "CHAT_LOOKUP_PUB", "CHAT_PRESENCE", "CHAT_SEND", "CHAT_PULL", "CHAT_RELAY", "CHAT_READ",
        "STOR_LIST",
        
        # Mempool utilities
        "MEMPOOL_PRUNE", "GET_MEMPOOL",
    }
    # ----------------------------------------------------------------------------------
    # ----------------------------------------------------------------------------------
    
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

    BOOTSTRAP_ALLOW = {"HELLO", "GET_FULL_SYNC", "FULL_SYNC"}
    if (mtype in MINERS) and (mtype not in BOOTSTRAP_ALLOW) and (not _is_miner_sender()):
        return {"error": "forbidden: miners-only endpoint"}
    
    if (mtype not in MINERS) and (mtype not in USER) and (mtype not in NODE_STORAGE):
        return {"error": "unknown type"}

    # =============== NODE MESSAGES ===============
    if mtype == "HELLO":
        log.debug("[process_message] HELLO from %s", addr)
        return self._handle_hello(message, addr)

    elif mtype == "NEW_BLOCK":
        self.broadcast.receive_block(message, addr, self.peers)
        log.debug("[process_message] NEW_BLOCK processed from %s", addr)
        return {"status": "ok"}

    elif mtype == "GET_FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"type": "SYNC_REDIRECT", "reason": "full_sync_disabled"}
        log.debug("[process_message] GET_FULL_SYNC from %s", addr)
        return self._handle_get_full_sync(message, addr)

    elif mtype == "FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"status": "ignored", "reason": "full_sync_disabled"}
        log.debug("[process_message] FULL_SYNC from %s", addr)
        return self._handle_full_sync(message, addr)

    elif mtype == "CHAIN":
        if self._validate_incoming_chain(message):
            log.debug("[process_message] CHAIN accepted from %s", addr)
        return {"status": "ok"}

    elif mtype == "MEMPOOL":
        self.broadcast.receive_mempool(message)
        log.debug("[process_message] MEMPOOL processed from %s", addr)
        return {"status": "mempool received"}

    # =============== USER MESSAGES ===============

    elif mtype == "PING":
        log.trace("[process_message] PING from %s", addr)
        return {"type": "PONG"}

    elif mtype in ("GET_BALANCE", "GET_BALANCES"):
        addrs_raw = message.get("addresses") or []
        if not addrs_raw and message.get("address"):
            addrs_raw = [message["address"]]
        if not isinstance(addrs_raw, list) or not addrs_raw:
            return {"error": "missing addresses"}
        if len(addrs_raw) > CFG.MAX_ADDRS_PER_REQ:
            return {"error": "too many addresses (max %d)" % CFG.MAX_ADDRS_PER_REQ}
        
        log.debug("[process_message] %s from %s", mtype, addr)
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

    elif mtype == "MEMPOOL_PRUNE":
        try:
            # remove any mempool tx already mined in chain
            in_chain = set()
            for b in self.broadcast.blockchain.chain:
                for t in getattr(b, "transactions", []) or []:
                    try:
                        if getattr(t, "txid", None):
                            in_chain.add(t.txid.hex())
                    except Exception:
                        pass
            cur = self.broadcast.mempool.load_pool()
            kept = []
            removed = []
            for item in cur:
                try:
                    if isinstance(item, dict):
                        tid = item.get("txid")
                    else:
                        tid = getattr(item, "txid", b"").hex()
                except Exception:
                    tid = None
                if tid and tid in in_chain:
                    removed.append(tid)
                    continue
                kept.append(item)
            self.broadcast.mempool.save_pool(kept)
        except Exception:
            log.exception("[process_message] MEMPOOL_PRUNE error")

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
        log.debug("[process_message] GET_TX_HISTORY for %s from %s", _mask_addr(addr_str), addr)
        return {"type": "TX_HISTORY", "address": addr_str, **history}

    elif mtype == "GET_TX_DETAIL":
        txid_hex = message.get("txid")
        if not txid_hex:
            log.debug("[process_message] GET_TX_DETAIL missing txid from %s", addr)
            return {"error": "missing txid"}
        return self._get_tx_detail(txid_hex)

    elif mtype == "GET_UTXOS":
        address = (message.get("address") or "").strip().lower()
        if not address:
            return {"error": "missing address"}
        
        if len(address) > CFG.MAX_UTXO_ADDR_LEN:
            return {"error": "address too long"}
        
        utxos = self.broadcast.utxodb.get(address)
        log.debug("[process_message] GET_UTXOS for %s from %s", _mask_addr(address), addr)
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

        message["hops"] = hops + 1
        try:
            self._relay_presence_async(message, exclude=addr)
        except Exception:
            log.exception("[process_message] CHAT_PRESENCE relay error from %s", addr)
            pass
        return {"type": "CHAT_PRESENCE_OK"}


    elif mtype == "CHAT_SEND":
        ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"
        frm = (message.get("from") or "").strip().lower()
        to  = (message.get("to")   or "").strip().lower()
        enc = message.get("enc")
        mid = message.get("msg_id")
        ts  = int(message.get("ts") or 0)
        chat_sig = (message.get("chat_sig") or "").strip().lower()

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
        try:
            nonce_hex = str((enc or {}).get("nonce") or "")
            ct_hex    = str((enc or {}).get("ct")    or "")
            fp_hex    = (message.get("from_pub")    or "").strip().lower()     # eph X25519
            fs_hex = (message.get("from_static") or "").strip().lower()
            exp = self.chat_presence_pub.get(frm)
            if not exp or fs_hex != exp:
                return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_static"}     # static X25519
        except Exception:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_enc"}

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
        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(sp))
            chat_bytes = b"|".join([
                b"CHAT_SEND",
                frm.encode(), to.encode(),
                str(mid).encode(), str(ts).encode(),
                bytes.fromhex(fp_hex), bytes.fromhex(fs_hex),
                bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex)
            ])
            vk.verify(bytes.fromhex(chat_sig), chat_bytes, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_sig"}

        ok = self._mailbox_put(to, {
            "type": "CHAT_ITEM",
            "from": frm,
            "to": to,
            "enc": {"nonce": enc.get("nonce"), "ct": enc.get("ct")},
            "from_pub": (message.get("from_pub") or "").strip().lower(),
            "from_static": fs_hex,
            "msg_id": mid,
            "ts": ts,
        }, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)
        
        if not ok:
            return {"type": "CHAT_ACK", "status": "mailbox_full"}
        try:
            self._enqueue_rcpt(frm, "delivered", mid, frm, to, ts)
        except Exception:
            log.exception("[process_message] CHAT_SEND enqueue_rcpt error from %s", addr)
            pass

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
        data    = message.get("data") or {}
        msg_id  = data.get("msg_id")
        to_addr = (data.get("to") or "").strip().lower()
        
        if not msg_id or not to_addr:
            return {"status": "ignored"}
        with self.chat_lock:
            if not self._chat_seen_add_locked(msg_id):
                return {"status": "dup"}
            self._chat_enqueue_locked(to_addr, data)
            
        self._relay_chat_async(data, exclude=addr)
        return {"status": "ok"}
    
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