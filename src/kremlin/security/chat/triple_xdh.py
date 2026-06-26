# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: libsecp256k1; Signal-X3DH; Signal-DoubleRatchet; RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM

import os
import time
import random
import hashlib
from typing import Callable, Optional, Dict, Any, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------- Local Project (With Node) ----------------
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import sign_digest_der_low_s_native

# ---------------- Local Project (Wallet Only) ----------------
from ..chat.chat_common import pack, unpack
from ..chat.double_ratchet import RatchetSession
from ..data_security import (Wallet,
    load_or_create_chat_dh_key,
    get_prekey_bundle_local,
    get_local_prekeys_for_recv,
    consume_opk_priv,
    ensure_signed_prekey,
    add_one_time_prekeys,
    get_prekey_inventory,
    rotate_signed_prekey,
    load_chat_session,
    store_chat_session,
    delete_chat_session,
)

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.chat_security")


class ChatManager:
    def __init__(self,
        rpc_send: Callable[[Dict[str, Any], Callable[[Optional[Dict[str, Any]]], None]], None],
        password_prompt_cb: Callable[[str], Optional[str]],
        key_ttl_sec: Optional[int] = None,):
        
        self.rpc_send = rpc_send
        self.password_prompt_cb = password_prompt_cb
        self.key_ttl_sec = int(key_ttl_sec if key_ttl_sec is not None else CFG.CHAT_KEY_TTL_SEC)

        # caches (exposed to the GUI when needed)
        self.priv_cache: Dict[str, tuple[str, float]] = {}
        self.pub_cache: Dict[str, str] = {}
        self.read_sent: set[int] = set()
        self._chat_dh_cache: Dict[str, tuple[str, str, float]] = {}
        self._pwd_cache: Dict[str, tuple[str, float]] = {}
        self._last_prekey_publish: Dict[str, float] = {}
        self._last_inventory_check: Dict[str, float] = {}
        self._prekey_bundle_cache: Dict[str, tuple[Dict[str, str], float]] = {}
        self._prekey_check_interval = max(float(CFG.CHAT_PUBLISH_MIN_INTERVAL_S or 0), 5.0)

        self._sessions: Dict[tuple[str, str], "RatchetSession"] = {}
        self._pending_used_opk: Dict[tuple[str, str], str] = {}
        self.on_partner_key_changed: Optional[Callable[[str, str, str], None]] = None
        self.on_partner_presence: Optional[Callable[[str, Optional[int]], None]] = None
        self.presence_ts: Dict[str, int] = {}
        os.makedirs(CFG.CHAT_SESSION_DIR, exist_ok=True)

    # ---------- key management ----------
    def _now(self) -> float:
        return time.time()
    
    def _pwd_cache_put(self, addr: str, pwd: str, ttl_sec: Optional[int] = None) -> None:
        ttl = ttl_sec if ttl_sec is not None else CFG.CHAT_PWD_CACHE_TTL_SEC
        self._pwd_cache[self._canon(addr)] = (pwd, self._now() + int(ttl))
        
    def _pwd_cache_get(self, addr: str) -> Optional[str]:
        rec = self._pwd_cache.get(self._canon(addr))
        return rec[0] if rec and self._now() < rec[1] else None
    
    def _pwd_provider_for(self, addr: str):
        a = self._canon(addr)
        def _provider(_prompt: str = "") -> Optional[str]:
            pwd = self._pwd_cache_get(a)
            if pwd:
                return pwd
            pwd = self.password_prompt_cb(a)
            if pwd: self._pwd_cache_put(a, pwd)
            return pwd
        return _provider

    def _ensure_prekey_inventory(self, addr: str, force: bool = False) -> None:
        now = self._now()
        if not force:
            last = self._last_inventory_check.get(addr)
            if last and now - last < self._prekey_check_interval:
                return
        self._last_inventory_check[addr] = now

        provider = self._pwd_provider_for(addr)
        inv = get_prekey_inventory(addr, provider)
        rotated = False
        rotate_after = CFG.CHAT_SPK_ROTATE_INTERVAL_S
        created = int(inv.get("created") or 0)
        if rotate_after and created and now - created >= rotate_after:
            rotate_signed_prekey(addr, provider)
            add_one_time_prekeys(addr, CFG.CHAT_OPK_REFILL_COUNT, provider)
            rotated = True
            self._prekey_bundle_cache.pop(addr, None)
            inv = get_prekey_inventory(addr, provider)
        if int(inv.get("opk_queue") or 0) < CFG.CHAT_OPK_MIN_THRESHOLD:
            add_one_time_prekeys(addr, CFG.CHAT_OPK_REFILL_COUNT, provider)
            self._prekey_bundle_cache.pop(addr, None)
        needs_publish = rotated or int(inv.get("opk_queue") or 0) < CFG.CHAT_OPK_MIN_THRESHOLD
        if needs_publish and self._can_publish_prekeys(addr):
            self.publish_prekeys(addr, on_done=lambda _resp: None, force_refresh_bundle=True)

    def _can_publish_prekeys(self, addr: str) -> bool:
        interval = float(CFG.CHAT_PUBLISH_MIN_INTERVAL_S or 0)
        if interval <= 0:
            return True
        last = self._last_prekey_publish.get(addr)
        if last is None:
            return True
        if self._now() - last >= interval:
            return True
        return False

    def _session_key(self, me: str, peer: str) -> Tuple[str, str]:
        return (self._canon(me), self._canon(peer))

    def _load_session_from_disk(self, me: str, peer: str) -> Optional["RatchetSession"]:
        provider = self._pwd_provider_for(me)
        data = load_chat_session(me, peer, provider)
        if not data:
            return None
        return RatchetSession.from_dict(data)

    def _persist_session(self, me: str, peer: str, sess: "RatchetSession") -> None:
        provider = self._pwd_provider_for(me)
        store_chat_session(me, peer, sess.to_dict(), provider)

    def _delete_session(self, me: str, peer: str) -> None:
        delete_chat_session(me, peer)

    def _get_session(self, me: str, peer: str) -> Optional["RatchetSession"]:
        key = self._session_key(me, peer)
        sess = self._sessions.get(key)
        if sess is not None:
            return sess
        sess = self._load_session_from_disk(me, peer)
        if sess is not None:
            self._sessions[key] = sess
        return sess
    
    def try_unlock(self, address: str) -> tuple[Optional[str], Optional[str]]:
        addr = self._canon(address)
        pwd = self.password_prompt_cb(addr)
        if pwd:
            self._pwd_cache_put(addr, pwd)
        if not pwd:
            return None, "cancelled"
        w = Wallet.unlock(pwd, addr)
        priv_hex = w["private_key"]
        self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
        self._pwd_cache_put(addr, pwd)
        return priv_hex, None

    def get_priv_for_chat(self, address: str) -> Optional[str]:
        addr = self._canon(address)
        cached = self.priv_cache.get(addr)
        if cached and self._now() < cached[1]:
            return cached[0]

        # try short-lived pwd cache first (avoid extra prompt)
        pwd = self._pwd_cache_get(addr)
        if not pwd:
            pwd = self._pwd_cache_get(addr) or self.password_prompt_cb(addr)
            
        if not pwd:
            return None
        w = Wallet.unlock(pwd, addr)
        priv_hex = w["private_key"]
        self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
        self._pwd_cache_put(addr, pwd)
        return priv_hex

    # ---------- pubkey directory ----------
    def lookup_pub(self, addr: str, cb: Callable[[Optional[str]], None]) -> None:
        a = self._canon(addr)
        if a in self.pub_cache:
            cb(self.pub_cache[a]); return

        def _on(resp: Optional[Dict[str, Any]]):
            pub = None
            last_seen = None
            if resp and resp.get("type") in ("CHAT_PUBKEY", "CHAT_PUB"):
                pub = resp.get("pubkey") or resp.get("chat_pub")
                ts_val = resp.get("last_seen")
                if isinstance(ts_val, (int, float)):
                    last_seen = int(ts_val)
                    self.presence_ts[a] = last_seen
                    if callable(self.on_partner_presence):
                        try:
                            self.on_partner_presence(a, last_seen)
                        except Exception:
                            log.exception("Unhandled exception")
            if pub:
                old = self.pub_cache.get(a)
                self.pub_cache[a] = pub
                if old and old != pub and callable(self.on_partner_key_changed):
                    self.on_partner_key_changed(a, old, pub)
            cb(pub)
        self.rpc_send({"type": "CHAT_LOOKUP_PUB", "address": a}, _on)

    def expected_pub_or_lookup(self, addr: str) -> Optional[str]:
        a = self._canon(addr)
        pub = self.pub_cache.get(a)
        if pub is None:
            self.lookup_pub(a, lambda _p: None)
        return pub

    # ---------- chat DH cache ----------
    def _get_chat_dh(self, address: str) -> tuple[str, str]:
        a = self._canon(address)
        now = self._now()
        cached = self._chat_dh_cache.get(a)
        if cached and now < cached[2]:
            return cached[0], cached[1]
        sk_hex, pk_hex = load_or_create_chat_dh_key(a, self._pwd_provider_for(a))
        self._chat_dh_cache[a] = (sk_hex, pk_hex, now + self.key_ttl_sec)
        return sk_hex, pk_hex

    # ---------- Session bootstrap (X3DH-like) + Double Ratchet ----------
    def ensure_session(self, me_addr: str, peer_addr: str, cb: Callable[[Optional[str]],None]) -> None:
        me = self._canon(me_addr)
        peer = self._canon(peer_addr)
        if self._get_session(me, peer):
            cb(None); return
            
        self._ensure_prekey_inventory(me)
        my_sk_hex, my_pk_hex = self._get_chat_dh(me)   # identity (IK)
        
        def _on_bundle(resp: Optional[Dict[str, Any]]):
            if not resp or resp.get("type") != "CHAT_PREKEY_BUNDLE":
                cb("no_bundle"); return
                
            b = resp.get("bundle") or {}
            rik = (b.get("ik") or "").lower()          # receiver identity
            spk = (b.get("spk") or "").lower()         # signed prekey
            opk = (b.get("opk") or "").lower()         # optional one-time
            spend_pub = (b.get("spend_pub") or "").lower()
            sig_hex = (b.get("sig") or "").lower()
            
            if not spend_pub:
                log.warning("[ensure_session] bundle missing spend_pub for %s", peer)
                cb("bundle_missing_spend_pub"); return
                
            if len(spend_pub) != 66 or any(c not in "0123456789abcdef" for c in spend_pub):
                log.warning("[ensure_session] spend_pub invalid format for %s", peer)
                cb("bundle_invalid_spend_pub"); return
                
            if not sig_hex:
                log.warning("[ensure_session] bundle missing SPK signature for %s", peer)
                cb("bundle_missing_spk_sig"); return
                
            try:
                vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(spend_pub))
                payload = b"TSAR-SPK|" + bytes.fromhex(spk) + b"|" + bytes.fromhex(spend_pub)
                vk.verify(bytes.fromhex(sig_hex), payload, ec.ECDSA(hashes.SHA256()))
                
            except Exception as e:
                log.exception("Unhandled exception")
                log.warning("[ensure_session] SPK signature verify failed for %s: %s", peer, e)
                cb("bundle_spk_verify_failed"); return
                
            # 2) X3DH derive
            eph = x25519.X25519PrivateKey.generate()
            eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            IKs = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_sk_hex))
            IKr = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(rik))
            SPKr= x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(spk))
            dh1 = IKs.exchange(SPKr)              # IKs × SPKr
            dh2 = eph.exchange(IKr)               # EPh × IKr
            dh3 = eph.exchange(SPKr)              # EPh × SPKr
            secret = dh1 + dh2 + dh3
            
            if opk:
                OPKr = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(opk))
                secret += IKs.exchange(OPKr)      # optional IKs x OPKr
                
            rk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tsar:x3dh:v1").derive(secret)
            sess = RatchetSession.init_as_initiator(
                root_key=rk,
                my_identity=my_pk_hex,
                their_identity=rik,
                my_ratchet_priv=eph,
                their_ratchet_pub_hex=spk,
                my_static_hex=my_pk_hex,
            )
            
            key = self._session_key(me, peer)
            self._sessions[key] = sess
            self._persist_session(me, peer, sess)

            if opk:
                self._pending_used_opk[key] = opk
            cb(None)
                
        self.rpc_send({"type":"CHAT_GET_PREKEY","address": peer}, _on_bundle)

    # ---------- SAS (safety words/emoji) ----------
    def sas(self, addr_a: str, addr_b: str) -> str:
        pa = (self.expected_pub_or_lookup(addr_a) or "").lower()
        pb = (self.expected_pub_or_lookup(addr_b) or "").lower()
        keys = sorted([pa, pb])
        data = ("SAS|" + keys[0] + "|" + keys[1]).encode()
        digest = hashlib.sha256(data).digest()
        emojis = ["🐙","🦊","🐼","🐧","🐯","🐸","🦁","🐵","🦄","🐺","🐤","🦉","🐢","🐬","🦒","🐳"]
        return "".join(emojis[digest[i] % len(emojis)] for i in range(6))

    # ---------- high-level ops: register / send / poll ----------
    def _canon(self, address: str) -> str:
        return (address or "").strip().lower()

    @staticmethod
    def _ec_priv_from_hex(h: str) -> ec.EllipticCurvePrivateKey:
        return ec.derive_private_key(int.from_bytes(bytes.fromhex(h), "big"), ec.SECP256K1())

    def pub_hex_from_priv(self, sk: ec.EllipticCurvePrivateKey) -> str:
        nums = sk.public_key().public_numbers()
        prefix = 0x02 | (nums.y & 1)
        return f"{prefix:02x}{nums.x:064x}"

    def sign(self, priv_hex: str, data: bytes) -> str:
        digest = hashlib.sha256(data).digest()
        sig = sign_digest_der_low_s_native(priv_hex, digest)
        return sig.hex()

    def register(self, address: str, on_done: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        
        addr = self._canon(address)
        priv_hex = self.get_priv_for_chat(addr)
        if not priv_hex:
            on_done({"error": "unlock_failed"}); return
            
        spend_pub = self.pub_hex_from_priv(self._ec_priv_from_hex(priv_hex))
        chat_sk_hex, chat_pk_hex = self._get_chat_dh(addr)
        ts_now = int(time.time())
        reg_bytes = b"|".join([
            b"CHAT_REG",
            addr.encode(),
            bytes.fromhex(spend_pub),
            bytes.fromhex(chat_pk_hex),
            str(ts_now).encode()
        ])
        reg_sig = self.sign(priv_hex, reg_bytes).lower()
        
        pres_bytes = b"|".join([
            b"CHAT_PRESENCE",
            addr.encode(),
            bytes.fromhex(chat_pk_hex),
            bytes.fromhex(spend_pub),
            str(ts_now).encode()
        ])
        presence_sig = self.sign(priv_hex, pres_bytes).lower()
        
        bundle = {}
        ensure_signed_prekey(addr, self._pwd_provider_for(addr))
        bundle = get_prekey_bundle_local(addr, self._pwd_provider_for(addr)) or {}
        spk_hex = (bundle.get("spk") or "").lower()
        if spk_hex:
            payload_spk = b"TSAR-SPK|" + bytes.fromhex(spk_hex) + b"|" + bytes.fromhex(spend_pub)
            bundle["sig"] = self.sign(priv_hex, payload_spk)

        def _on(resp: Optional[Dict[str, Any]]):
            if not resp:
                on_done(resp)
                return

            if resp.get("error"):
                err = str(resp.get("error"))
                rtype = resp.get("type")
                if err == "bad reg_sig":
                    log.warning("[register] reg_sig refuse for %s ", addr)
                elif err == "rate_limited":
                    log.warning("[register] rate limited for %s (type=%s)", addr, rtype)
                else:
                    log.warning("[register] failed for %s error=%s type=%s", addr, err, rtype)
                on_done(resp)
                return

            if resp.get("type") == "CHAT_REGISTERED":
                self.pub_cache[addr] = chat_pk_hex
                setattr(self, "_registered_addrs", getattr(self, "_registered_addrs", set()))
                self._registered_addrs.add(addr)
                self.publish_prekeys(addr, on_done=lambda _r: None)
            on_done(resp)

        payload = {
            "type": "CHAT_REGISTER",
            "address": addr,
            "spend_pub": spend_pub,
            "chat_pub": chat_pk_hex,
            "ts": ts_now,
            "reg_sig": reg_sig,
            "presence_sig": presence_sig,
        }
        if bundle:
            if bundle.get("spk") and bundle.get("sig"):
                payload["spk"] = (bundle.get("spk") or "").lower()
                payload["sig"] = (bundle.get("sig") or "").lower()
            if bundle.get("opk"):
                payload["opk"] = (bundle.get("opk") or "").lower()
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[register] Benchmark : %.3f ms", result)
            
        self.rpc_send(payload, _on)

    def _ensure_registered(self, addr: str, cb: Callable[[Optional[str]], None]) -> None:
        regset = getattr(self, "_registered_addrs", set())
        if addr in regset:
            cb(None); return
        
        def _on(resp):
            if resp and resp.get("type") == "CHAT_REGISTERED":
                rs = getattr(self, "_registered_addrs", set())
                rs.add(addr)
                self._registered_addrs = rs
                log.info("[register] registered ok untuk %s", addr)
                cb(None)
            else:
                if resp and resp.get("error"):
                    log.warning("[register] auto-register gagal untuk %s error=%s type=%s", addr, resp.get("error"), resp.get("type"))
                cb("register_failed")
                
        log.debug("[send_message] auto-register for %s", addr)
        self.register(addr, _on)

    def send_message(self, from_addr: str, to_addr: str, text: str,
                    on_queued, on_result) -> None:
        frm = self._canon(from_addr)
        to  = self._canon(to_addr)

        priv_hex = self.get_priv_for_chat(frm)
        if not priv_hex:
            on_result({"status": "unlock_failed"})
            return

        self._ensure_prekey_inventory(frm)

        def _do_send_after_session(err: Optional[str]):
            if err:
                on_result({"status": "sess_error", "reason": err})
                return
            sess = self._get_session(frm, to)
            if not sess:
                on_result({"status": "sess_missing"})
                return
            mid = random.randint(0, 2**31 - 1)
            ts = int(time.time())
            pt = pack(text)
            try:
                msg = sess.encrypt(pt, frm, to, mid, ts)
            except Exception as exc:
                log.exception("[send_message] encrypt failed for %s -> %s", frm, to)
                on_result({"status": "encrypt_failed", "reason": str(exc)})
                return

            header = msg.get("ratchet", {})
            eph_hex = (header.get("eph_pub") or "").lower()
            static_hex = (header.get("static_pub") or "").lower()
            pn_val = int(header.get("pn", 0))
            n_val = int(header.get("n", 0))

            try:
                sig_parts = [
                    b"CHAT_SEND",
                    frm.encode(), to.encode(),
                    str(mid).encode(), str(ts).encode(),
                    bytes.fromhex(eph_hex), bytes.fromhex(static_hex),
                    str(pn_val).encode(), str(n_val).encode(),
                    bytes.fromhex(msg["enc"]["nonce"]),
                    bytes.fromhex(msg["enc"]["ct"]),
                ]
            except Exception:
                log.exception("Unhandled exception")
                on_result({"status": "ratchet_header_invalid"})
                return

            chat_sig = self.sign(priv_hex, b"|".join(sig_parts)).lower()
            payload = {
                "type": "CHAT_SEND",
                "from": frm,
                "to": to,
                "msg_id": mid,
                "ts": ts,
                "from_static": static_hex,
                "from_pub": eph_hex,
                "ratchet_pn": pn_val,
                "ratchet_n": n_val,
                "enc": msg["enc"],
                "chat_sig": chat_sig,
            }

            key = self._session_key(frm, to)
            used = self._pending_used_opk.pop(key, None)
            if used:
                payload["used_opk"] = used

            self._persist_session(frm, to, sess)
            on_queued(mid, ts)

            def _wrapped(resp):
                r = dict(resp or {})
                r.setdefault("msg_id", mid)
                r.setdefault("to", to)
                r.setdefault("from", frm)
                on_result(r)

            self.rpc_send(payload, _wrapped)

        def _after_registered(err: Optional[str]):
            if err:
                on_result({"status": "register_failed", "reason": err})
                return
            sess = self._get_session(frm, to)
            if sess is None:
                self.ensure_session(frm, to, _do_send_after_session)
            else:
                _do_send_after_session(None)

        self._ensure_registered(frm, _after_registered)

    # -- New: publish prekeys (IK, SPK+sig, OPK) ke node
    def publish_prekeys(self, address: str, on_done=None, force_refresh_bundle: bool = False) -> None:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        
        addr = self._canon(address)
        if not self._can_publish_prekeys(addr):
            (on_done or (lambda _r: None))({"skipped": "cooldown"})
            return
        now = self._now()
        bundle: Optional[Dict[str, str]] = None

        if not force_refresh_bundle:
            cached = self._prekey_bundle_cache.get(addr)
            if cached and now - cached[1] < self._prekey_check_interval:
                bundle = cached[0]

        if bundle is None:
            ensure_signed_prekey(addr, self._pwd_provider_for(addr))
            bundle = get_prekey_bundle_local(addr, self._pwd_provider_for(addr))  # {"ik","spk","sig","opk"}
            self._prekey_bundle_cache[addr] = (bundle, now)

        priv_hex_for_sign = self.get_priv_for_chat(addr)
        if priv_hex_for_sign and bundle.get("spk"):
            spend_pub = self.pub_hex_from_priv(self._ec_priv_from_hex(priv_hex_for_sign))
            payload_spk = b"TSAR-SPK|" + bytes.fromhex(bundle["spk"]) + b"|" + bytes.fromhex(spend_pub)
            bundle["sig"] = self.sign(priv_hex_for_sign, payload_spk)

        payload = {
            "type": "CHAT_PUBLISH_PREKEYS",
            "address": addr,
            "ik":  (bundle.get("ik")  or "").lower(),
            "spk": (bundle.get("spk") or "").lower(),
            "sig": (bundle.get("sig") or "").lower(),
        }
        if bundle.get("opk"):
            payload["opk"] = (bundle["opk"] or "").lower()
        self._last_prekey_publish[addr] = now

        def _after(resp):
            try:
                if not resp or resp.get("error"):
                    self._last_prekey_publish.pop(addr, None)
                    self._prekey_bundle_cache.pop(addr, None)
            finally:
                (on_done or (lambda _r: None))(resp)
                
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[publish_prekeys] Benchmark : %.3f ms", result)
            
        self.rpc_send(payload, _after)
        
    # (Optional helper for UI) — signed read receipt
    def send_read_receipt(self, sender: str, reader: str, msg_id: int, on_result) -> None:
        priv_hex = self.get_priv_for_chat(reader)
        if not priv_hex:
            on_result({"error": "unlock_failed"})
            return
        ts = int(time.time())
        rr = b"|".join([b"CHAT_READ", sender.encode(), reader.encode(), str(msg_id).encode(), str(ts).encode()])
        read_sig = self.sign(priv_hex, rr).lower()
        self.rpc_send({"type": "CHAT_READ", "sender": sender, "reader": reader, "msg_id": int(msg_id), "ts": ts, "read_sig": read_sig}, on_result)

    def poll(self, address: str, n: int, on_items, on_done=None) -> None:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        me = self._canon(address)
        priv_hex = self.get_priv_for_chat(me)
        if not priv_hex:
            if on_done: on_done({"error": "unlock_failed"}); return
            return

        self._ensure_prekey_inventory(me)
        ts_now = int(time.time())
        pull_sig = self.sign(priv_hex, b"|".join([b"CHAT_PULL", me.encode(), str(ts_now).encode()]))

        def _on(resp):
            if resp and resp.get("type") == "CHAT_NONE" and str(resp.get("error")) == "not_registered":
                log.info("[poll] %s belum terdaftar, mencoba auto-register", me)
                return self._ensure_registered(me, lambda err: (
                    self.rpc_send({"type": "CHAT_PULL","address": me,"n": int(n),
                                   "ts": ts_now, "pull_sig": pull_sig}, _on) if not err else (on_done and on_done({"error":"register_failed"}))
            ))
            
            try:
                if not resp or resp.get("type") not in ("CHAT_ITEMS", "CHAT_NONE"):
                    on_items([])
                    if on_done: on_done(resp)
                    return

                items = resp.get("items") or []
                out = []
                my_sk_hex, _ = self._get_chat_dh(me)
                for it in items:
                    if (it.get("type") != "CHAT_ITEM"):
                        
                        if (it.get("type") == "CHAT_RCPT"):
                            out.append({
                                "type": "rcpt",
                                "rcpt": it.get("rcpt"),
                                "msg_id": it.get("msg_id"),
                                "from": it.get("from"),
                                "to": it.get("to"),
                                "ts": it.get("ts"),
                            })
                        continue

                    frm = (it.get("from") or "").lower()
                    from_pub = (it.get("from_pub") or "").lower()
                    from_static = (it.get("from_static") or "").lower()
                    used_opk = (it.get("used_opk") or "").lower()
                    mid = int(it.get("msg_id") or 0)
                    ts = int(it.get("ts") or 0)
                    enc = it.get("enc") or {}
                    pn_val = int(it.get("ratchet_pn") or 0)
                    n_val = int(it.get("ratchet_n") or 0)

                    header = {
                        "eph_pub": from_pub,
                        "static_pub": from_static,
                        "pn": pn_val,
                        "n": n_val,
                    }

                    sess = self._get_session(me, frm)
                    if not sess:
                        provider_me = self._pwd_provider_for(me)
                        pkinfo = get_local_prekeys_for_recv(me, provider_me)
                        spk_sk = (pkinfo.get("spk_sk") or "")
                        if not spk_sk:
                            raise ValueError("missing_spk_sk")
                        exp_static = self.expected_pub_or_lookup(frm)
                        if exp_static and exp_static != from_static:
                            log.warning("[poll] static pub mismatch for %s expected=%s got=%s", frm, exp_static, from_static)
                            if callable(self.on_partner_key_changed):
                                try:
                                    self.on_partner_key_changed(frm, exp_static, from_static)
                                except Exception:
                                    log.exception("Unhandled exception")
                            continue
                        
                        IKr = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_sk_hex))
                        SPKs = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(spk_sk))
                        IKs_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(from_static))
                        EPh_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(from_pub))
                        dh1 = SPKs.exchange(IKs_pub)
                        dh2 = IKr.exchange(EPh_pub)
                        dh3 = SPKs.exchange(EPh_pub)
                        secret = dh1 + dh2 + dh3
                        if used_opk:
                            opk_sk = consume_opk_priv(me, used_opk, provider_me)
                            if opk_sk:
                                OPKs = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(opk_sk))
                                secret += OPKs.exchange(IKs_pub)
                        rk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tsar:x3dh:v1").derive(secret)
                        _, my_pk_hex = self._get_chat_dh(me)
                        sess = RatchetSession.init_as_responder(
                            root_key=rk,
                            my_identity=my_pk_hex,
                            their_identity=from_static,
                            their_first_eph=from_pub,
                            my_ratchet_priv=SPKs,
                            my_static_hex=my_pk_hex,
                        )
                        key = self._session_key(me, frm)
                        self._sessions[key] = sess
                        self._persist_session(me, frm, sess)

                    msg_text = None
                    if sess:
                        pt = sess.decrypt(enc, frm, me, mid, ts, header)
                        if pt is not None:
                            msg_text = unpack(pt)
                        self._persist_session(me, frm, sess)

                    if msg_text is not None:
                        out.append({"type": "chat", "from": frm, "text": msg_text, "msg_id": mid, "ts": ts, "to": me})
                    else:
                        log.debug("[poll] decrypt failed for %s mid=%s", frm, mid)

                on_items(out)
                
            finally:
                if on_done: on_done(resp)
                
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[pool] Benchmark : %.3f ms", result)
            
        self.rpc_send({"type": "CHAT_PULL", "address": me, "n": int(n), "ts": ts_now, "pull_sig": pull_sig}, _on)