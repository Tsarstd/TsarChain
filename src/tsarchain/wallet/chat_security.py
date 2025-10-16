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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

# ---------------- Local Project (With Node) ----------------
from ..utils import config as CFG

# ---------------- Local Project (Wallet Only) ----------------
from .data_security import (Wallet,
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
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet(chat_security)")


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

        self._sessions: Dict[tuple[str, str], "RatchetSession"] = {}
        self._pending_used_opk: Dict[tuple[str, str], str] = {}
        self.on_partner_key_changed: Optional[Callable[[str, str, str], None]] = None

        try:
            os.makedirs(CFG.CHAT_SESSION_DIR, exist_ok=True)
        except Exception:
            log.debug("unable to ensure chat session directory exists", exc_info=True)

    # ---------- helpers: EC (secp for register), X25519 for chat ----------
    def _pack(self, s: str, bucket_sizes=(128, 256, 512, 1024)) -> bytes:
        b = s.encode("utf-8")
        L = len(b)
        target = next((k for k in bucket_sizes if L + 2 <= k), L + 2)
        pad = os.urandom(max(0, target - (L + 2)))
        return len(b).to_bytes(2, "big") + b + pad

    def _unpack(self, pt: bytes) -> str:
        if len(pt) < 2:
            return ""
        L = int.from_bytes(pt[:2], "big")
        raw = pt[2:2+L]
        try:
            return raw.decode("utf-8", "ignore")
        except Exception:
            return ""

    @staticmethod
    def _aad_bytes(frm: str, to: str, mid: int, ts: int,
                from_static_hex: str, from_pub_hex: str,
                pn: Optional[int] = None, n: Optional[int] = None) -> bytes:
        parts = [
            b"TSAR-AAD1",
            frm.encode(), to.encode(),
            str(int(mid)).encode(), str(int(ts)).encode(),
            bytes.fromhex(from_static_hex),
            bytes.fromhex(from_pub_hex),
        ]
        if pn is not None:
            parts.append(str(int(pn)).encode())
        if n is not None:
            parts.append(str(int(n)).encode())
        return b"|".join(parts)
        
    @staticmethod
    def _hkdf_sha256(secret: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)

    @staticmethod
    def _x_priv_from_hex(h: str) -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(h))

    @staticmethod
    def _x_pub_from_hex(h: str) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(h))

    def _chat_encrypt_for(self, my_static_sk_hex: str, recipient_dh_pub_hex: str, padded_pt: bytes, aad_fields: dict) -> tuple[dict, str]:
        rec_pk = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_dh_pub_hex))
        eph_sk = x25519.X25519PrivateKey.generate()
        eph_pub_hex = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        my_sk = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_static_sk_hex))
        
        dh1 = eph_sk.exchange(rec_pk)
        dh2 = my_sk.exchange(rec_pk)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tsar:chat:v2").derive(dh1 + dh2)
        
        nonce = os.urandom(12)
        aad = self._aad_bytes(aad_fields["frm"], aad_fields["to"], aad_fields["mid"], aad_fields["ts"], aad_fields["from_static"], eph_pub_hex)
        ct = AESGCM(key).encrypt(nonce, padded_pt, aad)
        return {"nonce": nonce.hex(), "ct": ct.hex()}, eph_pub_hex

    def _chat_decrypt_with(self, my_dh_sk_hex: str, sender_eph_pub_hex: str, sender_static_pub_hex: str, enc: dict, aad: bytes) -> str | None:
        try:
            my_sk  = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_dh_sk_hex))
            e_pub  = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(sender_eph_pub_hex))
            s_pub  = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(sender_static_pub_hex))
            
            dh1 = my_sk.exchange(e_pub)
            dh2 = my_sk.exchange(s_pub)
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tsar:chat:v2").derive(dh1 + dh2)
            
            nonce = bytes.fromhex(enc.get("nonce") or "")
            ct    = bytes.fromhex(enc.get("ct") or "")
            pt = AESGCM(key).decrypt(nonce, ct, aad)
            return self._unpack(pt)
        except Exception:
            return None

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

    def _ensure_prekey_inventory(self, addr: str) -> None:
        provider = self._pwd_provider_for(addr)
        try:
            inv = get_prekey_inventory(addr, provider)
        except Exception:
            log.exception("[_ensure_prekey_inventory] inventory read failed for %s", addr)
            return
        now = self._now()
        rotated = False
        rotate_after = getattr(CFG, "CHAT_SPK_ROTATE_INTERVAL_S", 0)
        created = int(inv.get("created") or 0)
        if rotate_after and created and now - created >= rotate_after:
            try:
                rotate_signed_prekey(addr, provider)
                add_one_time_prekeys(addr, CFG.CHAT_OPK_REFILL_COUNT, provider)
                rotated = True
                inv = get_prekey_inventory(addr, provider)
            except Exception:
                log.exception("[_ensure_prekey_inventory] rotate signed prekey failed for %s", addr)
        if int(inv.get("opk_queue") or 0) < CFG.CHAT_OPK_MIN_THRESHOLD:
            try:
                add_one_time_prekeys(addr, CFG.CHAT_OPK_REFILL_COUNT, provider)
            except Exception:
                log.exception("[_ensure_prekey_inventory] refill OPK failed for %s", addr)
        needs_publish = rotated or int(inv.get("opk_queue") or 0) < CFG.CHAT_OPK_MIN_THRESHOLD
        if needs_publish and self._can_publish_prekeys(addr):
            try:
                self.publish_prekeys(addr, on_done=lambda _resp: None)
            except Exception:
                log.debug("[_ensure_prekey_inventory] publish_prekeys defer for %s", addr, exc_info=True)

    def _can_publish_prekeys(self, addr: str) -> bool:
        try:
            interval = float(getattr(CFG, "CHAT_PUBLISH_MIN_INTERVAL_S", 0) or 0)
        except Exception:
            interval = 0.0
        if interval <= 0:
            return True
        last = self._last_prekey_publish.get(addr)
        if last is None:
            return True
        if self._now() - last >= interval:
            return True
        log.debug("[_can_publish_prekeys] skip publish for %s (cooldown active)", addr)
        return False

    def _session_key(self, me: str, peer: str) -> Tuple[str, str]:
        return (self._canon(me), self._canon(peer))

    def _session_path(self, me: str, peer: str) -> str:
        return os.path.join(CFG.CHAT_SESSION_DIR, self._canon(me) or "_", f"{self._canon(peer) or '_'}")

    def _load_session_from_disk(self, me: str, peer: str) -> Optional["RatchetSession"]:
        provider = self._pwd_provider_for(me)
        try:
            data = load_chat_session(me, peer, provider)
        except Exception:
            log.exception("[_load_session_from_disk] failed loading chat session %s -> %s", me, peer)
            return None
        if not data:
            return None
        try:
            return RatchetSession.from_dict(data)
        except Exception:
            log.exception("[_load_session_from_disk] failed decoding chat session %s -> %s", me, peer)
            return None

    def _persist_session(self, me: str, peer: str, sess: "RatchetSession") -> None:
        provider = self._pwd_provider_for(me)
        try:
            store_chat_session(me, peer, sess.to_dict(), provider)
        except Exception:
            log.exception("[_persist_session] failed persisting chat session %s -> %s", me, peer)

    def _delete_session(self, me: str, peer: str) -> None:
        try:
            delete_chat_session(me, peer)
        except Exception:
            log.exception("[_delete_session] failed deleting chat session %s -> %s", me, peer)

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
            try: self._pwd_cache_put(addr, pwd)
            except Exception:
                pass
        if not pwd:
            return None, "cancelled"
        try:
            w = Wallet.unlock(pwd, addr)
            priv_hex = w["private_key"]
            self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
            self._pwd_cache_put(addr, pwd)
            return priv_hex, None
        except Exception as e:
            return None, str(e)

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
        try:
            w = Wallet.unlock(pwd, addr)
            priv_hex = w["private_key"]
            self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
            self._pwd_cache_put(addr, pwd)
            try:
                self._pwd_cache_put(addr, pwd)
            except Exception:
                pass
            return priv_hex
        except Exception:
            return None

    # ---------- pubkey directory ----------
    def lookup_pub(self, addr: str, cb: Callable[[Optional[str]], None]) -> None:
        a = self._canon(addr)
        if a in self.pub_cache:
            cb(self.pub_cache[a]); return

        def _on(resp: Optional[Dict[str, Any]]):
            pub = None
            if resp and resp.get("type") in ("CHAT_PUBKEY", "CHAT_PUB"):
                pub = resp.get("pubkey") or resp.get("chat_pub")
            if pub:
                old = self.pub_cache.get(a)
                self.pub_cache[a] = pub
                if old and old != pub and callable(self.on_partner_key_changed):
                    try: self.on_partner_key_changed(a, old, pub)
                    except Exception:
                        pass
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
    
    # ---------- Safety Number (60 digit) ----------
    def safety_number(self, addr_a: str, addr_b: str) -> str:
        pa = (self.expected_pub_or_lookup(addr_a) or "").lower()
        pb = (self.expected_pub_or_lookup(addr_b) or "").lower()
        keys = "|".join(sorted([pa, pb])).encode()
        h = hashlib.sha256(b"TSAR-SAFETY|"+keys).digest()
        # 60-digit decimal fingerprint
        n = int.from_bytes(h, "big") % (10**60)
        return f"{n:060d}"

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
            log.debug("[ensure_session] bundle keys=%s", list(b.keys()))
            
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
                log.warning("[ensure_session] SPK signature verify failed for %s: %s", peer, e)
                cb("bundle_spk_verify_failed"); return
                
            # 2) X3DH derive
            try:
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
                log.debug("[ensure_session] init_as_initiator OK (peer=%s) eph=%s bound as first ratchet key", peer, eph_pub[:12])

                key = self._session_key(me, peer)
                self._sessions[key] = sess
                self._persist_session(me, peer, sess)

                if opk:
                    self._pending_used_opk[key] = opk
                cb(None)
                
            except Exception as e:
                cb(f"x3dh_error:{e}")
                
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
        try:
            return (address or "").strip().lower()
        except Exception:
            return ""

    @staticmethod
    def _ec_priv_from_hex(h: str) -> ec.EllipticCurvePrivateKey:
        return ec.derive_private_key(int.from_bytes(bytes.fromhex(h), "big"), ec.SECP256K1())

    def pub_hex_from_priv(self, sk: ec.EllipticCurvePrivateKey) -> str:
        nums = sk.public_key().public_numbers()
        prefix = 0x02 | (nums.y & 1)
        return f"{prefix:02x}{nums.x:064x}"

    def sign(self, priv_hex: str, data: bytes) -> str:
        sk = self._ec_priv_from_hex(priv_hex)
        sig = sk.sign(data, ec.ECDSA(hashes.SHA256()))
        return sig.hex()

    def register(self, address: str, on_done: Callable[[Optional[Dict[str, Any]]], None]) -> None:
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

        def _on(resp: Optional[Dict[str, Any]]):
            if resp and resp.get("type") == "CHAT_REGISTERED":
                self.pub_cache[addr] = chat_pk_hex
                try:
                    setattr(self, "_registered_addrs", getattr(self, "_registered_addrs", set()))
                    self._registered_addrs.add(addr)
                    log.debug("[register] registered ok for %s (pub=%s…)", addr, chat_pk_hex[:12])
                except Exception:
                    pass
                try:
                    self.publish_prekeys(addr, on_done=lambda _r: None)
                except Exception as e:
                    log.warning("[register] auto publish_prekeys failed: %s", e)
                    
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
        self.rpc_send(payload, _on)

    def _ensure_registered(self, addr: str, cb: Callable[[Optional[str]], None]) -> None:
        try:
            regset = getattr(self, "_registered_addrs", set())
            if addr in regset:
                cb(None); return
        except Exception:
            pass
        
        def _on(resp):
            if resp and resp.get("type") == "CHAT_REGISTERED":
                try:
                    rs = getattr(self, "_registered_addrs", set())
                    rs.add(addr)
                    self._registered_addrs = rs
                    log.debug("[register] registered ok for %s", addr)
                except Exception:
                    pass
                cb(None)
            else:
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
            pt = self._pack(text)
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

            log.debug("[send_message] %s -> %s mid=%d eph=%s static=%s pn=%d n=%d", frm, to, mid, eph_hex[:12], static_hex[:12], pn_val, n_val)

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

            try:
                on_queued(mid, ts)
            except Exception:
                pass

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
    def publish_prekeys(self, address: str, on_done=None) -> None:
        addr = self._canon(address)
        if not self._can_publish_prekeys(addr):
            log.debug("[publish_prekeys] skip publish for %s (cooldown)", addr)
            try:
                (on_done or (lambda _r: None))({"skipped": "cooldown"})
            except Exception:
                pass
            return
        try:
            ensure_signed_prekey(addr, self._pwd_provider_for(addr))
            bundle = get_prekey_bundle_local(addr, self._pwd_provider_for(addr))  # {"ik","spk","sig","opk"}
            payload = {
                "type": "CHAT_PUBLISH_PREKEYS",
                "address": addr,
                "ik":  (bundle.get("ik")  or "").lower(),
                "spk": (bundle.get("spk") or "").lower(),
                "sig": (bundle.get("sig") or "").lower(),
            }
            if bundle.get("opk"):
                payload["opk"] = (bundle["opk"] or "").lower()
            self._last_prekey_publish[addr] = self._now()
        except Exception as e:
            (on_done or (lambda _r: None))({"error": f"bundle_error:{e}"})
            return

        def _after(resp):
            try:
                status = (resp or {}).get("type")
                log.debug("[publish_prekeys] resp_type=%s", status)
                if not resp or resp.get("error"):
                    self._last_prekey_publish.pop(addr, None)
                try:
                    if getattr(CFG, "CHAT_PUBLISH_SELF_CHECK", False):
                        def _selfcheck(r):
                            r_type = (r or {}).get("type")
                            if r_type == "CHAT_PREKEY_BUNDLE":
                                bundle = r.get("bundle") or {}
                                has_opk = bool(bundle.get("opk"))
                                log.debug("[publish_prekeys.selfcheck] bundle_ok=True has_opk=%s", has_opk)
                            else:
                                log.debug("[publish_prekeys.selfcheck] resp_type=%s", r_type)
                        self.rpc_send({"type": "CHAT_GET_PREKEY", "address": addr}, _selfcheck)
                except Exception:
                    log.debug("[publish_prekeys] self-check skipped due to error", exc_info=True)
            finally:
                (on_done or (lambda _r: None))(resp)
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

    def poll(self, address: str, n: int,
            on_items, on_done=None) -> None:
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
                log.debug("[poll] got not_registered for %s → auto-register & retry", me)
                
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
                        try:
                            provider_me = self._pwd_provider_for(me)
                            pkinfo = get_local_prekeys_for_recv(me, provider_me)
                            spk_sk = (pkinfo.get("spk_sk") or "")
                            if not spk_sk:
                                raise ValueError("missing_spk_sk")
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
                            log.debug("[poll] bootstrap responder X3DH (from=%s) used_opk=%s", frm, used_opk[:12] if used_opk else "-")
                        except Exception:
                            log.exception("[poll] failed bootstrap for %s", frm)
                            sess = None

                    msg_text = None
                    if sess:
                        pt = sess.decrypt(enc, frm, me, mid, ts, header)
                        if pt is not None:
                            msg_text = self._unpack(pt)
                        self._persist_session(me, frm, sess)

                    if msg_text is not None:
                        out.append({"from": frm, "text": msg_text, "msg_id": mid, "ts": ts})
                    else:
                        log.debug("[poll] decrypt failed for %s mid=%s", frm, mid)

                log.debug("[poll] %s item(s) for %s", len(out), me)
                on_items(out)
                
            finally:
                if on_done: on_done(resp)

        self.rpc_send({"type": "CHAT_PULL", "address": me, "n": int(n), "ts": ts_now, "pull_sig": pull_sig}, _on)


# ==================================================
# ============ Double Ratchet (minimal) ============
# ==================================================
class RatchetSession:
    MAX_SKIP = CFG.CHAT_RATCHET_MAX_SKIP

    def __init__(
        self,
        root_key: bytes,
        send_ck: Optional[bytes],
        recv_ck: Optional[bytes],
        my_ratchet_priv: Optional[x25519.X25519PrivateKey],
        their_ratchet_pub_hex: Optional[str],
        my_identity: str,
        their_identity: str,
        my_static_hex: Optional[str],
        ns: int = 0,
        nr: int = 0,
        pn: int = 0,
        skipped: Optional[Dict[str, str]] = None,
    ) -> None:
        
        self.rk = root_key
        self.CKs = send_ck
        self.CKr = recv_ck
        self.DHs = my_ratchet_priv or x25519.X25519PrivateKey.generate()
        self.DHr = (their_ratchet_pub_hex or None)
        self.Ns = int(ns)
        self.Nr = int(nr)
        self.Pn = int(pn)
        self.skipped: Dict[str, bytes] = {}
        
        if skipped:
            for k, v in skipped.items():
                try:
                    self.skipped[k] = bytes.fromhex(v)
                except Exception:
                    continue
                
        self.my_identity = my_identity
        self.their_identity = their_identity
        self.my_static_hex = my_static_hex or my_identity
        self._needs_send_rotation = False

    @staticmethod
    def _kdf(secret: bytes, info: bytes, length: int = 32, salt: Optional[bytes] = None) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)

    @staticmethod
    def _kdf_rk(root_key: bytes, shared_secret: bytes) -> tuple[bytes, bytes]:
        material = RatchetSession._kdf(shared_secret, b"tsar:ratchet:rk", length=64, salt=root_key)
        return material[:32], material[32:]

    @staticmethod
    def _kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
        material = RatchetSession._kdf(chain_key, b"tsar:ratchet:ck", length=64)
        return material[:32], material[32:]

    @staticmethod
    def _serialize_priv(priv: x25519.X25519PrivateKey) -> str:
        return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()

    @staticmethod
    def _deserialize_priv(data: str) -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(data))

    @classmethod
    def init_as_initiator(
        cls,
        root_key: bytes,
        my_identity: str,
        their_identity: str,
        my_ratchet_priv: x25519.X25519PrivateKey,
        their_ratchet_pub_hex: str,
        my_static_hex: Optional[str] = None,
    ) -> "RatchetSession":
        
        sck = cls._kdf(root_key, b"tsar:ratchet:send")
        rck = cls._kdf(root_key, b"tsar:ratchet:recv")
        
        return cls(root_key, sck, rck, my_ratchet_priv, their_ratchet_pub_hex, my_identity, their_identity, my_static_hex, ns=0, nr=0, pn=0)

    @classmethod
    def init_as_responder(
        cls,
        root_key: bytes,
        my_identity: str,
        their_identity: str,
        their_first_eph: str,
        my_ratchet_priv: Optional[x25519.X25519PrivateKey] = None,
        my_static_hex: Optional[str] = None,
    ) -> "RatchetSession":
        
        sck = cls._kdf(root_key, b"tsar:ratchet:recv")
        rck = cls._kdf(root_key, b"tsar:ratchet:send")
        inst = cls(root_key, sck, rck, my_ratchet_priv, their_first_eph, my_identity, their_identity, my_static_hex, ns=0, nr=0, pn=0)
        inst._needs_send_rotation = True
        
        return inst

    def to_dict(self) -> dict:
        return {
            "rk": self.rk.hex(),
            "cks": self.CKs.hex() if self.CKs else None,
            "ckr": self.CKr.hex() if self.CKr else None,
            "dhs": self._serialize_priv(self.DHs),
            "dhr": self.DHr,
            "ns": self.Ns,
            "nr": self.Nr,
            "pn": self.Pn,
            "skipped": {k: v.hex() for k, v in self.skipped.items()},
            "my_identity": self.my_identity,
            "their_identity": self.their_identity,
            "my_static_hex": self.my_static_hex,
            "needs_send_rotation": getattr(self, "_needs_send_rotation", False),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RatchetSession":
        rk = bytes.fromhex(data["rk"])
        cks = bytes.fromhex(data["cks"]) if data.get("cks") else None
        ckr = bytes.fromhex(data["ckr"]) if data.get("ckr") else None
        dhs = cls._deserialize_priv(data["dhs"])
        inst = cls(
            root_key=rk,
            send_ck=cks,
            recv_ck=ckr,
            my_ratchet_priv=dhs,
            their_ratchet_pub_hex=data.get("dhr"),
            my_identity=data.get("my_identity", ""),
            their_identity=data.get("their_identity", ""),
            my_static_hex=data.get("my_static_hex"),
            ns=int(data.get("ns", 0)),
            nr=int(data.get("nr", 0)),
            pn=int(data.get("pn", 0)),
            skipped=data.get("skipped"),
        )
        inst._needs_send_rotation = bool(data.get("needs_send_rotation", False))
        
        return inst

    def _remote_pub(self, pub_hex: str) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))

    def _skip_key_id(self, dh_hex: str, index: int) -> str:
        return f"{dh_hex}:{index}"

    def _store_skipped(self, dh_hex: str, index: int, mk: bytes) -> None:
        key = self._skip_key_id(dh_hex, index)
        if len(self.skipped) >= self.MAX_SKIP:
            try:
                oldest = next(iter(self.skipped))
                self.skipped.pop(oldest, None)
            except StopIteration:
                pass
        self.skipped[key] = mk

    def _consume_skipped(self, dh_hex: str, index: int) -> Optional[bytes]:
        key = self._skip_key_id(dh_hex, index)
        return self.skipped.pop(key, None)

    def _next_sending_message_key(self) -> tuple[bytes, int]:
        if self.CKs is None:
            raise ValueError("send chain not established")
        self.CKs, mk = self._kdf_ck(self.CKs)
        idx = self.Ns
        self.Ns += 1
        return mk, idx

    def _next_receiving_message_key(self) -> tuple[bytes, int]:
        if self.CKr is None:
            raise ValueError("recv chain not established")
        self.CKr, mk = self._kdf_ck(self.CKr)
        idx = self.Nr
        self.Nr += 1
        return mk, idx

    def _skip_message_keys(self, until: int, dh_hex: Optional[str]) -> None:
        if dh_hex is None or self.CKr is None:
            return
        while self.Nr < until:
            mk, idx = self._next_receiving_message_key()
            self._store_skipped(dh_hex, idx, mk)

    def _rotate_send_chain(self) -> None:
        if self.DHr is None:
            raise ValueError("cannot rotate send chain without peer key")
        remote = self._remote_pub(self.DHr)
        self.DHs = x25519.X25519PrivateKey.generate()
        self.Pn = self.Ns
        self.Ns = 0
        self.rk, self.CKs = self._kdf_rk(self.rk, self.DHs.exchange(remote))
        self._needs_send_rotation = False

    def _dh_ratchet(self, their_pub_hex: str) -> None:
        their_pub = self._remote_pub(their_pub_hex)
        # preserve prior sending key for recv chain update
        prev_dhs = self.DHs
        if prev_dhs is None:
            prev_dhs = x25519.X25519PrivateKey.generate()
        self.Pn = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.rk, self.CKr = self._kdf_rk(self.rk, prev_dhs.exchange(their_pub))
        self.DHr = their_pub_hex
        self.DHs = x25519.X25519PrivateKey.generate()
        self.rk, self.CKs = self._kdf_rk(self.rk, self.DHs.exchange(their_pub))
        self._needs_send_rotation = False

    def encrypt(self, pt: bytes, frm: str, to: str, mid: int, ts: int) -> dict:
        if getattr(self, "_needs_send_rotation", False):
            self._rotate_send_chain()
        mk, idx = self._next_sending_message_key()
        header = {
            "eph_pub": self.DHs.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "static_pub": self.my_static_hex or self.my_identity,
            "pn": self.Pn,
            "n": idx,
        }
        nonce = os.urandom(12)
        aad = ChatManager._aad_bytes(frm, to, mid, ts, header["static_pub"], header["eph_pub"], header["pn"], header["n"])
        ct = AESGCM(mk).encrypt(nonce, pt, aad)
        try:
            mkh = hashlib.sha256(mk).hexdigest()[:8]
        except Exception:
            mkh = "?"
        log.debug("[ratchet.encrypt] frm=%s to=%s mid=%s eph=%s pn=%s n=%s mk#=%s", frm, to, mid, header["eph_pub"][:12], header["pn"], header["n"], mkh)
        return {
            "ratchet": header,
            "enc": {"nonce": nonce.hex(), "ct": ct.hex()},
        }

    def _decrypt_with_mk(self, mk: bytes, enc: dict, frm: str, to: str, mid: int, ts: int, static_hex: str, eph_hex: str, pn: int, n: int) -> Optional[bytes]:
        nonce = bytes.fromhex(enc.get("nonce") or "")
        ct = bytes.fromhex(enc.get("ct") or "")
        aad = ChatManager._aad_bytes(frm, to, mid, ts, static_hex, eph_hex, pn, n)
        try:
            pt = AESGCM(mk).decrypt(nonce, ct, aad)
            try:
                mkh = hashlib.sha256(mk).hexdigest()[:8]
            except Exception:
                mkh = "?"
            log.debug("[ratchet.decrypt] ok frm=%s to=%s mid=%s eph=%s pn=%s n=%s mk#=%s", frm, to, mid, eph_hex[:12], pn, n, mkh)
            return pt
        except Exception:
            log.debug("[ratchet.decrypt] fail frm=%s to=%s mid=%s eph=%s pn=%s n=%s", frm, to, mid, eph_hex[:12], pn, n)
            return None

    def decrypt(self, enc: dict, frm: str, to: str, mid: int, ts: int, header: dict) -> Optional[bytes]:
        eph_hex = (header.get("eph_pub") or "").lower()
        static_hex = (header.get("static_pub") or "").lower()
        pn = int(header.get("pn", 0))
        n = int(header.get("n", 0))

        if not eph_hex or not static_hex:
            log.debug("[ratchet.decrypt] missing header pieces frm=%s mid=%s", frm, mid)
            return None

        skipped_mk = self._consume_skipped(eph_hex, n)
        if skipped_mk:
            return self._decrypt_with_mk(skipped_mk, enc, frm, to, mid, ts, static_hex, eph_hex, pn, n)

        if self.DHr is not None:
            self._skip_message_keys(pn, self.DHr)

        if self.DHr != eph_hex:
            self._dh_ratchet(eph_hex)

        self._skip_message_keys(n, self.DHr)
        mk, idx = self._next_receiving_message_key()
        pt = self._decrypt_with_mk(mk, enc, frm, to, mid, ts, static_hex, eph_hex, pn, n)
        if pt is None:
            # store for possible reprocessing if decrypt failed
            self._store_skipped(eph_hex, idx, mk)
        return pt
