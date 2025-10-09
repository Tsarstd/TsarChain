# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: libsecp256k1

import os
import time
import random
import hashlib
from typing import Callable, Optional, Dict, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------- Local Project (Wallet Only) ----------------
from .data_security import Wallet, load_or_create_chat_dh_key


class ChatManager:
    def __init__(self,
        rpc_send: Callable[[Dict[str, Any], Callable[[Optional[Dict[str, Any]]], None]], None],
        password_prompt_cb: Callable[[str], Optional[str]],
        key_ttl_sec: int = 15 * 60,):
        
        self.rpc_send = rpc_send
        self.password_prompt_cb = password_prompt_cb
        self.key_ttl_sec = int(key_ttl_sec)

        # caches (exposed to the GUI when needed)
        self.priv_cache: Dict[str, tuple[str, float]] = {}
        self.pub_cache: Dict[str, str] = {}
        self.read_sent: set[int] = set()
        self._chat_dh_cache: Dict[str, tuple[str, str, float]] = {}

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
                from_static_hex: str, from_pub_hex: str) -> bytes:
        return b"|".join([
            b"TSAR-AAD1",
            frm.encode(), to.encode(),
            str(int(mid)).encode(), str(int(ts)).encode(),
            bytes.fromhex(from_static_hex),
            bytes.fromhex(from_pub_hex),
        ])
        
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
    
    def try_unlock(self, address: str) -> tuple[Optional[str], Optional[str]]:
        addr = self._canon(address)
        pwd = self.password_prompt_cb(addr)
        if not pwd:
            return None, "cancelled"
        try:
            w = Wallet.unlock(pwd, addr)
            priv_hex = w["private_key"]
            self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
            return priv_hex, None
        except Exception as e:
            return None, str(e)

    def get_priv_for_chat(self, address: str) -> Optional[str]:
        addr = self._canon(address)
        cached = self.priv_cache.get(addr)
        if cached and self._now() < cached[1]:
            return cached[0]

        pwd = self.password_prompt_cb(addr)
        if not pwd:
            return None
        try:
            w = Wallet.unlock(pwd, addr)
            priv_hex = w["private_key"]
            self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
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
                self.pub_cache[a] = pub
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
        sk_hex, pk_hex = load_or_create_chat_dh_key(a, self.password_prompt_cb)
        self._chat_dh_cache[a] = (sk_hex, pk_hex, now + self.key_ttl_sec)
        return sk_hex, pk_hex

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

    def send_message(self, from_addr: str, to_addr: str, text: str,
                    on_queued, on_result) -> None:
        frm = self._canon(from_addr)
        to  = self._canon(to_addr)

        priv_hex = self.get_priv_for_chat(frm)
        if not priv_hex:
            on_result({"status": "unlock_failed"}); return

        to_pub = self.expected_pub_or_lookup(to)
        if not to_pub:
            self.lookup_pub(to, lambda _p: on_result({"status": "no_pubkey"}))
            return
        my_sk_hex, my_pk_hex = self._get_chat_dh(frm)
        mid = random.randint(0, 2**31 - 1)
        ts  = int(time.time())

        padded = self._pack(text)
        enc, eph_pub = self._chat_encrypt_for(
            my_sk_hex, to_pub, padded,
            {"frm": frm, "to": to, "mid": mid, "ts": ts, "from_static": my_pk_hex}
        )
        
        chat_bytes = b"|".join([
            b"CHAT_SEND",
            frm.encode(), to.encode(),
            str(mid).encode(), str(ts).encode(),
            bytes.fromhex(eph_pub), bytes.fromhex(my_pk_hex),
            bytes.fromhex(enc["nonce"]), bytes.fromhex(enc["ct"])
        ])
        chat_sig = self.sign(priv_hex, chat_bytes).lower()

        payload = {
            "type": "CHAT_SEND",
            "from": frm, "to": to,
            "msg_id": mid, "ts": ts,
            "from_static": my_pk_hex,
            "from_pub": eph_pub,
            "enc": enc,
            "chat_sig": self.sign(priv_hex, b"|".join([b"CHAT_SEND", frm.encode(), to.encode(), str(mid).encode(), str(ts).encode(), bytes.fromhex(eph_pub), bytes.fromhex(my_pk_hex), bytes.fromhex(enc["nonce"]), bytes.fromhex(enc["ct"])])),
        }
        try:
            on_queued(mid, ts)
        except Exception:
            pass
        
        self.rpc_send(payload, on_result)
        
    # (Optional helper for UI) — send a signed read receipt
    def send_read_receipt(self, sender: str, reader: str, msg_id: int, on_result) -> None:
        priv_hex = self.get_priv_for_chat(reader)
        if not priv_hex:
            on_result({"error": "unlock_failed"}); return
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

        ts_now = int(time.time())
        pull_sig = self.sign(priv_hex, b"|".join([b"CHAT_PULL", me.encode(), str(ts_now).encode()]))

        def _on(resp):
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
                    mid = int(it.get("msg_id") or 0)
                    ts  = int(it.get("ts") or 0)
                    enc = it.get("enc") or {}

                    aad = self._aad_bytes(frm, me, mid, ts, from_static, from_pub)
                    msg = self._chat_decrypt_with(my_sk_hex, from_pub, from_static, enc, aad)
                    if msg is not None:
                        out.append({"from": frm, "text": msg, "msg_id": mid, "ts": ts})
                on_items(out)
            finally:
                if on_done: on_done(resp)

        self.rpc_send({"type": "CHAT_PULL", "address": me, "n": int(n),
                    "ts": ts_now, "pull_sig": pull_sig}, _on)
