# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: libsecp256k1; Signal-X3DH; Signal-DoubleRatchet; RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM

"""
Double Ratchet session implementation for end-to-end encryption.

This module have 7 categories helper functions for:
1. Initialization & Configuration
2. Session Serialization
3. Message Key Management (Skipped Keys)
4. Chain Key Derivation
5. Ratchet Operations
6. Encryption / Decryption
7. Helper: Public Key Conversion

All cryptographic primitives follow the Signal protocol specifications.
"""

import os
import time
from typing import Optional, Dict

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..chat import chat_common as COM
from tsarchain.utils import config as CFG

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.security.chat.double_ratchet")


class RatchetSession:

    # ----------------------------------------------------------------------
    # Initialization & Configuration
    # ----------------------------------------------------------------------
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
                self.skipped[k] = bytes.fromhex(v)

        self.my_identity = my_identity
        self.their_identity = their_identity
        self.my_static_hex = my_static_hex or my_identity
        self._needs_send_rotation = False

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
        
        sck = COM.hkdf(root_key, b"tsar:ratchet:send")
        rck = COM.hkdf(root_key, b"tsar:ratchet:recv")

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
        
        sck = COM.hkdf(root_key, b"tsar:ratchet:recv")
        rck = COM.hkdf(root_key, b"tsar:ratchet:send")
        inst = cls(root_key, sck, rck, my_ratchet_priv, their_first_eph, my_identity, their_identity, my_static_hex, ns=0, nr=0, pn=0)
        inst._needs_send_rotation = True
        return inst

    # ----------------------------------------------------------------------
    # Session Serialization
    # ----------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "rk": self.rk.hex(),
            "cks": self.CKs.hex() if self.CKs else None,
            "ckr": self.CKr.hex() if self.CKr else None,
            "dhs": COM.serialize_priv(self.DHs),
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
        dhs = COM.deserialize_priv(data["dhs"])
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

    # ----------------------------------------------------------------------
    # Message Key Management (Skipped Keys)
    # ----------------------------------------------------------------------
    def _skip_key_id(self, dh_hex: str, index: int) -> str:
        return f"{dh_hex}:{index}"

    def _store_skipped(self, dh_hex: str, index: int, mk: bytes) -> None:
        key = self._skip_key_id(dh_hex, index)
        if len(self.skipped) >= CFG.CHAT_RATCHET_MAX_SKIP:
            try:
                oldest = next(iter(self.skipped))
                self.skipped.pop(oldest, None)
            except StopIteration:
                log.exception("error__store_skipped")
                pass
        self.skipped[key] = mk

    def _consume_skipped(self, dh_hex: str, index: int) -> Optional[bytes]:
        key = self._skip_key_id(dh_hex, index)
        return self.skipped.pop(key, None)

    # ----------------------------------------------------------------------
    # Chain Key Derivation
    # ----------------------------------------------------------------------
    def _next_sending_message_key(self) -> tuple[bytes, int]:
        if self.CKs is None:
            raise ValueError("send chain not established")
        self.CKs, mk = COM.hkdf_ck(self.CKs)
        idx = self.Ns
        self.Ns += 1
        return mk, idx

    def _next_receiving_message_key(self) -> tuple[bytes, int]:
        if self.CKr is None:
            raise ValueError("recv chain not established")
        self.CKr, mk = COM.hkdf_ck(self.CKr)
        idx = self.Nr
        self.Nr += 1
        return mk, idx

    def _skip_message_keys(self, until: int, dh_hex: Optional[str]) -> None:
        if dh_hex is None or self.CKr is None:
            return
        while self.Nr < until:
            mk, idx = self._next_receiving_message_key()
            self._store_skipped(dh_hex, idx, mk)

    # ----------------------------------------------------------------------
    # Ratchet Operations
    # ----------------------------------------------------------------------
    def _rotate_send_chain(self) -> None:
        if self.DHr is None:
            raise ValueError("cannot rotate send chain without peer key")
        remote = self._remote_pub(self.DHr)
        self.DHs = x25519.X25519PrivateKey.generate()
        self.Pn = self.Ns
        self.Ns = 0
        self.rk, self.CKs = COM.hkdf_rk(self.rk, self.DHs.exchange(remote))
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
        self.rk, self.CKr = COM.hkdf_rk(self.rk, prev_dhs.exchange(their_pub))
        self.DHr = their_pub_hex
        self.DHs = x25519.X25519PrivateKey.generate()
        self.rk, self.CKs = COM.hkdf_rk(self.rk, self.DHs.exchange(their_pub))
        self._needs_send_rotation = False

    # ----------------------------------------------------------------------
    # Encryption / Decryption
    # ----------------------------------------------------------------------
    def encrypt(self, pt: bytes, frm: str, to: str, mid: int, ts: int) -> dict:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()

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
        aad = COM.build_aad_bytes(frm, to, mid, ts, header["static_pub"], header["eph_pub"], header["pn"], header["n"])
        ct = AESGCM(mk).encrypt(nonce, pt, aad)

        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[encrypt] Benchmark : %.3f ms", result)

        return {
            "ratchet": header,
            "enc": {"nonce": nonce.hex(), "ct": ct.hex()},
        }

    def _decrypt_with_mk(self, mk: bytes, enc: dict, frm: str, to: str, mid: int, ts: int, static_hex: str, eph_hex: str, pn: int, n: int) -> Optional[bytes]:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()

        nonce = bytes.fromhex(enc.get("nonce") or "")
        ct = bytes.fromhex(enc.get("ct") or "")
        aad = COM.build_aad_bytes(frm, to, mid, ts, static_hex, eph_hex, pn, n)
        pt = AESGCM(mk).decrypt(nonce, ct, aad)

        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[_decrypt_with_mk] Benchmark : %.3f ms", result)

        return pt

    def decrypt(self, enc: dict, frm: str, to: str, mid: int, ts: int, header: dict) -> Optional[bytes]:
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()

        eph_hex = (header.get("eph_pub") or "").lower()
        static_hex = (header.get("static_pub") or "").lower()
        pn = int(header.get("pn", 0))
        n = int(header.get("n", 0))

        if not eph_hex or not static_hex:
            log.debug("[ratchet.decrypt] missing header pieces frm=%s mid=%s", frm, mid)
            return None

        # Try skipped message key first
        skipped_mk = self._consume_skipped(eph_hex, n)
        if skipped_mk:
            try:
                return self._decrypt_with_mk(skipped_mk, enc, frm, to, mid, ts, static_hex, eph_hex, pn, n)
            except Exception as e:
                log.warning("[decrypt] skipped mk decrypt failed for %s mid=%s: %s", frm, mid, e)
                return None

        # Skip keys if previous chain length is ahead
        if self.DHr is not None:
            self._skip_message_keys(pn, self.DHr)

        # Perform DH ratchet if peer ephemeral key changed
        if self.DHr != eph_hex:
            self._dh_ratchet(eph_hex)

        # Skip keys up to the current message index
        self._skip_message_keys(n, self.DHr)
        mk, idx = self._next_receiving_message_key()
        pt = self._decrypt_with_mk(mk, enc, frm, to, mid, ts, static_hex, eph_hex, pn, n)

        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[decrypt] Benchmark : %.3f ms", result)

        return pt
    
    # ----------------------------------------------------------------------
    # Helper: Public Key Conversion
    # ----------------------------------------------------------------------
    def _remote_pub(self, pub_hex: str) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))