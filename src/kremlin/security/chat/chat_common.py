# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: libsecp256k1; Signal-X3DH; Signal-DoubleRatchet; RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM

"""
Shared utilities for X3DH and Double Ratchet chat modules.

This module have 7 categories helper functions for:
1. AAD & Message Packing Utilities
2. HKDF & Ratchet Key Derivation
3. X25519 Key Serialization
4. Address Canonicalization & EC Helpers
5. Chat Key Management (X25519 identity key)
6. Prekey Management (signed prekey + one-time prekeys)
7. Chat Session Storage (for Double Ratchet state)

All cryptographic primitives follow the Signal protocol specifications.
"""

import os
import re
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import sign_digest_der_low_s_native

from ...security import data_security as WALL

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.security.chat.chat_common")

# ----------------------------------------------------------------------
# AAD & Message Packing Utilities
# ----------------------------------------------------------------------
def build_aad_bytes(
    frm: str,
    to: str,
    mid: int,
    ts: int,
    from_static_hex: str,
    from_pub_hex: str,
    pn: Optional[int] = None,
    n: Optional[int] = None
) -> bytes:
    parts = [
        b"TSAR-AAD1",
        frm.encode(),
        to.encode(),
        str(int(mid)).encode(),
        str(int(ts)).encode(),
        bytes.fromhex(from_static_hex),
        bytes.fromhex(from_pub_hex),
    ]
    if pn is not None:
        parts.append(str(int(pn)).encode())
    if n is not None:
        parts.append(str(int(n)).encode())
    return b"|".join(parts)

def pack(s: str, bucket_sizes=(128, 256, 512, 1024)) -> bytes:
    b = s.encode("utf-8")
    L = len(b)
    target = next((k for k in bucket_sizes if L + 2 <= k), L + 2)
    pad = os.urandom(max(0, target - (L + 2)))
    return len(b).to_bytes(2, "big") + b + pad

def unpack(pt: bytes) -> str:
    if len(pt) < 2:
        return ""
    L = int.from_bytes(pt[:2], "big")
    raw = pt[2:2+L]
    return raw.decode("utf-8", "ignore")

# ----------------------------------------------------------------------
# HKDF & Ratchet Key Derivation
# ----------------------------------------------------------------------
def hkdf(secret: bytes, info: bytes, length: int = 32, salt: Optional[bytes] = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)

def hkdf_rk(root_key: bytes, shared_secret: bytes) -> tuple[bytes, bytes]:
    material = hkdf(shared_secret, b"tsar:ratchet:rk", length=64, salt=root_key)
    return material[:32], material[32:]

def hkdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    material = hkdf(chain_key, b"tsar:ratchet:ck", length=64)
    return material[:32], material[32:]

# ----------------------------------------------------------------------
# X25519 Key Serialization
# ----------------------------------------------------------------------
def serialize_priv(priv: x25519.X25519PrivateKey) -> str:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()

def deserialize_priv(data: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(data))

# ----------------------------------------------------------------------
# Address Canonicalization & EC Helpers
# ----------------------------------------------------------------------
def canon(address: str) -> str:
    return (address or "").strip().lower()

def ec_priv_from_hex(h: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(bytes.fromhex(h), "big"), ec.SECP256K1())

def pub_hex_from_priv(sk: ec.EllipticCurvePrivateKey) -> str:
    nums = sk.public_key().public_numbers()
    prefix = 0x02 | (nums.y & 1)
    return f"{prefix:02x}{nums.x:064x}"

def sign(priv_hex: str, data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    sig = sign_digest_der_low_s_native(priv_hex, digest)
    return sig.hex()

def _ecdsa_sign_spend(priv_hex: str, data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    sig_der = sign_digest_der_low_s_native(priv_hex, digest)
    return sig_der.hex()

# ----------------------------------------------------------------------
# Chat Key Management (X25519 identity key)
# ----------------------------------------------------------------------
def _chat_key_path(addr: str) -> str:
    return os.path.join(CFG.CHAT_KEYS_DIR, f"{addr.lower()}.json")

def chat_dh_gen_keypair() -> tuple[str, str]:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    sk_hex = sk.private_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption()
    ).hex()
    pk_hex = pk.public_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PublicFormat.Raw
    ).hex()
    return sk_hex, pk_hex

def load_or_create_chat_dh_key(addr: str, password_provider=None) -> tuple[str, str]:
    addr_c = addr.lower()
    path = Path(_chat_key_path(addr_c))
    data, legacy = WALL._secure_load(
        namespace="chat_key",
        key=addr_c,
        path=path,
        password_provider=password_provider,
        prompt=f"Unlock chat key for {addr_c}",
    )
    if data:
        if legacy:
            WALL._secure_store("chat_key", addr_c, path, data, password_provider,
                          f"Migrate chat key for {addr_c}")
        sk_hex = data.get("sk_hex")
        pk_hex = data.get("pk_hex")
        if not sk_hex or not pk_hex:
            raise ValueError("Chat key store corrupted")
        return sk_hex, pk_hex

    if not callable(password_provider):
        raise ValueError("Password required to create chat key")

    sk_hex, pk_hex = chat_dh_gen_keypair()
    record = {"sk_hex": sk_hex, "pk_hex": pk_hex, "created": int(time.time())}
    path.parent.mkdir(parents=True, exist_ok=True)
    WALL._secure_store("chat_key", addr_c, path, record, password_provider,
                  f"Create encrypted chat key for {addr_c}")
    return sk_hex, pk_hex

# ----------------------------------------------------------------------
# Prekey Management (signed prekey + one‑time prekeys)
# ----------------------------------------------------------------------
def _prekey_path(addr: str) -> str:
    safe = re.sub(r"[^0-9a-z]", "_", addr.lower())
    return os.path.join(CFG.PREKEY_DIR, f"{safe}.json")

def _load_prekey_record(addr: str, password_provider=None) -> Optional[Dict]:
    addr_c = addr.lower()
    path = Path(_prekey_path(addr_c))
    record, legacy = WALL._secure_load(
        namespace="chat_prekey",
        key=addr_c,
        path=path,
        password_provider=password_provider,
        prompt=f"Unlock chat prekeys for {addr_c}",
    )
    if record is None:
        return None
    if legacy:
        WALL._secure_store("chat_prekey", addr_c, path, record, password_provider, f"Migrate chat prekeys for {addr_c}")
    return record

def _store_prekey_record(addr: str, record: Dict, password_provider) -> None:
    addr_c = addr.lower()
    path = Path(_prekey_path(addr_c))
    path.parent.mkdir(parents=True, exist_ok=True)
    WALL._secure_store("chat_prekey", addr_c, path, record, password_provider, f"Store chat prekeys for {addr_c}")

def get_priv_for_address(address: str, password: str) -> str:
    ks = WALL.load_keystore(password)
    entry = ks["wallets"].get(address)
    if not entry:
        raise ValueError("Address not found in keystore")
    return WALL.decrypt_privkey(entry["payload"], password)

def ensure_signed_prekey(addr: str, password_provider=None) -> dict:
    addr_c = addr.lower()
    record = _load_prekey_record(addr_c, password_provider)
    if record and record.get("spk") and record.get("spk_sk") and record.get("sig"):
        record.setdefault("opk_list", [])
        record.setdefault("opk_pairs", [])
        record.setdefault("addr", addr_c)
        return record

    if not callable(password_provider):
        raise ValueError("password required")

    pwd = password_provider(addr)
    if not pwd:
        raise ValueError("password required")
    sp_priv = get_priv_for_address(addr, pwd)
    sp_pub = WALL.pubkey_from_privhex(sp_priv)
    spk_sk, spk_pk = chat_dh_gen_keypair()
    payload = b"TSAR-SPK|" + bytes.fromhex(spk_pk) + b"|" + sp_pub
    sig = _ecdsa_sign_spend(sp_priv, payload)

    record = record or {}
    record.update({
        "addr": addr_c,
        "ik": record.get("ik"),
        "spk": spk_pk,
        "spk_sk": spk_sk,
        "sig": sig,
        "created": int(time.time()),
        "opk_list": record.get("opk_list") or [],
        "opk_pairs": record.get("opk_pairs") or [],
    })

    _store_prekey_record(addr_c, record, password_provider)
    return record

def add_one_time_prekeys(addr: str, n: int, password_provider=None) -> dict:
    if not callable(password_provider):
        raise ValueError("password required")
    record = ensure_signed_prekey(addr, password_provider)
    record.setdefault("opk_list", [])
    record.setdefault("opk_pairs", [])
    for _ in range(int(n)):
        sk, pk = chat_dh_gen_keypair()
        record["opk_list"].append(pk)
        record["opk_pairs"].append({"sk": sk, "pk": pk, "used": False})
    _store_prekey_record(addr, record, password_provider)
    return record

def get_prekey_inventory(addr: str, password_provider=None) -> dict:
    record = _load_prekey_record(addr, password_provider)
    if record is None:
        return {"opk_queue": 0, "opk_unused_pairs": 0, "created": 0}
    opk_queue = len(record.get("opk_list") or [])
    unused_pairs = sum(1 for it in record.get("opk_pairs") or [] if not it.get("used"))
    return {
        "opk_queue": opk_queue,
        "opk_unused_pairs": unused_pairs,
        "created": int(record.get("created") or 0),
    }

def rotate_signed_prekey(addr: str, password_provider=None) -> dict:
    if not callable(password_provider):
        raise ValueError("password provider required for SPK rotation")
    pwd = password_provider(addr)
    if not pwd:
        raise ValueError("password required")
    sp_priv = get_priv_for_address(addr, pwd)
    sp_pub  = WALL.pubkey_from_privhex(sp_priv)
    spk_sk, spk_pk = chat_dh_gen_keypair()
    payload = b"TSAR-SPK|" + bytes.fromhex(spk_pk) + b"|" + sp_pub
    sig = _ecdsa_sign_spend(sp_priv, payload)
    record = _load_prekey_record(addr, password_provider) or {}
    record.update({
        "addr": addr.lower(),
        "ik": record.get("ik"),
        "spk": spk_pk,
        "spk_sk": spk_sk,
        "sig": sig,
        "created": int(time.time()),
        "opk_list": [],
        "opk_pairs": [],
    })
    _store_prekey_record(addr, record, password_provider)
    return record

def get_prekey_bundle_local(addr: str, password_provider=None) -> dict:
    _, ik = load_or_create_chat_dh_key(addr, password_provider)
    b = ensure_signed_prekey(addr, password_provider)
    opk = None
    if (b.get("opk_list") or []):
        opk = (b["opk_list"]).pop(0)
        _store_prekey_record(addr, b, password_provider)
    else:
        _store_prekey_record(addr, b, password_provider)
    return {"ik": ik, "spk": b["spk"], "sig": b["sig"], "opk": opk}

def get_local_prekeys_for_recv(addr: str, password_provider=None) -> dict:
    record = _load_prekey_record(addr, password_provider)
    if not record:
        return {}
    return {
        "spk_sk": record.get("spk_sk"),
        "spk": record.get("spk"),
        "opk_pairs": record.get("opk_pairs") or [],
    }

def consume_opk_priv(addr: str, opk_pk_hex: str, password_provider=None) -> str | None:
    record = _load_prekey_record(addr, password_provider)
    if not record:
        return None
    pairs = record.get("opk_pairs") or []
    for it in pairs:
        if (it.get("pk") or "").lower() == (opk_pk_hex or "").lower() and not it.get("used"):
            it["used"] = True
            _store_prekey_record(addr, record, password_provider)
            return it.get("sk")
    return None

# ----------------------------------------------------------------------
# Chat Session Storage (for Double Ratchet state)
# ----------------------------------------------------------------------
def _session_storage_key(me: str, peer: str) -> str:
    return f"{(me or '').lower()}|{(peer or '').lower()}"

def _session_path(me: str, peer: str) -> Path:
    base = Path(CFG.CHAT_SESSION_DIR)
    me_c = (me or "").lower() or "_"
    peer_c = (peer or "").lower() or "_"
    return base / me_c / peer_c

def load_chat_session(me: str, peer: str, password_provider) -> Optional[Dict]:
    key = _session_storage_key(me, peer)
    path = _session_path(me, peer)
    record, legacy = WALL._secure_load(
        namespace="chat_session",
        key=key,
        path=path,
        password_provider=password_provider,
        prompt=f"Unlock chat session for {me.lower() if me else ''}",
    )
    if record and legacy:
        WALL._secure_store("chat_session", key, path, record, password_provider,
                      f"Migrate chat session for {me.lower() if me else ''}")
    return record

def store_chat_session(me: str, peer: str, record: Dict, password_provider) -> None:
    key = _session_storage_key(me, peer)
    path = _session_path(me, peer)
    WALL._secure_store("chat_session", key, path, record, password_provider,
                  f"Store chat session for {me.lower() if me else ''}")

def delete_chat_session(me: str, peer: str) -> None:
    key = _session_storage_key(me, peer)
    path = _session_path(me, peer)
    WALL._secure_backend_delete("chat_session", key, path)