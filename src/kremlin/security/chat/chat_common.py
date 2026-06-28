# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: libsecp256k1; Signal-X3DH; Signal-DoubleRatchet; RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM


import os
import hashlib
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from tsarchain.utils.helpers import sign_digest_der_low_s_native

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.security.chat.chat_common")

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

def hkdf(secret: bytes, info: bytes, length: int = 32, salt: Optional[bytes] = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)

def hkdf_rk(root_key: bytes, shared_secret: bytes) -> tuple[bytes, bytes]:
    material = hkdf(shared_secret, b"tsar:ratchet:rk", length=64, salt=root_key)
    return material[:32], material[32:]

def hkdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    material = hkdf(chain_key, b"tsar:ratchet:ck", length=64)
    return material[:32], material[32:]

def serialize_priv(priv: x25519.X25519PrivateKey) -> str:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()

def deserialize_priv(data: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(data))

def canon(address: str) -> str:
    return (address or "").strip().lower()

def ec_priv_from_hex(h: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(bytes.fromhex(h), "big"), ec.SECP256K1())

def pub_hex_from_priv(self, sk: ec.EllipticCurvePrivateKey) -> str:
    nums = sk.public_key().public_numbers()
    prefix = 0x02 | (nums.y & 1)
    return f"{prefix:02x}{nums.x:064x}"

def sign(self, priv_hex: str, data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    sig = sign_digest_der_low_s_native(priv_hex, digest)
    return sig.hex()