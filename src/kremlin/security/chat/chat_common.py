# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: libsecp256k1; Signal-X3DH; Signal-DoubleRatchet; RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM


import os
from typing import Optional

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