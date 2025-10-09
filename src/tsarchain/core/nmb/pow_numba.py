# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from typing import Final
from numba import njit
import numpy as np
HAVE_NUMBA: Final[bool] = True

# ---- Minimal SHA-256 implementation for Numba ----

if HAVE_NUMBA:
    @njit(cache=True)
    def _rotr(x: np.uint32, n: int) -> np.uint32:
        return np.uint32(((x >> n) | (x << (32 - n))) & 0xFFFFFFFF)

    @njit(cache=True)
    def _ch(x: np.uint32, y: np.uint32, z: np.uint32) -> np.uint32:
        return np.uint32((x & y) ^ ((~x) & z))

    @njit(cache=True)
    def _maj(x: np.uint32, y: np.uint32, z: np.uint32) -> np.uint32:
        return np.uint32((x & y) ^ (x & z) ^ (y & z))

    @njit(cache=True)
    def _sha256_compress(block_words: np.ndarray, H: np.ndarray) -> None:
        K = np.array([
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        ], dtype=np.uint32)

        W = np.zeros(64, dtype=np.uint32)
        for t in range(16):
            W[t] = block_words[t]
        for t in range(16, 64):
            s0 = _rotr(W[t-15], 7) ^ _rotr(W[t-15], 18) ^ np.uint32(W[t-15] >> 3)
            s1 = _rotr(W[t-2], 17) ^ _rotr(W[t-2], 19) ^ np.uint32(W[t-2] >> 10)
            W[t] = np.uint32((W[t-16] + s0 + W[t-7] + s1) & 0xFFFFFFFF)

        a,b,c,d,e,f,g,h = H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]

        for t in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = _ch(e, f, g)
            temp1 = np.uint32((h + S1 + ch + K[t] + W[t]) & 0xFFFFFFFF)
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = _maj(a, b, c)
            temp2 = np.uint32((S0 + maj) & 0xFFFFFFFF)

            h = g
            g = f
            f = e
            e = np.uint32((d + temp1) & 0xFFFFFFFF)
            d = c
            c = b
            b = a
            a = np.uint32((temp1 + temp2) & 0xFFFFFFFF)

        H[0] = (H[0] + a) & 0xFFFFFFFF
        H[1] = (H[1] + b) & 0xFFFFFFFF
        H[2] = (H[2] + c) & 0xFFFFFFFF
        H[3] = (H[3] + d) & 0xFFFFFFFF
        H[4] = (H[4] + e) & 0xFFFFFFFF
        H[5] = (H[5] + f) & 0xFFFFFFFF
        H[6] = (H[6] + g) & 0xFFFFFFFF
        H[7] = (H[7] + h) & 0xFFFFFFFF

    @njit(cache=True)
    def _sha256_80bytes(header80: np.ndarray) -> np.ndarray:
        H = np.array([
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
        ], dtype=np.uint32)

        B0 = np.zeros(16, dtype=np.uint32)
        for i in range(16):
            j = 4*i
            B0[i] = (np.uint32(header80[j]) << 24) | (np.uint32(header80[j+1]) << 16) | (np.uint32(header80[j+2]) << 8) | np.uint32(header80[j+3])
        _sha256_compress(B0, H)

        B1 = np.zeros(16, dtype=np.uint32)
        off = 64
        for i in range(4):
            j = off + 4*i
            B1[i] = (np.uint32(header80[j]) << 24) | (np.uint32(header80[j+1]) << 16) | (np.uint32(header80[j+2]) << 8) | np.uint32(header80[j+3])
        B1[4]  = np.uint32(0x80000000)
        B1[14] = np.uint32(0)
        B1[15] = np.uint32(80 * 8)
        _sha256_compress(B1, H)

        out32 = np.zeros(32, dtype=np.uint8)
        for i in range(8):
            out32[4*i+0] = (H[i] >> 24) & 0xFF
            out32[4*i+1] = (H[i] >> 16) & 0xFF
            out32[4*i+2] = (H[i] >> 8) & 0xFF
            out32[4*i+3] = (H[i] >> 0) & 0xFF
        return out32

    @njit(cache=True)
    def _sha256_32bytes(digest32: np.ndarray) -> np.ndarray:
        H = np.array([
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
        ], dtype=np.uint32)

        B0 = np.zeros(16, dtype=np.uint32)
        for i in range(8):
            j = 4*i
            B0[i] = (np.uint32(digest32[j]) << 24) | (np.uint32(digest32[j+1]) << 16) | (np.uint32(digest32[j+2]) << 8) | np.uint32(digest32[j+3])
        B0[8]  = np.uint32(0x80000000)
        B0[15] = np.uint32(32 * 8)
        _sha256_compress(B0, H)

        out32 = np.zeros(32, dtype=np.uint8)
        for i in range(8):
            out32[4*i+0] = (H[i] >> 24) & 0xFF
            out32[4*i+1] = (H[i] >> 16) & 0xFF
            out32[4*i+2] = (H[i] >> 8) & 0xFF
            out32[4*i+3] = (H[i] >> 0) & 0xFF
        return out32

    @njit(cache=True)
    def double_sha256_numba(header80: np.ndarray) -> np.ndarray:
        first = _sha256_80bytes(header80)
        second = _sha256_32bytes(first)
        return second  # 32-byte big-endian

    def pow_hash(header80_bytes: bytes) -> bytes:
        if len(header80_bytes) != 80:
            raise ValueError("pow_hash expects exactly 80 bytes")
        arr = np.frombuffer(header80_bytes, dtype=np.uint8)
        return bytes(double_sha256_numba(arr))

else:
    raise ImportError("Numba is required but HAVE_NUMBA=False")
