# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from typing import Final

try:
    from .pow_numba import HAVE_NUMBA as _HAVE_NUMBA, pow_hash as _pow_hash
    HAVE_NUMBA: Final[bool] = bool(_HAVE_NUMBA)

    def pow_hash(header80: bytes) -> bytes:
        return _pow_hash(header80)

except Exception:
    import hashlib
    HAVE_NUMBA: Final[bool] = False

    def pow_hash(header80: bytes) -> bytes:
        if len(header80) != 80:
            raise ValueError("pow_hash expects exactly 80 bytes (block header).")
        return hashlib.sha256(hashlib.sha256(header80).digest()).digest()

__all__ = ["HAVE_NUMBA", "pow_hash"]
