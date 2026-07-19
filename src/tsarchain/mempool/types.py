# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.types")

__all__ = [
    "PrevoutRef",
    "PrevoutMeta",
    "normalize_prevout_set",
]


@dataclass(frozen=True)
class PrevoutRef:
    txid: str
    vout: int

    @classmethod
    def from_values(cls, txid_value: Any, vout_value: Any) -> "PrevoutRef | None":
        if txid_value is None or vout_value is None:
            return None
        if isinstance(txid_value, (bytes, bytearray)):
            txid_hex = txid_value.hex().lower()
        else:
            txid_hex = str(txid_value).lower()
        vout = int(vout_value)
        return cls(txid_hex, vout)

    def key(self) -> tuple[str, int]:
        return (self.txid, self.vout)


@dataclass(frozen=True)
class PrevoutMeta:
    amount: int
    script_pubkey: bytes
    is_coinbase: bool
    born_height: int


def normalize_prevout_set(items: Iterable[Any]) -> set[PrevoutRef]:
    normalized: set[PrevoutRef] = set()
    for item in items or []:
        if isinstance(item, PrevoutRef):
            normalized.add(item)
            continue
        if isinstance(item, tuple) and len(item) == 2:
            ref = PrevoutRef.from_values(item[0], item[1])
            if ref:
                normalized.add(ref)
    return normalized

