# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from typing import Any, Dict

from ...utils import config as CFG
from .base import BroadcastHandlerProxy

from ...utils.helpers import bits_to_target
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.chain_utils")


class ChainUtilsHandler(BroadcastHandlerProxy):
    def calc_chainwork_from_list(self, chain_list) -> int:
        total = 0
        last_bits = None
        for i, b in enumerate(chain_list):
            if isinstance(b, dict):
                raw = b.get("bits")
            else:
                try:
                    raw = b.bits
                except AttributeError:
                    raw = None
            bits = self._parse_bits(raw)
            if bits is None:
                bits = CFG.INITIAL_BITS if i == 0 or last_bits is None else last_bits
            if bits > CFG.MAX_BITS:
                bits = CFG.MAX_BITS
            total += self._work_from_bits(bits)
            last_bits = bits
        return total


    def validate_incoming_chain(self, message: Dict[str, Any]) -> bool:
        chain_data = message.get("data", [])
        if not chain_data:
            return False

        if chain_data[0].get("height") != 0:
            return False

        for i in range(1, len(chain_data)):
            if chain_data[i].get("height") != chain_data[i - 1].get("height") + 1:
                return False
            if chain_data[i].get("prev_block_hash") != chain_data[i - 1].get("hash"):
                return False
        return True


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    @staticmethod
    def _parse_bits(bits):
        if bits is None:
            return None
        if isinstance(bits, float):
            if bits.is_integer():
                return int(bits)
            raise TypeError(f"bits float non-integer: {bits}")
        if isinstance(bits, int):
            return bits & 0xFFFFFFFF
        if isinstance(bits, str):
            s = bits.strip().lower()
            return int(s, 16) if s.startswith("0x") else int(s)
        raise TypeError(f"bits must be int/hexstr, got {type(bits)}")

    def _work_from_bits(self, bits):
        parsed = self._parse_bits(bits)
        if parsed is None:
            return 0
        target = bits_to_target(parsed)
        if target <= 0:
            return 0
        return (1 << 256) // (target + 1)


__all__ = ["ChainUtilsHandler"]
