# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

# ---------------- Local Project ----------------
from ..utils import config as CFG

class RewardMixin:
    def _scheduled_reward(self, height: int) -> int:
        if height < 0:
            return 0
        if height == 0 and getattr(CFG, "GENESIS_REWARD", False):
            try:
                return int(CFG.GENESIS_REWARD_AMOUNT)
            except Exception:
                return int(CFG.INITIAL_REWARD)
        try:
            return int(CFG.INITIAL_REWARD) // (2 ** (int(max(0, height)) // int(CFG.BLOCKS_PER_HALVING)))
        except Exception:
            return 0

    def _cumulative_supply_until(self, height: int) -> int:
        total = 0
        if height <= 0:
            return 0
        for h in range(height):
            base = self._scheduled_reward(h)
            if base <= 0:
                break
            if total + base > CFG.MAX_SUPPLY:
                base = CFG.MAX_SUPPLY - total
            total += base
            if total >= CFG.MAX_SUPPLY:
                return CFG.MAX_SUPPLY
        return total

    def get_block_reward(self, height: int) -> int:
        base = self._scheduled_reward(height)
        if base <= 0:
            return 0
        minted_before = self._cumulative_supply_until(height)
        remaining = max(0, CFG.MAX_SUPPLY - minted_before)
        return min(base, remaining)

    def calculate_total_supply(self) -> int:
        tip_height = len(self.chain)
        return self._cumulative_supply_until(tip_height)
