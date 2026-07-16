# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

# ---------------- Local Project ----------------
from ..utils import config as CFG

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.rewards')

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .blockchain import Blockchain

class RewardCalculator:
    def __init__(self, blockchain: "Blockchain"):
        self.blockchain = blockchain


    def scheduled_reward(self, height: int) -> int:
        if height < 0:
            return 0
        if height == 0 and CFG.GENESIS_REWARD:
            return int(CFG.GENESIS_REWARD_AMOUNT)
        return int(CFG.INITIAL_REWARD) // (2 ** (int(max(0, height)) // int(CFG.BLOCKS_PER_HALVING)))


    def cumulative_supply_until(self, height: int) -> int:
        total = 0
        if height <= 0:
            return 0
        for h in range(height):
            base = self.scheduled_reward(h)
            if base <= 0:
                break
            if total + base > CFG.MAX_SUPPLY:
                base = CFG.MAX_SUPPLY - total
            total += base
            if total >= CFG.MAX_SUPPLY:
                return CFG.MAX_SUPPLY
        return total


    def get_block_reward(self, height: int) -> int:
        base = self.scheduled_reward(height)
        if base <= 0:
            return 0
        minted_before = self.cumulative_supply_until(height)
        remaining = max(0, CFG.MAX_SUPPLY - minted_before)
        return min(base, remaining)


    def calculate_total_supply(self) -> int:
        tip_height = len(self.blockchain.chain)
        return self.cumulative_supply_until(tip_height)