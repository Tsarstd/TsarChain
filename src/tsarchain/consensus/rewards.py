# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
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
        epoch = int(max(0, height)) // int(CFG.BLOCKS_PER_HALVING)
        if epoch >= 64:
            return 0
        return int(CFG.INITIAL_REWARD) // (2 ** epoch)


    def cumulative_supply_until(self, height: int) -> int:
        if height <= 0:
            return 0

        blocks_per_halving = max(1, int(CFG.BLOCKS_PER_HALVING))
        max_supply = int(CFG.MAX_SUPPLY)

        total = self.scheduled_reward(0)
        if height == 1:
            return min(total, max_supply)

        remaining_blocks = height - 1
        current_h = 1

        while remaining_blocks > 0:
            reward = self.scheduled_reward(current_h)
            if reward <= 0:
                break

            epoch = current_h // blocks_per_halving
            next_epoch_h = (epoch + 1) * blocks_per_halving
            blocks_in_epoch = min(remaining_blocks, next_epoch_h - current_h)

            total += blocks_in_epoch * reward
            if total >= max_supply:
                return max_supply

            remaining_blocks -= blocks_in_epoch
            current_h += blocks_in_epoch

        return min(total, max_supply)


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