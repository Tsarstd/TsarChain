# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations
from typing import List

# ---------------- Local Project ----------------
from ..core.block import Block
from ..utils import config as CFG
from ..utils.helpers import bits_to_target, target_to_bits, target_to_difficulty, difficulty_to_target

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.difficulty')

class DifficultyMixin:
    def _expected_bits_on_prefix(self, prefix: "List[Block]", next_height: int) -> int:
        T = int(CFG.TARGET_BLOCK_TIME)
        if next_height <= 0 or not prefix:
            return int(CFG.MAX_BITS)
        if len(prefix) < 2:
            return int(getattr(prefix[-1], "bits", CFG.MAX_BITS))

        N = min(int(CFG.LWMA_WINDOW), len(prefix))
        window = prefix[-N:]
        k = (N * (N - 1)) // 2
        sum_wst = 0
        sum_diff = 0

        def _ts(b) -> int:
            t = getattr(b, "timestamp", 0)
            return int(t) if isinstance(t, (int, float)) else 0

        prev_ts = _ts(window[0])
        for i in range(1, N):
            b = window[i]
            st = _ts(b) - prev_ts
            if st < -6 * T: st = -6 * T
            if st >  6 * T: st =  6 * T
            if st < 1:      st = 1
            sum_wst += i * st

            bits_val = int(getattr(b, "bits", CFG.MAX_BITS))
            tgt  = bits_to_target(bits_val)
            diff = max(1, int(target_to_difficulty(tgt)))
            sum_diff += diff

            prev_ts = _ts(b)

        avg_diff = max(1, sum_diff // (N - 1))
        lwma_st  = max(1, sum_wst // k)
        next_diff = max(1, (avg_diff * T) // lwma_st)

        next_target = difficulty_to_target(next_diff)
        max_target  = bits_to_target(int(CFG.MAX_BITS))
        if next_target > max_target:
            next_target = max_target

            try:
                if CFG.ENABLE_DIFF_CLAMP:
                    prev_bits   = int(getattr(prefix[-1], "bits", CFG.MAX_BITS))
                    prev_target = bits_to_target(prev_bits)
                    factor = float(next_target) / float(prev_target or 1)
                    if factor > float(CFG.DIFF_CLAMP_MAX_UP):
                        next_target = int(prev_target * float(CFG.DIFF_CLAMP_MAX_UP))
                    elif factor < float(CFG.DIFF_CLAMP_MAX_DOWN):
                        next_target = int(prev_target * float(CFG.DIFF_CLAMP_MAX_DOWN))
                    if next_target > max_target:
                        next_target = max_target
            except Exception:
                pass

            try:
                if CFG.ENABLE_EDA:
                    T = int(CFG.TARGET_BLOCK_TIME)
                    M = min(int(CFG.EDA_WINDOW), len(prefix))
                    if M >= 2:
                        def _ts(b) -> int:
                            t = getattr(b, "timestamp", 0)
                            return int(t) if isinstance(t, (int, float)) else 0
                        times = [_ts(b) for b in prefix[-M:]]
                        intervals = []
                        for i in range(1, len(times)):
                            dt = times[i] - times[i-1]
                            if dt < 1: dt = 1
                            intervals.append(dt)
                        if intervals:
                            avg_dt = sum(intervals) / len(intervals)
                            if avg_dt > float(CFG.EDA_TRIGGER_RATIO) * T:
                                eased = int(bits_to_target(int(getattr(prefix[-1], "bits", CFG.MAX_BITS))) * float(CFG.EDA_EASE_MULTIPLIER))
                                next_target = min(int(eased), int(max_target))
            except Exception:
                pass

        return int(target_to_bits(next_target))

    def calculate_expected_bits(self, next_height: int) -> int:
        if next_height <= 0:
            return int(CFG.MAX_BITS)
        prefix = self.chain[:next_height]
        return self._expected_bits_on_prefix(prefix, next_height)

    def _validate_difficulty(self, block: Block) -> bool:
        if block.height == 0:
            return True
        try:
            expected_bits = self.calculate_expected_bits(block.height)
            if int(block.bits) != int(expected_bits):
                return False
            return True
        except Exception:
            log.exception("[_validate_difficulty] Error calculating expected bits")
            return False

    def _work_from_bits(self, bits: int) -> int:
        try:
            target = int(bits_to_target(bits))
            if target <= 0:
                return 0
            return (1 << 256) // (target + 1)
        except Exception:
            return 0

    def _compute_chainwork_for_chain(self, chain: List[Block]) -> int:
        cw = 0
        for b in chain:
            w = self._work_from_bits(b.bits)
            cw += w
            try:
                setattr(b, 'chainwork', cw)
            except Exception:
                pass
        return cw

    def _common_ancestor_height(self, other_chain_blocks: List[Block]) -> int:
        if not self.chain or not other_chain_blocks:
            return -1
        index = { self.chain[i].hash(): i for i in range(len(self.chain)) }
        for j in range(len(other_chain_blocks)-1, -1, -1):
            h = other_chain_blocks[j].hash()
            if h in index:
                return index[h]
        return -1

    def median_time_past(self, k: int = CFG.MTP_WINDOWS) -> int:
        if not self.chain:
            return 0

        def _to_int_ts(v):
            if isinstance(v, (int, float)):
                return int(v)
            return 0

        window = self.chain[-k:] if len(self.chain) >= k else self.chain
        times = sorted(_to_int_ts(getattr(b, "timestamp", 0)) for b in window)
        return times[len(times) // 2]
