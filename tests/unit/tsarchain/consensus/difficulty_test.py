# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from typing import List
from unittest.mock import Mock, patch

from tsarchain.core.block import Block
from tsarchain.consensus.difficulty import DifficultyManager


# --- Helper untuk membuat block dummy ---
def make_block(height: int, bits: int, timestamp: int, hash_val: bytes = b"dummyhash") -> Block:
    block = Mock(spec=Block)
    block.height = height
    block.bits = bits
    block.timestamp = timestamp
    block.hash = Mock(return_value=hash_val)
    return block


# --- Kelas turunan untuk menguji mixin ---
class DummyBlockchain:
    def __init__(self, chain: List[Block] = None):
        self.chain = chain or []


# --- Fixture untuk instance mixin ---
@pytest.fixture
def manager():
    return DifficultyManager(DummyBlockchain())


# --- Fixture untuk patch global CFG dan helpers ---
@pytest.fixture(autouse=True)
def patch_config_and_helpers():
    with patch("tsarchain.consensus.difficulty.CFG") as mock_cfg, \
         patch("tsarchain.consensus.difficulty.bits_to_target") as mock_bits_to_target, \
         patch("tsarchain.consensus.difficulty.target_to_bits") as mock_target_to_bits, \
         patch("tsarchain.consensus.difficulty.target_to_difficulty") as mock_target_to_difficulty, \
         patch("tsarchain.consensus.difficulty.difficulty_to_target") as mock_difficulty_to_target:

        mock_cfg.TARGET_BLOCK_TIME = 68
        mock_cfg.MAX_BITS = 0x1F9FFFFF
        mock_cfg.LWMA_WINDOW = 75
        mock_cfg.DIFF_CLAMP_MAX_UP = 1.5
        mock_cfg.DIFF_CLAMP_MAX_DOWN = 0.4
        mock_cfg.ENABLE_EDA = True
        mock_cfg.EDA_WINDOW = 48
        mock_cfg.EDA_TRIGGER_RATIO = 3.0
        mock_cfg.EDA_EASE_MULTIPLIER = 2.0
        mock_cfg.MTP_WINDOWS = 11

        # Mock fungsi helper
        def bits_to_target_side_effect(bits):
            if bits == 0:
                return 0
            exp = (bits >> 24) & 0xFF
            mant = bits & 0xFFFFFF
            if exp < 3:
                return 0
            return mant << (8 * (exp - 3))
        mock_bits_to_target.side_effect = bits_to_target_side_effect

        def target_to_bits_side_effect(target):
            if target <= 0:
                return 0
            # Cari exp dan mant
            exp = (target.bit_length() + 7) // 8
            if exp < 3:
                exp = 3
            mant = target >> (8 * (exp - 3))
            if mant > 0xFFFFFF:
                exp += 1
                mant >>= 8
            return (exp << 24) | (mant & 0xFFFFFF)
        mock_target_to_bits.side_effect = target_to_bits_side_effect

        def target_to_difficulty_side_effect(target):
            if target <= 0:
                return 1
            return (1 << 256) // (target + 1)
        mock_target_to_difficulty.side_effect = target_to_difficulty_side_effect

        def difficulty_to_target_side_effect(diff):
            if diff <= 0:
                return (1 << 256) - 1
            return (1 << 256) // (diff + 1) - 1
        mock_difficulty_to_target.side_effect = difficulty_to_target_side_effect

        yield mock_cfg, mock_bits_to_target, mock_target_to_bits, mock_target_to_difficulty, mock_difficulty_to_target


# ========================== TEST _expected_bits_on_prefix ==========================

def test_expected_bits_on_prefix_empty_or_zero_height(manager, patch_config_and_helpers):
    mock_cfg, _, _, _, _ = patch_config_and_helpers
    # next_height <= 0
    assert manager._expected_bits_on_prefix([], 0) == int(mock_cfg.MAX_BITS)
    assert manager._expected_bits_on_prefix([], -5) == int(mock_cfg.MAX_BITS)

    block = make_block(0, 0x1F9FFFFF, 1000)
    result = manager._expected_bits_on_prefix([block], 1)
    assert result == block.bits

    block_no_bits = make_block(0, 0, 1000)  # buat block biasa
    block_no_bits.bits = None               # set atribut bits ke None
    result = manager._expected_bits_on_prefix([block_no_bits], 1)
    assert result == int(mock_cfg.MAX_BITS)


def test_expected_bits_on_prefix_normal(manager, patch_config_and_helpers):
    mock_cfg, mock_bits_to_target, _, mock_target_to_difficulty, mock_difficulty_to_target = patch_config_and_helpers
    mock_cfg.LWMA_WINDOW = 3
    b0 = make_block(0, 0x1F9FFFFF, 0)
    b1 = make_block(1, 0x1F9FFFFF, 68)
    b2 = make_block(2, 0x1F9FFFFF, 136)
    prefix = [b0, b1, b2]
    result = manager._expected_bits_on_prefix(prefix, 3)
    assert isinstance(result, int)
    assert result > 0


def test_expected_bits_on_prefix_with_clamp(manager, patch_config_and_helpers):
    mock_cfg, _, _, _, _ = patch_config_and_helpers
    mock_cfg.LWMA_WINDOW = 2
    b0 = make_block(0, 0x1F9FFFFF, 0)
    b1 = make_block(1, 0x1F9FFFF0, 68)
    prefix = [b0, b1]
    with patch("tsarchain.consensus.difficulty.target_to_difficulty") as mock_t2d:
        def t2d_side_effect(target):
            if target == 0x9FFFFF << (8*(0x1F-3)):
                return 1
            else:
                return 1000
        mock_t2d.side_effect = t2d_side_effect
        result = manager._expected_bits_on_prefix(prefix, 2)
        assert isinstance(result, int)
        assert result > 0


def test_expected_bits_on_prefix_with_eda(manager, patch_config_and_helpers):
    mock_cfg, _, _, _, _ = patch_config_and_helpers
    mock_cfg.LWMA_WINDOW = 5
    mock_cfg.ENABLE_EDA = True
    mock_cfg.EDA_WINDOW = 3
    mock_cfg.EDA_TRIGGER_RATIO = 2.0
    mock_cfg.EDA_EASE_MULTIPLIER = 2.0
    b0 = make_block(0, 0x1F9FFFFF, 0)
    b1 = make_block(1, 0x1F9FFFFF, 200)
    b2 = make_block(2, 0x1F9FFFFF, 400)
    prefix = [b0, b1, b2]
    with patch("tsarchain.consensus.difficulty.target_to_difficulty") as mock_t2d:
        mock_t2d.return_value = 1
        result = manager._expected_bits_on_prefix(prefix, 3)
        # EDA akan aktif dan hasilnya max_bits
        assert result == int(mock_cfg.MAX_BITS)


# ========================== TEST calculate_expected_bits ==========================

def test_calculate_expected_bits(manager, patch_config_and_helpers):
    mock_cfg, _, _, _, _ = patch_config_and_helpers
    assert manager.calculate_expected_bits(0) == int(mock_cfg.MAX_BITS)
    assert manager.calculate_expected_bits(-1) == int(mock_cfg.MAX_BITS)
    assert manager.calculate_expected_bits(5) == int(mock_cfg.MAX_BITS)

    block = make_block(0, 0x1F9FFFFF, 0)
    manager.blockchain.chain = [block]
    result = manager.calculate_expected_bits(1)
    assert result == block.bits


# ========================== TEST _validate_difficulty ==========================

def test_validate_difficulty(manager):
    block0 = make_block(0, 0x123456, 100)
    assert manager._validate_difficulty(block0) is True

    block1 = make_block(1, 0x1F9FFFFF, 200)
    with patch.object(manager, 'calculate_expected_bits', return_value=0x1F9FFFFF):
        assert manager._validate_difficulty(block1) is True

    block2 = make_block(2, 0x123456, 300)
    with patch.object(manager, 'calculate_expected_bits', return_value=0x1F9FFFFF):
        assert manager._validate_difficulty(block2) is False


# ========================== TEST _work_from_bits ==========================

def test_work_from_bits(manager):
    bits = 0x1F9FFFFF
    work = manager._work_from_bits(bits)
    assert work > 0

    bits_zero = 0
    work_zero = manager._work_from_bits(bits_zero)
    assert work_zero == 0

    # bits yang menghasilkan target negatif (tidak mungkin) -> return 0
    with patch("tsarchain.consensus.difficulty.bits_to_target", return_value=-1):
        work_neg = manager._work_from_bits(0x1F9FFFFF)
        assert work_neg == 0


# ========================== TEST _compute_chainwork_for_chain ==========================

def test_compute_chainwork_for_chain(manager):
    b0 = make_block(0, 0x1F9FFFFF, 0)
    b1 = make_block(1, 0x1F9FFFFF, 68)
    b2 = make_block(2, 0x1F9FFFFF, 136)
    chain = [b0, b1, b2]
    with patch.object(manager, '_work_from_bits', side_effect=[10, 20, 30]) as mock_work:
        total_work = manager._compute_chainwork_for_chain(chain)
        assert total_work == 60
        assert chain[0].chainwork == 10
        assert chain[1].chainwork == 30
        assert chain[2].chainwork == 60


# ========================== TEST _common_ancestor_height ==========================

def test_common_ancestor_height(manager):
    b0 = make_block(0, 0, 0, hash_val=b"hash0")
    b1 = make_block(1, 0, 0, hash_val=b"hash1")
    b2 = make_block(2, 0, 0, hash_val=b"hash2")
    b0.hash = Mock(return_value=b"hash0")
    b1.hash = Mock(return_value=b"hash1")
    b2.hash = Mock(return_value=b"hash2")
    manager.blockchain.chain = [b0, b1, b2]

    # Chain lain dengan ancestor di height 1
    b0_other = make_block(0, 0, 0, hash_val=b"hash0")
    b1_other = make_block(1, 0, 0, hash_val=b"hash1")
    b2_other = make_block(2, 0, 0, hash_val=b"hash_other2")
    other_chain = [b0_other, b1_other, b2_other]
    ancestor = manager._common_ancestor_height(other_chain)
    assert ancestor == 1

    # Tidak ada common ancestor
    other_chain_no_common = [
        make_block(0, 0, 0, hash_val=b"no0"),
        make_block(1, 0, 0, hash_val=b"no1"),
    ]
    ancestor = manager._common_ancestor_height(other_chain_no_common)
    assert ancestor == -1

    # Chain kosong
    manager.blockchain.chain = []
    ancestor = manager._common_ancestor_height(other_chain)
    assert ancestor == -1

    # other_chain kosong
    manager.blockchain.chain = [b0, b1, b2]
    ancestor = manager._common_ancestor_height([])
    assert ancestor == -1


# ========================== TEST median_time_past ==========================

def test_median_time_past(manager, patch_config_and_helpers):
    mock_cfg, _, _, _, _ = patch_config_and_helpers
    mock_cfg.MTP_WINDOWS = 3

    # Chain kosong
    manager.blockchain.chain = []
    assert manager.median_time_past(k=3) == 0

    b0 = make_block(0, 0, 100)
    manager.blockchain.chain = [b0]
    assert manager.median_time_past(k=3) == 100

    b1 = make_block(1, 0, 200)
    manager.blockchain.chain = [b0, b1]
    assert manager.median_time_past(k=3) == 200

    b2 = make_block(2, 0, 150)
    manager.blockchain.chain = [b0, b1, b2]
    assert manager.median_time_past(k=3) == 150

    for i in range(3, 10):
        manager.blockchain.chain.append(make_block(i, 0, 100 + i * 10))

    assert manager.median_time_past(k=3) == 180
    assert manager.median_time_past(k=4) == 180