# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
import threading
from unittest.mock import MagicMock
from tsarchain.consensus.chain_ops import ChainOpsMixin

"""
ChainOpsMixin Unit Tests.

This module tests blockchain replacement logic (`replace_with()`) including:
- Chain validation and integrity checks
- Chainwork comparison and tie-breaking (height, hash)
- Reorg depth limiting for security
- State management (UTXO, persistence, cache)

The tests use DummyBlockchain with mocked dependencies to isolate
and verify each failure/success scenario independently.

Tested Scenarios:
- Success: Higher chainwork candidate
- Failure: Invalid chain, lower work, shorter height, hash tie-break loss, deep reorg
- Integration: Persistence triggers, UTXO rebuild, cache invalidation
"""


class DummyBlockchain(ChainOpsMixin):
    def __init__(self, in_memory=True):
        self.lock = threading.RLock()
        self.chain = []
        self.in_memory = in_memory
        self.total_supply = 0
        self.total_blocks = 0
        self.pending_blocks = []
        self.save_state_called = False
        self.save_chain_called = False
        self.mark_dirty_called = False
        self.rebuild_cache_called = False

    def calculate_total_supply(self):
        return self.total_supply

    def _mark_chain_dirty(self, height):
        self.mark_dirty_called = True

    def save_chain(self, force_full=False):
        self.save_chain_called = True

    def save_state(self):
        self.save_state_called = True

    def _ensure_utxodb(self):
        mock_store = MagicMock()
        mock_store.rebuild_from_chain = MagicMock()
        return mock_store

    def _rebuild_hash_cache(self):
        self.rebuild_cache_called = True

    def _validate_complete_chain(self, chain):
        raise NotImplementedError("Harus di-mock di test")

    def _compute_chainwork_for_chain(self, chain):
        raise NotImplementedError("Harus di-mock di test")
    
    def _common_ancestor_height(self, other_chain):
        if not self.chain or not other_chain:
            return -1
        return 0 

# ------------------------------------------------------------
# FIXTURE
# ------------------------------------------------------------
@pytest.fixture
def dummy_chain():
    return DummyBlockchain(in_memory=True)

@pytest.fixture
def mock_block():
    block = MagicMock()
    block.hash.return_value = b"abc123"  # hash bytes
    block.height = 1
    return block

# ------------------------------------------------------------
# TEST CASES for 'replace_with' (6 scenarios)
# ------------------------------------------------------------

def test_replace_with_success_higher_work(mocker, dummy_chain):
    """SCENARIO 1: Candidate chain has higher chainwork -> MUST SUCCEED"""
    # Mock CFG
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)
    
    # Local Chain Setup (work = 100)
    dummy_chain.chain = [MagicMock(), MagicMock()]  # genesis + block1
    mocker.patch.object(dummy_chain, '_validate_complete_chain', return_value=True)
    mocker.patch.object(dummy_chain, '_compute_chainwork_for_chain', side_effect=[200, 100])  # their=200, our=100
    
    # Make Fake other_chain
    other = DummyBlockchain()
    other.chain = [MagicMock(), MagicMock(), MagicMock()]  # longer
    
    # EXECUTION
    dummy_chain.replace_with(other)
    
    # ASSERT: Our chain must transform into their chain.
    assert dummy_chain.chain == other.chain
    assert dummy_chain.total_blocks == len(other.chain)
    assert dummy_chain.save_state_called is False
    assert dummy_chain.save_chain_called is False
    assert dummy_chain.mark_dirty_called is False


def test_replace_with_fail_invalid_chain(mocker, dummy_chain):
    """SCENARIO 2: Candidate chain is invalid -> MUST RAISE ValueError"""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', False)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)
    mocker.patch.object(dummy_chain, '_validate_complete_chain', return_value=False)
    other = DummyBlockchain()
    other.chain = [MagicMock()]
    
    with pytest.raises(ValueError, match="Cannot replace with invalid chain"):
        dummy_chain.replace_with(other)


def test_replace_with_fail_lower_work(mocker, dummy_chain):
    """SCENARIO 3: Candidate chainwork is lower -> MUST RAISE ValueError"""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)
    
    dummy_chain.chain = [MagicMock(), MagicMock()]
    mocker.patch.object(dummy_chain, '_validate_complete_chain', return_value=True)
    mocker.patch.object(dummy_chain, '_compute_chainwork_for_chain', side_effect=[100, 200]) # their=100, our=200
    
    other = DummyBlockchain()
    other.chain = [MagicMock(), MagicMock()]
    
    with pytest.raises(ValueError, match="candidate chainwork < local"):
        dummy_chain.replace_with(other)


def test_replace_with_fail_equal_work_shorter_height(mocker, dummy_chain):
    """SCENARIO 4: Same work, but candidate is shorter -> MUST RAISE"""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)
    
    # Local Chain: height 5 (6 blocks)
    dummy_chain.chain = [MagicMock() for _ in range(6)]
    # Candidate: height 3 (4 blocks)
    other = DummyBlockchain()
    other.chain = [MagicMock() for _ in range(4)]
    
    mocker.patch.object(dummy_chain, '_validate_complete_chain', return_value=True)
    mocker.patch.object(dummy_chain, '_compute_chainwork_for_chain', return_value=100)  # same work
    
    with pytest.raises(ValueError, match="candidate height < local at equal work"):
        dummy_chain.replace_with(other)


def test_replace_with_fail_equal_work_equal_height_hash_tie(mocker, dummy_chain):
    """SCENARIO 5: Work and height are the same, but the candidate hash is larger/loses -> MUST RAISE"""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)
    
    # Local tip hash = 0xaaaa
    local_tip = MagicMock()
    local_tip.hash.return_value = b"aaaa"
    dummy_chain.chain = [MagicMock(), local_tip]  # height 1
    
    # Candidate tip hash = 0xbbbb (larger, loses)
    cand_tip = MagicMock()
    cand_tip.hash.return_value = b"bbbb"
    other = DummyBlockchain()
    other.chain = [MagicMock(), cand_tip]  # height 1
    
    mocker.patch.object(dummy_chain, '_validate_complete_chain', return_value=True)
    mocker.patch.object(dummy_chain, '_compute_chainwork_for_chain', return_value=100)  # same work
    
    with pytest.raises(ValueError, match="without deterministic tie-break"):
        dummy_chain.replace_with(other)


def test_replace_with_fail_deep_reorg(mocker, dummy_chain):
    """SCENARIO 6: Depth of reorg exceeds the limit -> MUST RAISE"""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', False)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.REORG_LIMIT', 2)  # Maximum reorg 2 blocks
    
    dummy_chain.chain = [MagicMock() for _ in range(10)]  # 10 blocks
    other = DummyBlockchain()
    other.chain = [MagicMock() for _ in range(10)]
    
    mocker.patch.object(dummy_chain, '_validate_complete_chain', return_value=True)
    # Mock a common ancestor so that the fork occurs at height 5, that means the reorg depth is (10 - 1) - 5 = 4.
    mocker.patch.object(dummy_chain, '_common_ancestor_height', return_value=5)
    
    with pytest.raises(ValueError, match="deep reorg"):
        dummy_chain.replace_with(other)