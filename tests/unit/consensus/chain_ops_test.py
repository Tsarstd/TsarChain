# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import re
import time
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
        
# ============================================================
# TESTS FOR add_block, swap_tip_if_better, _prune_mempool_confirmed
# ============================================================

class ExtendedDummyBlockchain(DummyBlockchain):
    """A dummy with a basic implementation for the called method."""
    def __init__(self, in_memory=True):
        super().__init__(in_memory)
        self._utxo_dirty = False
        self._utxo_last_flush_height = -1
        self._utxo_synced = False
        self._hash_cache = {}
        self.mempool = None
        self.pending_blocks = []
        self.save_chain_calls = 0
        self.save_state_calls = 0
        self.mark_chain_dirty_calls = 0
        
    @property
    def height(self):
        """Return the current chain height (last block index), or -1 if empty."""
        return len(self.chain) - 1 if self.chain else -1

    def get_last_block(self):
        if self.chain:
            return self.chain[-1]
        return None

    def _schedule_persist(self, force_full=False, flush_force=False, save_state=False):
        self.save_chain_calls += 1
        if save_state:
            self.save_state_calls += 1

    def _mark_utxo_dirty(self):
        self._utxo_dirty = True

    def _ensure_utxodb(self):
        # Return mock UTXO store
        store = MagicMock()
        store.update = MagicMock()
        store.rebuild_from_chain = MagicMock()
        return store

    def _compute_txids_for_block(self, block):
        return True

    def _expected_bits_on_prefix(self, prefix, height):
        return 0x1d00ffff  # placeholder

    def _scheduled_reward(self, height):
        # Stub: return 50 * 10^8
        return 50_0000_0000

    def _work_from_bits(self, bits):
        return 1

    def get_mempool(self):
        if self.mempool is None:
            self.mempool = MagicMock()
            self.mempool.remove_many = MagicMock(return_value=0)
            self.mempool.drop_conflicts = MagicMock(return_value=0)
            self.mempool.prune_stale_entries = MagicMock(return_value=0)
            self.mempool.flush = MagicMock()
            self.mempool.remove_tx = MagicMock(return_value=True)
        return self.mempool

    def _common_ancestor_height(self, other_chain):
        return 0

    def _validate_complete_chain(self, chain):
        return True

    def _compute_chainwork_for_chain(self, chain):
        return len(chain)


def create_mock_block(height, prev_hash=None, hash_val=None, bits=0x1d00ffff, txs=None, timestamp=None):
    """Helper to create a mock block with the required attributes."""
    block = MagicMock()
    block.height = height
    block.prev_block_hash = prev_hash or b"0000"
    block.bits = bits
    block.transactions = txs or []
    block.timestamp = timestamp or int(time.time())
    if hash_val is not None:
        block.hash.return_value = hash_val
    else:
        block.hash.return_value = f"block{height}".encode()
    block.chainwork = 0
    block.difficulty = 0
    return block

# ---- Tests for add_block ----

def test_add_block_genesis_success(mocker):
    """Adding a genesis block when the chain is empty must succeed."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', None)

    bc = ExtendedDummyBlockchain(in_memory=True)
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    bc._ensure_utxodb = MagicMock(return_value=MagicMock())

    result = bc.add_block(genesis)
    assert result is True
    assert len(bc.chain) == 1
    assert bc.chain[0] == genesis
    assert bc.total_blocks == 1
    assert bc._hash_cache.get(0) == genesis.hash().hex()
    assert bc.save_chain_calls == 0

def test_add_block_genesis_hash_mismatch(mocker):
    """If GENESIS_HASH is set and the genesis hash does not match -> ValueError."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', b"expected_genesis_hash")

    bc = ExtendedDummyBlockchain(in_memory=True)
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"wrong_hash")
    with pytest.raises(ValueError, match="does not match TSAR_GENESIS_HASH"):
        bc.add_block(genesis)

def test_add_block_non_genesis_success(mocker):
    """Adding the next block with the correct height and prev_hash."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', None)

    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    bc.add_block(block0)

    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    # mock _ensure_utxodb
    bc._ensure_utxodb = MagicMock(return_value=MagicMock())
    result = bc.add_block(block1)
    assert result is True
    assert len(bc.chain) == 2
    assert bc.chain[-1] == block1
    assert bc.total_blocks == 2
    assert bc._hash_cache.get(1) == block1.hash().hex()

def test_add_block_height_mismatch(mocker):
    """Height block does not match last_height+1 -> ValueError."""
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000")
    bc.add_block(block0)
    block_wrong = create_mock_block(height=2, prev_hash=b"block0")  # should be 1
    with pytest.raises(ValueError, match="Height mismatch"):
        bc.add_block(block_wrong)

def test_add_block_prev_hash_mismatch(mocker):
    """prev_block_hash does not match the hash of the last block -> ValueError."""
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    bc.add_block(block0)
    block_wrong = create_mock_block(height=1, prev_hash=b"wrong_prev", hash_val=b"block1")
    with pytest.raises(ValueError, match="prev_block_hash does not match"):
        bc.add_block(block_wrong)

# ---- Tests for swap_tip_if_better ----

def test_swap_tip_if_better_success_higher_work(mocker):
    """Tip candidate with higher chainwork -> successful swap."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)

    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    bc.chain = [block0, block1]
    bc.total_blocks = 2

    candidate = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"candidate")
    bc._validate_complete_chain = MagicMock(return_value=True)
    bc._compute_chainwork_for_chain = MagicMock(side_effect=[5, 10])  # local=5, candidate=10

    old_tip = bc.swap_tip_if_better(candidate)
    assert old_tip == block1
    assert bc.chain[-1] == candidate
    assert bc.total_blocks == 2
    assert bc._hash_cache.get(1) == candidate.hash().hex()

def test_swap_tip_if_better_fail_lower_work(mocker):
    """Tip candidate with lower chainwork -> None."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    bc.chain = [block0, block1]
    bc._validate_complete_chain = MagicMock(return_value=True)
    # local=5, candidate=3 -> candidate has lower work
    bc._compute_chainwork_for_chain = MagicMock(side_effect=[5, 3])

    candidate = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"candidate")
    result = bc.swap_tip_if_better(candidate)
    assert result is None
    assert bc.chain[-1] == block1

def test_swap_tip_if_better_fail_parent_mismatch(mocker):
    """Candidate prev_block_hash does not match parent -> None."""
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    bc.chain = [block0, block1]
    candidate = create_mock_block(height=1, prev_hash=b"wrong_parent", hash_val=b"candidate")
    result = bc.swap_tip_if_better(candidate)
    assert result is None

def test_swap_tip_if_better_fail_height_mismatch(mocker):
    """Height candidate does not match -> None."""
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    bc.chain = [block0, block1]
    candidate = create_mock_block(height=2, prev_hash=b"block0", hash_val=b"candidate")
    result = bc.swap_tip_if_better(candidate)
    assert result is None

def test_swap_tip_if_better_fail_invalid_candidate_chain(mocker):
    """Candidate chain validation fails -> None."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', False)
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    bc.chain = [block0, block1]
    bc._validate_complete_chain = MagicMock(return_value=False)
    candidate = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"candidate")
    result = bc.swap_tip_if_better(candidate)
    assert result is None

def test_swap_tip_if_better_equal_work_hash_tie_win(mocker):
    """Same Work: smaller candidate hash -> swap successful."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")  # hash = b"block1"
    bc.chain = [block0, block1]
    bc._validate_complete_chain = MagicMock(return_value=True)
    # Work sama
    bc._compute_chainwork_for_chain = MagicMock(return_value=5)  # sama
    candidate = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block0")  # hash smaller than b"block1"
    old_tip = bc.swap_tip_if_better(candidate)
    assert old_tip == block1
    assert bc.chain[-1] == candidate

def test_swap_tip_if_better_equal_work_hash_tie_lose(mocker):
    """Same Work: larger candidate hash -> None."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    bc = ExtendedDummyBlockchain(in_memory=True)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    bc.chain = [block0, block1]
    bc._validate_complete_chain = MagicMock(return_value=True)
    bc._compute_chainwork_for_chain = MagicMock(return_value=5)
    candidate = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block2")  # more big hash
    result = bc.swap_tip_if_better(candidate)
    assert result is None
    assert bc.chain[-1] == block1

# ---- Tests for _prune_mempool_confirmed ----

def test_prune_mempool_confirmed_basic(mocker):
    """Ensure that `prune_mempool_confirmed` calls the appropriate pool method."""
    tx1 = MagicMock()
    tx1.is_coinbase = False
    txin1 = MagicMock()
    txin1.txid = b"txid1"
    txin1.vout = 0
    tx1.inputs = [txin1]
    tx1.txid = "a" * 64  # string 64

    tx2 = MagicMock()
    tx2.is_coinbase = False
    txin2 = MagicMock()
    txin2.txid = b"txid2"
    txin2.vout = 1
    tx2.inputs = [txin2]
    tx2.txid = "b" * 64

    coinbase = MagicMock()
    coinbase.is_coinbase = True

    block = MagicMock()
    block.transactions = [coinbase, tx1, tx2]

    bc = ExtendedDummyBlockchain(in_memory=True)
    pool_mock = MagicMock()
    pool_mock.remove_many = MagicMock(return_value=2)
    pool_mock.drop_conflicts = MagicMock(return_value=1)
    pool_mock.prune_stale_entries = MagicMock(return_value=1)
    pool_mock.flush = MagicMock()
    bc.mempool = pool_mock

    bc._prune_mempool_confirmed(block)

    pool_mock.remove_many.assert_called_once()
    called_args = pool_mock.remove_many.call_args[0][0]
    assert ("a" * 64) in called_args
    assert ("b" * 64) in called_args

    # drop_conflicts call with spent_prevouts
    pool_mock.drop_conflicts.assert_called_once()
    spent_prevouts_arg = pool_mock.drop_conflicts.call_args[0][0]
    assert (b"txid1".hex(), 0) in spent_prevouts_arg
    assert (b"txid2".hex(), 1) in spent_prevouts_arg

    pool_mock.prune_stale_entries.assert_called_once()
    pool_mock.flush.assert_called_once()

def test_prune_mempool_confirmed_no_txs(mocker):
    """If the block has no transactions other than the coinbase, no remove calls are made."""
    block = MagicMock()
    block.transactions = [MagicMock(is_coinbase=True)]
    bc = ExtendedDummyBlockchain(in_memory=True)
    pool_mock = MagicMock()
    bc.mempool = pool_mock
    bc._prune_mempool_confirmed(block)
    pool_mock.remove_many.assert_not_called()
    pool_mock.drop_conflicts.assert_not_called()
    pool_mock.prune_stale_entries.assert_not_called()
    pool_mock.flush.assert_not_called()
    
# ============================================================
# TESTS FOR _is_chain_consistent
# ============================================================

def test_is_chain_consistent_valid(mocker):
    """A valid chain with sequential heights and correct prev hashes -> True."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    bc = DummyBlockchain()
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    block1 = create_mock_block(height=1, prev_hash=b"genesis", hash_val=b"block1")
    bc.chain = [genesis, block1]
    assert bc._is_chain_consistent() is True


def test_is_chain_consistent_invalid_height(mocker):
    """Height sequence broken -> False."""
    bc = DummyBlockchain()
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    block1 = create_mock_block(height=2, prev_hash=b"genesis", hash_val=b"block1")  # should be 1
    bc.chain = [genesis, block1]
    assert bc._is_chain_consistent() is False


def test_is_chain_consistent_invalid_prev_hash(mocker):
    """prev_block_hash does not match parent hash -> False."""
    bc = DummyBlockchain()
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    block1 = create_mock_block(height=1, prev_hash=b"wrong", hash_val=b"block1")
    bc.chain = [genesis, block1]
    assert bc._is_chain_consistent() is False


def test_is_chain_consistent_empty(mocker):
    """Empty chain is considered consistent."""
    bc = DummyBlockchain()
    bc.chain = []
    assert bc._is_chain_consistent() is True


# ============================================================
# HELPER CLASS FOR _validate_complete_chain TESTS
# ============================================================

class ValidatorBlockchain(ChainOpsMixin):
    """Minimal mixin that does NOT override _validate_complete_chain."""
    def __init__(self):
        self.lock = threading.RLock()
        self.chain = []
        self.in_memory = True

    def _scheduled_reward(self, height):
        return 50_0000_0000  # 50 coins

    def _expected_bits_on_prefix(self, prefix, height):
        return 0x1d00ffff  # fixed bits

    def _compute_txids_for_block(self, block):
        return True  # assume txids are valid

    def _work_from_bits(self, bits):
        return 1

    def _compute_chainwork_for_chain(self, chain):
        return len(chain)


# ============================================================
# TESTS FOR _validate_complete_chain
# ============================================================

def test_validate_complete_chain_valid(mocker):
    """A fully valid chain (genesis + one block) -> True."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MAX_SUPPLY', 21_000_000 * 10**8)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MTP_WINDOWS', 11)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.FUTURE_DRIFT', 7200)
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', None)
    # Mock merkle_root to return a fixed value
    mocker.patch('tsarchain.consensus.chain_ops.merkle_root', return_value=b"merkle")

    bc = ValidatorBlockchain()

    # Genesis
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    genesis.bits = 0x1d00ffff
    cb = MagicMock()
    cb.is_coinbase = True
    cb.outputs = [MagicMock(amount=50_0000_0000)]
    genesis.transactions = [cb]
    genesis.merkle_root = b"merkle"
    genesis.timestamp = int(time.time())

    # Second block
    block1 = create_mock_block(height=1, prev_hash=b"genesis", hash_val=b"block1")
    block1.bits = 0x1d00ffff
    cb1 = MagicMock()
    cb1.is_coinbase = True
    cb1.outputs = [MagicMock(amount=50_0000_0000)]
    block1.transactions = [cb1]
    block1.merkle_root = b"merkle"
    block1.timestamp = int(time.time())

    chain = [genesis, block1]
    assert bc._validate_complete_chain(chain) is True


def test_validate_complete_chain_invalid_genesis_prev_hash(mocker):
    """Genesis prev_block_hash must be ZERO_HASH -> False."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MAX_SUPPLY', 21_000_000 * 10**8)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MTP_WINDOWS', 11)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.FUTURE_DRIFT', 7200)
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', None)
    mocker.patch('tsarchain.consensus.chain_ops.merkle_root', return_value=b"merkle")

    bc = ValidatorBlockchain()
    genesis = create_mock_block(height=0, prev_hash=b"wrong", hash_val=b"genesis")
    genesis.bits = 0x1d00ffff
    cb = MagicMock()
    cb.is_coinbase = True
    cb.outputs = [MagicMock(amount=50_0000_0000)]
    genesis.transactions = [cb]
    genesis.merkle_root = b"merkle"
    genesis.timestamp = int(time.time())

    chain = [genesis]
    assert bc._validate_complete_chain(chain) is False


def test_validate_complete_chain_invalid_coinbase_amount(mocker):
    """Coinbase output amount does not equal reward + fees -> False."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MAX_SUPPLY', 21_000_000 * 10**8)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MTP_WINDOWS', 11)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.FUTURE_DRIFT', 7200)
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', None)
    mocker.patch('tsarchain.consensus.chain_ops.merkle_root', return_value=b"merkle")

    bc = ValidatorBlockchain()
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    genesis.bits = 0x1d00ffff
    cb = MagicMock()
    cb.is_coinbase = True
    cb.outputs = [MagicMock(amount=123)]  # wrong amount
    genesis.transactions = [cb]
    genesis.merkle_root = b"merkle"
    genesis.timestamp = int(time.time())

    chain = [genesis]
    assert bc._validate_complete_chain(chain) is False


def test_validate_complete_chain_invalid_pow(mocker):
    """Block hash does not meet the target (bits too low) -> False."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MAX_SUPPLY', 21_000_000 * 10**8)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.MTP_WINDOWS', 11)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.FUTURE_DRIFT', 7200)
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', None)
    mocker.patch('tsarchain.consensus.chain_ops.merkle_root', return_value=b"merkle")
    # Force bits_to_target to return a very small target (so any hash fails)
    mocker.patch('tsarchain.consensus.chain_ops.bits_to_target', return_value=1)

    bc = ValidatorBlockchain()
    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    genesis.bits = 0x1d00ffff
    cb = MagicMock()
    cb.is_coinbase = True
    cb.outputs = [MagicMock(amount=50_0000_0000)]
    genesis.transactions = [cb]
    genesis.merkle_root = b"merkle"
    genesis.timestamp = int(time.time())

    chain = [genesis]
    assert bc._validate_complete_chain(chain) is False
    
# ============================================================
# TESTS FOR PERSISTENCE MODE (in_memory=False)
# ============================================================

def test_replace_with_persistent_mode(mocker):
    """When in_memory=False, replace_with should call save_chain, save_state, and rebuild UTXO."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)

    bc = ExtendedDummyBlockchain(in_memory=False)
    bc.chain = [MagicMock(), MagicMock()]  # local chain

    # Mock dependencies
    mocker.patch.object(bc, '_validate_complete_chain', return_value=True)
    mocker.patch.object(bc, '_compute_chainwork_for_chain', side_effect=[200, 100])  # higher work

    # Mock UTXO store
    mock_store = MagicMock()
    mock_store.rebuild_from_chain = MagicMock()
    bc._ensure_utxodb = MagicMock(return_value=mock_store)

    other = DummyBlockchain()
    other.chain = [MagicMock(), MagicMock(), MagicMock()]

    # Execute
    bc.replace_with(other)

    # Assert persistence calls
    assert bc.save_chain_called is True
    assert bc.save_state_called is True
    assert bc.mark_dirty_called is True
    mock_store.rebuild_from_chain.assert_called_once_with(bc.chain)
    # Check UTXO state flags
    assert bc._utxo_dirty is False
    assert bc._utxo_synced is True
    assert bc._utxo_last_flush_height == bc.height


def test_add_block_persistent_mode(mocker):
    """When in_memory=False, add_block should trigger _schedule_persist and UTXO update."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ZERO_HASH', b"0000")
    mocker.patch('tsarchain.consensus.chain_ops.GENESIS_HASH', None)

    bc = ExtendedDummyBlockchain(in_memory=False)
    # Reset call counters
    bc.save_chain_calls = 0
    bc.save_state_calls = 0

    # Mock UTXO store
    mock_store = MagicMock()
    mock_store.update = MagicMock()
    bc._ensure_utxodb = MagicMock(return_value=mock_store)

    genesis = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"genesis")
    bc.add_block(genesis)

    # Verify _schedule_persist was called (with force flags)
    assert bc.save_chain_calls == 1
    assert bc.save_state_calls == 1
    mock_store.update.assert_called_once()
    # Check that chain was marked dirty
    assert bc.mark_dirty_called is True


def test_swap_tip_if_better_persistent_mode(mocker):
    """When in_memory=False, swap_tip_if_better should call save_chain, save_state, and rebuild UTXO."""
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_CHAINWORK_RULE', True)
    mocker.patch('tsarchain.consensus.chain_ops.CFG.ENABLE_REORG_LIMIT', False)

    bc = ExtendedDummyBlockchain(in_memory=False)
    block0 = create_mock_block(height=0, prev_hash=b"0000", hash_val=b"block0")
    block1 = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"block1")
    bc.chain = [block0, block1]
    bc.total_blocks = 2

    # Mock validation and work
    bc._validate_complete_chain = MagicMock(return_value=True)
    bc._compute_chainwork_for_chain = MagicMock(side_effect=[5, 10])  # candidate better

    # Mock UTXO store
    mock_store = MagicMock()
    mock_store.rebuild_from_chain = MagicMock()
    bc._ensure_utxodb = MagicMock(return_value=mock_store)

    candidate = create_mock_block(height=1, prev_hash=b"block0", hash_val=b"candidate")
    old_tip = bc.swap_tip_if_better(candidate)

    assert old_tip == block1
    assert bc.save_chain_called is True
    assert bc.save_state_called is True
    assert bc.mark_dirty_called is True
    mock_store.rebuild_from_chain.assert_called_once_with(bc.chain)
    assert bc._utxo_dirty is False
    
# ============================================================
# TESTS FOR _has_pending_blocks
# ============================================================

def test_has_pending_blocks_true(mocker):
    """Should return True when pending_blocks is non-empty."""
    bc = ExtendedDummyBlockchain()
    bc.pending_blocks = [MagicMock(), MagicMock()]  # simulate pending blocks
    assert bc._has_pending_blocks() is True

def test_has_pending_blocks_false(mocker):
    """Should return False when pending_blocks is empty."""
    bc = ExtendedDummyBlockchain()
    bc.pending_blocks = []
    assert bc._has_pending_blocks() is False
    
# ============================================================
# TESTS FOR print_chain
# ============================================================

def create_attr_block(height, prev_hash=None, hash_val=None, bits=0x1d00ffff,
                                  txs=None, timestamp=None, block_id=None):
    """Helper to create a mock block with additional attributes for print_chain testing."""
    block = create_mock_block(height, prev_hash, hash_val, bits, txs, timestamp)
    if block_id is not None:
        block.block_id = block_id
    return block

def test_print_chain_empty_chain():
    """Printing an empty chain should only return the header."""
    bc = DummyBlockchain()
    bc.chain = []
    output = bc.print_chain()
    
    assert "height" in output
    assert "time" in output
    assert "txs" in output
    assert "block_id" in output
    assert "hash" in output
    assert "prev" in output
    lines = output.strip().split('\n')
    assert len(lines) == 1  # only header

def test_print_chain_default():
    """Default print_chain with a chain of several blocks."""
    bc = DummyBlockchain()
    txs1 = [MagicMock(), MagicMock()]  # coinbase + one tx
    txs2 = [MagicMock()]  # only coinbase
    txs3 = [MagicMock(), MagicMock(), MagicMock()]  # coinbase + 2 txs

    block0 = create_attr_block(height=0, prev_hash=b"0000", hash_val=b"genesis",
                                          txs=txs1, timestamp=1600000000, block_id="b0")
    block1 = create_attr_block(height=1, prev_hash=b"genesis", hash_val=b"block1",
                                          txs=txs2, timestamp=1600003600, block_id="b1")
    block2 = create_attr_block(height=2, prev_hash=b"block1", hash_val=b"block2",
                                          txs=txs3, timestamp=1600007200, block_id="b2")
    bc.chain = [block0, block1, block2]

    output = bc.print_chain()
    lines = output.strip().split('\n')
    # Header + 3 rows
    assert len(lines) == 4
    assert "0" in lines[1] and "2" in lines[1]  # height 0, txs=2
    assert "1" in lines[2] and "1" in lines[2]  # height 1, txs=1
    assert "2" in lines[3] and "3" in lines[3]  # height 2, txs=3
    assert "b0" in lines[1]
    assert "b1" in lines[2]
    assert "b2" in lines[3]
    assert "67656e657369" in lines[1]

def test_print_chain_max_blocks():
    """max_blocks limits the number of displayed blocks."""
    bc = DummyBlockchain()
    blocks = []
    for i in range(5):
        b = create_attr_block(height=i, prev_hash=b"prev", hash_val=f"block{i}".encode(),
                                         txs=[MagicMock()], timestamp=1600000000+i*3600)
        blocks.append(b)
    bc.chain = blocks

    output = bc.print_chain(max_blocks=2)
    lines = output.strip().split('\n')
    assert len(lines) == 3
    assert re.search(r'\s+3\s+\|', lines[1]) is not None
    assert re.search(r'\s+4\s+\|', lines[2]) is not None
    assert re.search(r'\s+0\s+\|', lines[1]) is None
    assert re.search(r'\s+0\s+\|', lines[2]) is None

def test_print_chain_custom_columns():
    """Custom columns selection."""
    bc = DummyBlockchain()
    block0 = create_attr_block(height=0, prev_hash=b"0000", hash_val=b"genesis",
                                          txs=[MagicMock()], timestamp=1600000000)
    block1 = create_attr_block(height=1, prev_hash=b"genesis", hash_val=b"block1",
                                          txs=[MagicMock(), MagicMock()], timestamp=1600003600)
    bc.chain = [block0, block1]

    # Only 'height' and 'txs'
    output = bc.print_chain(columns=("height", "txs"))
    lines = output.strip().split('\n')
    assert len(lines) == 3
    # Header should contain only those columns
    assert "height" in lines[0] and "txs" in lines[0]
    assert "time" not in lines[0]
    assert "hash" not in lines[0]
    assert "prev" not in lines[0]
    # Check rows contain height and txs
    assert "0" in lines[1] and "1" in lines[1]  # txs=1
    assert "1" in lines[2] and "2" in lines[2]  # txs=2

    output_invalid = bc.print_chain(columns=("invalid", "height"))
    lines_inv = output_invalid.strip().split('\n')
    assert "height" in lines_inv[0]
    assert "txs" not in lines_inv[0]
    assert len(lines_inv) == 3

def test_print_chain_widths_and_hash_len():
    """Custom widths and hash length."""
    bc = DummyBlockchain()
    block0 = create_attr_block(height=0, prev_hash=b"0000", hash_val=b"abcdefghijklmnop",
                                          txs=[MagicMock()], timestamp=1600000000)
    block1 = create_attr_block(height=1, prev_hash=b"abcdefghijklmnop", hash_val=b"1234567890123456",
                                          txs=[MagicMock()], timestamp=1600003600)
    bc.chain = [block0, block1]

    output = bc.print_chain(widths={"height": 10, "txs": 5}, hash_len=4)
    lines = output.strip().split('\n')
    assert "6162" in lines[1]
    assert "3132" in lines[2]

def test_print_chain_block_id_from_coinbase():
    """If block doesn't have block_id, it should be taken from coinbase transaction."""
    bc = DummyBlockchain()
    block0 = create_attr_block(height=0, prev_hash=b"0000", hash_val=b"genesis",
                                          txs=[MagicMock()], timestamp=1600000000)

    coinbase = MagicMock()
    coinbase.is_coinbase = True
    coinbase.block_id = "cb_id_123"
    block0.transactions = [coinbase]
    if hasattr(block0, 'block_id'):
        delattr(block0, 'block_id')

    bc.chain = [block0]
    output = bc.print_chain()
    assert "cb_id_123" in output

def test_print_chain_timestamp_formats():
    """Different timestamp formats (int, str, None)."""
    bc = DummyBlockchain()
    # Block with int timestamp
    b1 = create_attr_block(height=0, prev_hash=b"0000", hash_val=b"b1",
                                      txs=[MagicMock()], timestamp=1600000000)
    # Block with string timestamp (ISO format)
    b2 = create_attr_block(height=1, prev_hash=b"b1", hash_val=b"b2",
                                      txs=[MagicMock()], timestamp="2021-01-01T12:34:56Z")
    # Block with None timestamp: create then override
    b3 = create_attr_block(height=2, prev_hash=b"b2", hash_val=b"b3",
                                      txs=[MagicMock()], timestamp=None)
    b3.timestamp = None  # force None
    bc.chain = [b1, b2, b3]

    output = bc.print_chain()
    time_pattern = re.compile(r'\d{2}:\d{2}:\d{2}')
    times = re.findall(time_pattern, output)
    assert len(times) >= 2
    assert "--:--:--" in output

def test_print_chain_no_transactions():
    """Blocks with no transactions (or None) should show txs=0."""
    bc = DummyBlockchain()
    block0 = create_attr_block(height=0, prev_hash=b"0000", hash_val=b"genesis",
                                          txs=None, timestamp=1600000000)
    block1 = create_attr_block(height=1, prev_hash=b"genesis", hash_val=b"block1",
                                          txs=[], timestamp=1600003600)
    bc.chain = [block0, block1]
    output_txs = bc.print_chain(columns=("height", "txs"))
    lines_txs = output_txs.strip().split('\n')
    parts1 = [p.strip() for p in lines_txs[1].split('|')]
    parts2 = [p.strip() for p in lines_txs[2].split('|')]
    assert parts1[0] == '0' and parts1[1] == '0'
    assert parts2[0] == '1' and parts2[1] == '0'