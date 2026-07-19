# test_consensus_mixins.py
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md

"""
Unit tests for consensus mixins: RewardMixin and UTXOMixin.

These tests cover:
- Reward calculation (halving, supply caps, genesis bonus)
- UTXO store management (in-memory/persistent, rebuild, flush, sync)
"""

from __future__ import annotations

import pytest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tsarchain.consensus.rewards import RewardCalculator

# -------------------------------
# 1. Fixtures & Mocks
# -------------------------------

@pytest.fixture
def mock_config(monkeypatch):
    """Mock the config module with deterministic values for tests."""
    cfg = SimpleNamespace()
    # Monetary
    cfg.GENESIS_REWARD = True
    cfg.GENESIS_REWARD_AMOUNT = 2_500_000 * 100_000_000  # 250M TSAR
    cfg.INITIAL_REWARD = 250 * 100_000_000               # 25 TSAR
    cfg.BLOCKS_PER_HALVING = 235_000
    cfg.MAX_SUPPLY = 252_500_000 * 100_000_000
    cfg.ALLOW_AUTO_GENESIS = 1
    cfg.COINBASE_MATURITY = 3
    cfg.MAX_COINBASE_EXTRADATA = 95
    cfg.UTXO_FLUSH_INTERVAL = 10
    return cfg


@pytest.fixture
def mock_utxodb_class(monkeypatch):
    """Mock the UTXODB class to track instantiations and calls."""
    class MockUTXODB:
        def __init__(self, persist=True):
            self.persist = persist
            self.utxos = {}
            self._dirty = False
            self._dirty_keys = set()
            self._removed_keys = set()
            self._rewrite_all = False
            self.flush_calls = []
            self.rebuild_calls = []

        def flush(self, force=False):
            self.flush_calls.append(force)
            return True

        def rebuild_from_chain(self, chain):
            self.rebuild_calls.append(chain)
            self.utxos.clear()

        def clear(self):
            self.utxos.clear()

    return MockUTXODB


@pytest.fixture
def mock_logger(monkeypatch):
    """Mock the logger to avoid logging during tests."""
    mock_log = Mock()
    monkeypatch.setattr("tsarchain.consensus.utxo_validate.log", mock_log)
    return mock_log





class UTXOTestClass:
    """A dummy class that includes UTXOMixin and provides necessary attributes."""
    def __init__(self, chain=None, height=0, in_memory=False):
        self.chain = chain if chain is not None else []
        self.height = height
        self.in_memory = in_memory
        self._utxodb = None
        self._utxo_dirty = False
        self._utxo_last_flush_height = -1
        self._utxo_synced = False
        self._utxo_flush_interval = 10
        self._in_memory_utxodb = None
        self._in_memory_utxo_tip = -1
        # For genesis lock simulation
        self._utxo_last_flush_height = -1


# -------------------------------
# 2. Tests for RewardMixin
# -------------------------------

class TestRewardMixin:
    """Tests for the RewardMixin reward calculation logic."""

    def test_scheduled_reward_negative_height(self, mock_config, monkeypatch):
        """scheduled_reward returns 0 for negative height."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)

        class MockBC: pass
        obj = RewardCalculator(MockBC())
        assert obj.scheduled_reward(-1) == 0
        assert obj.scheduled_reward(-10) == 0

    def test_scheduled_reward_genesis(self, mock_config, monkeypatch):
        """scheduled_reward at height 0 returns genesis amount if enabled."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)
        class MockBC: pass
        obj = RewardCalculator(MockBC())
        expected = mock_config.GENESIS_REWARD_AMOUNT
        assert obj.scheduled_reward(0) == expected

        # Disable genesis reward
        mock_config.GENESIS_REWARD = False
        expected = mock_config.INITIAL_REWARD
        assert obj.scheduled_reward(0) == expected

    def testscheduled_reward_halving(self, mock_config, monkeypatch):
        """scheduled_reward computes halving correctly."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)
        class MockBC: pass
        obj = RewardCalculator(MockBC())
        initial = mock_config.INITIAL_REWARD
        halving = mock_config.BLOCKS_PER_HALVING

        # Height exactly at halving interval
        h = halving
        expected = initial // 2
        assert obj.scheduled_reward(h) == expected

        # Height before halving
        h = halving - 1
        expected = initial // (2 ** (0))  # halving count 0
        assert obj.scheduled_reward(h) == initial

        # After two halvings
        h = 2 * halving
        expected = initial // 4
        assert obj.scheduled_reward(h) == expected

        # After many halvings (reward becomes 0 due to integer division)
        h = 10 * halving
        expected = initial // (2 ** 10)
        assert obj.scheduled_reward(h) == expected

    def test_cumulative_supply_until_zero(self, mock_config, monkeypatch):
        """cumulative_supply_until returns 0 for height <=0."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)
        class MockBC: pass
        obj = RewardCalculator(MockBC())
        assert obj.cumulative_supply_until(0) == 0
        assert obj.cumulative_supply_until(-5) == 0

    def test_cumulative_supply_basic(self, mock_config, monkeypatch):
        """cumulative_supply_until sums rewards correctly without hitting cap."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)
        class MockBC: pass
        obj = RewardCalculator(MockBC())
        obj.scheduled_reward = lambda h: 10
        assert obj.cumulative_supply_until(3) == 30

    def test_cumulative_supply_cap(self, mock_config, monkeypatch):
        """cumulative_supply_until caps at MAX_SUPPLY."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)
        class MockBC: pass
        obj = RewardCalculator(MockBC())
        obj.scheduled_reward = lambda h: 100
        mock_config.MAX_SUPPLY = 250
        # height 5 would give 500 but cap at 250
        assert obj.cumulative_supply_until(5) == 250

    def test_get_block_reward(self, mock_config, monkeypatch):
        """get_block_reward returns min(base, remaining)."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)
        class MockBC: pass
        obj = RewardCalculator(MockBC())
        obj.scheduled_reward = lambda h: 100
        obj.cumulative_supply_until = lambda h: 50 if h == 10 else (950 if h == 20 else 0)
        # At height 10, remaining = max_supply - 50. Let's set max supply 1000
        mock_config.MAX_SUPPLY = 1000
        # base=100, remaining=1000-50=950 -> min=100
        assert obj.get_block_reward(10) == 100
        # At height 20, remaining=1000-950=50 -> min(100,50)=50
        assert obj.get_block_reward(20) == 50

        # Now test when remaining <= 0 (should return 0)
        mock_config.MAX_SUPPLY = 900
        # At height 20, remaining = 900 - 950 = -50 -> max(0, -50)=0 -> min=0
        assert obj.get_block_reward(20) == 0

        # Also verify height 10 still returns 100 (remaining positive)
        assert obj.get_block_reward(10) == 100  # remaining = 900-50=850 -> min(100,850)=100

    def test_calculate_total_supply(self, mock_config, monkeypatch):
        """calculate_total_supply uses chain length as tip height."""
        monkeypatch.setattr("tsarchain.consensus.rewards.CFG", mock_config)
        class MockBC: pass
        bc = MockBC()
        obj = RewardCalculator(bc)
        obj.cumulative_supply_until = lambda h: h * 100
        bc.chain = [1, 2, 3]
        assert obj.calculate_total_supply() == 300  # 3*100

        bc.chain = []  # length 0
        assert obj.calculate_total_supply() == 0


# -------------------------------
# 3. Tests for UTXOMixin
# -------------------------------

class TestUTXOValidator:
    """Tests for UTXOMixin UTXO store management."""

    def test_ensure_utxodb_in_memory_creates_store(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """ensure_utxodb creates in-memory UTXODB and rebuilds if needed."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = True
                self.chain = [b'block1', b'block2']
                self.height = 2
                self._in_memory_utxodb = None
                self._in_memory_utxo_tip = -1

        bc = MockBC()
        obj = UTXOValidator(bc)

        store = obj.ensure_utxodb()
        assert store is not None
        assert isinstance(store, mock_utxodb_class)
        # It should have called rebuild_from_chain because tip mismatch (-1 != height)
        assert store.rebuild_calls == [obj.blockchain.chain]
        # The store should be stored in _in_memory_utxodb
        assert obj.blockchain._in_memory_utxodb is store
        assert obj.blockchain._in_memory_utxo_tip == 2

        # Second call: tip matches, no rebuild
        store2 = obj.ensure_utxodb()
        assert store2 is store
        # No new rebuild
        assert len(store.rebuild_calls) == 1

    def test_ensure_utxodb_persistent_creates_and_syncs(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """ensure_utxodb persistent creates UTXODB and syncs if not synced."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = [b'block1']
                self.height = 1
                self._utxodb = None
                self._utxo_dirty = False
                self._utxo_last_flush_height = -1
                self._utxo_synced = False
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        obj.sync_calls = []
        def mock_sync(force=False):
            obj.sync_calls.append(force)
            bc._utxo_synced = True
        obj._sync_utxo_store = mock_sync
        store = obj.ensure_utxodb()
        assert obj.blockchain._utxodb is not None
        assert isinstance(obj.blockchain._utxodb, mock_utxodb_class)
        assert obj.sync_calls == [True]
        assert obj.blockchain._utxo_synced is True

        store2 = obj.ensure_utxodb()
        assert store2 is store
        assert len(obj.sync_calls) == 1

    def test_sync_utxo_store_chain_empty_no_clear_if_utxos_exist(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """When chain empty and UTXO store already has entries, avoid clearing."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = []
                self.height = 0
                self._utxodb = mock_utxodb_class()
                self._utxodb.utxos = {'key': 'value'}
                self._utxo_synced = False
                self._utxo_dirty = False
                self._utxo_last_flush_height = -1
                self._utxo_flush_interval = 10
        bc = MockBC()
        obj = UTXOValidator(bc)
        obj._sync_utxo_store()
        assert obj.blockchain._utxodb.utxos == {'key': 'value'}
        assert obj.blockchain._utxo_synced is True
        assert obj.blockchain._utxo_dirty is False
        assert obj.blockchain._utxo_last_flush_height == 0

    def test_sync_utxo_store_chain_empty_and_no_utxos_clears(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """When chain empty and UTXO store empty, clear it."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = []
                self.height = 0
                self._utxodb = mock_utxodb_class()
                self._utxodb.utxos = {}
                self._utxo_synced = False
                self._utxo_dirty = False
                self._utxo_last_flush_height = -1
                self._utxo_flush_interval = 10
        bc = MockBC()
        obj = UTXOValidator(bc)
        # Spy on flush
        with patch.object(obj.blockchain._utxodb, 'flush') as mock_flush:
            obj._sync_utxo_store()
            # Should call flush(force=True)
            mock_flush.assert_called_once_with(force=True)
        # No rebuild, just clear via flush
        # _utxo_synced becomes True
        assert obj.blockchain._utxo_synced is True

    def test_sync_utxo_store_chain_nonempty_rebuilds(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """When chain nonempty, rebuild_from_chain is called."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = [b'block1', b'block2']
                self.height = 2
                self._utxodb = mock_utxodb_class()
                self._utxo_synced = False
                self._utxo_dirty = False
                self._utxo_last_flush_height = -1
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        obj._sync_utxo_store()
        assert obj.blockchain._utxodb.rebuild_calls == [obj.blockchain.chain]
        assert obj.blockchain._utxo_synced is True
        assert obj.blockchain._utxo_dirty is False
        assert obj.blockchain._utxo_last_flush_height == 2

    def testmaybe_flush_utxo_in_memory_does_nothing(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """In-memory mode: maybe_flush_utxo does nothing."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = True
                self.chain = [b'block1']
                self.height = 1
                self._utxodb = None
                self._utxo_dirty = False
                self._utxo_last_flush_height = -1
                self._utxo_synced = True
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        # Ensure no store created
        obj.maybe_flush_utxo()
        # Nothing should happen
        assert obj.blockchain._utxodb is None

    def testmaybe_flush_utxo_not_dirty_skip(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """If not dirty, skip flush."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = [b'block1']
                self.height = 1
                self._utxodb = mock_utxodb_class()
                self._utxo_dirty = False  # not dirty
                self._utxo_last_flush_height = -1
                self._utxo_synced = True
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        with patch.object(obj.blockchain._utxodb, 'flush') as mock_flush:
            obj.maybe_flush_utxo()
            mock_flush.assert_not_called()

    def testmaybe_flush_utxo_flush_interval_not_reached(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """Skip flush if interval not reached."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = [b'block1']
                self.height = 5
                self._utxodb = mock_utxodb_class()
                self._utxo_dirty = True
                self._utxo_last_flush_height = 0  # interval=10, height=5, diff=5 <10
                self._utxo_synced = True
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        with patch.object(obj.blockchain._utxodb, 'flush') as mock_flush:
            obj.maybe_flush_utxo()
            mock_flush.assert_not_called()

    def testmaybe_flush_utxo_flush_interval_reached(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """Flush when interval reached and dirty."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = [b'block1']
                self.height = 15
                self._utxodb = mock_utxodb_class()
                self._utxo_dirty = True
                self._utxo_last_flush_height = 0  # diff=15 >=10
                self._utxo_synced = True
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        with patch.object(obj.blockchain._utxodb, 'flush') as mock_flush:
            obj.maybe_flush_utxo()
            mock_flush.assert_called_once_with()  # flush() no force
            assert obj.blockchain._utxo_dirty is False
            assert obj.blockchain._utxo_last_flush_height == 15

    def testmaybe_flush_utxo_force_true(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """force=True triggers flush regardless of dirty and interval."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = [b'block1']
                self.height = 5
                self._utxodb = mock_utxodb_class()
                self._utxo_dirty = False  # not dirty but force
                self._utxo_last_flush_height = 0
                self._utxo_synced = True
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        with patch.object(obj.blockchain._utxodb, 'flush') as mock_flush:
            obj.maybe_flush_utxo(force=True)
            mock_flush.assert_called_once_with(force=True)
            assert obj.blockchain._utxo_dirty is False  # remains False
            assert obj.blockchain._utxo_last_flush_height == 5

    def testmaybe_flush_utxo_genesis_lock_skip(self, mock_config, mock_utxodb_class, mock_logger, monkeypatch):
        """When chain empty and genesis lock active, skip flush."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.UTXODB", mock_utxodb_class)
        mock_config.ALLOW_AUTO_GENESIS = 0
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.GENESIS_HASH", b'fakehash')

        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self.chain = []  # empty
                self.height = 0
                self._utxodb = mock_utxodb_class()
                self._utxo_dirty = True
                self._utxo_last_flush_height = -1
                self._utxo_synced = True
                self._utxo_flush_interval = 10

        bc = MockBC()
        obj = UTXOValidator(bc)
        with patch.object(obj.blockchain._utxodb, 'flush') as mock_flush:
            obj.maybe_flush_utxo()  # not force
            mock_flush.assert_not_called()
            # _utxo_dirty remains True (no flush)
            assert obj.blockchain._utxo_dirty is True
            
        with patch.object(obj.blockchain._utxodb, 'flush') as mock_flush:
            obj.maybe_flush_utxo(force=True)
            mock_flush.assert_called_once_with(force=True)
            assert obj.blockchain._utxo_dirty is False
            assert obj.blockchain._utxo_last_flush_height == 0

    def test_mark_utxo_dirty(self, mock_config, monkeypatch):
        """mark_utxo_dirty sets dirty flag if not in_memory."""
        monkeypatch.setattr("tsarchain.consensus.utxo_validate.CFG", mock_config)
        from tsarchain.consensus.utxo_validate import UTXOValidator

        class MockBC:
            def __init__(self):
                self.in_memory = False
                self._utxo_dirty = False

        bc = MockBC()
        obj = UTXOValidator(bc)
        obj.mark_utxo_dirty()
        assert obj.blockchain._utxo_dirty is True

        # In memory: no effect
        obj.blockchain.in_memory = True
        obj.blockchain._utxo_dirty = False
        obj.mark_utxo_dirty()
        assert obj.blockchain._utxo_dirty is False