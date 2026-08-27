# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import pytest
from unittest.mock import Mock, MagicMock, patch

from tsarchain.consensus.blockchain import Blockchain

# -----------------------------------------------------------------------------
# Fixtures for mocking external dependencies
# -----------------------------------------------------------------------------

@pytest.fixture
def mock_block_module():
    """Mock the Block class used inside blockchain module."""
    with patch('tsarchain.consensus.blockchain.Block') as MockBlock:
        block_instance = Mock()
        block_instance.hash.return_value = b'abcdefgh' * 4
        block_instance.height = 0
        block_instance.to_dict.return_value = {'height': 0, 'hash': 'abcdefgh' * 4}
        MockBlock.from_dict.return_value = block_instance
        yield MockBlock


@pytest.fixture
def mock_utxo():
    """Mock UTXODB from storage.utxo."""
    with patch('tsarchain.storage.utxo.UTXODB') as MockUTXODB:
        mock_db = Mock()
        MockUTXODB.return_value = mock_db
        yield mock_db


@pytest.fixture
def mock_mempool():
    """Mock TxPool from mempool.pool."""
    with patch('tsarchain.mempool.pool.TxPool') as MockTxPool:
        yield MockTxPool


@pytest.fixture(autouse=True)
def mock_kv():
    """Mock iter_prefix and _ensure_env from storage.kv across modules."""
    mock_iter_prefix = Mock(return_value=[])
    mock_store = MagicMock()
    with patch('tsarchain.consensus.chain_storage.iter_prefix', mock_iter_prefix), \
         patch('tsarchain.storage.kv.iter_prefix', mock_iter_prefix), \
         patch('tsarchain.storage.kv._ensure_env', return_value=mock_store):
        yield mock_iter_prefix


@pytest.fixture(autouse=True)
def mock_empty_genesis_state():
    with patch('tsarchain.consensus.blockchain.GenesisManager._persist_empty_state_if_needed'):
        yield


@pytest.fixture
def mock_config(monkeypatch):
    """Mock CFG attributes safely without replacing CFG with a bare MagicMock."""
    import tsarchain.consensus.blockchain as bc_mod
    import tsarchain.consensus.chain_storage as cs_mod

    monkeypatch.setattr(bc_mod.CFG, "HASH_CACHE_MAX", 100)
    monkeypatch.setattr(bc_mod.CFG, "UTXO_FLUSH_INTERVAL", 10)
    monkeypatch.setattr(bc_mod.CFG, "NODE_DATA_DIR", "/tmp/non_existent_lmdb")

    monkeypatch.setattr(cs_mod.CFG, "LMDB_CHAIN_DIR", "/tmp/non_existent_blocks.json")
    monkeypatch.setattr(cs_mod.CFG, "NODE_DATA_DIR", "/tmp/non_existent_lmdb")
    monkeypatch.setattr(cs_mod.CFG, "BLOCK_BACKUP_SNAPSHOT", 0)
    yield bc_mod.CFG


@pytest.fixture
def mock_logger():
    """Mock get_ctx_logger."""
    with patch('tsarchain.consensus.blockchain.get_ctx_logger') as get_logger:
        logger = Mock()
        get_logger.return_value = logger
        yield logger





# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

def test_init_default(mock_config):
    """Blockchain default initialisation."""
    with patch.object(Blockchain, 'load_chain'), patch.object(Blockchain, 'load_state'):
        bc = Blockchain()
        assert bc.chain == []
        assert bc.total_blocks == 0
        assert bc.total_supply == 0
        assert bc.height == -1
        assert bc.get_last_block() is None
        assert len(bc._hash_cache) == 0


def test_init_with_miner_address(mock_config):
    with patch.object(Blockchain, 'load_chain'), patch.object(Blockchain, 'load_state'):
        bc = Blockchain(miner_address="tsar1abc")
        assert bc.miner_address == "tsar1abc"


def test_property_height(mock_config):
    bc = Blockchain()
    block1 = Mock()
    block1.height = 0
    block2 = Mock()
    block2.height = 1
    bc.chain = [block1, block2]
    assert bc.height == 1


def test_get_last_block(mock_config):
    bc = Blockchain()
    block1 = Mock()
    block2 = Mock()
    bc.chain = [block1, block2]
    assert bc.get_last_block() is block2


def test_rebuild_hash_cache(mock_config):
    bc = Blockchain()
    # Create blocks with deterministic hashes
    block0 = Mock()
    block0.hash.return_value = b'hash0' + b'\x00' * 28
    block0.height = 0
    block1 = Mock()
    block1.hash.return_value = b'hash1' + b'\x00' * 28
    block1.height = 1
    bc.chain = [block0, block1]
    bc._rebuild_hash_cache()
    assert len(bc._hash_cache) == 2
    assert bc._hash_cache[0] == (b'hash0' + b'\x00' * 28).hex()
    assert bc._hash_cache[1] == (b'hash1' + b'\x00' * 28).hex()


def test_get_block_hash_cache(mock_config):
    bc = Blockchain()
    block0 = Mock()
    block0.hash.return_value = b'hash0' + b'\x00' * 28
    block0.height = 0
    block1 = Mock()
    block1.hash.return_value = b'hash1' + b'\x00' * 28
    block1.height = 1
    bc.chain = [block0, block1]
    bc._rebuild_hash_cache()

    # Test cache hit
    h0 = bc.get_block_hash(0)
    assert h0 == (b'hash0' + b'\x00' * 28).hex()
    # Test cache miss (height not in cache)
    h1 = bc.get_block_hash(1)
    assert h1 == (b'hash1' + b'\x00' * 28).hex()
    # Test invalid heights
    assert bc.get_block_hash(10) is None
    assert bc.get_block_hash(1) == (b'hash1' + b'\x00' * 28).hex()


def test_get_block_hash_fallback(mock_config):
    bc = Blockchain()
    block0 = Mock()
    block0.hash.return_value = b'hash0' + b'\x00' * 28
    block0.height = 0
    bc.chain = [block0]
    # Ensure cache is empty
    bc._hash_cache = {}
    h = bc.get_block_hash(0)
    assert h == (b'hash0' + b'\x00' * 28).hex()
    # Cache should now have the entry
    assert 0 in bc._hash_cache


def test_reload_chain_from_kv(mock_config):
    """Successfully reload chain from LMDB via load_chain and load_state."""
    with patch.object(Blockchain, 'load_chain') as mock_load, \
         patch.object(Blockchain, 'load_state') as mock_state:
        bc = Blockchain()
        def fake_load():
            bc.chain = [Mock(height=0)]
        mock_load.side_effect = fake_load
        res = bc._reload_chain_from_kv()
        assert res is True
        assert len(bc.chain) == 1


def test_reload_chain_from_kv_empty(mock_config):
    """Reload returns False when chain remains empty."""
    with patch.object(Blockchain, 'load_chain'), patch.object(Blockchain, 'load_state'):
        bc = Blockchain()
        bc.chain = []
        result = bc._reload_chain_from_kv()
        assert result is False
        assert bc.chain == []


def test_to_dict(mock_config):
    bc = Blockchain()
    block0 = Mock()
    block0.to_dict.return_value = {'height': 0}
    block1 = Mock()
    block1.to_dict.return_value = {'height': 1}
    bc.chain = [block0, block1]
    result = bc.to_dict()
    assert result == [{'height': 0}, {'height': 1}]


def test_from_dict(mock_config, mock_block_module):
    data_list = [{'height': 0}, {'height': 1}]
    bc = Blockchain.from_dict(data_list)

    assert isinstance(bc, Blockchain)
    assert len(bc.chain) == 2
    assert bc.total_blocks == 2
    assert bc.total_supply == 0
    assert mock_block_module.from_dict.call_count == 2


def test_attach_mempool(mock_config):
    bc = Blockchain()
    assert bc.get_mempool_size() == 0
    mock_pool = Mock()
    mock_pool._pool = {"tx1": "data", "tx2": "data"}
    bc.attach_mempool(mock_pool)
    assert bc.get_mempool() is mock_pool
    assert bc.get_mempool_size() == 2


def test_shutdown(mock_config):
    bc = Blockchain()
    with patch.object(bc, '_stop_persist_worker') as mock_stop:
        bc.shutdown()
        mock_stop.assert_called_once()


def test_start_persist_worker(mock_config):
    """Worker thread is started on Blockchain init."""
    with patch('threading.Thread') as mock_thread, \
         patch('queue.Queue') as mock_queue, \
         patch.object(Blockchain, 'load_chain', autospec=True) as mock_load, \
         patch.object(Blockchain, 'load_state', autospec=True) as mock_state:
        thread_instance = Mock()
        mock_thread.return_value = thread_instance
        queue_instance = Mock()
        mock_queue.return_value = queue_instance

        bc = Blockchain()
        mock_thread.assert_called_once()
        thread_instance.start.assert_called_once()
        assert bc._persist_queue is not None
        mock_load.assert_called_once()
        mock_state.assert_called_once()


def test_schedule_persist(mock_config):
    with patch('threading.Thread') as mock_thread, \
         patch('queue.Queue') as mock_queue, \
         patch.object(Blockchain, 'load_chain', autospec=True), \
         patch.object(Blockchain, 'load_state', autospec=True):
        queue_instance = Mock()
        mock_queue.return_value = queue_instance
        bc = Blockchain()

        with patch.object(bc, 'save_chain') as mock_save_chain, \
             patch.object(bc, 'maybe_flush_utxo') as mock_flush, \
             patch.object(bc, 'save_state') as mock_save_state:

            # Synchronous (wait=True)
            bc._schedule_persist(force_full=True, flush_force=True, save_state=False, wait=True)
            mock_save_chain.assert_called_once_with(force_full=True)
            mock_flush.assert_called_once_with(force=True)
            mock_save_state.assert_not_called()

            mock_save_chain.reset_mock()
            mock_flush.reset_mock()
            mock_save_state.reset_mock()

            # Asynchronous (wait=False)
            bc._schedule_persist(force_full=False, flush_force=False, save_state=True, wait=False)
            queue_instance.put.assert_called_once()
            assert bc._persist_opts['force_full'] is False
            assert bc._persist_opts['flush_force'] is False
            assert bc._persist_opts['save_state'] is True
            assert bc._persist_pending is True


def test_stop_persist_worker(mock_config):
    with patch('threading.Thread') as mock_thread, \
         patch('queue.Queue') as mock_queue, \
         patch.object(Blockchain, 'load_chain', autospec=True), \
         patch.object(Blockchain, 'load_state', autospec=True), \
         patch('tsarchain.consensus.blockchain.GenesisManager._persist_empty_state_if_needed'), \
         patch('tsarchain.consensus.genesis.GENESIS_HASH', None):
        queue_instance = Mock()
        mock_queue.return_value = queue_instance
        thread_instance = Mock()
        thread_instance.is_alive.return_value = False
        mock_thread.return_value = thread_instance

        bc = Blockchain()
        bc.chain = [Mock()]
        bc._persist_thread = thread_instance
        bc._persist_queue = queue_instance
        bc._persist_stop = Mock()

        with patch.object(bc, 'save_chain') as mock_save_chain, \
             patch.object(bc, 'maybe_flush_utxo') as mock_flush, \
             patch.object(bc, 'save_state') as mock_save_state:

            bc._stop_persist_worker()

            bc._persist_stop.set.assert_called_once()
            queue_instance.put.assert_called_with(None, timeout=1.0)
            thread_instance.join.assert_called_with(timeout=5.0)

            mock_save_chain.assert_called_with(force_full=True)
            mock_flush.assert_called_with(force=True)
            mock_save_state.assert_called()

            assert bc._persist_thread is None
            assert bc._persist_queue is None


def test_init_auto_genesis_disabled(mock_config, mock_kv):
    """When no chain exists, blockchain stays empty."""
    with patch.object(Blockchain, 'load_chain', autospec=True) as mock_load_chain, \
        patch.object(Blockchain, 'load_state', autospec=True) as mock_load_state, \
        patch.object(Blockchain, '_reload_chain_from_kv', return_value=False) as mock_reload_kv, \
        patch('tsarchain.consensus.blockchain.GenesisManager._persist_empty_state_if_needed') as mock_persist_empty, \
        patch.object(Blockchain, '_start_persist_worker', autospec=True) as mock_start_worker, \
        patch('tsarchain.consensus.blockchain.GenesisManager._enforce_genesis_lock') as mock_enforce:

        mock_load_chain.return_value = None  # no chain loaded
        bc = Blockchain()
        assert bc.chain == []
        assert bc.total_blocks == 0
        mock_load_chain.assert_called_once()
        mock_load_state.assert_called_once()
        mock_persist_empty.assert_called_once()
        mock_start_worker.assert_called_once()
        mock_enforce.assert_not_called()


def test_init_chain_exists(mock_config):
    """When load_chain fills the chain, genesis lock and hash cache are rebuilt."""
    with patch.object(Blockchain, 'load_chain', autospec=True) as mock_load_chain, \
        patch.object(Blockchain, 'load_state', autospec=True) as mock_load_state, \
        patch.object(Blockchain, '_start_persist_worker', autospec=True) as mock_start_worker, \
        patch('tsarchain.consensus.blockchain.GenesisManager._enforce_genesis_lock', autospec=True) as mock_enforce, \
        patch.object(Blockchain, '_rebuild_hash_cache', autospec=True) as mock_rebuild, \
        patch('tsarchain.consensus.genesis.GENESIS_HASH', None):

        block_mock = Mock()
        block_mock.height = 0

        def load_chain_side_effect(self):
            self.chain = [block_mock]
            self.total_blocks = 1

        mock_load_chain.side_effect = load_chain_side_effect

        bc = Blockchain()
        assert len(bc.chain) == 1
        assert bc.total_blocks == 1
        mock_load_chain.assert_called_once()
        mock_load_state.assert_called_once()
        mock_start_worker.assert_called_once()
        mock_enforce.assert_called_once()
        mock_rebuild.assert_called_once()

def test_hash_cache_lru(mock_config):
    """Ensure the hash cache does not exceed HASH_CACHE_MAX and implements LRU."""
    mock_config.HASH_CACHE_MAX = 2
    bc = Blockchain()

    # Make 3 bloks
    block0 = Mock()
    block0.hash.return_value = b'hash0' + b'\x00' * 28
    block0.height = 0
    block1 = Mock()
    block1.hash.return_value = b'hash1' + b'\x00' * 28
    block1.height = 1
    block2 = Mock()
    block2.hash.return_value = b'hash2' + b'\x00' * 28
    block2.height = 2
    bc.chain = [block0, block1, block2]

    bc.get_block_hash(0)
    bc.get_block_hash(1)
    bc.get_block_hash(2)

    assert len(bc._hash_cache) == 2
    assert 0 not in bc._hash_cache
    assert 1 in bc._hash_cache
    assert 2 in bc._hash_cache
    
def test_reload_chain_from_kv_exception(mock_config):
    """Reload handles exception gracefully and returns False."""
    with patch.object(Blockchain, 'load_chain'), patch.object(Blockchain, 'load_state'):
        bc = Blockchain()
        bc.load_chain = Mock(side_effect=Exception("LMDB error"))
        result = bc._reload_chain_from_kv()
        assert result is False


def test_blockchain_expected_bits_proxy():
    """Verify Blockchain._expected_bits_on_prefix proxies to DifficultyManager."""
    with patch('tsarchain.consensus.blockchain.BlockValidator'), \
         patch('tsarchain.consensus.blockchain.ChainOperations'), \
         patch('tsarchain.consensus.blockchain.ChainStorage'):
        bc = Blockchain()
        mock_diff = MagicMock()
        mock_diff._expected_bits_on_prefix.return_value = 0x1d00ffff
        bc.difficulty_manager = mock_diff

        result = bc._expected_bits_on_prefix(["dummy_block"], 5)
        assert result == 0x1d00ffff
        mock_diff._expected_bits_on_prefix.assert_called_once_with(["dummy_block"], 5)