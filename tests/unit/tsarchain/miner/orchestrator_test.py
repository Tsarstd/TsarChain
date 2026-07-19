# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import time
import pytest
import signal
from unittest.mock import MagicMock, patch

from tsarchain.miner.orchestrator import (
    SimpleMiner, 
    NodeRunner, 
    _stamp, 
    set_clog_func, 
    clog,
    _enable_siginterrupt, 
    _register_bootstrap_peers,
    _run_snapshot_bootstrap,
)


# --- Setup & Fixtures ---

@pytest.fixture
def mock_config(monkeypatch):
    monkeypatch.setattr("tsarchain.miner.orchestrator.CFG.BOOTSTRAP_NODES", [("127.0.0.1", 8080)])
    monkeypatch.setattr("tsarchain.miner.orchestrator.CFG.SYNC_TIMEOUT", 1)

@pytest.fixture
def mock_network_cls():
    with patch("tsarchain.miner.orchestrator.Network") as mock:
        yield mock

@pytest.fixture
def mock_blockchain_cls():
    with patch("tsarchain.miner.orchestrator.Blockchain") as mock:
        yield mock


# --- Helper Functions Tests ---

def test_stamp():
    s = _stamp()
    assert isinstance(s, str)
    assert "." in s

def test_clog_custom_func():
    out = []
    def my_clog(msg, color):
        out.append((msg, color))
    set_clog_func(my_clog)
    clog("test message", "red")
    assert len(out) == 1
    assert out[0] == ("test message", "red")
    set_clog_func(None)  # Reset to default

def test_enable_siginterrupt():
    # Calling this should not raise any exceptions
    _enable_siginterrupt()

def test_register_bootstrap_peers(mock_config):
    net_mock = MagicMock()
    net_mock.persistent_peers = set()
    net_mock.peers = set()
    net_mock._is_self_bootstrap = lambda h, p: False
    
    count = _register_bootstrap_peers(net_mock)
    assert count == 1
    assert ("127.0.0.1", 8080) in net_mock.peers
    assert ("127.0.0.1", 8080) in net_mock.persistent_peers

@patch("tsarchain.miner.orchestrator.maybe_bootstrap_snapshot")
def test_run_snapshot_bootstrap(mock_maybe_bootstrap):
    mock_maybe_bootstrap.return_value = MagicMock(status="installed", reason="")
    res = _run_snapshot_bootstrap(True)
    assert res.status == "installed"
    
    # If disabled, should return None
    res_false = _run_snapshot_bootstrap(False)
    assert res_false is None


# --- SimpleMiner Tests (Skipping start_mining) ---

@pytest.fixture
def miner():
    # Using a valid length tsarchain address
    return SimpleMiner("tsar1" + "a" * 24, cores=1, bootstrap_snapshot=False)

def test_miner_validate_address():
    m_invalid = SimpleMiner("invalid_addr", 1)
    assert m_invalid.validate_address() is False
    
    m_valid = SimpleMiner("tsar1" + "a" * 24, 1)
    assert m_valid.validate_address() is True

def test_miner_signal_handler(miner):
    assert miner.mining_alive is True
    assert not miner.cancel_mining.is_set()
    
    miner.signal_handler(signal.SIGINT, None)
    
    assert miner.mining_alive is False
    assert miner.cancel_mining.is_set()

def test_miner_queue_block_for_broadcast(miner):
    block_mock = MagicMock()
    block_mock.hash.return_value.hex.return_value = "deadbeef"
    
    # Queue new block
    miner._queue_block_for_broadcast(block_mock)
    assert "deadbeef" in miner._pending_block_hashes
    assert len(miner._pending_blocks) == 1
    
    # Queue duplicate block (should be ignored)
    miner._queue_block_for_broadcast(block_mock)
    assert len(miner._pending_blocks) == 1

def test_miner_flush_pending_blocks(miner):
    miner.network = MagicMock()
    miner.network.publish_block.return_value = 1
    
    block_mock = MagicMock()
    block_mock.hash.return_value.hex.return_value = "deadbeef"
    miner._queue_block_for_broadcast(block_mock)
    
    miner._flush_pending_blocks()
    
    # Ensure block is removed from pending list
    assert len(miner._pending_blocks) == 0
    assert "deadbeef" not in miner._pending_block_hashes
    miner.network.publish_block.assert_called_once()

def test_miner_has_active_peers(miner):
    assert miner._has_active_peers() is False
    miner.network = MagicMock()
    miner.network.inbound_peers = {("127.0.0.1", 1234)}
    assert miner._has_active_peers() is True

def test_miner_start_node(miner, mock_network_cls, mock_blockchain_cls):
    res = miner.start_node()
    assert res is True
    assert miner.blockchain is not None
    assert miner.network is not None

@patch("tsarchain.miner.orchestrator.time.sleep", return_value=None)
def test_miner_wait_for_sync_timeout(mock_sleep, miner, mock_network_cls):
    miner.network = mock_network_cls()
    miner.blockchain = MagicMock(height=-1)
    miner._trusted_best_height = MagicMock(return_value=10)
    
    # timeout immediately
    res = miner.wait_for_sync(timeout=0)
    assert res is False

@patch("tsarchain.miner.orchestrator.time.sleep", return_value=None)
def test_miner_wait_for_sync_success(mock_sleep, miner, mock_network_cls):
    miner.network = mock_network_cls()
    miner.blockchain = MagicMock(height=10)
    miner.blockchain.get_last_block.return_value.hash.return_value.hex.return_value = "abc"
    miner._trusted_best_height = MagicMock(return_value=10)
    miner._trusted_tip_hash = MagicMock(return_value="abc")
    
    # The loop should break returning True when height >= trusted_best_height
    res = miner.wait_for_sync(timeout=10)
    assert res is True

def test_miner_stop(miner):
    miner.network = MagicMock()
    miner.thread_monitor = MagicMock()
    
    miner.stop()
    
    assert miner.mining_alive is False
    assert miner.cancel_mining.is_set()
    miner.network.shutdown.assert_called_once()
    miner.thread_monitor.stop_monitoring.assert_called_once()


# --- NodeRunner Tests ---

def test_noderunner_init():
    nr = NodeRunner()
    assert nr.running is True

def test_noderunner_handle_signal():
    nr = NodeRunner()
    nr._handle_signal(signal.SIGINT, None)
    assert nr.running is False

def test_noderunner_has_active_peers():
    nr = NodeRunner()
    assert nr._has_active_peers() is False
    
    nr.network = MagicMock()
    nr.network.peers = {("127.0.0.1", 8080)}
    assert nr._has_active_peers() is True

@patch("tsarchain.miner.orchestrator.time.sleep")
def test_noderunner_start(mock_sleep, mock_network_cls, mock_blockchain_cls):
    nr = NodeRunner(bootstrap_snapshot=False)
    
    # We want to kill the infinite while-loop after the first sleep
    def sleep_side_effect(*args, **kwargs):
        nr.running = False
        
    mock_sleep.side_effect = sleep_side_effect
    
    nr.start()
    
    assert nr.blockchain is not None
    assert nr.network is None
    assert nr.running is False
    # Shutdown should be called implicitly inside start()'s finally block
    # so _threads should be empty
    assert len(nr._threads) == 0

@patch("tsarchain.miner.orchestrator.time.sleep")
def test_noderunner_sync_daemon(mock_sleep):
    nr = NodeRunner()
    nr.running = True
    nr.blockchain = MagicMock(height=5)
    nr.network = MagicMock()
    nr.network.peers = {("127.0.0.1", 8080)}
    # Provide a recent sync time so _sync_ready becomes True
    nr.network._peer_last_sync = {("127.0.0.1", 8080): time.time()}
    
    def sleep_side_effect(*args, **kwargs):
        nr.running = False
        
    mock_sleep.side_effect = sleep_side_effect
    
    nr._sync_daemon()
    assert nr._sync_ready is True


# --- Tests for start_mining ---

def test_miner_start_mining_invalid_address(miner):
    miner.address = "invalid"
    assert miner.start_mining() is False

@patch.object(SimpleMiner, 'start_node', return_value=False)
def test_miner_start_mining_start_node_fails(mock_start, miner):
    assert miner.start_mining() is False

@patch.object(SimpleMiner, 'start_node', return_value=True)
@patch.object(SimpleMiner, 'wait_for_sync', return_value=False)
def test_miner_start_mining_sync_fails(mock_sync, mock_start, miner):
    assert miner.start_mining() is False

@patch.object(SimpleMiner, 'start_node', return_value=True)
@patch.object(SimpleMiner, 'wait_for_sync', return_value=True)
def test_miner_start_mining_genesis_fails(mock_sync, mock_start, miner, mock_blockchain_cls):
    # Simulate height < 0 and genesis fails
    miner.blockchain = mock_blockchain_cls.return_value
    miner.blockchain.height = -1
    miner.blockchain.ensure_genesis.return_value = False
    
    assert miner.start_mining() is False

@patch.object(SimpleMiner, 'start_node', return_value=True)
@patch.object(SimpleMiner, 'wait_for_sync', return_value=True)
def test_miner_start_mining_behind_trusted(mock_sync, mock_start, miner, mock_blockchain_cls):
    miner.blockchain = mock_blockchain_cls.return_value
    miner.blockchain.height = 1
    miner._has_active_peers = MagicMock(return_value=True)
    
    # Gap detected
    miner._trusted_best_height = MagicMock(return_value=5)
    
    # We want it to break after hitting the gap block
    with patch("tsarchain.miner.orchestrator.time.sleep") as mock_sleep:
        def sleep_effect(*args):
            miner.mining_alive = False
        mock_sleep.side_effect = sleep_effect
        
        miner.start_mining()
        
    assert mock_sleep.called

@patch.object(SimpleMiner, 'start_node', return_value=True)
@patch.object(SimpleMiner, 'wait_for_sync', return_value=True)
def test_miner_start_mining_hash_mismatch(mock_sync, mock_start, miner, mock_blockchain_cls):
    miner.blockchain = mock_blockchain_cls.return_value
    miner.blockchain.height = 1
    miner._has_active_peers = MagicMock(return_value=True)
    
    # Heights match but hashes differ
    miner._trusted_best_height = MagicMock(return_value=1)
    miner._trusted_tip_hash = MagicMock(return_value="trusted_hash")
    miner._get_local_tip = MagicMock(return_value=(1, "local_hash"))
    
    with patch("tsarchain.miner.orchestrator.time.sleep") as mock_sleep:
        def sleep_effect(*args):
            miner.mining_alive = False
        mock_sleep.side_effect = sleep_effect
        
        miner.start_mining()
        
    assert mock_sleep.called
