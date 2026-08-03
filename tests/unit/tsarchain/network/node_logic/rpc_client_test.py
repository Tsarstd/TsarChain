# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import time
import pytest
import threading

from collections import OrderedDict
from unittest.mock import MagicMock, patch

from tsarchain.network.node_logic.rpc_client import (
    rpc_request,
    request_mempool_inline,
    request_mempool_snapshot,
    request_full_sync,
    prefetch_rpc_connections,
    prefetch_peer_channel,
)


class MockNode:
    def __init__(self):
        self.node_id = "test_node_id"
        self.pubkey = "test_pubkey"
        self.privkey = "test_privkey"
        self.port = 8333
        self.node_ctx = {"test": "ctx"}
        self._rpc_backoff = {}
        self._rpc_conn_cache = OrderedDict()
        self._rpc_conn_cache_lock = threading.RLock()
        self._rpc_prefetched = set()
        self.peer_pubkeys = {}
        self._peer_last_mempool_sync = {}
        self._snapshot_unreachable = set()
        self._full_sync_backoff = {}
        self._full_sync_last_request = {}
        self._peer_last_sync = {}
        self.persistent_peers = [("127.0.0.1", 8333)]

        self.broadcast = MagicMock()
        self.broadcast.mempool.add_valid_tx.return_value = True
        self.broadcast.blockchain.height = 100
        self.broadcast.receive_full_sync.return_value = True

    def normalize_peer(self, peer):
        if not peer:
            return None
        if isinstance(peer, str):
            return (peer, self.port)
        return peer

    def get_pinned(self, *args):
        return None

    def set_pinned(self, *args):
        pass

    def reward_peer(self, peer, amount):
        pass

    def penalize_peer(self, peer, amount):
        pass

    def nonce_guard(self, *args):
        return True

    def rpc_request(self, peer, payload, timeout=None):
        return None

    def request_mempool_snapshot(self, peer, force=False):
        return None


@pytest.fixture
def mock_node():
    node = MockNode()
    return node


# ---------------------------------------------------------
# rpc_request tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.rpc_client.CFG")
@patch("tsarchain.network.node_logic.rpc_client.build_envelope")
@patch("tsarchain.network.node_logic.rpc_client.is_envelope")
@patch("tsarchain.network.node_logic.rpc_client.verify_and_unwrap")
@patch("tsarchain.network.node_logic.rpc_client.send_message")
@patch("tsarchain.network.node_logic.rpc_client.recv_message")
@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
@patch("tsarchain.network.node_logic.rpc_client.SecureChannel")
def test_rpc_request_success_new_connection(
    mock_channel,
    mock_socket,
    mock_recv,
    mock_send,
    mock_verify,
    mock_is_env,
    mock_build_env,
    mock_cfg,
    mock_node,
):
    mock_cfg.DEBUG_BENCHMARKS = False
    mock_cfg.SYNC_TIMEOUT = 10.0
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.BUFFER_SIZE = 8192
    
    mock_chan = MagicMock()
    mock_chan.recv.return_value = json.dumps({"status": "ok"}).encode("utf-8")
    mock_channel.return_value = mock_chan
    mock_build_env.return_value = {"type": "TEST_ENV"}
    mock_is_env.return_value = False

    peer = ("127.0.0.1", 8333)
    resp = rpc_request(mock_node, peer, {"test": "data"})
    
    assert resp == {"status": "ok"}
    # Cache should be updated
    assert peer in mock_node._rpc_conn_cache

@patch("tsarchain.network.node_logic.rpc_client.time.time")
def test_rpc_request_backoff(mock_time, mock_node):
    mock_time.return_value = 1000.0
    peer = ("127.0.0.1", 8333)
    mock_node._rpc_backoff[peer] = 1010.0  # Still in backoff

    resp = rpc_request(mock_node, peer, {"test": "data"})
    assert resp is None

@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
def test_rpc_request_connection_refused(mock_socket, mock_node):
    mock_sock_inst = MagicMock()
    mock_sock_inst.connect.side_effect = ConnectionRefusedError()
    mock_socket.return_value = mock_sock_inst

    peer = ("127.0.0.1", 8333)
    resp = rpc_request(mock_node, peer, {"test": "data"})
    assert resp is None


# ---------------------------------------------------------
# request_mempool_inline tests
# ---------------------------------------------------------
def test_request_mempool_inline_success(mock_node):
    peer = ("127.0.0.1", 8333)
    
    # Mocking rpc_request on the node object directly
    mock_node.rpc_request = MagicMock(return_value={
        "type": "MEMPOOL",
        "mode": "inline",
        "txs": [{"txid": "123", "data": "abc"}]
    })

    with patch("tsarchain.network.node_logic.rpc_client.Tx.from_dict", return_value="mock_tx_obj"):
        res = request_mempool_inline(mock_node, peer, force=True)
    
    assert res is True
    mock_node.broadcast.mempool.add_valid_tx.assert_called_with("mock_tx_obj")


def test_request_mempool_inline_invalid_response(mock_node):
    peer = ("127.0.0.1", 8333)
    
    # Wrong type
    mock_node.rpc_request = MagicMock(return_value={"type": "ERROR"})
    res = request_mempool_inline(mock_node, peer, force=True)
    assert res is False


def test_request_mempool_inline_rate_limit(mock_node):
    peer = ("127.0.0.1", 8333)
    mock_node._peer_last_mempool_sync[peer] = time.time()
    
    # Should return None due to rate limiting
    res = request_mempool_inline(mock_node, peer, force=False)
    assert res is None


# ---------------------------------------------------------
# request_mempool_snapshot tests
# ---------------------------------------------------------
def test_request_mempool_snapshot_success(mock_node):
    peer = ("127.0.0.1", 8333)
    
    mock_node.rpc_request = MagicMock(return_value={
        "type": "MEMPOOL_SYNC",
        "status": "ok",
        "count": 10
    })

    res = request_mempool_snapshot(mock_node, peer, force=True)
    assert res is True
    assert peer not in mock_node._snapshot_unreachable


def test_request_mempool_snapshot_failure(mock_node):
    peer = ("127.0.0.1", 8333)
    
    mock_node.rpc_request = MagicMock(return_value=None)
    mock_node.penalize_peer = MagicMock()

    res = request_mempool_snapshot(mock_node, peer, force=True)
    assert res is None
    assert peer in mock_node._snapshot_unreachable
    mock_node.penalize_peer.assert_called_once()


# ---------------------------------------------------------
# request_full_sync tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.rpc_client.CFG")
def test_request_full_sync_success(mock_cfg, mock_node):
    mock_cfg.ENABLE_FULL_SYNC = True
    mock_cfg.FULL_SYNC_MIN_INTERVAL = 60
    mock_cfg.REPLAY_WINDOW_SEC = 300
    mock_cfg.SYNC_TIMEOUT = 10.0
    peer = ("127.0.0.1", 8333)
    
    mock_node.rpc_request = MagicMock(return_value={
        "type": "FULL_SYNC",
        "data": {"chain": [1, 2], "utxos": {"a": "b"}, "mempool": []},
        "ts": int(time.time()),
        "nonce": "12345"
    })

    res = request_full_sync(mock_node, peer, force=True)
    assert res is True
    mock_node.broadcast.receive_full_sync.assert_called_once()
    assert peer in mock_node._peer_last_sync


@patch("tsarchain.network.node_logic.rpc_client.CFG")
def test_request_full_sync_reject(mock_cfg, mock_node):
    mock_cfg.ENABLE_FULL_SYNC = True
    mock_cfg.SYNC_TIMEOUT = 10.0
    mock_cfg.FULL_SYNC_MIN_INTERVAL = 60
    mock_cfg.REPLAY_WINDOW_SEC = 300
    mock_cfg.FULL_SYNC_BACKOFF_MAX = 300.0
    peer = ("127.0.0.1", 8333)
    
    mock_node.rpc_request = MagicMock(return_value={
        "type": "SYNC_REJECT",
        "retry_after": 60.0
    })

    res = request_full_sync(mock_node, peer, force=True)
    assert res is False
    assert peer in mock_node._full_sync_backoff


@patch("tsarchain.network.node_logic.rpc_client.CFG")
def test_request_full_sync_no_response(mock_cfg, mock_node):
    mock_cfg.ENABLE_FULL_SYNC = True
    mock_cfg.SYNC_TIMEOUT = 10.0
    mock_cfg.FULL_SYNC_MIN_INTERVAL = 60
    mock_cfg.REPLAY_WINDOW_SEC = 300
    peer = ("127.0.0.1", 8333)
    
    mock_node.rpc_request = MagicMock(return_value=None)
    mock_node.penalize_peer = MagicMock()

    res = request_full_sync(mock_node, peer, force=True)
    assert res is False
    mock_node.penalize_peer.assert_called_once()


# ---------------------------------------------------------
# prefetch_rpc_connections & prefetch_peer_channel tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
@patch("tsarchain.network.node_logic.rpc_client.SecureChannel")
def test_prefetch_rpc_connections(mock_channel, mock_socket, mock_node):
    mock_sock_inst = MagicMock()
    mock_socket.return_value = mock_sock_inst
    
    prefetch_rpc_connections(mock_node)
    
    peer = ("127.0.0.1", 8333)
    assert peer in mock_node._rpc_conn_cache
    assert peer in mock_node._rpc_prefetched
    mock_sock_inst.connect.assert_called_with(peer)


@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
@patch("tsarchain.network.node_logic.rpc_client.SecureChannel")
def test_prefetch_peer_channel(mock_channel, mock_socket, mock_node):
    mock_sock_inst = MagicMock()
    mock_socket.return_value = mock_sock_inst
    
    peer = ("192.168.1.1", 8333)
    prefetch_peer_channel(mock_node, peer)
    
    assert peer in mock_node._rpc_conn_cache
    assert peer in mock_node._rpc_prefetched
    mock_sock_inst.connect.assert_called_with(peer)

def test_rpc_request_invalid_peer(mock_node):
    assert rpc_request(mock_node, None, {}) is None

@patch("tsarchain.network.node_logic.rpc_client.CFG")
@patch("tsarchain.network.node_logic.rpc_client.build_envelope")
@patch("tsarchain.network.node_logic.rpc_client.SecureChannel")
@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
def test_rpc_request_p2p_enc(mock_socket, mock_channel_class, mock_build, mock_cfg, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    
    mock_chan = MagicMock()
    mock_chan.recv.return_value = b'{"status": "ok"}'
    mock_channel_class.return_value = mock_chan
    
    mock_build.return_value = {"type": "TEST_ENV"}
    
    resp = rpc_request(mock_node, ("127.0.0.1", 8333), {"test": "data"})
    assert resp == {"status": "ok"}
    mock_chan.handshake.assert_called_once()
    mock_chan.send.assert_called_once()

@patch("tsarchain.network.node_logic.rpc_client.SecureChannel")
@patch("tsarchain.network.node_logic.rpc_client.build_envelope")
@patch("tsarchain.network.node_logic.rpc_client.CFG")
@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
def test_rpc_request_cache_eviction(mock_socket, mock_cfg, mock_build, mock_chan_cls, mock_node):
    mock_build.return_value = {}
    mock_chan = MagicMock()
    mock_chan.recv.return_value = b'{}'
    mock_chan_cls.return_value = mock_chan
    mock_cfg.RPC_CONN_CACHE_MAX = 1
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.SYNC_TIMEOUT = 10.0
    
    peer1 = ("127.0.0.1", 8333)
    peer2 = ("127.0.0.1", 8334)
    
    rpc_request(mock_node, peer1, {})
    rpc_request(mock_node, peer2, {})
        
    assert peer1 not in mock_node._rpc_conn_cache
    assert peer2 in mock_node._rpc_conn_cache

@patch("tsarchain.network.node_logic.rpc_client.SecureChannel")
@patch("tsarchain.network.node_logic.rpc_client.build_envelope")
@patch("tsarchain.network.node_logic.rpc_client.CFG")
@patch("tsarchain.network.node_logic.rpc_client.verify_and_unwrap")
@patch("tsarchain.network.node_logic.rpc_client.is_envelope")
@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
def test_rpc_request_envelope_unwrap(mock_socket, mock_is_env, mock_unwrap, mock_cfg, mock_build, mock_chan_cls, mock_node):
    mock_build.return_value = {}
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.SYNC_TIMEOUT = 10.0
    mock_chan = MagicMock()
    mock_chan.recv.return_value = json.dumps({
        "from": "nodeA",
        "pubkey": "pubA",
        "data": "xyz"
    }).encode("utf-8")
    mock_chan_cls.return_value = mock_chan
    mock_is_env.return_value = True
    mock_unwrap.return_value = {"unwrapped": "data"}
    
    resp = rpc_request(mock_node, ("127.0.0.1", 8333), {})
    assert resp == {"unwrapped": "data"}
    assert mock_node.peer_pubkeys["nodeA"] == "pubA"

def test_request_mempool_inline_invalid_peer(mock_node):
    assert request_mempool_inline(mock_node, None) is False

def test_request_mempool_inline_backoff(mock_node):
    peer = ("127.0.0.1", 8333)
    mock_node._rpc_backoff[peer] = time.time() + 100
    with patch("tsarchain.network.node_logic.rpc_client.time.time", return_value=0):
        assert request_mempool_inline(mock_node, peer) is None

def test_request_mempool_inline_invalid_mode(mock_node):
    peer = ("127.0.0.1", 8333)
    mock_node.rpc_request = MagicMock(return_value={"type": "MEMPOOL", "mode": "wrong"})
    assert request_mempool_inline(mock_node, peer, force=True) is False

def test_request_mempool_snapshot_invalid_peer(mock_node):
    assert request_mempool_snapshot(mock_node, None) is False

def test_request_mempool_snapshot_backoff(mock_node):
    peer = ("127.0.0.1", 8333)
    mock_node._rpc_backoff[peer] = time.time() + 100
    with patch("tsarchain.network.node_logic.rpc_client.time.time", return_value=0):
        assert request_mempool_snapshot(mock_node, peer, force=True) is None

def test_request_full_sync_invalid_peer(mock_node):
    assert request_full_sync(mock_node, None, force=True) is False

@patch("tsarchain.network.node_logic.rpc_client.CFG")
def test_request_full_sync_replay_guard_failure(mock_cfg, mock_node):
    mock_cfg.ENABLE_FULL_SYNC = True
    mock_cfg.SYNC_TIMEOUT = 10.0
    peer = ("127.0.0.1", 8333)
    mock_node.rpc_request = MagicMock(return_value={"type": "FULL_SYNC", "ts": 123, "nonce": "abc"})
    mock_node.nonce_guard = MagicMock(return_value=False)
    assert request_full_sync(mock_node, peer, force=True) is False

@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
def test_prefetch_rpc_connections_exception(mock_socket, mock_node):
    mock_sock_inst = MagicMock()
    mock_sock_inst.connect.side_effect = Exception("conn error")
    mock_socket.return_value = mock_sock_inst
    
    prefetch_rpc_connections(mock_node)
    assert len(mock_node._rpc_prefetched) == 0

