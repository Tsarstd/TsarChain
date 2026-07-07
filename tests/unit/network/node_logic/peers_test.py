# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
import threading
from unittest.mock import MagicMock, patch

from tsarchain.network.node_logic.peers import (
    normalize_peer,
    penalize_peer,
    reward_peer,
    publish_block,
    _collect_broadcast_peers,
)

class MockNode:
    def __init__(self):
        self.lock = threading.RLock()
        self.peers = set()
        self.peer_scores = {}
        self.outbound_peers = set()
        self.inbound_peers = set()
        self._peer_best_height = {}
        self._peer_last_sync = {}
        self._peer_last_mempool_sync = {}
        
        self.broadcast = MagicMock()
        
    def normalize_peer(self, peer):
        return normalize_peer(self, peer)

@pytest.fixture
def mock_node():
    return MockNode()

# ---------------------------------------------------------
# normalize_peer tests
# ---------------------------------------------------------
def test_normalize_peer(mock_node):
    assert normalize_peer(mock_node, ("127.0.0.1", 8333)) == ("127.0.0.1", 8333)
    assert normalize_peer(mock_node, ["127.0.0.1", 8333]) == ("127.0.0.1", 8333)
    assert normalize_peer(mock_node, None) is None
    assert normalize_peer(mock_node, "invalid") is None
    assert normalize_peer(mock_node, ("127.0.0.1",)) is None

# ---------------------------------------------------------
# penalize_peer tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.peers.CFG")
def test_penalize_peer(mock_cfg, mock_node):
    mock_cfg.PEER_SCORE_START = 100
    mock_cfg.PEER_SCORE_MIN = 0
    peer = ("127.0.0.1", 8333)
    mock_node.peer_scores[peer] = 50
    mock_node.peers.add(peer)
    mock_node.outbound_peers.add(peer)
    mock_node._peer_best_height[peer] = 10
    
    penalize_peer(mock_node, peer, 10)
    assert mock_node.peer_scores[peer] == 40
    assert peer in mock_node.peers
    
    # Penalize below min
    penalize_peer(mock_node, peer, 50)
    assert peer not in mock_node.peers
    assert peer not in mock_node.outbound_peers
    assert peer not in mock_node._peer_best_height

def test_penalize_peer_invalid(mock_node):
    # Should not raise exception
    penalize_peer(mock_node, None, 10)
    penalize_peer(mock_node, "invalid", 10)

# ---------------------------------------------------------
# reward_peer tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.peers.CFG")
def test_reward_peer(mock_cfg, mock_node):
    mock_cfg.PEER_SCORE_START = 100
    mock_cfg.MAX_OUTBOUND_PEERS = 5
    peer = ("127.0.0.1", 8333)
    
    reward_peer(mock_node, peer, 20)
    assert mock_node.peer_scores[peer] == 120
    assert peer in mock_node.peers
    assert peer in mock_node.outbound_peers
    
    # Max score is START * 5
    reward_peer(mock_node, peer, 1000)
    assert mock_node.peer_scores[peer] == 500

def test_reward_peer_invalid(mock_node):
    reward_peer(mock_node, None)

# ---------------------------------------------------------
# _collect_broadcast_peers tests
# ---------------------------------------------------------
def test_collect_broadcast_peers(mock_node):
    mock_node.outbound_peers = {("1.1.1.1", 80)}
    mock_node.inbound_peers = {("2.2.2.2", 80)}
    mock_node.peers = {("3.3.3.3", 80)}
    
    targets = _collect_broadcast_peers(mock_node)
    assert targets == {("1.1.1.1", 80), ("2.2.2.2", 80)}
    
    # If out/inbound are empty, fallback to peers
    mock_node.outbound_peers = set()
    mock_node.inbound_peers = set()
    targets = _collect_broadcast_peers(mock_node)
    assert targets == {("3.3.3.3", 80)}

# ---------------------------------------------------------
# publish_block tests
# ---------------------------------------------------------
def test_publish_block(mock_node):
    mock_node.outbound_peers = {("1.1.1.1", 80)}
    mock_node.broadcast.broadcast_block.return_value = 1
    
    mock_block = MagicMock()
    # It does a type check if `Block` is defined, but in peers.py `Block = None` so it passes
    res = publish_block(mock_node, mock_block)
    assert res == 1
    mock_node.broadcast.broadcast_block.assert_called_once()
    
def test_publish_block_no_peers(mock_node):
    res = publish_block(mock_node, MagicMock())
    assert res == 0
