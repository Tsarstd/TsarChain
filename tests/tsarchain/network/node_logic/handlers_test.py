# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import threading
from unittest.mock import MagicMock, patch
import pytest

from tsarchain.network.node_logic.handlers import (
    handle_hello,
    handle_get_headers,
    handle_get_blocks,
    handle_get_block_at,
    handle_get_block_by_hash,
)

class MockBlock:
    def __init__(self, height, hx, prev_hash=""):
        self.height = height
        self._hash = hx
        self.prev_block_hash = prev_hash
        self.timestamp = 1000
        self.bits = 1
        
    def hash(self):
        m = MagicMock()
        m.hex.return_value = self._hash
        return m

    def to_dict(self):
        return {"height": self.height, "hash": self._hash}


class MockNode:
    def __init__(self):
        self.lock = threading.RLock()
        self.port = 8333
        self.peers = set()
        self.peer_scores = {}
        self.storage_peers = {}
        self._peer_best_height = {}

        self.broadcast = MagicMock()
        self.broadcast.lock = threading.RLock()
        self.broadcast.blockchain.height = 10
        self.broadcast.blockchain.chain = [
            MockBlock(i, f"hash{i}", f"hash{i-1}") for i in range(11)
        ]

    def _is_local_address(self, ip):
        return ip == "127.0.0.1"

    def reward_peer(self, peer):
        pass

    def serialize_block(self, b):
        return b.to_dict()

    def bhash_hex(self, b):
        return b.hash().hex()


@pytest.fixture
def mock_node():
    return MockNode()


# -------------------------------------------------------------------
# handle_hello tests
# -------------------------------------------------------------------
@patch("tsarchain.network.node_logic.handlers.CFG")
@patch("tsarchain.network.node_logic.handlers.register_storage_peer")
def test_handle_hello_normal(mock_register, mock_cfg, mock_node):
    mock_cfg.PEER_SCORE_START = 100
    msg = {
        "ip": "192.168.1.10",
        "port": 8334,
        "role": "NODE",
        "height": 5,
        "peers": [{"ip": "10.0.0.1", "port": 8335}]
    }
    
    res = handle_hello(mock_node, msg, ("192.168.1.10", 8334))
    
    assert res["type"] == "HELLO_RESPONSE"
    assert res["port"] == 8333
    assert res["height"] == 10
    
    assert ("192.168.1.10", 8334) in mock_node.peers
    assert mock_node.peer_scores[("192.168.1.10", 8334)] == 100
    assert mock_node._peer_best_height[("192.168.1.10", 8334)] == 5
    
    assert ("10.0.0.1", 8335) in mock_node.peers
    assert mock_node.peer_scores[("10.0.0.1", 8335)] == 50
    mock_node.broadcast.send_mempool_to_peer.assert_called_with(("192.168.1.10", 8334))
    mock_register.assert_not_called()

@patch("tsarchain.network.node_logic.handlers.decode_address")
@patch("tsarchain.network.node_logic.handlers.register_storage_peer")
def test_handle_hello_storage_success(mock_register, mock_decode, mock_node):
    msg = {
        "ip": "192.168.1.10",
        "port": 8334,
        "role": "NODE_STORAGE",
        "address": "TsarABC",
        "url": "http://test",
    }
    
    res = handle_hello(mock_node, msg, ("192.168.1.10", 8334), src_node_id="nid1", src_pubkey="pub1")
    
    assert res["type"] == "HELLO_RESPONSE"
    mock_register.assert_called_once()
    args, kwargs = mock_register.call_args
    assert args[1] == "192.168.1.10"
    assert args[2]["node_id"] == "nid1"
    assert args[2]["addr"] == "tsarabc"

def test_handle_hello_storage_missing_auth(mock_node):
    msg = {"role": "NODE_STORAGE"}
    res = handle_hello(mock_node, msg, ("192.168.1.10", 8334))
    assert res == {"error": "storage_auth_required"}

def test_handle_hello_storage_missing_addr(mock_node):
    msg = {"role": "NODE_STORAGE"}
    res = handle_hello(mock_node, msg, ("192.168.1.10", 8334), src_node_id="nid", src_pubkey="pub")
    assert res == {"error": "storage_address_required"}

@patch("tsarchain.network.node_logic.handlers.decode_address")
def test_handle_hello_storage_invalid_addr(mock_decode, mock_node):
    mock_decode.side_effect = Exception("invalid")
    msg = {"role": "NODE_STORAGE", "address": "invalid"}
    res = handle_hello(mock_node, msg, ("192.168.1.10", 8334), src_node_id="nid", src_pubkey="pub")
    assert res == {"error": "storage_address_invalid"}

@patch("tsarchain.network.node_logic.handlers.decode_address")
def test_handle_hello_storage_pubkey_pinned(mock_decode, mock_node):
    mock_node.storage_peers = {"192.168.1.10": {"node_id": "nid1", "pubkey": "pub1"}}
    msg = {"role": "NODE_STORAGE", "address": "TsarABC"}
    res = handle_hello(mock_node, msg, ("192.168.1.10", 8334), src_node_id="nid1", src_pubkey="pub2")
    assert res == {"error": "storage_pubkey_pinned"}


# -------------------------------------------------------------------
# handle_get_headers tests
# -------------------------------------------------------------------
@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_headers(mock_cfg, mock_node):
    mock_cfg.HEADERS_BATCH_MAX = 5
    mock_cfg.DEBUG_BENCHMARKS = False
    
    # locator matching hash5, so should return from index 6
    msg = {"locator": ["hash99", "hash5", "hash0"]}
    res = handle_get_headers(mock_node, msg, ("192.168.1.10", 8334))
    
    assert res["type"] == "HEADERS"
    assert len(res["headers"]) == 5
    assert res["headers"][0]["hash"] == "hash6"
    assert res["headers"][-1]["hash"] == "hash10"
    assert res["more"] is False
    assert res["best_height"] == 10

@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_headers_no_locator(mock_cfg, mock_node):
    mock_cfg.HEADERS_BATCH_MAX = 2
    mock_cfg.DEBUG_BENCHMARKS = False
    
    msg = {}
    res = handle_get_headers(mock_node, msg, ("192.168.1.10", 8334))
    
    assert res["type"] == "HEADERS"
    assert len(res["headers"]) == 2
    assert res["headers"][0]["hash"] == "hash0"
    assert res["more"] is True


# -------------------------------------------------------------------
# handle_get_blocks tests
# -------------------------------------------------------------------
@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_blocks(mock_cfg, mock_node):
    mock_cfg.BLOCK_DOWNLOAD_BATCH_MAX = 5
    mock_cfg.DEBUG_BENCHMARKS = False
    
    msg = {"heights": [2, 4, 99, 10]}
    res = handle_get_blocks(mock_node, msg, ("192.168.1.10", 8334))
    
    assert res["type"] == "BLOCKS"
    assert len(res["blocks"]) == 3
    assert res["blocks"][0]["hash"] == "hash2"
    assert res["blocks"][1]["hash"] == "hash4"
    assert res["blocks"][2]["hash"] == "hash10"


# -------------------------------------------------------------------
# handle_get_block_at tests
# -------------------------------------------------------------------
@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_block_at_success(mock_cfg, mock_node):
    mock_cfg.DEBUG_BENCHMARKS = False
    mock_cfg.CANONICAL_SEP = (',', ':')
    
    res = handle_get_block_at(mock_node, 5)
    
    assert res["type"] == "BLOCK"
    assert res["height"] == 5
    assert res["hash"] == "hash5"

@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_block_at_out_of_range(mock_cfg, mock_node):
    mock_cfg.DEBUG_BENCHMARKS = False
    
    res = handle_get_block_at(mock_node, 99)
    assert res == {"type": "BLOCK", "error": "height_out_of_range"}


# -------------------------------------------------------------------
# handle_get_block_by_hash tests
# -------------------------------------------------------------------
@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_block_by_hash_success(mock_cfg, mock_node):
    mock_cfg.DEBUG_BENCHMARKS = False
    mock_cfg.CANONICAL_SEP = (',', ':')
    
    res = handle_get_block_by_hash(mock_node, "hash5")
    
    assert res["type"] == "BLOCK"
    assert res["height"] == 5
    assert res["hash"] == "hash5"


@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_block_by_hash_0x_prefix(mock_cfg, mock_node):
    mock_cfg.DEBUG_BENCHMARKS = False
    mock_cfg.CANONICAL_SEP = (',', ':')

    res = handle_get_block_by_hash(mock_node, "0xhash5")

    assert res["type"] == "BLOCK"
    assert res["height"] == 5
    assert res["hash"] == "hash5"


@patch("tsarchain.network.node_logic.handlers.CFG")
def test_handle_get_block_by_hash_not_found(mock_cfg, mock_node):
    mock_cfg.DEBUG_BENCHMARKS = False
    
    res = handle_get_block_by_hash(mock_node, "hash99")
    assert res == {"type": "BLOCK", "error": "not_found"}

