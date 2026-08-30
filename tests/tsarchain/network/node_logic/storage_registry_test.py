# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
import threading

from tsarchain.network.node_logic.storage_registry import (
    init_storage_registry,
    register_storage_peer,
)


class MockNode:
    def __init__(self):
        self.lock = threading.RLock()


def test_init_storage_registry():
    node = MockNode()
    init_storage_registry(node)
    assert node.storage_peers == {}


def test_register_storage_peer():
    node = MockNode()
    init_storage_registry(node)

    meta1 = {
        "node_id": "nid1",
        "pubkey": "pk1",
        "port": 9001,
        "addr": "addr1",
    }
    register_storage_peer(node, "127.0.0.1", meta1)
    assert ("127.0.0.1", 9001) in node.storage_peers
    assert node.storage_peers[("127.0.0.1", 9001)] == meta1

    # Update with new port for same node_id and same pubkey removes old entry
    meta2 = {
        "node_id": "nid1",
        "pubkey": "pk1",
        "port": 9002,
        "addr": "addr1",
    }
    register_storage_peer(node, "127.0.0.1", meta2)
    assert ("127.0.0.1", 9001) not in node.storage_peers
    assert ("127.0.0.1", 9002) in node.storage_peers

    # Different pubkey for same node_id is rejected (ignored)
    meta3 = {
        "node_id": "nid1",
        "pubkey": "pk_different",
        "port": 9003,
        "addr": "addr1",
    }
    register_storage_peer(node, "127.0.0.1", meta3)
    assert ("127.0.0.1", 9003) not in node.storage_peers
    assert ("127.0.0.1", 9002) in node.storage_peers
