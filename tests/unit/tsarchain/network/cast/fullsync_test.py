# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
from unittest.mock import patch, MagicMock

from tsarchain.network.cast.fullsync import FullSyncHandler
from tsarchain.network.cast.chain_utils import ChainUtilsHandler

class DummySync(FullSyncHandler, ChainUtilsHandler):
    def __init__(self):
        self.blockchain = MagicMock()
        self.mempool = MagicMock()
        self.utxodb = MagicMock()
        self.lock = MagicMock()
        self.state = {"test": 123}
        self.last_sync_time = 0
    
    def _send(self, peer, payload):
        return True
    
    def rebuild_utxo_from_chain_locked(self):
        pass

@pytest.fixture
def sync():
    return DummySync()

def test_snapshot_components(sync):
    sync.blockchain.chain = [MagicMock(to_dict=lambda: {"hash": "B1"})]
    sync.mempool.get_all_txs.return_value = [MagicMock(to_dict=lambda: {"txid": "T1"})]
    sync.utxodb.to_dict.return_value = {"u1": "v1"}
    
    with patch("tsarchain.network.cast.fullsync.CFG.KV_BACKEND", "json"):
        chain_data, utxo_dict, state_view, mempool_data = sync._snapshot_components()
        assert len(chain_data) == 1
        assert chain_data[0]["hash"] == "B1"
        assert len(utxo_dict) == 1
        assert state_view == {"test": 123}
        assert len(mempool_data) == 1
        
    # KV mode
    with patch("tsarchain.network.cast.fullsync.CFG.KV_BACKEND", "lmdb"):
        with patch("tsarchain.network.cast.fullsync.H.kv_load_utxo_dict_native", return_value={"u2": "v2"}):
            _, utxo_dict_kv, _, _ = sync._snapshot_components()
            assert utxo_dict_kv == {"u2": "v2"}

def test_build_full_sync_payload(sync):
    sync.blockchain.chain = []
    sync.mempool.get_all_txs.return_value = []
    sync.utxodb.to_dict.return_value = {}
    
    payload, c, u, m = sync.build_full_sync_payload()
    assert payload["type"] == "FULL_SYNC"
    assert "chain" in payload["data"]
    assert "utxos" in payload["data"]
    assert "state" in payload["data"]
    assert "mempool" in payload["data"]
    assert "ts" in payload
    assert "nonce" in payload
    assert c == 0
    assert u == 0
    assert m == 0

@patch("tsarchain.network.cast.fullsync.CFG.ENABLE_FULL_SYNC", False)
def test_receive_full_sync_disabled(sync):
    assert sync.receive_full_sync({}) is False

@patch("tsarchain.network.cast.fullsync.CFG.ENABLE_FULL_SYNC", True)
def test_receive_full_sync_bad_payload(sync):
    assert sync.receive_full_sync({}) is False
    assert sync.receive_full_sync({"chain": "not_a_list"}) is False
    assert sync.receive_full_sync({"chain": []}) is False
    
    # invalid chain
    with patch.object(sync, "validate_incoming_chain", return_value=False):
        assert sync.receive_full_sync({"chain": [{"height": 0}]}) is False

@patch("tsarchain.network.cast.fullsync.CFG.ENABLE_FULL_SYNC", True)
def test_receive_full_sync_better_chain(sync):
    # Simulate a successful receive where incoming chain is better
    b_local = MagicMock()
    b_local.to_dict.return_value = {"height": 0, "hash": "A", "bits": "0x1d00ffff"}
    sync.blockchain.chain = [b_local]
    sync.blockchain.height = 0
    
    incoming = [
        {"height": 0, "hash": "A", "bits": "0x1d00ffff"},
        {"height": 1, "hash": "B", "bits": "0x1d00ffff"}
    ]
    
    with patch.object(sync, "validate_incoming_chain", return_value=True):
        with patch("tsarchain.network.cast.fullsync.Blockchain.from_dict") as mock_from_dict:
            sync.receive_full_sync({"chain": incoming, "mempool": [{"txid": "a"*64}]})
            
            mock_from_dict.assert_called_once_with(incoming)
            sync.blockchain.replace_with.assert_called_once()
            sync.mempool.add_valid_tx.assert_called_once()
            sync.mempool.flush.assert_called_once()

@patch("tsarchain.network.cast.fullsync.CFG.ENABLE_FULL_SYNC", True)
def test_receive_full_sync_worse_chain(sync):
    b_local = MagicMock()
    b_local.to_dict.return_value = {"height": 1, "hash": "B", "bits": "0x1d00ffff"}
    sync.blockchain.chain = [b_local]
    sync.blockchain.height = 1
    
    incoming = [
        {"height": 0, "hash": "A", "bits": "0x1d00ffff"}
    ]
    
    with patch.object(sync, "validate_incoming_chain", return_value=True):
        res = sync.receive_full_sync({"chain": incoming})
        assert res is False
