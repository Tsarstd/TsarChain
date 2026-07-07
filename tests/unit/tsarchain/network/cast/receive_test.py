# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
from unittest.mock import MagicMock, patch

from tsarchain.network.cast.receive import ReceiveMixin

class DummyNode(ReceiveMixin):
    def __init__(self):
        self.lock = MagicMock()
        self.blockchain = MagicMock()
        self.mempool = MagicMock()
        self.utxodb = MagicMock()
        self.network = MagicMock()
        self.seen_blocks = set()
        self._processing_blocks = set()
        self.seen_txs = set()
        self.state = {}
        self._utxo_shared = False
        self.broadcast_block = MagicMock()
        self._broadcast_tx_fluff = MagicMock()
        self.request_full_sync = MagicMock()
        self._calc_chainwork_from_list = MagicMock(return_value=100)
        self._validate_incoming_chain = MagicMock(return_value=True)
        self._rebuild_utxo_from_chain_locked = MagicMock()
        self._maybe_flush_local_utxo = MagicMock()
        self.dandelion = MagicMock()
        self.dandelion.enabled.return_value = False

@pytest.fixture
def dummy_node():
    return DummyNode()

def test_log_block_reject(dummy_node):
    with patch("tsarchain.network.cast.receive.log") as mock_log:
        dummy_node._log_block_reject(
            stage="test_stage",
            block_id="1234567890abcdef1234567890abcdef",
            height=100,
            peer="1.2.3.4",
            reason="test_reason",
            extra={"foo": "bar"}
        )
        assert mock_log.warning.called
        args, kwargs = mock_log.warning.call_args
        assert "[block_reject] stage=%s" in args[0]
        assert args[1] == "test_stage"
        assert args[2] == 100
        assert args[3] == "1234567890abcdef"
        assert args[4] == "1.2.3.4"
        assert args[5] == "test_reason"
        assert args[6] == {"foo": "bar"}

def test_native_script_hex():
    assert ReceiveMixin._native_script_hex(None) is None
    assert ReceiveMixin._native_script_hex(b"\x00\x01") == "0001"
    assert ReceiveMixin._native_script_hex("ABCDEF") == "abcdef"
    
    mock_obj = MagicMock()
    mock_obj.serialize.return_value = b"\xaa\xbb"
    assert ReceiveMixin._native_script_hex(mock_obj) == "aabb"
    
    mock_wrapper = MagicMock()
    del mock_wrapper.serialize
    mock_wrapper.script_pubkey = "112233"
    assert ReceiveMixin._native_script_hex(mock_wrapper) == "112233"

def test_native_script_bytes():
    assert ReceiveMixin._native_script_bytes(None) is None
    assert ReceiveMixin._native_script_bytes(b"\x00\x01") == b"\x00\x01"
    assert ReceiveMixin._native_script_bytes("abcdef") == b"\xab\xcd\xef"
    
    mock_obj = MagicMock()
    mock_obj.serialize.return_value = b"\xaa\xbb"
    assert ReceiveMixin._native_script_bytes(mock_obj) == b"\xaa\xbb"
    
    mock_wrapper = MagicMock()
    del mock_wrapper.serialize
    mock_wrapper.script_pubkey = "112233"
    assert ReceiveMixin._native_script_bytes(mock_wrapper) == b"\x11\x22\x33"

def test_normalize_native_prevout(dummy_node):
    entry_dict = {
        "tx_out": {
            "amount": 1000
        },
        "script_pubkey": "aabbcc",
        "is_coinbase": True,
        "block_height": 50
    }
    result = dummy_node._normalize_native_prevout(entry_dict, "key")
    assert result == (1000, b"\xaa\xbb\xcc", True, 50)
    
    mock_entry = MagicMock()
    mock_tx_out = MagicMock()
    mock_tx_out.amount = 2000
    mock_tx_out.serialize.return_value = b"\xdd\xee"
    mock_entry.tx_out = mock_tx_out
    mock_entry.is_coinbase = False
    mock_entry.block_height = 100
    
    result = dummy_node._normalize_native_prevout(mock_entry, "key")
    assert result == (2000, b"\xdd\xee", False, 100)
    
    invalid_entry = {"amount": 10}
    assert dummy_node._normalize_native_prevout(invalid_entry, "key") is None

def test_build_native_prevout_snapshot(dummy_node):
    mock_block = MagicMock()
    mock_tx1 = MagicMock()
    mock_tx1.is_coinbase = True
    txid1 = "1111111111111111111111111111111111111111111111111111111111111111"
    mock_tx1.txid = txid1
    
    mock_tx2 = MagicMock()
    mock_tx2.is_coinbase = False
    txid2 = "2222222222222222222222222222222222222222222222222222222222222222"
    mock_tx2.txid = txid2
    
    mock_input = MagicMock()
    prev_txid = "3333333333333333333333333333333333333333333333333333333333333333"
    mock_input.txid = prev_txid
    mock_input.vout = 0
    mock_tx2.inputs = [mock_input]
    
    mock_block.transactions = [mock_tx1, mock_tx2]
    
    dummy_node.utxodb.lookup_entry.return_value = {
        "tx_out": {"amount": 500},
        "script_pubkey": "00",
        "is_coinbase": False,
        "block_height": 10
    }
    
    snapshot, utxo_items = dummy_node._build_native_prevout_snapshot(mock_block)
    
    key = f"{prev_txid}:0"
    assert key in snapshot
    assert snapshot[key]["amount"] == 500
    assert snapshot[key]["script_pubkey"] == b"\x00"
    
    assert len(utxo_items) == 1
    assert utxo_items[0] == (bytes.fromhex(prev_txid), 0, 500, b"\x00", False, 10)

def test_native_precheck_block(dummy_node):
    mock_block = MagicMock()
    mock_block.hash.return_value = b"\x00" * 32
    # If snapshot is None, it returns True
    with patch.object(dummy_node, "_build_native_prevout_snapshot", return_value=None):
        assert dummy_node._native_precheck_block(mock_block) is True

    # Test with valid snapshot but native_validate_block_txs fails
    with patch.object(dummy_node, "_build_native_prevout_snapshot", return_value=({}, None)):
        with patch("tsarchain.network.cast.receive.native_validate_block_txs", return_value=(False, "error", [])):
            assert dummy_node._native_precheck_block(mock_block) is False

    # Test with valid snapshot and native_validate_block_txs succeeds
    with patch.object(dummy_node, "_build_native_prevout_snapshot", return_value=({}, None)):
        with patch("tsarchain.network.cast.receive.native_validate_block_txs", return_value=(True, "", [100])):
            assert dummy_node._native_precheck_block(mock_block) is True
            assert mock_block._native_fee_hint == [100]

def test_receive_chain_invalid(dummy_node):
    dummy_node._validate_incoming_chain.return_value = False
    assert dummy_node.receive_chain({}) is False

@patch("tsarchain.network.cast.receive.Blockchain")
def test_receive_chain_valid_better(mock_blockchain_class, dummy_node):
    mock_incoming = MagicMock()
    mock_incoming.height = 10
    mock_blockchain_class.from_dict.return_value = mock_incoming
    
    dummy_node.blockchain.height = 5
    dummy_node.blockchain.chain = []
    
    dummy_node._calc_chainwork_from_list.side_effect = [100, 200]
    
    msg = {"data": [{"hash": "abc"}]}
    assert dummy_node.receive_chain(msg) is True
    dummy_node.blockchain.replace_with.assert_called_once_with(mock_incoming)
    dummy_node._rebuild_utxo_from_chain_locked.assert_called_once()

@patch("tsarchain.network.cast.receive.Blockchain")
def test_receive_chain_valid_worse(mock_blockchain_class, dummy_node):
    mock_incoming = MagicMock()
    mock_incoming.height = 5
    mock_blockchain_class.from_dict.return_value = mock_incoming
    
    dummy_node.blockchain.height = 10
    dummy_node.blockchain.chain = []
    
    dummy_node._calc_chainwork_from_list.side_effect = [200, 100]
    
    msg = {"data": [{"hash": "abc"}]}
    assert dummy_node.receive_chain(msg) is False
    dummy_node.blockchain.replace_with.assert_not_called()

def test_receive_block_empty(dummy_node):
    assert dummy_node.receive_block({}, ("127.0.0.1", 8333), set()) is False

@patch("tsarchain.network.cast.receive.Block")
def test_receive_block_already_seen(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.hash.return_value.hex.return_value = "blockhash"
    mock_block_class.deserialize_block.return_value = mock_block
    
    dummy_node.seen_blocks.add("blockhash")
    
    msg = {"data": {"hash": "blockhash"}}
    assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is True
    
    dummy_node.blockchain.add_block.assert_not_called()

@patch("tsarchain.network.cast.receive.Block")
def test_receive_block_success(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.height = 10
    mock_block.transactions = []
    mock_block.hash.return_value.hex.return_value = "newhash"
    mock_block_class.deserialize_block.return_value = mock_block
    
    dummy_node.blockchain.get_last_block.return_value.height = 9
    dummy_node.blockchain.get_last_block.return_value.hash.return_value = "prevhash"
    mock_block.prev_block_hash = "prevhash"
    
    dummy_node.blockchain.validate_block.return_value = True
    dummy_node.blockchain.add_block.return_value = True
    
    with patch.object(dummy_node, "_native_precheck_block", return_value=True):
        msg = {"data": {"hash": "newhash"}}
        assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is True
        
        dummy_node.blockchain.add_block.assert_called_once_with(mock_block)
        dummy_node.mempool.flush.assert_called()
        dummy_node.broadcast_block.assert_called_once()

def test_receive_tx_already_seen(dummy_node):
    tx = MagicMock()
    tx.txid.hex.return_value = "txhash"
    dummy_node.seen_txs.add("txhash")
    
    msg = {"data": tx}
    assert dummy_node.receive_tx(msg, ("127.0.0.1", 8333), set()) is False

def test_receive_tx_success(dummy_node):
    tx = MagicMock()
    tx.txid.hex.return_value = "txhash"
    
    dummy_node.mempool.add_valid_tx.return_value = True
    
    msg = {"data": tx}
    assert dummy_node.receive_tx(msg, ("127.0.0.1", 8333), set()) is True
    
    dummy_node.mempool.add_valid_tx.assert_called_once_with(tx)
    dummy_node._broadcast_tx_fluff.assert_called_once()

@patch("tsarchain.network.cast.receive.UTXODB")
def test_receive_utxos(mock_utxodb_class, dummy_node):
    dummy_node.blockchain.chain = []  # Empty chain
    mock_utxo_instance = MagicMock()
    mock_utxodb_class.from_dict.return_value = mock_utxo_instance
    dummy_node.blockchain.in_memory = False
    
    dummy_node.receive_utxos({"data": {"some": "data"}})
    
    assert dummy_node.utxodb == mock_utxo_instance
    mock_utxo_instance.flush.assert_called_once_with(force=True)

def test_receive_state(dummy_node):
    dummy_node.receive_state({"data": {"key": "value"}})
    assert dummy_node.state == {"key": "value"}

def test_receive_mempool(dummy_node):
    dummy_node.blockchain.height = 100
    dummy_node.network.is_caught_up.return_value = True
    
    tx1 = MagicMock()
    tx2 = MagicMock()
    dummy_node.mempool.add_valid_tx.side_effect = [True, False]
    dummy_node.mempool.recheck_orphans = MagicMock(return_value=1)
    
    dummy_node.receive_mempool({"data": [tx1, tx2]})
    
    assert dummy_node.mempool.add_valid_tx.call_count == 2
    dummy_node.mempool.flush.assert_called_once()
