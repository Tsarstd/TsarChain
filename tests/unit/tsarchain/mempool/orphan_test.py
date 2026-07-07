# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

from unittest.mock import MagicMock, patch

from tsarchain.mempool.orphan import OrphanPoolMixin

class DummyMempool(OrphanPoolMixin):
    def __init__(self):
        self._orphan_pool = {}
        self._orphan_missing = {}
        self.last_error_reason = None
        self.mock_add_valid_tx_result = True
        
    def add_valid_tx(self, tx_obj):
        return self.mock_add_valid_tx_result


def test_queue_orphan_with_tx_dict_txid():
    mempool = DummyMempool()
    tx_mock = MagicMock()
    tx_mock.to_dict.return_value = {"txid": "abcdef123456"}
    
    mempool._queue_orphan(tx_mock, "MISSING_KEY_1")
    
    assert "abcdef123456" in mempool._orphan_pool
    assert mempool._orphan_pool["abcdef123456"] == {"txid": "abcdef123456"}
    assert mempool._orphan_missing["abcdef123456"] == "missing_key_1"
    tx_mock.to_dict.assert_called_once_with(include_txid=True)


def test_queue_orphan_fallback_to_tx_attr():
    mempool = DummyMempool()
    tx_mock = MagicMock()
    tx_mock.to_dict.return_value = {}  # txid not in dict
    tx_mock.txid = b'\xab\xcd\xef'
    
    mempool._queue_orphan(tx_mock, "MISSING_KEY_2")
    
    expected_hex = "abcdef"
    assert expected_hex in mempool._orphan_pool
    assert mempool._orphan_pool[expected_hex] == {"txid": expected_hex}
    assert mempool._orphan_missing[expected_hex] == "missing_key_2"


def test_queue_orphan_no_txid():
    mempool = DummyMempool()
    tx_mock = MagicMock()
    tx_mock.to_dict.return_value = {}
    tx_mock.txid = None  # getattr will return None
    
    mempool._queue_orphan(tx_mock, "missing")
    
    assert len(mempool._orphan_pool) == 0


def test_recheck_orphans_empty():
    mempool = DummyMempool()
    assert mempool.recheck_orphans() == 0


@patch('tsarchain.mempool.orphan.Tx')
def test_recheck_orphans_success(mock_tx_class):
    mempool = DummyMempool()
    mempool._orphan_pool = {"tx1": {"txid": "tx1"}}
    mempool._orphan_missing = {"tx1": "missing1"}
    
    mock_tx_instance = MagicMock()
    mock_tx_class.from_dict.return_value = mock_tx_instance
    mempool.mock_add_valid_tx_result = True
    
    added = mempool.recheck_orphans()
    
    assert added == 1
    assert len(mempool._orphan_pool) == 0
    mock_tx_class.from_dict.assert_called_once_with({"txid": "tx1"})


@patch('tsarchain.mempool.orphan.Tx')
def test_recheck_orphans_fail_prevout_missing(mock_tx_class):
    mempool = DummyMempool()
    # Need mock to handle re-queueing
    mock_tx_instance = MagicMock()
    mock_tx_instance.to_dict.return_value = {"txid": "tx1"}
    mock_tx_class.from_dict.return_value = mock_tx_instance
    
    mempool._orphan_pool = {"tx1": {"txid": "tx1"}}
    mempool._orphan_missing = {"tx1": "missing1"}
    mempool.mock_add_valid_tx_result = False
    mempool.last_error_reason = "prevout_missing some_missing_txid"
    
    added = mempool.recheck_orphans()
    
    assert added == 0
    # It should have re-queued the orphan under 'tx1' with missing key 'some_missing_txid'
    assert "tx1" in mempool._orphan_pool
    assert mempool._orphan_missing["tx1"] == "some_missing_txid"


@patch('tsarchain.mempool.orphan.Tx')
def test_recheck_orphans_fail_orphan_waiting(mock_tx_class):
    mempool = DummyMempool()
    mock_tx_instance = MagicMock()
    mock_tx_instance.to_dict.return_value = {"txid": "tx2"}
    mock_tx_class.from_dict.return_value = mock_tx_instance
    
    mempool._orphan_pool = {"tx2": {"txid": "tx2"}}
    mempool._orphan_missing = {"tx2": "old_missing"}
    mempool.mock_add_valid_tx_result = False
    mempool.last_error_reason = "orphan_waiting new_missing"
    
    added = mempool.recheck_orphans()
    
    assert added == 0
    assert "tx2" in mempool._orphan_pool
    assert mempool._orphan_missing["tx2"] == "new_missing"


@patch('tsarchain.mempool.orphan.Tx')
def test_recheck_orphans_fail_other_reason(mock_tx_class):
    mempool = DummyMempool()
    mock_tx_instance = MagicMock()
    mock_tx_class.from_dict.return_value = mock_tx_instance
    
    mempool._orphan_pool = {"tx3": {"txid": "tx3"}}
    mempool._orphan_missing = {"tx3": "missing3"}
    mempool.mock_add_valid_tx_result = False
    mempool.last_error_reason = "some_other_error"
    
    added = mempool.recheck_orphans()
    
    assert added == 0
    # Since reason is neither prevout_missing nor orphan_waiting, it shouldn't be re-queued
    assert len(mempool._orphan_pool) == 0
    assert len(mempool._orphan_missing) == 0


@patch('tsarchain.mempool.orphan.Tx')
def test_recheck_orphans_fail_none_reason(mock_tx_class):
    mempool = DummyMempool()
    mock_tx_instance = MagicMock()
    mock_tx_class.from_dict.return_value = mock_tx_instance
    
    mempool._orphan_pool = {"tx4": {"txid": "tx4"}}
    mempool._orphan_missing = {"tx4": "missing4"}
    mempool.mock_add_valid_tx_result = False
    mempool.last_error_reason = None
    
    added = mempool.recheck_orphans()
    
    assert added == 0
    # Should not be re-queued
    assert len(mempool._orphan_pool) == 0
    assert len(mempool._orphan_missing) == 0
