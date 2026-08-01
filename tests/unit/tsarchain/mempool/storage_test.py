# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from tsarchain.core.tx import Tx
from collections import OrderedDict
from unittest.mock import MagicMock, patch
from tsarchain.mempool.storage import MempoolStorageMixin

class DummyMempool(MempoolStorageMixin):
    def __init__(self):
        self._pool = OrderedDict()
        self._size_map = {}
        self._prevout_index = {}
        self._fee_heap = []
        self._heap_entries = {}
        self.current_size = 0
        self.max_size_mb = 300
        self._dirty = False
        self._change_seq = 0
        self._last_flush = 0
        self.filepath = "dummy.json"
        
        class MockLock:
            def __enter__(self): pass
            def __exit__(self, exc_type, exc_val, exc_tb): pass
        self._lock = MockLock()
        
        self.save_json = MagicMock()
        self.load_json = MagicMock()

    def _ensure_space(self, needed_space: int) -> None:
        pass
    def _drop_tx_prevouts(self, tx_obj):
        pass
    def _index_tx_prevouts(self, tx_obj):
        pass

@pytest.fixture
def mempool():
    return DummyMempool()

def test_load_storage_pool(mempool):
    with patch("tsarchain.mempool.storage.kv_enabled", return_value=False):
        mempool.load_json.return_value = {"txs": [{"txid": "abcd"}], "meta": {"schema_version": 1}}
        entries, meta = mempool._load_storage_pool()
        assert len(entries) == 1
        assert meta["schema_version"] == 1

def test_hydrate_pool(mempool):
    tx = Tx()
    tx.txid = bytes.fromhex("abcd")
    mempool._hydrate_pool([{"txid": "abcd"}])
    assert "abcd" in mempool._pool

def test_normalize_txid(mempool):
    assert mempool._normalize_txid(b"abc") == b"abc".hex()
    assert mempool._normalize_txid("ABC") == "abc"

def test_tx_from_any(mempool):
    tx = Tx()
    tx.txid = b"abc"
    assert mempool._tx_from_any(tx) == tx
    assert isinstance(mempool._tx_from_any({}), Tx)

def test_build_meta_snapshot(mempool):
    mempool._pool = {"a": 1, "b": 2}
    mempool.current_size = 1000
    meta = mempool._build_meta_snapshot()
    assert meta["count"] == 2
    assert meta["virtual_size"] == 1000

def test_mark_dirty(mempool):
    mempool._mark_dirty()
    assert mempool._dirty
    assert mempool.change_seq == 1

def test_maybe_flush_after_mutation(mempool):
    mempool._dirty = True
    mempool._last_flush = 0
    with patch.object(mempool, "flush") as mock_flush:
        mempool._maybe_flush_after_mutation()
        mock_flush.assert_called_once_with(force=False)

def test_compute_fee_rate(mempool):
    tx = Tx()
    tx.fee = 1000
    assert mempool._compute_fee_rate(tx, 250) == 4.0

def test_record_remove_fee_rate(mempool):
    tx = Tx()
    tx.fee = 1000
    mempool._record_fee_rate("abc", tx, 250)
    assert "abc" in mempool._heap_entries
    mempool._remove_fee_record("abc")
    assert "abc" not in mempool._heap_entries

def test_flush(mempool):
    mempool._dirty = True
    mempool._last_flush = 0
    with patch("tsarchain.mempool.storage.kv_enabled", return_value=False):
        assert mempool.flush()
        assert not mempool._dirty

def test_save_pool(mempool):
    with patch.object(mempool, "flush") as mock_flush:
        tx = Tx()
        tx.txid = bytes.fromhex("abcd")
        mempool.save_pool([tx])
        assert mock_flush.called
        assert "abcd" in mempool._pool

def test_get_all_txs(mempool):
    tx = Tx()
    mempool._pool = OrderedDict({"abc": tx})
    assert mempool.get_all_txs() == [tx]

def test_stats(mempool):
    mempool._pool = {"abc": Tx()}
    mempool.current_size = 500
    stats = mempool.stats()
    assert stats["count"] == 1
    assert stats["virtual_size"] == 500

def test_has_tx(mempool):
    mempool._pool = {"abc": Tx()}
    assert mempool.has_tx("abc")
    assert mempool.has_tx(b"\xab\xc0") == False
    assert mempool.has_tx("ABC")

def test_add_tx(mempool):
    tx = Tx()
    tx.txid = bytes.fromhex("def0")
    with patch.object(mempool, "_maybe_flush_after_mutation"):
        mempool.add_tx(tx)
        assert mempool.has_tx("def0")

def test_remove_tx(mempool):
    tx = Tx()
    tx.txid = bytes.fromhex("def0")
    mempool.add_tx(tx)
    assert mempool.remove_tx("def0")
    assert not mempool.has_tx("def0")

def test_remove_many(mempool):
    tx = Tx()
    tx.txid = bytes.fromhex("def0")
    mempool.add_tx(tx)
    assert mempool.remove_many(["def0"]) == 1

def test_clear(mempool):
    tx = Tx()
    tx.txid = bytes.fromhex("def0")
    mempool.add_tx(tx)
    mempool.clear()
    assert not mempool.has_tx("def0")
    assert mempool.current_size == 0
