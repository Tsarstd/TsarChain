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
        self._tx_prevouts = {}
        
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
    import struct
    tx = Tx()
    tx.txid = bytes.fromhex("abcd")
    raw_tx = tx.to_storage_bytes()
    hdr = struct.pack("<dIII", 100.0, 10, 100, 400)
    mock_data = [
        (b"__meta__", b'{"schema_version": 1}'),
        (b"abcd", hdr + raw_tx)
    ]
    with patch("tsarchain.mempool.storage.iter_prefix", return_value=mock_data):
        entries, meta = mempool._load_storage_pool()
        assert len(entries) == 1
        assert meta["schema_version"] == 1

def test_flush(mempool):
    mempool._dirty = True
    mempool._last_flush = 0
    with patch("tsarchain.mempool.storage.clear_db"), \
         patch("tsarchain.mempool.storage.batch"):
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
