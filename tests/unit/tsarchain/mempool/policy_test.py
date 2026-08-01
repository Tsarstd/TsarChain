# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
import heapq
from tsarchain.core.tx import Tx
from unittest.mock import MagicMock, patch
from tsarchain.mempool.policy import MempoolPolicyMixin
from tsarchain.mempool.types import PrevoutRef

class DummyUTXO:
    def __init__(self):
        self.version = 1
        self.utxos = {}
        self.loaded = False
        
    def _load(self):
        self.loaded = True
        
    def _get_tip_height_from_state(self):
        return 100

class DummyMempoolPolicy(MempoolPolicyMixin):
    def __init__(self):
        self._pool = {}
        self._size_map = {}
        self._prevout_index = {}
        self._fee_heap = []
        self._heap_entries = {}
        self.current_size = 0
        self._dirty = False
        self.utxo = DummyUTXO()
        self.last_error_reason = None
        self._last_prune_version = None
        self._last_prune_reload_ts = 0
        self._orphans_queued = []
        self._removed_txs = []
        
        class MockLock:
            def __enter__(self): pass
            def __exit__(self, exc_type, exc_val, exc_tb): pass
        self._lock = MockLock()
        
    def _normalize_txid(self, txid):
        if not txid: return None
        if isinstance(txid, bytes): return txid.hex()
        return str(txid)
        
    def _mark_dirty(self):
        self._dirty = True
        
    def _maybe_flush_after_mutation(self):
        pass
        
    def _remove_fee_record(self, txid):
        pass
        
    def validate_transaction(self, tx, utxo_set, spend_at_height=None):
        return True
        
    def has_tx(self, txid):
        return txid in self._pool
        
    def add_tx(self, tx):
        txid = self._normalize_txid(tx.txid)
        if txid:
            self._pool[txid] = tx

    def remove_tx(self, txid):
        self._removed_txs.append(txid)
        self._pool.pop(txid, None)

    def _queue_orphan(self, tx, missing):
        self._orphans_queued.append((tx, missing))

@pytest.fixture
def mempool():
    with patch("tsarchain.mempool.policy._estimate_tx_size_bytes", return_value=100):
        yield DummyMempoolPolicy()

# Test _prevout_key
def test_prevout_key(mempool):
    key = mempool._prevout_key("abc", 1)
    assert key is not None
    assert key.txid == "abc"
    assert key.vout == 1
    
    key_none = mempool._prevout_key(None, 1)
    assert key_none is None

# Test _index_tx_prevouts
def test_index_tx_prevouts_standard(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    tx.inputs = [txin]
    tx.is_coinbase = False
    
    mempool._index_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 1
    assert mempool._prevout_index[PrevoutRef("prev", 0)] == "616263"

def test_index_tx_prevouts_coinbase(mempool):
    tx = Tx()
    tx.txid = b"abc"
    tx.is_coinbase = True
    mempool._index_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 0

def test_index_tx_prevouts_no_owner_txid(mempool):
    tx = Tx()
    tx.txid = None
    tx.is_coinbase = False
    mempool._index_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 0

def test_index_tx_prevouts_no_inputs(mempool):
    tx = Tx()
    tx.txid = b"abc"
    tx.inputs = None
    tx.is_coinbase = False
    mempool._index_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 0

def test_index_tx_prevouts_fallback_attrs(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    del txin.txid
    del txin.vout
    txin.prev_tx = "prev"
    txin.prev_index = 1
    tx.inputs = [txin]
    tx.is_coinbase = False
    
    mempool._index_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 1
    assert mempool._prevout_index[PrevoutRef("prev", 1)] == "616263"

def test_index_tx_prevouts_none_key(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    txin.txid = None
    txin.vout = None
    tx.inputs = [txin]
    tx.is_coinbase = False
    
    mempool._index_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 0


# Test _drop_tx_prevouts
def test_drop_tx_prevouts_standard(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    tx.inputs = [txin]
    tx.is_coinbase = False
    
    mempool._index_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 1
    mempool._drop_tx_prevouts(tx)
    assert len(mempool._prevout_index) == 0

def test_drop_tx_prevouts_none(mempool):
    mempool._drop_tx_prevouts(None)

def test_drop_tx_prevouts_coinbase(mempool):
    tx = Tx()
    tx.is_coinbase = True
    mempool._drop_tx_prevouts(tx)

def test_drop_tx_prevouts_no_txid(mempool):
    tx = Tx()
    tx.txid = None
    tx.is_coinbase = False
    mempool._drop_tx_prevouts(tx)

def test_drop_tx_prevouts_empty_index(mempool):
    tx = Tx()
    tx.txid = b"abc"
    tx.is_coinbase = False
    mempool._drop_tx_prevouts(tx)

def test_drop_tx_prevouts_no_match(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    tx.inputs = [txin]
    tx.is_coinbase = False
    
    mempool._index_tx_prevouts(tx)
    
    tx2 = Tx()
    tx2.txid = b"def"
    tx2.is_coinbase = False
    mempool._drop_tx_prevouts(tx2)
    
    assert len(mempool._prevout_index) == 1

# Test _ensure_space
def test_ensure_space_not_needed(mempool):
    mempool._ensure_space(0)
    mempool._ensure_space(-1)

def test_ensure_space_has_room(mempool):
    with patch("tsarchain.mempool.policy.CFG") as mock_cfg:
        mock_cfg.MEMPOOL_MAX_SIZE = 1000
        mempool.current_size = 800
        mempool._ensure_space(100) # 800 + 100 <= 1000
        assert mempool._dirty == False

def test_ensure_space_evicts(mempool):
    with patch("tsarchain.mempool.policy.CFG") as mock_cfg:
        mock_cfg.MEMPOOL_MAX_SIZE = 1000
        mempool.current_size = 800
        
        tx = Tx()
        tx.txid = b"old"
        mempool._pool["old"] = tx
        mempool._size_map["old"] = 300
        mempool._heap_entries["old"] = 1.0
        heapq.heappush(mempool._fee_heap, (1.0, "old"))
        
        mempool._ensure_space(400) # 800 + 400 > 1000, target 200
        assert "old" not in mempool._pool
        assert mempool.current_size == 500
        assert mempool._dirty == True

def test_ensure_space_stale_heap_entry(mempool):
    with patch("tsarchain.mempool.policy.CFG") as mock_cfg:
        mock_cfg.MEMPOOL_MAX_SIZE = 1000
        mempool.current_size = 800
        
        # entry_rate is None
        heapq.heappush(mempool._fee_heap, (1.0, "old_none"))
        
        # entry_rate != rate
        mempool._heap_entries["old_diff"] = 2.0
        heapq.heappush(mempool._fee_heap, (1.0, "old_diff"))
        
        mempool._ensure_space(400)
        assert mempool.current_size == 800 # Didn't free anything

def test_ensure_space_tx_not_in_pool(mempool):
    with patch("tsarchain.mempool.policy.CFG") as mock_cfg:
        mock_cfg.MEMPOOL_MAX_SIZE = 1000
        mempool.current_size = 800
        mempool._heap_entries["old"] = 1.0
        heapq.heappush(mempool._fee_heap, (1.0, "old"))
        
        mempool._ensure_space(400)
        assert mempool.current_size == 800

def test_ensure_space_estimate_tx_size(mempool):
    with patch("tsarchain.mempool.policy.CFG") as mock_cfg:
        mock_cfg.MEMPOOL_MAX_SIZE = 1000
        mempool.current_size = 800
        
        tx = Tx()
        tx.txid = b"old"
        mempool._pool["old"] = tx
        # No _size_map entry, will fallback to _estimate_tx_size (returns 100)
        mempool._heap_entries["old"] = 1.0
        heapq.heappush(mempool._fee_heap, (1.0, "old"))
        
        mempool._ensure_space(400)
        assert "old" not in mempool._pool
        assert mempool.current_size == 700

def test_ensure_space_negative_size(mempool):
    with patch("tsarchain.mempool.policy.CFG") as mock_cfg:
        mock_cfg.MEMPOOL_MAX_SIZE = 1000
        mempool.current_size = 800
        
        tx = Tx()
        tx.txid = b"old"
        mempool._pool["old"] = tx
        mempool._size_map["old"] = 1000 # Evicting this will make current_size negative
        mempool._heap_entries["old"] = 1.0
        heapq.heappush(mempool._fee_heap, (1.0, "old"))
        
        mempool._ensure_space(400)
        assert mempool.current_size == 0

# Test drop_conflicts
def test_drop_conflicts_empty(mempool):
    assert mempool.drop_conflicts([]) == 0
    assert mempool.drop_conflicts([("", -1)]) == 0

def test_drop_conflicts_no_conflict(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    txin.txid = "prev1"
    txin.vout = 0
    tx.inputs = [txin]
    mempool._pool["abc"] = tx
    
    assert mempool.drop_conflicts([("prev2", 0)]) == 0

def test_drop_conflicts_match(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    tx.inputs = [txin]
    mempool._pool["abc"] = tx
    mempool._size_map["abc"] = 100
    mempool.current_size = 100
    
    removed = mempool.drop_conflicts([("prev", 0)])
    assert removed == 1
    assert "abc" not in mempool._pool
    assert mempool.current_size == 0
    assert mempool._dirty == True

def test_drop_conflicts_negative_size(mempool):
    tx = Tx()
    tx.txid = b"abc"
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    tx.inputs = [txin]
    mempool._pool["abc"] = tx
    mempool._size_map["abc"] = 200
    mempool.current_size = 100
    
    removed = mempool.drop_conflicts([("prev", 0)])
    assert removed == 1
    assert mempool.current_size == 0

# Test prune_stale_entries
def test_prune_stale_entries_same_version(mempool):
    mempool._last_prune_version = 1
    mempool.utxo.version = 1
    assert mempool.prune_stale_entries() == 0

def test_prune_stale_entries_reload(mempool):
    mempool._last_prune_version = 0
    mempool.utxo.version = 1
    mempool._last_prune_reload_ts = 0 # Forces reload since time.time() > 60
    mempool.prune_stale_entries()
    assert mempool.utxo.loaded == True

def test_prune_stale_entries_remove(mempool):
    tx = Tx()
    tx.txid = b"abc"
    mempool._pool["abc"] = tx
    mempool._size_map["abc"] = 100
    mempool.current_size = 100
    mempool._last_prune_version = 0
    
    with patch.object(mempool, "validate_transaction", return_value=False):
        removed = mempool.prune_stale_entries()
        assert removed == 1
        assert "abc" not in mempool._pool
        assert mempool.current_size == 0
        assert mempool._last_prune_version == 1
        assert mempool._dirty == True

def test_prune_stale_entries_keep(mempool):
    tx = Tx()
    tx.txid = b"abc"
    mempool._pool["abc"] = tx
    mempool._size_map["abc"] = 100
    mempool.current_size = 100
    mempool._last_prune_version = 0
    
    with patch.object(mempool, "validate_transaction", return_value=True):
        removed = mempool.prune_stale_entries()
        assert removed == 0
        assert "abc" in mempool._pool
        assert mempool.current_size == 100

def test_prune_stale_entries_negative_size(mempool):
    tx = Tx()
    tx.txid = b"abc"
    mempool._pool["abc"] = tx
    mempool._size_map["abc"] = 200
    mempool.current_size = 100
    mempool._last_prune_version = 0
    
    with patch.object(mempool, "validate_transaction", return_value=False):
        removed = mempool.prune_stale_entries()
        assert removed == 1
        assert mempool.current_size == 0


# Test add_valid_tx
def test_add_valid_tx_from_dict(mempool):
    tx_dict = {"txid": "abcd", "inputs": [], "outputs": []}
    with patch("tsarchain.mempool.policy.Tx.from_dict") as mock_from_dict:
        mock_tx = Tx()
        mock_tx.txid = bytes.fromhex("abcd")
        mock_from_dict.return_value = mock_tx
        assert mempool.add_valid_tx(tx_dict)
        assert "abcd" in mempool._pool

def test_add_valid_tx_already_in_pool(mempool):
    tx = Tx()
    tx.txid = bytes.fromhex("abcd")
    mempool._pool["abcd"] = tx
    assert not mempool.add_valid_tx(tx)
    assert mempool.last_error_reason == "tx_already_in_pool"

def test_add_valid_tx_validation_fails(mempool):
    tx = Tx()
    tx.txid = bytes.fromhex("abcd")
    
    with patch.object(mempool, "validate_transaction", return_value=False):
        assert not mempool.add_valid_tx(tx)
        assert mempool.last_error_reason == "tx_validation_failed"
        
    def mock_validate_missing(transaction_obj, utxo_set, spend_at_height):
        mempool.last_error_reason = "prevout_missing prev123"
        return False
        
    with patch.object(mempool, "validate_transaction", side_effect=mock_validate_missing):
        assert not mempool.add_valid_tx(tx)
        assert mempool.last_error_reason == "orphan_waiting prev123"
        assert len(mempool._orphans_queued) == 1
        assert mempool._orphans_queued[0] == (tx, "prev123")

def test_add_valid_tx_conflicts_evict_old(mempool):
    # Setup conflict in pool
    old_tx = Tx()
    old_tx.txid = bytes.fromhex("1111")
    old_tx.fee = 1000
    mempool._pool["1111"] = old_tx
    mempool._prevout_index[PrevoutRef("prev", 0)] = "1111"
    
    new_tx = Tx()
    new_tx.txid = bytes.fromhex("2222")
    new_tx.fee = 2000 # Higher fee -> should evict old
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    new_tx.inputs = [txin]
    
    assert mempool.add_valid_tx(new_tx)
    assert "2222" in mempool._pool
    assert "1111" in mempool._removed_txs

def test_add_valid_tx_conflicts_reject_new(mempool):
    # Setup conflict in pool
    old_tx = Tx()
    old_tx.txid = bytes.fromhex("1111")
    old_tx.fee = 2000
    mempool._pool["1111"] = old_tx
    mempool._prevout_index[PrevoutRef("prev", 0)] = "1111"
    
    new_tx = Tx()
    new_tx.txid = bytes.fromhex("2222")
    new_tx.fee = 1000 # Lower fee -> should be rejected
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    new_tx.inputs = [txin]
    
    assert not mempool.add_valid_tx(new_tx)
    assert "2222" not in mempool._pool
    assert mempool.last_error_reason is not None
    assert mempool.last_error_reason.startswith("double_spend_conflict")
    assert "prev:0" in mempool.last_error_reason
    assert "1111" in mempool.last_error_reason

def test_add_valid_tx_conflicts_reject_new_tuple_prevout(mempool):
    # Setup conflict in pool
    old_tx = Tx()
    old_tx.txid = bytes.fromhex("1111")
    old_tx.fee = 2000
    mempool._pool["1111"] = old_tx
    
    # Mock _prevout_key to return a tuple instead of PrevoutRef
    # to hit the line: prev_str = f"{any_prev[0]}:{any_prev[1]}"
    with patch.object(mempool, "_prevout_key", return_value=("prev", 0)):
        mempool._prevout_index[("prev", 0)] = "1111"
        
        new_tx = Tx()
        new_tx.txid = bytes.fromhex("2222")
        new_tx.fee = 1000 
        txin = MagicMock()
        new_tx.inputs = [txin]
        
        assert not mempool.add_valid_tx(new_tx)
        assert mempool.last_error_reason is not None
        assert mempool.last_error_reason.startswith("double_spend_conflict")
        assert "prev:0" in mempool.last_error_reason

def test_add_valid_tx_conflict_missing_in_pool(mempool):
    # Conflict id is in _prevout_index but not in _pool
    mempool._prevout_index[PrevoutRef("prev", 0)] = "1111"
    
    new_tx = Tx()
    new_tx.txid = bytes.fromhex("2222")
    new_tx.fee = 1000
    txin = MagicMock()
    txin.txid = "prev"
    txin.vout = 0
    new_tx.inputs = [txin]
    
    assert mempool.add_valid_tx(new_tx)
    assert "2222" in mempool._pool
