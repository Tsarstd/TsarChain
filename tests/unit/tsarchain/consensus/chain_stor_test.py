# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import os
import json
import pytest
import threading
from unittest.mock import MagicMock, Mock, patch


from tsarchain.core.tx import Tx
from tsarchain.core.block import Block
from tsarchain.utils import config as CFG
from tsarchain.storage.utxo import UTXODB
from tsarchain.consensus.chain_storage import ChainStorage
from tsarchain.contracts.graffiti_registry import GraffitiRegistry


# ----------------------------------------------------------------------
# Dummy class to test StorageMixin
# ----------------------------------------------------------------------
class TestChainStorage:
    """Concrete class for testing StorageMixin."""
    __test__ = False

    
    def __init__(self, in_memory=False):
        self.chain_storage = ChainStorage(self)

        self.in_memory = in_memory
        self.chain = []
        self.lock = threading.Lock()
        self._persisted_height = -1
        self._chain_dirty_from = None
        self._snapshot_last_backup_height = -1
        self._utxo_last_flush_height = -1
        self._utxo_dirty = False
        self._state_snapshot_cache = None
        self._utxo_db = None
        self.total_blocks = 0
        self.total_supply = 0
        self.supply_in_tsar = 0
        self._snapshot_backup_active = False
        self._snapshot_backup_lock = threading.Lock()

    
    def _build_block_meta(self, block, cw_prev=0): return self.chain_storage._build_block_meta(block, cw_prev)
    def _serialize_block_for_store(self, block, prev_cw=0): return self.chain_storage._serialize_block_for_store(block, prev_cw)
    def _mark_chain_dirty(self, height=0): return self.chain_storage._mark_chain_dirty(height)
    def _prune_chain_store(self, start_height): return self.chain_storage._prune_chain_store(start_height)
    def _reset_chain_store(self): return self.chain_storage._reset_chain_store()
    def _backup_snapshot_enabled(self): return self.chain_storage._backup_snapshot_enabled()
    def _write_snapshot_manifest(self, target_dir, meta, height): return self.chain_storage._write_snapshot_manifest(target_dir, meta, height)
    def _maybe_backup_snapshot(self, tip_height, tip_timestamp=None): return self.chain_storage._maybe_backup_snapshot(tip_height, tip_timestamp=tip_timestamp)
    def _copy_snapshot_env(self, target_dir): return self.chain_storage._copy_snapshot_env(target_dir)
    def _hash_file(self, path): return self.chain_storage._hash_file(path)
    def _chain_journal_enabled(self): return self.chain_storage._chain_journal_enabled()
    def _chain_journal_size(self): return self.chain_storage._chain_journal_size()
    def _clear_chain_journal(self): return self.chain_storage._clear_chain_journal()
    def _append_chain_journal(self, start_height, blocks): return self.chain_storage._append_chain_journal(start_height, blocks)
    def _apply_chain_journal(self, chain_data): return self.chain_storage._apply_chain_journal(chain_data)
    def save_chain(self, force_full=False): return self.chain_storage.save_chain(force_full=force_full)
    def load_chain(self): return self.chain_storage.load_chain()
    def _read_snapshot_state(self): return self.chain_storage._read_snapshot_state()
    def load_state(self): return self.chain_storage.load_state()
    def save_state(self): return self.chain_storage.save_state()
    def _compute_state_snapshot(self): return self.chain_storage._compute_state_snapshot()

    def ensure_utxodb(self):

        if self._utxo_db is None:
            self._utxo_db = UTXODB()
        return self._utxo_db

    def calculate_total_supply(self):
        # stub: compute sum of coinbase outputs
        total = 0
        for blk in self.chain:
            txs = getattr(blk, "transactions", []) or []
            if txs:
                coinbase = txs[0]
                for out in getattr(coinbase, "outputs", []):
                    total += getattr(out, "amount", 0)
        return total

    def median_time_past(self):
        # stub: return last block timestamp if any
        if self.chain:
            return getattr(self.chain[-1], "timestamp", 0)
        return 0

    def _compute_chainwork_for_chain(self, chain):
        return 0

    def scheduled_reward(self, height):
        # mock implementation: return 50_000_000_000 (50 TSAR) as constant
        return 50_000_000_000

    def get_mempool(self):
        return None

    # ---- tambahan stub yang hilang ----
    def _work_from_bits(self, bits):
        # stub untuk _build_block_meta
        return 0

    @property
    def height(self):
        return len(self.chain) - 1


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
@pytest.fixture
def storage():
    return TestChainStorage(in_memory=False)


@pytest.fixture
def storage_mem():
    return TestChainStorage(in_memory=True)


@pytest.fixture
def mock_tx():
    tx = MagicMock(spec=Tx)
    tx.inputs = []
    tx.outputs = []
    tx.txid = b'abc123'
    tx.to_dict = Mock(return_value={"txid": "abc123"})
    return tx


@pytest.fixture
def mock_block(mock_tx):
    block = MagicMock(spec=Block)
    block.transactions = [mock_tx]
    block.height = 100
    block.bits = 0x1d00ffff
    block.timestamp = 1234567890
    block.prev_block_hash = b'\x00'*32
    block.hash = Mock(return_value=b'\x11'*32)
    block.to_dict = Mock(return_value={"height": 100, "transactions": [mock_tx.to_dict()]})
    block.chainwork = 0
    return block


# ----------------------------------------------------------------------
# Tests for helper methods
# ----------------------------------------------------------------------
def test_build_block_meta(storage, mock_block):
    cw_prev = 1000
    meta = storage._build_block_meta(mock_block, cw_prev)
    assert meta["schema_version"] == CFG.DATA_SCHEMA_VERSION
    assert meta["tx_count"] == 1
    assert meta["size_bytes"] > 0
    assert meta["chainwork"] > 0
    assert meta["target"] is not None
    assert meta["difficulty"] is not None


def test_serialize_block_for_store(storage, mock_block):
    # Override stub _work_from_bits agar chainwork bertambah
    storage._work_from_bits = lambda bits: 1
    prev_cw = 5000
    blk_dict, new_cw = storage._serialize_block_for_store(mock_block, prev_cw)
    assert "_meta" in blk_dict
    meta = blk_dict["_meta"]
    assert meta["chainwork"] > prev_cw
    assert meta["graffiti_post_count"] == 0
    assert meta["comment_count"] == 0
    assert meta["payout_count"] == 0
    assert new_cw == meta["chainwork"]


def test_mark_chain_dirty(storage):
    assert storage._chain_dirty_from is None
    storage._mark_chain_dirty(5)
    assert storage._chain_dirty_from == 5
    storage._mark_chain_dirty(3)
    assert storage._chain_dirty_from == 3
    storage._mark_chain_dirty(-1)
    assert storage._chain_dirty_from == 0


def test_prune_chain_store(storage, monkeypatch):
    # Mock kv_enabled and iter_prefix
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)
    monkeypatch.setattr('tsarchain.consensus.chain_storage.iter_prefix', lambda db, prefix: [
        (b'h:000000000000', b'data1'),
        (b'h:000000000001', b'data2'),
        (b'h:000000000002', b'data3'),
    ])
    delete_mock = Mock()
    monkeypatch.setattr('tsarchain.consensus.chain_storage.delete', delete_mock)

    storage._prune_chain_store(1)
    # Should delete keys with height >= 1 => two keys
    assert delete_mock.call_count == 2
    delete_mock.assert_any_call('chain', b'h:000000000001')
    delete_mock.assert_any_call('chain', b'h:000000000002')

    # If in_memory, should not prune
    storage.in_memory = True
    delete_mock.reset_mock()
    storage._prune_chain_store(0)
    delete_mock.assert_not_called()


def test_reset_chain_store(storage, monkeypatch):
    # Mock kv_enabled, clear_db, os.remove, etc.
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)
    clear_db_mock = Mock()
    monkeypatch.setattr('tsarchain.consensus.chain_storage.clear_db', clear_db_mock)

    # Mock file existence
    monkeypatch.setattr('os.path.exists', lambda p: True)
    remove_mock = Mock()
    monkeypatch.setattr('os.remove', remove_mock)

    # Set attributes
    storage._persisted_height = 10
    storage._chain_dirty_from = 5
    storage._snapshot_last_backup_height = 10

    storage._reset_chain_store()

    clear_db_mock.assert_called_once_with('chain')
    assert remove_mock.call_count == 2  # meta and journal
    assert storage._persisted_height == -1
    assert storage._chain_dirty_from is None
    assert storage._snapshot_last_backup_height == -1

    # in_memory: should skip
    storage.in_memory = True
    clear_db_mock.reset_mock()
    remove_mock.reset_mock()
    storage._reset_chain_store()
    clear_db_mock.assert_not_called()


# ----------------------------------------------------------------------
# Snapshot backup tests
# ----------------------------------------------------------------------
def test_backup_snapshot_enabled(storage):
    storage.in_memory = False
    CFG.BACKUP_SNAPSHOT = True
    assert storage._backup_snapshot_enabled() is True
    CFG.BACKUP_SNAPSHOT = False
    assert storage._backup_snapshot_enabled() is False
    storage.in_memory = True
    assert storage._backup_snapshot_enabled() is False


def test_write_snapshot_manifest(storage, tmp_path):
    target_dir = str(tmp_path)
    meta = {"sha256": "abc", "size": 123, "height": 100, "generated_at": 12345}
    storage._write_snapshot_manifest(target_dir, meta, 100)
    manifest_path = os.path.join(target_dir, "snapshot.manifest.json")
    assert os.path.exists(manifest_path)
    with open(manifest_path) as f:
        data = json.load(f)
    assert data["sha256"] == "abc"
    assert data["size"] == 123
    assert data["height"] == 100


def test_maybe_backup_snapshot(storage, monkeypatch, tmp_path):
    # Setup conditions
    storage.in_memory = False
    CFG.BACKUP_SNAPSHOT = True
    CFG.BLOCK_BACKUP_SNAPSHOT = 10
    CFG.SNAPSHOT_BACKUP_DIR = str(tmp_path / "backup")

    # Mock kv_enabled
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)

    # ---- perbaikan mock threading ----
    class FakeThread:
        def __init__(self, target, args, name, daemon):
            self.target = target
            self.args = args
        def start(self):
            self.target(*self.args)
    monkeypatch.setattr('threading.Thread', FakeThread)

    # Mock _copy_snapshot_env, _hash_file, annotate_local_snapshot_meta
    def fake_copy(target):
        os.makedirs(target, exist_ok=True)
        with open(os.path.join(target, "data.mdb"), "w") as f:
            f.write("dummy")
    storage.chain_storage._copy_snapshot_env = Mock(side_effect=fake_copy)
    storage.chain_storage._hash_file = Mock(return_value="abc123")
    annotate_mock = Mock(return_value={"height": 5, "size": 200, "sha256": "abc123"})
    monkeypatch.setattr('tsarchain.consensus.chain_storage.annotate_local_snapshot_meta', annotate_mock)

    # Set chain with tip
    storage.chain = [Mock(timestamp=1000)]

    # First call: should trigger backup
    storage._snapshot_last_backup_height = -1
    storage._maybe_backup_snapshot(5)
    # It will spawn thread, but we run synchronously
    assert storage._snapshot_last_backup_height == 5
    storage.chain_storage._copy_snapshot_env.assert_called_once()

    # Second call: interval not reached
    storage.chain_storage._copy_snapshot_env.reset_mock()
    storage._maybe_backup_snapshot(14)
    storage.chain_storage._copy_snapshot_env.assert_not_called()

    # Third call: interval reached
    storage._maybe_backup_snapshot(15)
    storage.chain_storage._copy_snapshot_env.assert_called_once()


def test_copy_snapshot_env(storage, monkeypatch, tmp_path):
    target = str(tmp_path / "snapshot")
    # Mock _ensure_env and env.copy
    env_mock = Mock()
    env_mock.copy = Mock()
    monkeypatch.setattr('tsarchain.consensus.chain_storage._ensure_env', lambda: env_mock)
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)

    storage._copy_snapshot_env(target)
    # Should create tmp dir and copy
    env_mock.copy.assert_called_once()
    # Check that target exists after replace
    assert os.path.exists(target)


def test_hash_file(tmp_path):
    # Test hashing a file
    file_path = tmp_path / "test.bin"
    with open(file_path, "wb") as f:
        f.write(b"hello world")
    hash_val = ChainStorage._hash_file(str(file_path))
    assert hash_val == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"  # sha256 of "hello world"

    # Non-existent file
    hash_val = ChainStorage._hash_file("nonexistent")
    assert hash_val is None


# ----------------------------------------------------------------------
# Journal tests (fallback for non-LMDB)
# ----------------------------------------------------------------------
def test_chain_journal_enabled(storage):
    storage.in_memory = False
    CFG.USE_LMDB = False  # but we need to mock kv_enabled
    with patch('tsarchain.consensus.chain_storage.kv_enabled', return_value=False):
        assert storage._chain_journal_enabled() is True
    with patch('tsarchain.consensus.chain_storage.kv_enabled', return_value=True):
        assert storage._chain_journal_enabled() is False
    storage.in_memory = True
    assert storage._chain_journal_enabled() is False


def test_chain_journal_size(storage, tmp_path):
    path = tmp_path / "journal.jsonl"
    CFG.CHAIN_JOURNAL_FILE = str(path)
    with open(path, "w") as f:
        f.write("dummy")
    size = storage._chain_journal_size()
    assert size == len("dummy")
    # Non-existent
    os.remove(path)
    size = storage._chain_journal_size()
    assert size == 0


def test_clear_chain_journal(storage, tmp_path):
    path = tmp_path / "journal.jsonl"
    CFG.CHAIN_JOURNAL_FILE = str(path)
    with open(path, "w") as f:
        f.write("dummy")
    storage._clear_chain_journal()
    assert not os.path.exists(path)


def test_append_chain_journal(storage, tmp_path):
    path = tmp_path / "journal.jsonl"
    CFG.CHAIN_JOURNAL_FILE = str(path)
    CFG.CANONICAL_SEP = (',', ':')
    storage.in_memory = False
    with patch('tsarchain.consensus.chain_storage.kv_enabled', return_value=False):
        # Create blocks
        block1 = Mock(spec=Block)
        block1.to_dict = Mock(return_value={"height": 0})
        block2 = Mock(spec=Block)
        block2.to_dict = Mock(return_value={"height": 1})
        blocks = [block1, block2]
        storage._append_chain_journal(5, blocks)
        assert os.path.exists(path)
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) == 2
        data1 = json.loads(lines[0])
        assert data1["height"] == 5
        data2 = json.loads(lines[1])
        assert data2["height"] == 6


def test_apply_chain_journal(storage, tmp_path):
    path = tmp_path / "journal.jsonl"
    CFG.CHAIN_JOURNAL_FILE = str(path)
    # Write some entries
    entries = [
        {"height": 0, "block": {"height": 0}},
        {"height": 1, "block": {"height": 1}},
        {"height": 3, "block": {"height": 3}},  # gap (height 2 missing)
    ]
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    chain_data = [{"height": 0}]  # existing block at height 0
    result = storage._apply_chain_journal(chain_data)
    # Should incorporate height 1, skip height 3 because gap
    assert len(result) == 2
    assert result[0]["height"] == 0
    assert result[1]["height"] == 1


# ----------------------------------------------------------------------
# save_chain / load_chain tests
# ----------------------------------------------------------------------
def test_save_chain_in_memory(storage_mem):
    # Should do nothing
    storage_mem.save_chain()


def test_save_chain_with_kv(storage, monkeypatch):
    # Mock kv_enabled, batch, clear_db, etc.
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)
    clear_db_mock = Mock()
    monkeypatch.setattr('tsarchain.consensus.chain_storage.clear_db', clear_db_mock)

    # Create a batch context manager mock
    batch_mock = Mock()
    batch_mock.__enter__ = Mock(return_value=batch_mock)
    batch_mock.__exit__ = Mock(return_value=False)
    batch_mock.put = Mock()
    monkeypatch.setattr('tsarchain.consensus.chain_storage.batch', lambda db: batch_mock)

    # Create a chain with blocks
    block1 = Mock(spec=Block)
    block1.to_dict = Mock(return_value={"height": 0})
    block1.height = 0
    block1.bits = 0x1d00ffff
    block1.prev_block_hash = b'\x00'*32
    block1.chainwork = 0
    block1.hash = Mock(return_value=b'\x01'*32)
    block1.transactions = []

    monkeypatch.setattr('tsarchain.consensus.chain_storage.estimate_block_size_bytes', Mock(return_value=100))
    storage.chain_storage._build_block_meta = Mock(return_value={"chainwork": 100})
    storage.chain_storage._serialize_block_for_store = Mock(return_value=({"height": 0}, 100))

    storage.chain = [block1]
    storage._persisted_height = -1
    storage._chain_dirty_from = None

    # Save
    with patch.object(storage.chain_storage, '_maybe_backup_snapshot') as backup_mock:
        storage.save_chain(force_full=True)
        # Should call clear_db, batch put
        clear_db_mock.assert_called_once_with('chain')
        batch_mock.put.assert_called()
        assert storage._persisted_height == 0
        backup_mock.assert_called_once_with(0, tip_timestamp=0)
        # chain meta should be put
        # Check that __meta__ was put
        calls = batch_mock.put.call_args_list
        assert any(call[0][0] == b'__meta__' for call in calls)


def test_save_chain_without_kv_journal(storage, monkeypatch, tmp_path):
    # Simulate no LMDB, using journal
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: False)
    CFG.CHAIN_JOURNAL_FILE = str(tmp_path / "journal.jsonl")
    CFG.CHAIN_JOURNAL_MAX_BYTES = 1000
    CFG.CANONICAL_SEP = (',', ':')
    CFG.BLOCK_FILE = str(tmp_path / "blocks.json")

    # Create chain with 2 blocks
    block0 = Mock(spec=Block)
    block0.to_dict = Mock(return_value={"height": 0})
    block0.height = 0
    block0.bits = 0x1d00ffff
    block0.prev_block_hash = b'\x00'*32
    block0.chainwork = 0
    block0.hash = Mock(return_value=b'\x01'*32)
    block0.transactions = []
    block1 = Mock(spec=Block)
    block1.to_dict = Mock(return_value={"height": 1})
    block1.height = 1
    block1.bits = 0x1d00ffff
    block1.prev_block_hash = b'\x01'*32
    block1.chainwork = 100
    block1.hash = Mock(return_value=b'\x02'*32)
    block1.transactions = []
    storage.chain = [block0, block1]
    storage._persisted_height = -1
    storage._chain_dirty_from = None

    # Mock _serialize_block_for_store to return dummy
    storage.chain_storage._serialize_block_for_store = Mock(return_value=({"height": 0}, 0))
    storage._chain_journal_enabled = Mock(return_value=False)

    # First save: force_full -> write full blocks.json
    with patch('tsarchain.consensus.chain_storage.AtomicJSONFile') as mock_json:
        instance = mock_json.return_value
        instance.save = Mock()
        storage.save_chain(force_full=True)
        # Pastikan AtomicJSONFile dipanggil
        mock_json.assert_called_once_with(CFG.BLOCK_FILE)
        instance.save.assert_called_once()
        # Check content
        args = instance.save.call_args[0][0]
        assert args["meta"]["tip_height"] == 1
        assert len(args["blocks"]) == 2
        assert storage._persisted_height == 1
        # Journal should be cleared
        assert not os.path.exists(CFG.CHAIN_JOURNAL_FILE)

    block2 = Mock(spec=Block)
    block2.to_dict = Mock(return_value={"height": 2})
    block2.height = 2
    block2.bits = 0x1d00ffff
    block2.prev_block_hash = b'\x02'*32
    block2.chainwork = 200
    block2.hash = Mock(return_value=b'\x03'*32)
    block2.transactions = []
    storage.chain.append(block2)
    storage._persisted_height = 1
    storage._chain_dirty_from = None
    storage._mark_chain_dirty(2)  # dirty from 2
    storage._chain_journal_enabled = MagicMock(side_effect=storage.chain_storage._chain_journal_enabled)

    # Save again: should append to journal, not full flush
    with patch('tsarchain.consensus.chain_storage.AtomicJSONFile') as mock_json:
        instance = mock_json.return_value
        instance.save = Mock()
        storage.save_chain(force_full=False)
        # Journal should have one entry
        assert os.path.exists(CFG.CHAIN_JOURNAL_FILE)
        with open(CFG.CHAIN_JOURNAL_FILE) as f:
            lines = f.readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["height"] == 2
        # Full save not called
        instance.save.assert_not_called()
        assert storage._persisted_height == 2

    # Now simulate journal exceeding max bytes: add another block so that
    # save_chain will append it and then trigger full flush because of oversized journal.
    block3 = Mock(spec=Block)
    block3.to_dict = Mock(return_value={"height": 3})
    block3.height = 3
    block3.bits = 0x1d00ffff
    block3.prev_block_hash = b'\x03'*32
    block3.chainwork = 300
    block3.hash = Mock(return_value=b'\x04'*32)
    block3.transactions = []
    storage.chain.append(block3)
    storage._persisted_height = 2  # still at 2
    storage._chain_dirty_from = None
    storage._mark_chain_dirty(3)  # dirty from 3

    # Enlarge journal file so that its size exceeds CFG.CHAIN_JOURNAL_MAX_BYTES
    with open(CFG.CHAIN_JOURNAL_FILE, "a") as f:
        f.write("x" * 2000)  # exceed max

    # Now save_chain should append block3, see journal size > max, and perform full flush
    with patch('tsarchain.consensus.chain_storage.AtomicJSONFile') as mock_json:
        instance = mock_json.return_value
        instance.save = Mock()
        storage.save_chain(force_full=False)
        # Full flush should have been called
        instance.save.assert_called_once()
        # Journal file should be cleared
        assert not os.path.exists(CFG.CHAIN_JOURNAL_FILE)
        # Persisted height should be updated to 3
        assert storage._persisted_height == 3


def test_load_chain_with_kv(storage, monkeypatch):
    # Mock kv_enabled and iter_prefix to return blocks
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)

    # Provide proper hex strings (64 characters)
    ZERO_HASH_HEX = "0" * 64
    GENESIS_HASH_HEX = "1" * 64

    # Mock iter_prefix to return some blocks and meta
    def mock_iter_prefix(db, prefix):
        if prefix == b'':
            return [
                (b'__meta__', b'{"tip_height": 2}'),
                (b'h:000000000000', b'{"height": 0, "prev_block_hash": "' + ZERO_HASH_HEX.encode() + b'", "hash": "' + GENESIS_HASH_HEX.encode() + b'"}'),
                (b'h:000000000001', b'{"height": 1, "prev_block_hash": "' + GENESIS_HASH_HEX.encode() + b'"}'),
                (b'h:000000000002', b'{"height": 2, "prev_block_hash": "' + GENESIS_HASH_HEX.encode() + b'"}'),
            ]
        return []
    monkeypatch.setattr('tsarchain.consensus.chain_storage.iter_prefix', mock_iter_prefix)

    # Mock Block.from_dict to return a block with proper attributes
    def mock_from_dict(d):
        b = Mock(spec=Block)
        b.height = d.get("height", 0)
        prev = d.get("prev_block_hash", ZERO_HASH_HEX)
        b.prev_block_hash = bytes.fromhex(prev)
        b.hash = Mock(return_value=bytes.fromhex(GENESIS_HASH_HEX))
        b.transactions = []
        b.timestamp = 0
        b.bits = 0x1d00ffff
        b.chainwork = 0
        return b
    monkeypatch.setattr('tsarchain.consensus.chain_storage.Block', Mock(from_dict=mock_from_dict))

    # Mock GENESIS_HASH to match
    monkeypatch.setattr('tsarchain.consensus.chain_storage.GENESIS_HASH', bytes.fromhex(GENESIS_HASH_HEX))
    monkeypatch.setattr('tsarchain.consensus.chain_storage.CFG.ZERO_HASH', bytes.fromhex(ZERO_HASH_HEX))

    # Mock calculate_total_supply etc.
    storage.calculate_total_supply = Mock(return_value=1000)

    # Bypass journal – it is a fallback and not needed for this test
    storage._apply_chain_journal = lambda data: data  # no-op

    # Also need to patch ensure_utxodb and annotate
    storage.ensure_utxodb = Mock()
    annotate_mock = Mock()
    monkeypatch.setattr('tsarchain.consensus.chain_storage.annotate_local_snapshot_meta', annotate_mock)

    storage.load_chain()
    assert len(storage.chain) == 3
    assert storage._persisted_height == 2

    # Test backup alignment (only if interval > 0)
    CFG.BLOCK_BACKUP_SNAPSHOT = 10
    storage.load_chain()
    assert storage._snapshot_last_backup_height == 0  # (2 // 10) * 10 = 0


def test_load_chain_invalid_genesis(storage, monkeypatch):
    # Mock kv_enabled to return a block with wrong genesis height
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)

    ZERO_HASH_HEX = "0" * 64

    # This block has height 1, which is invalid for genesis (should be 0)
    def mock_iter_prefix(db, prefix):
        if prefix == b'':
            return [
                (b'h:000000000000', b'{"height": 1, "prev_block_hash": "' + ZERO_HASH_HEX.encode() + b'"}'),
            ]
        return []
    monkeypatch.setattr('tsarchain.consensus.chain_storage.iter_prefix', mock_iter_prefix)

    # Mock Block.from_dict
    def mock_from_dict(d):
        b = Mock(spec=Block)
        b.height = d["height"]
        b.prev_block_hash = bytes.fromhex(d["prev_block_hash"])
        b.hash = Mock(return_value=bytes.fromhex("1" * 64))
        return b
    monkeypatch.setattr('tsarchain.consensus.chain_storage.Block', Mock(from_dict=mock_from_dict))
    monkeypatch.setattr('tsarchain.consensus.chain_storage.CFG.ZERO_HASH', bytes.fromhex(ZERO_HASH_HEX))

    # Mock reset_chain_store
    storage.chain_storage._reset_chain_store = Mock()

    # Bypass journal
    storage._apply_chain_journal = lambda data: data

    storage.load_chain()
    # Should log error and reset
    storage.chain_storage._reset_chain_store.assert_called_once()


def test_load_chain_wrong_genesis_hash(storage, monkeypatch):
    # Simulate correct height but wrong hash
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)
    def mock_iter_prefix(db, prefix):
        if prefix == b'':
            return [
                (b'h:000000000000', b'{"height": 0, "prev_block_hash": "0000000000000000000000000000000000000000000000000000000000000000"}'),
            ]
        return []
    monkeypatch.setattr('tsarchain.consensus.chain_storage.iter_prefix', mock_iter_prefix)

    def mock_from_dict(d):
        b = Mock(spec=Block)
        b.height = d["height"]
        b.prev_block_hash = bytes.fromhex(d["prev_block_hash"])
        b.hash = Mock(return_value=bytes.fromhex("ff"*32))  # different from GENESIS
        return b
    monkeypatch.setattr('tsarchain.consensus.chain_storage.Block', Mock(from_dict=mock_from_dict))
    monkeypatch.setattr('tsarchain.consensus.chain_storage.GENESIS_HASH', bytes.fromhex("11"*32))
    monkeypatch.setattr('tsarchain.consensus.chain_storage.CFG.ZERO_HASH', bytes.fromhex("00"*32))

    storage.chain_storage._reset_chain_store = Mock()
    storage.load_chain()
    storage.chain_storage._reset_chain_store.assert_called_once()


# ----------------------------------------------------------------------
# State I/O tests
# ----------------------------------------------------------------------
def test_read_snapshot_state_kv(storage, monkeypatch):
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)
    # Mock iter_prefix to return state items
    def mock_iter_prefix(db, prefix):
        if prefix == b'k:':
            return [
                (b'k:snapshot', b'{"total_supply": 100, "total_blocks": 10}'),
                (b'k:total_supply', b'100'),
                (b'k:total_blocks', b'10'),
            ]
        return []
    monkeypatch.setattr('tsarchain.consensus.chain_storage.iter_prefix', mock_iter_prefix)

    data = storage._read_snapshot_state()
    assert data["total_supply"] == 100
    assert data["total_blocks"] == 10


def test_read_snapshot_state_nonkv(storage, monkeypatch, tmp_path):
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: False)
    CFG.STATE_FILE = str(tmp_path / "state.json")
    with open(CFG.STATE_FILE, "w") as f:
        json.dump({"total_supply": 200, "total_blocks": 20}, f)
    data = storage._read_snapshot_state()
    assert data["total_supply"] == 200


def test_load_state(storage):
    storage.chain_storage._read_snapshot_state = Mock(return_value={"total_supply": 300, "total_blocks": 30})
    storage.load_state()
    assert storage.total_supply == 300
    assert storage.total_blocks == 30
    assert storage.supply_in_tsar == 300 / CFG.TSAR   # <-- changed


def test_save_state(storage, monkeypatch):
    # Provide a chain of 5 dummy blocks so that len(chain) == 5
    mock_blk = Mock()
    mock_blk.transactions = []
    storage.chain = [mock_blk for _ in range(5)]
    # Mock calculate_total_supply to return 500
    storage.calculate_total_supply = Mock(return_value=500)

    # The following manual assignments are no longer needed because save_state
    # will recompute them, but we keep them as a safety net.
    storage.total_blocks = 5
    storage.total_supply = 500
    storage.supply_in_tsar = 0.0005

    storage.chain_storage._compute_state_snapshot = Mock(return_value={"schema_version": 1, "last_updated": "now"})

    # KV enabled
    monkeypatch.setattr('tsarchain.consensus.chain_storage.kv_enabled', lambda: True)
    batch_mock = Mock()
    batch_mock.__enter__ = Mock(return_value=batch_mock)
    batch_mock.__exit__ = Mock(return_value=False)
    batch_mock.put = Mock()
    monkeypatch.setattr('tsarchain.consensus.chain_storage.batch', lambda db: batch_mock)

    storage.save_state()

    assert batch_mock.put.call_count == 3
    snapshot_call = [call for call in batch_mock.put.call_args_list if call[0][0] == b'k:snapshot']
    assert snapshot_call
    snapshot_data = json.loads(snapshot_call[0][0][1].decode())
    assert snapshot_data["total_supply"] == 500   # now passes
    assert snapshot_data["total_blocks"] == 5


def test_compute_state_snapshot(storage, monkeypatch):
    # Build a chain with blocks and UTXO
    # Create block with coinbase tx
    cb_tx = Mock(spec=Tx)
    cb_tx.outputs = [Mock(amount=50_000_000_000, address="miner1")]
    cb_tx.to_dict = Mock(return_value={})
    block0 = Mock(spec=Block)
    block0.height = 0
    block0.transactions = [cb_tx]
    block0.timestamp = 1000
    block0.bits = 0x1d00ffff
    block0.chainwork = 0
    block0.hash = Mock(return_value=b'\x01'*32)
    block0.to_dict = Mock(return_value={"height": 0, "transactions": [cb_tx.to_dict()]})

    block1 = Mock(spec=Block)
    block1.height = 1
    block1.transactions = [cb_tx]  # same coinbase
    block1.timestamp = 2000
    block1.bits = 0x1d00ffff
    block1.chainwork = 100
    block1.hash = Mock(return_value=b'\x02'*32)
    # MUST set to_dict to return a dict to avoid Mock subscripting
    block1.to_dict = Mock(return_value={"height": 1, "hash": "somehash", "timestamp": 2000})

    storage.chain = [block0, block1]
    storage.total_blocks = 2
    storage.total_supply = 100_000_000_000

    # Mock UTXODB
    utxo = Mock(spec=UTXODB)
    utxo.version = 1
    utxo.utxos = {
        "txid1": {
            "tx_out": Mock(amount=1000),
            "is_coinbase": False,
            "block_height": 0,
        },
        "txid2": {
            "tx_out": Mock(amount=2000),
            "is_coinbase": True,
            "block_height": 0,  # immature
        }
    }
    utxo._lock = threading.Lock()

    # Attach graffiti registry to utxo to use our data
    registry = Mock(spec=GraffitiRegistry)
    registry.data = {
        "posts": {"art1": {"size": 100, "stats": {"pool_balance": 50}}},
        "comments": {"art1": ["comment1"]},
        "payouts": {"art1": ["payout1"]}
    }
    utxo._graffiti_registry = registry

    storage.ensure_utxodb = Mock(return_value=utxo)

    # Mock helpers
    mock_estimate = Mock(return_value=200)
    monkeypatch.setattr('tsarchain.consensus.chain_storage.estimate_block_size_bytes', mock_estimate)
    storage._compute_chainwork_for_chain = Mock(return_value=100)
    storage.median_time_past = Mock(return_value=1500)
    storage.scheduled_reward = Mock(return_value=50_000_000_000)
    storage.get_mempool = Mock(return_value=None)

    # Mock bits_to_target and target_to_difficulty
    monkeypatch.setattr('tsarchain.consensus.chain_storage.bits_to_target', lambda x: 0xffff)
    monkeypatch.setattr('tsarchain.consensus.chain_storage.target_to_difficulty', lambda x: 1)

    # Call
    snapshot = storage._compute_state_snapshot()
    assert snapshot["chain"]["total_blocks"] == 2
    assert snapshot["chain"]["tip_height"] == 1
    assert snapshot["supply"]["emitted_subsidy"] == 100_000_000_000
    assert snapshot["utxo"]["utxo_set_size"] == 2
    assert snapshot["graffiti"]["posts"] == 1
    assert snapshot["graffiti"]["comments"] == 1
    assert snapshot["graffiti"]["payouts"] == 1
    assert snapshot["graffiti"]["pool_balances"] == 50

    # Check cache
    assert storage._state_snapshot_cache is not None
    token = (1, 1)
    assert storage._state_snapshot_cache["token"] == token
    assert storage._state_snapshot_cache["data"] == snapshot

    # Second call should use cache
    mock_estimate.reset_mock()
    snapshot2 = storage._compute_state_snapshot()
    mock_estimate.assert_not_called()
    assert snapshot2 == snapshot


# ----------------------------------------------------------------------
# Additional edge cases for save_chain
# ----------------------------------------------------------------------
def test_save_chain_no_dirty(storage, monkeypatch):
    # Create a proper block mock with hash returning bytes
    mock_block = Mock(spec=Block)
    mock_block.hash = Mock(return_value=b'\x00' * 32)
    mock_block.height = 0
    mock_block.timestamp = 1234567890
    storage.chain = [mock_block]
    storage._persisted_height = 0
    storage._chain_dirty_from = None
    with patch('tsarchain.consensus.chain_storage.kv_enabled', return_value=True):
        with patch('tsarchain.consensus.chain_storage.batch') as mock_batch:
            storage.save_chain(force_full=False)
            mock_batch.assert_not_called()


def test_save_chain_interval_not_reached(storage, monkeypatch):
    # CHAIN_FLUSH_INTERVAL prevents flush if pending < interval
    storage.chain = [Mock(), Mock()]  # height 0,1
    storage._persisted_height = 0
    storage._chain_dirty_from = 1
    CFG.CHAIN_FLUSH_INTERVAL = 5
    with patch('tsarchain.consensus.chain_storage.kv_enabled', return_value=True):
        with patch('tsarchain.consensus.chain_storage.batch') as mock_batch:
            storage.save_chain(force_full=False)
            mock_batch.assert_not_called()
            # but should mark dirty_from
            assert storage._chain_dirty_from == 1


def test_save_chain_prune_when_tip_lower(storage, monkeypatch):
    # If persisted_height > tip_height, prune extra blocks
    mock_block = Mock()
    mock_block.timestamp = 1234567890
    mock_block.hash = Mock(return_value=b'\x00' * 32)
    storage.chain = [mock_block]  # height 0
    storage._persisted_height = 5
    storage._chain_dirty_from = None

    with patch('tsarchain.consensus.chain_storage.kv_enabled', return_value=True):
        # Mock batch context manager so that if code tries to use it, it won't fail
        batch_mock = Mock()
        batch_mock.__enter__ = Mock(return_value=batch_mock)
        batch_mock.__exit__ = Mock(return_value=False)
        batch_mock.put = Mock()
        with patch('tsarchain.consensus.chain_storage.batch', return_value=batch_mock):
            with patch.object(storage.chain_storage, '_prune_chain_store') as prune_mock:
                storage.save_chain(force_full=False)

                # Verify pruning was called with tip_height + 1 (0+1)
                prune_mock.assert_called_once_with(1)
                # Persisted height should be updated to tip_height (0)
                assert storage._persisted_height == 0
                # No batch.put should be called because no blocks are being saved
                batch_mock.put.assert_not_called()


# ----------------------------------------------------------------------
# Run tests
if __name__ == "__main__":
    pytest.main([__file__])