# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import os
import pytest
from unittest.mock import MagicMock, patch
from tsarchain.storage import kv
from tsarchain.storage.kv import (
    kv_enabled, _init_native_store, _ensure_env,
    get, put, delete, clear_db, iter_prefix,
    batch
)

@pytest.fixture(autouse=True)
def reset_native_store():
    # Reset global _native_store before and after each test
    original_store = kv._native_store
    kv._native_store = None
    yield
    kv._native_store = original_store

def test_kv_enabled():
    with patch("tsarchain.storage.kv.CFG") as mock_cfg:
        mock_cfg.KV_BACKEND = "lmdb"
        assert kv_enabled() is True

        mock_cfg.KV_BACKEND = "json"
        assert kv_enabled() is False

def test_init_native_store_disabled():
    with patch("tsarchain.storage.kv.kv_enabled", return_value=False):
        assert _init_native_store() is None

def test_init_native_store_enabled():
    mock_store = MagicMock()
    with patch("tsarchain.storage.kv.kv_enabled", return_value=True), \
         patch("tsarchain.storage.kv._native_open_storage", return_value=mock_store) as mock_open:
        
        store = _init_native_store()
        assert store is mock_store
        # Calling it again should return cached store without re-opening
        assert _init_native_store() is mock_store
        assert mock_open.call_count == 1

def test_ensure_env_disabled():
    with patch("tsarchain.storage.kv.kv_enabled", return_value=False):
        assert _ensure_env() is None

def test_ensure_env_enabled_success():
    mock_store = MagicMock()
    with patch("tsarchain.storage.kv.kv_enabled", return_value=True), \
         patch("tsarchain.storage.kv._native_open_storage", return_value=mock_store):
        assert _ensure_env() is mock_store

def test_ensure_env_enabled_failure():
    with patch("tsarchain.storage.kv.kv_enabled", return_value=True), \
         patch("tsarchain.storage.kv._native_open_storage", return_value=None):
        with pytest.raises(RuntimeError, match="Native storage required but not initialized"):
            _ensure_env()

def test_get_disabled():
    with patch("tsarchain.storage.kv._ensure_env", return_value=None):
        assert get("test_db", b"key") is None

def test_get_enabled():
    mock_store = MagicMock()
    mock_store.get_bytes.return_value = b"value"
    with patch("tsarchain.storage.kv._ensure_env", return_value=mock_store):
        assert get("test_db", b"key") == b"value"
        mock_store.get_bytes.assert_called_once_with("test_db", b"key")

        # Test key not found
        mock_store.get_bytes.return_value = None
        assert get("test_db", b"key2") is None

def test_put_disabled():
    with patch("tsarchain.storage.kv._ensure_env", return_value=None):
        with pytest.raises(RuntimeError, match="KV not enabled"):
            put("test_db", b"key", b"value")

def test_put_enabled():
    mock_store = MagicMock()
    with patch("tsarchain.storage.kv._ensure_env", return_value=mock_store):
        put("test_db", b"key", b"value")
        mock_store.put_bytes.assert_called_once_with("test_db", b"key", b"value")

def test_delete_disabled():
    with patch("tsarchain.storage.kv._ensure_env", return_value=None):
        # Should not raise exception
        delete("test_db", b"key")

def test_delete_enabled():
    mock_store = MagicMock()
    with patch("tsarchain.storage.kv._ensure_env", return_value=mock_store):
        delete("test_db", b"key")
        mock_store.delete.assert_called_once_with("test_db", b"key")

def test_clear_db_disabled():
    with patch("tsarchain.storage.kv._ensure_env", return_value=None):
        assert clear_db("test_db") == 0

def test_clear_db_enabled():
    mock_store = MagicMock()
    mock_store.clear_db.return_value = 42
    with patch("tsarchain.storage.kv._ensure_env", return_value=mock_store):
        assert clear_db("test_db") == 42
        mock_store.clear_db.assert_called_once_with("test_db")

def test_iter_prefix_disabled():
    with patch("tsarchain.storage.kv._ensure_env", return_value=None):
        results = list(iter_prefix("test_db", b"prefix"))
        assert results == []

def test_iter_prefix_enabled():
    mock_store = MagicMock()
    # Mock behavior of iter_prefix_chunk
    # First call returns a chunk of data, second call returns empty to end iteration
    mock_store.iter_prefix_chunk.side_effect = [
        [(b"prefix_1", b"val1"), (b"prefix_2", b"val2")],
        []
    ]
    with patch("tsarchain.storage.kv._ensure_env", return_value=mock_store), \
         patch("tsarchain.storage.kv.CFG") as mock_cfg:
        mock_cfg.KV_ITER_CHUNK = 2
        
        results = list(iter_prefix("test_db", b"prefix"))
        assert results == [(b"prefix_1", b"val1"), (b"prefix_2", b"val2")]
        
        # Verify calls to iter_prefix_chunk
        mock_store.iter_prefix_chunk.assert_any_call("test_db", b"prefix", limit=2, start_after=None)
        mock_store.iter_prefix_chunk.assert_any_call("test_db", b"prefix", limit=2, start_after=b"prefix_2")

def test_batch_disabled():
    with patch("tsarchain.storage.kv._ensure_env", return_value=None):
        with pytest.raises(RuntimeError, match="KV not enabled"):
            with batch("test_db"):
                pass

def test_batch_enabled():
    mock_store = MagicMock()
    with patch("tsarchain.storage.kv._ensure_env", return_value=mock_store):
        with batch("test_db") as b:
            b.put(b"key1", b"val1")
            b.delete(b"key2")
        
        mock_store.put_batch.assert_called_once_with("test_db", [
            (b"key1", b"val1"),
            (b"key2", None)
        ])

def test_init_native_store_drive_type_override():
    mock_store = MagicMock()
    mock_store.drive_type = "hdd"
    with patch("tsarchain.storage.kv.kv_enabled", return_value=True), \
         patch.dict(os.environ, {"TSAR_STORAGE_DRIVE_TYPE": "hdd"}), \
         patch("tsarchain.storage.kv._native_open_storage", return_value=mock_store) as mock_open:
        
        store = _init_native_store()
        assert store is mock_store
        mock_open.assert_called_once()
        assert mock_open.call_args[1].get("drive_type") == "hdd"

def test_sync():
    # Test sync when disabled
    with patch("tsarchain.storage.kv._ensure_env", return_value=None):
        kv.sync()

    # Test sync when enabled
    mock_store = MagicMock()
    with patch("tsarchain.storage.kv._ensure_env", return_value=mock_store):
        kv.sync(force=True)
        mock_store.sync.assert_called_once_with(True)

