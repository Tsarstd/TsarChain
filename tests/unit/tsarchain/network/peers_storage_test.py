# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import pytest
from unittest.mock import patch, mock_open

from tsarchain.network import peers_storage

@pytest.fixture
def mock_kv():
    with patch("tsarchain.storage.kv.kv_enabled") as mock_enabled, \
         patch("tsarchain.network.peers_storage.get") as mock_get, \
         patch("tsarchain.network.peers_storage.put") as mock_put:
        yield mock_enabled, mock_get, mock_put

@pytest.fixture
def mock_cfg():
    with patch("tsarchain.network.peers_storage.CFG") as mock_cfg:
        mock_cfg.NODE_KEY_PATH = "node_key.json"
        mock_cfg.ARCHIVIST_KEY_PATH = "archivist_key.json"
        mock_cfg.PEER_KEYS_PATH = "peer_keys.json"
        mock_cfg.CANONICAL_SEP = (',', ':')
        yield mock_cfg

def test_load_record_kv_enabled_success(mock_kv, mock_cfg):
    mock_enabled, mock_get, mock_put = mock_kv
    mock_enabled.return_value = True
    
    mock_data = {"key": "value"}
    mock_get.return_value = json.dumps(mock_data).encode("utf-8")
    
    result = peers_storage._load_record("node_key")
    
    assert result == mock_data
    mock_get.assert_called_once_with("node_secrets", b"node_key")

def test_load_record_kv_enabled_decode_error(mock_kv, mock_cfg):
    mock_enabled, mock_get, mock_put = mock_kv
    mock_enabled.return_value = True
    
    mock_get.return_value = b"invalid_json"
    
    result = peers_storage._load_record("node_key")
    
    assert result is None

def test_load_record_kv_disabled_returns_none(mock_kv, mock_cfg):
    mock_enabled, mock_get, mock_put = mock_kv
    mock_get.return_value = None
    
    result = peers_storage._load_record("node_key")
    assert result is None

def test_load_record_kv_enabled_no_data(mock_kv, mock_cfg):
    mock_enabled, mock_get, mock_put = mock_kv
    mock_enabled.return_value = True
    mock_get.return_value = None
    
    with patch("os.path.exists", return_value=False):
        result = peers_storage._load_record("node_key")
        
    assert result is None
    mock_put.assert_not_called()

def test_store_record_kv_enabled(mock_kv, mock_cfg):
    mock_enabled, mock_get, mock_put = mock_kv
    mock_enabled.return_value = True
    
    mock_data = {"key": "value"}
    peers_storage._store_record("node_key", mock_data)
        
    mock_put.assert_called_once()

def test_store_record_kv_disabled(mock_kv, mock_cfg):
    mock_enabled, mock_get, mock_put = mock_kv
    mock_data = {"key": "value"}
    peers_storage._store_record("node_key", mock_data)
    mock_put.assert_called_once()

def test_load_node_key(mock_kv):
    with patch("tsarchain.network.peers_storage._load_record") as mock_load:
        mock_load.return_value = {"a": "b"}
        res = peers_storage.load_node_key("node_key")
        assert res == {"a": "b"}
        mock_load.assert_called_once_with("node_key")

def test_save_node_key(mock_kv):
    with patch("tsarchain.network.peers_storage._store_record") as mock_store:
        with patch("time.time", return_value=12345):
            peers_storage.save_node_key("node_key", {"k": "v"})
            mock_store.assert_called_once_with("node_key", {"k": "v", "updated": 12345})

def test_load_peer_keys():
    with patch("tsarchain.network.peers_storage._load_record") as mock_load:
        mock_load.return_value = {"peer1": "key1", "peer2": 123}
        res = peers_storage.load_peer_keys()
        assert res == {"peer1": "key1", "peer2": "123"}

def test_load_peer_keys_none():
    with patch("tsarchain.network.peers_storage._load_record") as mock_load:
        mock_load.return_value = None
        res = peers_storage.load_peer_keys()
        assert res == {}

def test_save_peer_keys():
    with patch("tsarchain.network.peers_storage._store_record") as mock_store:
        peers_storage.save_peer_keys({"peer1": "key1", "peer2": 123})
        mock_store.assert_called_once_with("peer_keys", {"peer1": "key1", "peer2": "123"})

def test_resolve_key_and_path(mock_cfg):
    key, path = peers_storage._resolve_key_and_path("node_key")
    assert key == "node_key"
    assert path == "node_key.json"

    key, path = peers_storage._resolve_key_and_path("node_key.json")
    assert key == "node_key"
    assert path == "node_key.json"

    key, path = peers_storage._resolve_key_and_path("custom/path.json")
    assert key == "custom/path.json"
    assert path == "custom/path.json"

def test_load_record_kv_enabled_auto_migration(mock_kv, mock_cfg):
    mock_enabled, mock_get, mock_put = mock_kv
    mock_enabled.return_value = True
    mock_get.return_value = None  # Key not in KV store yet
    
    mock_data = {"id": "node123", "pubkey": "abc"}
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=json.dumps(mock_data))):
            result = peers_storage._load_record("node_key.json")
        
    assert result == mock_data
    mock_put.assert_called_once_with("node_secrets", b"node_key", json.dumps(mock_data, separators=(',', ':')).encode("utf-8"))

