# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import os
import json
import pytest
import tempfile
from unittest.mock import patch, MagicMock

from tsarchain.utils.bootstrap import (
    _safe_lower,
    _safe_int,
    _hash_file,
    _write_meta,
    _load_meta,
    _verify_manifest_signature,
    annotate_local_snapshot_meta,
    _validate_snapshot_chain,
    _fetch_manifest,
    maybe_bootstrap_snapshot
)

def test_safe_lower():
    data = {"key1": " VALUE ", "key2": 123}
    assert _safe_lower(data, "key1") == "value"
    assert _safe_lower(data, "key2") == ""
    assert _safe_lower(data, "missing") == ""
    assert _safe_lower(None, "key") == ""

def test_safe_int():
    data = {"key1": "123", "key2": 456, "key3": "invalid"}
    assert _safe_int(data, "key1") == 123
    assert _safe_int(data, "key2") == 456
    assert _safe_int(None, "key") == 0
    with pytest.raises(ValueError):
        _safe_int(data, "key3")

def test_hash_file():
    content = b"test content for hashing"
    import hashlib
    expected_hash = hashlib.sha256(content).hexdigest()
    
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        temp_name = f.name
        
    try:
        assert _hash_file(temp_name) == expected_hash
    finally:
        os.remove(temp_name)

def test_write_and_load_meta():
    meta_data = {"version": 1, "status": "ok"}
    with tempfile.TemporaryDirectory() as temp_dir:
        meta_path = os.path.join(temp_dir, "meta.json")
        _write_meta(meta_path, meta_data)
        
        loaded = _load_meta(meta_path)
        assert loaded == meta_data
        
        assert _load_meta(os.path.join(temp_dir, "nonexistent.json")) == {}

@patch("tsarchain.utils.bootstrap.CFG")
def test_verify_manifest_signature(mock_cfg):
    mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = False
    assert _verify_manifest_signature(None) is True
    assert _verify_manifest_signature({"signature": ""}) is True

    mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = True
    assert _verify_manifest_signature({"signature": ""}) is False

    mock_cfg.SNAPSHOT_PUBKEY_HEX = ""
    assert _verify_manifest_signature({"signature": "abcd"}) is False

    # Simulate valid verification
    with patch("tsarchain.utils.bootstrap.VerifyingKey") as mock_vk:
        mock_cfg.SNAPSHOT_PUBKEY_HEX = "02" * 33
        mock_cfg.CANONICAL_SEP = (",", ":")
        
        instance = MagicMock()
        instance.verify.return_value = True
        mock_vk.from_string.return_value = instance

        manifest = {"signature": "abcd", "url": "test"}
        assert _verify_manifest_signature(manifest) is True

@patch("tsarchain.utils.bootstrap.urllib.request.urlopen")
@patch("tsarchain.utils.bootstrap.CFG")
def test_fetch_manifest(mock_cfg, mock_urlopen):
    mock_cfg.SNAPSHOT_MANIFEST_URL = "http://test.com/manifest"
    
    # Mock response
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"url": "http://test.com/snap"}).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    manifest = _fetch_manifest()
    assert manifest == {"url": "http://test.com/snap"}

@patch("tsarchain.utils.bootstrap.CFG")
def test_fetch_manifest_no_url(mock_cfg):
    mock_cfg.SNAPSHOT_MANIFEST_URL = ""
    assert _fetch_manifest() is None
    
@patch("tsarchain.utils.bootstrap.urllib.request.urlopen")
@patch("tsarchain.utils.bootstrap.CFG")
def test_fetch_manifest_exception(mock_cfg, mock_urlopen):
    mock_cfg.SNAPSHOT_MANIFEST_URL = "http://test.com/manifest"
    mock_urlopen.side_effect = Exception("error")
    assert _fetch_manifest() is None

@patch("tsarchain.utils.bootstrap.CFG")
def test_annotate_local_snapshot_meta(mock_cfg):
    with tempfile.TemporaryDirectory() as temp_dir:
        meta_path = os.path.join(temp_dir, "snapshot.meta.json")
        data_path = os.path.join(temp_dir, "data.mdb")
        
        with open(data_path, "wb") as f:
            f.write(b"data")
            
        mock_cfg.SNAPSHOT_META_PATH = meta_path
        mock_cfg.LMDB_DATA_FILE = data_path
        
        res = annotate_local_snapshot_meta(100, 1234567890)
        assert res["height"] == 100
        assert res["generated_at"] == 1234567890
        assert res["size"] == 4

        # Test with no updates
        res2 = annotate_local_snapshot_meta(100, 1234567890)
        assert res2["height"] == 100
        
@patch("tsarchain.utils.bootstrap.CFG")
def test_annotate_local_snapshot_meta_no_path(mock_cfg):
    mock_cfg.SNAPSHOT_META_PATH = ""
    assert annotate_local_snapshot_meta(100) is None

@patch("os.path.exists", return_value=False)
def test_validate_snapshot_chain_no_kv(mock_exists):
    valid, reason = _validate_snapshot_chain()
    assert not valid
    assert "missing" in reason.lower()

@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap.iter_prefix")
def test_validate_snapshot_chain_valid(mock_iter, mock_cfg):
    mock_cfg.LMDB_DATA_FILE = "some/dir"
    mock_cfg.ZERO_HASH.hex.return_value = "000abc"
    with patch("os.path.exists", return_value=True):
        entry = {"height": 0, "prev_block_hash": "000abc", "hash": "000abc"}
        mock_cfg.GENESIS_HASH_HEX = "000abc"
        mock_iter.return_value = [(b"h:0", json.dumps(entry).encode("utf-8"))]
        
        valid, reason = _validate_snapshot_chain()
        assert valid is True
        assert reason is None
        
        # Test mismatched height
        entry_h1 = {"height": 1}
        mock_iter.return_value = [(b"h:1", json.dumps(entry_h1).encode("utf-8"))]
        valid, reason = _validate_snapshot_chain()
        assert not valid
        assert "first height 1" in reason

@patch("tsarchain.utils.bootstrap.CFG")
def test_maybe_bootstrap_snapshot_disabled(mock_cfg):
    mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = False
    mock_cfg.LMDB_DATA_FILE = "test.mdb"
    with patch("os.makedirs"):
        with patch("os.path.isfile", return_value=False):
            res = maybe_bootstrap_snapshot()
            assert res.status == "skipped"

@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap._fetch_manifest")
def test_maybe_bootstrap_snapshot_skipped_no_url(mock_fetch, mock_cfg):
    mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = True
    mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = False
    mock_cfg.LMDB_DATA_FILE = "test.mdb"
    mock_fetch.return_value = {}
    
    with patch("os.makedirs"):
        with patch("os.path.isfile", return_value=False):
            res = maybe_bootstrap_snapshot()
            assert res.status == "skipped"
            assert res.reason == "no_snapshot_url"

@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap._fetch_manifest")
@patch("tsarchain.utils.bootstrap.urllib.request.urlopen")
def test_maybe_bootstrap_snapshot_success(mock_urlopen, mock_fetch, mock_cfg):
    mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = True
    mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = False
    mock_cfg.LMDB_DATA_FILE = "test.mdb"
    mock_cfg.SNAPSHOT_MIN_SIZE_BYTES = 1
    mock_fetch.return_value = {"url": "http://test.com/db", "height": 10}
    
    mock_resp = MagicMock()
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    with patch("os.makedirs"), \
         patch("os.path.isfile", return_value=False), \
         patch("shutil.copyfileobj") as mock_copy, \
         patch("os.path.getsize", return_value=100), \
         patch("os.path.exists", return_value=False), \
         patch("os.replace"), \
         patch("tsarchain.utils.bootstrap._write_meta"), \
         patch("tsarchain.utils.bootstrap._validate_snapshot_chain", return_value=(True, None)):
         
        res = maybe_bootstrap_snapshot()
        assert res.status == "installed"
        assert res.height == 10
        assert res.bytes_written == 100
        
@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap._fetch_manifest")
def test_maybe_bootstrap_snapshot_failed_validation(mock_fetch, mock_cfg):
    mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = True
    mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = True
    mock_cfg.LMDB_DATA_FILE = "test.mdb"
    mock_fetch.return_value = {"url": "http://test.com/db", "height": 10, "signature": "bad"}
    
    with patch("tsarchain.utils.bootstrap._verify_manifest_signature", return_value=False), \
         patch("os.makedirs"), \
         patch("os.path.isfile", return_value=False):
         
        res = maybe_bootstrap_snapshot()
        assert res.status == "failed"
        assert res.reason == "signature_invalid"

