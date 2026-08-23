# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import os
import io
import json
import pytest
import tarfile
import tempfile
from unittest.mock import patch, MagicMock

from tsarchain.core.block import Block
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
    _download_with_progress,
    _extract_snapshot_payload,
    maybe_bootstrap_snapshot,
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
        mock_cfg.SNAPSHOT_META_PATH = meta_path

        res = annotate_local_snapshot_meta(100, 1234567890)
        assert res["height"] == 100
        assert res["generated_at"] == 1234567890

        res2 = annotate_local_snapshot_meta(100, 1234567890)
        assert res2["height"] == 100


@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap.iter_prefix")
def test_validate_snapshot_chain_binary_and_dict(mock_iter, mock_cfg):
    mock_cfg.LMDB_CHAIN_DIR = "some/dir"
    mock_cfg.ZERO_HASH = b"\x00" * 32
    mock_cfg.GENESIS_HASH_HEX = ""

    with patch("os.path.exists", return_value=True):
        # 1. Test dictionary block
        entry_dict = {"height": 0, "prev_block_hash": "00" * 32, "transactions": []}
        mock_iter.return_value = [(b"h:0", json.dumps(entry_dict).encode("utf-8"))]

        valid, reason = _validate_snapshot_chain()
        assert valid is True
        assert reason is None

        # 2. Test mismatched height
        entry_h1 = {"height": 1, "prev_block_hash": "00" * 32}
        mock_iter.return_value = [(b"h:1", json.dumps(entry_h1).encode("utf-8"))]
        valid, reason = _validate_snapshot_chain()
        assert not valid
        assert "first height 1" in reason


def test_extract_snapshot_payload_tar():
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = os.path.join(temp_dir, "test.tar.gz")
        dest_dir = os.path.join(temp_dir, "extracted")

        # Create dummy tar.gz with chain subfolder
        dummy_data = os.path.join(temp_dir, "data.mdb")
        with open(dummy_data, "wb") as f:
            f.write(b"dummy mdb content")

        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(dummy_data, arcname="chain/data.mdb")

        _extract_snapshot_payload(archive_path, dest_dir, lambda msg: None)

        assert os.path.exists(os.path.join(dest_dir, "chain", "data.mdb"))


@patch("tsarchain.utils.bootstrap.CFG")
def test_maybe_bootstrap_snapshot_disabled(mock_cfg):
    mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = False
    mock_cfg.NODE_DATA_DIR = "test_dir"
    res = maybe_bootstrap_snapshot()
    assert res.status == "skipped"
    assert res.reason == "disabled"


@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap._fetch_manifest")
def test_maybe_bootstrap_snapshot_skipped_no_url(mock_fetch, mock_cfg):
    mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = True
    mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = False
    mock_cfg.NODE_DATA_DIR = "test_dir"
    mock_cfg.SNAPSHOT_FILE_URL = ""
    mock_fetch.return_value = {}

    res = maybe_bootstrap_snapshot()
    assert res.status == "skipped"
    assert res.reason == "no_snapshot_url"


@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap._fetch_manifest")
@patch("tsarchain.utils.bootstrap._get_local_chain_height", return_value=500)
def test_maybe_bootstrap_snapshot_skipped_local_ahead(mock_local_h, mock_fetch, mock_cfg):
    mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = True
    mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = False
    mock_cfg.NODE_DATA_DIR = "test_dir"
    mock_fetch.return_value = {"url": "http://test.com/snap.tar.gz", "height": 300}

    res = maybe_bootstrap_snapshot()
    assert res.status == "skipped"
    assert res.reason == "local_chain_ahead"


@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap._fetch_manifest")
@patch("tsarchain.utils.bootstrap._download_with_progress", return_value=1000)
@patch("tsarchain.utils.bootstrap._extract_snapshot_payload")
@patch("tsarchain.utils.bootstrap._validate_snapshot_chain", return_value=(True, None))
def test_maybe_bootstrap_snapshot_success(mock_val, mock_ext, mock_dl, mock_fetch, mock_cfg):
    with tempfile.TemporaryDirectory() as temp_dir:
        node_dir = os.path.join(temp_dir, "node")
        mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = True
        mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = False
        mock_cfg.SNAPSHOT_MIN_SIZE_BYTES = 100
        mock_cfg.NODE_DATA_DIR = node_dir
        mock_cfg.SNAPSHOT_META_PATH = os.path.join(node_dir, "snapshot.meta.json")
        mock_fetch.return_value = {"url": "http://test.com/snap.tar.gz", "height": 1000}

        res = maybe_bootstrap_snapshot()
        assert res.status == "installed"
        assert res.height == 1000
        assert res.bytes_written == 1000
        assert os.path.exists(node_dir)


@patch("tsarchain.utils.bootstrap.CFG")
@patch("tsarchain.utils.bootstrap._fetch_manifest")
@patch("tsarchain.utils.bootstrap._download_with_progress", return_value=1000)
@patch("tsarchain.utils.bootstrap._extract_snapshot_payload")
@patch("tsarchain.utils.bootstrap._validate_snapshot_chain", return_value=(False, "corrupted genesis"))
def test_maybe_bootstrap_snapshot_validation_failure_rollback(mock_val, mock_ext, mock_dl, mock_fetch, mock_cfg):
    with tempfile.TemporaryDirectory() as temp_dir:
        node_dir = os.path.join(temp_dir, "node")
        os.makedirs(node_dir, exist_ok=True)
        with open(os.path.join(node_dir, "existing_file.txt"), "w") as f:
            f.write("original node state")

        mock_cfg.SNAPSHOT_BOOTSTRAP_ENABLED = True
        mock_cfg.SNAPSHOT_REQUIRE_SIGNATURE = False
        mock_cfg.SNAPSHOT_MIN_SIZE_BYTES = 100
        mock_cfg.NODE_DATA_DIR = node_dir
        mock_cfg.SNAPSHOT_META_PATH = os.path.join(node_dir, "snapshot.meta.json")
        mock_fetch.return_value = {"url": "http://test.com/snap.tar.gz", "height": 1000}

        res = maybe_bootstrap_snapshot()
        assert res.status == "failed"
        assert "corrupted genesis" in res.reason
        # Ensure rollback preserved the original state
        assert os.path.exists(os.path.join(node_dir, "existing_file.txt"))


def test_extract_snapshot_payload_raw_mdb():
    with tempfile.TemporaryDirectory() as temp_dir:
        raw_mdb = os.path.join(temp_dir, "data.mdb")
        with open(raw_mdb, "wb") as f:
            f.write(b"raw mdb data")

        dest_dir = os.path.join(temp_dir, "extracted")
        _extract_snapshot_payload(raw_mdb, dest_dir, lambda msg: None)

        assert os.path.exists(os.path.join(dest_dir, "chain", "data.mdb"))


def test_extract_snapshot_payload_nested_tar():
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = os.path.join(temp_dir, "nested.tar.gz")
        dest_dir = os.path.join(temp_dir, "extracted")

        dummy_data = os.path.join(temp_dir, "data.mdb")
        with open(dummy_data, "wb") as f:
            f.write(b"nested chain data")

        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(dummy_data, arcname="node/chain/data.mdb")

        _extract_snapshot_payload(archive_path, dest_dir, lambda msg: None)

        assert os.path.exists(os.path.join(dest_dir, "chain", "data.mdb"))


@patch("tsarchain.utils.bootstrap.urllib.request.urlopen")
@patch("tsarchain.utils.bootstrap.CFG")
def test_download_with_progress(mock_cfg, mock_urlopen):
    import hashlib
    mock_cfg.SNAPSHOT_USER_AGENT = "TsarChainSnapshot/1.0"
    mock_cfg.SNAPSHOT_HTTP_TIMEOUT = 10
    mock_cfg.SNAPSHOT_CHUNK_BYTES = 1024

    content = b"A" * 4096
    expected_sha = hashlib.sha256(content).hexdigest()

    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Length": "4096"}
    mock_resp.read.side_effect = [b"A" * 1024, b"A" * 1024, b"A" * 1024, b"A" * 1024, b""]
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    with tempfile.TemporaryDirectory() as temp_dir:
        dest_file = os.path.join(temp_dir, "downloaded.tmp")
        messages = []
        downloaded_bytes = _download_with_progress(
            "http://test.com/snap.tar.gz",
            dest_file,
            expected_sha,
            lambda msg: messages.append(msg),
        )

        assert downloaded_bytes == 4096
        assert len(messages) > 0
        with open(dest_file, "rb") as f:
            assert f.read() == content



