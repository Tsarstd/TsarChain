# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest
from unittest.mock import patch, MagicMock

from archivist.database_archivist import ArchivistDatabase

@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "storage")
    return ArchivistDatabase(storage_dir=db_path, enable_blobs=True, enable_index=True)

def test_db_init_lmdb(tmp_path):
    db = ArchivistDatabase(storage_dir=str(tmp_path), enable_blobs=True, enable_index=True)
    test_idx = {"files": {"gid1": {"size_bytes": 100}}, "bytes_used": 100, "art_map": {"art1": "gid1"}}
    db.save_index(test_idx)
    
    loaded = db.load_index()
    assert loaded["bytes_used"] == 100

def test_db_init_disabled_index(tmp_path):
    db = ArchivistDatabase(storage_dir=str(tmp_path), enable_index=False)
    test_idx = {"files": {"gid1": {"size_bytes": 100}}, "bytes_used": 100, "art_map": {"art1": "gid1"}}
    db.save_index(test_idx)
    loaded = db.load_index()
    assert loaded["files"]["gid1"]["size_bytes"] == 100

def test_incoming_blobs(tmp_db):
    gid = "test_gid"
    chunk = b"hello world"
    
    # Test append
    new_size = tmp_db.append_incoming(gid, chunk, max_chunk=1024)
    assert new_size == len(chunk)
    
    # Test get bytes
    data = tmp_db.get_incoming_bytes(gid)
    assert data == chunk
    
    # Test pop (reads and deletes)
    popped = tmp_db.pop_incoming(gid)
    assert popped == chunk
    
    # Verify it was deleted
    assert tmp_db.get_incoming_bytes(gid) is None

def test_blob_limits(tmp_db):
    # Test chunk too big
    with pytest.raises(ValueError, match="chunk_too_big"):
        tmp_db.append_incoming("gid", b"12345", max_chunk=2)
        
    # Test file too large
    with patch("archivist.database_archivist.CFG.GRAFFITI_MAX_SIZE_BYTES", 2):
        with pytest.raises(ValueError, match="file_too_large"):
            tmp_db.append_incoming("gid", b"123", max_chunk=10)

def test_blobs_disabled(tmp_path):
    db = ArchivistDatabase(storage_dir=str(tmp_path), enable_blobs=False)
    with pytest.raises(RuntimeError, match="blobs_disabled"):
        db.append_incoming("gid", b"data", 100)
    with pytest.raises(RuntimeError, match="blobs_disabled"):
        db.get_incoming_bytes("gid")
    with pytest.raises(RuntimeError, match="blobs_disabled"):
        db.pop_incoming("gid")
    with pytest.raises(RuntimeError, match="blobs_disabled"):
        db.put_final("gid", b"data")
    with pytest.raises(RuntimeError, match="blobs_disabled"):
        db.promote_incoming("gid")
    with pytest.raises(RuntimeError, match="blobs_disabled"):
        db.delete_blob("gid", incoming=True, final=True)

@patch("archivist.database_archivist._native_open_storage")
@patch("tsarchain.storage.kv.kv_enabled", return_value=True)
def test_kv_operations(mock_kv_enabled, mock_native, tmp_path):
    # Mock LMDB store
    mock_store_idx = MagicMock()
    mock_store_final = MagicMock()
    mock_native.side_effect = [mock_store_idx, mock_store_final]
    
    db = ArchivistDatabase(storage_dir=str(tmp_path), enable_blobs=True, enable_index=True)
    
    # Test save_index to KV
    test_idx = {"files": {"gid1": {"size_bytes": 100}}, "bytes_used": 100, "art_map": {"art1": "gid1"}}
    db.save_index(test_idx)
    assert mock_store_idx.clear_db.called
    assert mock_store_idx.put_batch.called
    
    # Test promote incoming
    db.append_incoming("gid2", b"data", 100)
    promoted = db.promote_incoming("gid2")
    assert promoted is True
    assert mock_store_final.put_bytes.called
    
    # Test get_final_bytes_range
    mock_store_final.get_bytes_range.return_value = b"nal"
    res_range = db.get_final_bytes_range("gid2", 2, 3)
    assert res_range == b"nal"
    mock_store_final.get_bytes_range.assert_called_with("final", b"blob:gid2", 2, 3)
    
    # Test delete
    db.delete_blob("gid2", final=True)
    assert mock_store_final.delete.called

@patch("archivist.database_archivist._native_open_storage")
@patch("tsarchain.storage.kv.kv_enabled", return_value=True)
def test_load_index_kv(mock_kv, mock_native, tmp_path):
    mock_store_idx = MagicMock()
    mock_native.return_value = mock_store_idx
    
    db = ArchivistDatabase(storage_dir=str(tmp_path), enable_blobs=True, enable_index=True)
    
    def fake_iter_chunk(db_name, prefix, limit, start_after):
        if prefix == b"file:" and start_after is None:
            return [(b"file:gid1", b'{"size_bytes": 100}')]
        elif prefix == b"art:" and start_after is None:
            return [(b"art:art1", b'gid1')]
        return []
        
    mock_store_idx.iter_prefix_chunk.side_effect = fake_iter_chunk
    
    idx = db.load_index()
    assert idx["bytes_used"] == 100
    assert "gid1" in idx["files"]
    assert idx["art_map"]["art1"] == "gid1"
