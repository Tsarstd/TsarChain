# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import os
import pytest
import base64
from unittest.mock import patch, MagicMock

from archivist.node_route import handle_node_rpc

@pytest.fixture
def server(tmp_path):
    srv = MagicMock()
    srv.index = {"files": {}, "bytes_used": 0, "art_map": {}}
    srv.use_kv = False
    srv.storage_dir = str(tmp_path)
    srv.db = MagicMock()
    
    def norm(aid, meta):
        return meta
    srv._normalize_file_meta.side_effect = norm
    
    return srv

def test_ping(server):
    res = handle_node_rpc(server, {"type": "PING"})
    assert res == {"type": "PONG"}

def test_stor_index(server):
    server.index["files"]["gid1"] = {"size_bytes": 100}
    res = handle_node_rpc(server, {"type": "STOR_INDEX"})
    assert res["type"] == "STOR_INDEX"
    assert res["bytes_used"] == 100

def test_stor_paid_missing(server):
    res = handle_node_rpc(server, {"type": "STOR_PAID", "graffiti_id": "gid1"})
    assert res["status"] == "error"
    assert res["reason"] == "no_such"

def test_stor_paid_fs_mode(server, tmp_path):
    # Setup test file
    incoming_dir = tmp_path / "incoming"
    incoming_dir.mkdir()
    part_file = incoming_dir / "gid1.part"
    part_file.write_text("hello")
    
    server.index["files"]["gid1"] = {"size_bytes": 5, "path": str(part_file)}
    
    res = handle_node_rpc(server, {"type": "STOR_PAID", "graffiti_id": "gid1", "txid": "tx1", "block_height": 100})
    assert res["status"] == "ok"
    assert res["graffiti_id"] == "gid1"
    
    meta = server.index["files"]["gid1"]
    assert meta["paid"] is True
    assert meta["txid_paid"] == "tx1"
    assert meta["confirmed_at_height"] == 100
    assert "final" in meta["path"]
    assert os.path.exists(meta["path"])

def test_stor_paid_kv_mode(server):
    server.use_kv = True
    server.db.get_final_bytes_range.return_value = None
    server.db.pop_incoming.return_value = b"hello"
    
    server.index["files"]["gid1"] = {"size_bytes": 5}
    
    res = handle_node_rpc(server, {"type": "STOR_PAID", "graffiti_id": "gid1"})
    assert res["status"] == "ok"
    assert server.db.put_final.call_count == 1
    
    meta = server.index["files"]["gid1"]
    assert meta["paid"] is True
    assert meta["path"] == "lmdb://final/gid1"
    assert meta["state"] == "stored"

def test_stor_gc(server, tmp_path):
    file_path = tmp_path / "gid1.bin"
    file_path.write_text("hello")
    
    server.index["files"]["gid1"] = {"size_bytes": 5, "paid": False, "expire_at_height": 100, "path": str(file_path)}
    server.index["files"]["gid2"] = {"size_bytes": 10, "paid": True, "expire_at_height": 100}
    
    # tip is past expire height
    res = handle_node_rpc(server, {"type": "STOR_GC", "tip_height": 105})
    assert res["status"] == "ok"
    assert res["expired"] == 1
    
    assert "gid1" not in server.index["files"]
    assert "gid2" in server.index["files"]
    assert not os.path.exists(file_path)

def test_stor_gc_kv(server):
    server.use_kv = True
    server.index["files"]["gid1"] = {"size_bytes": 5, "paid": False, "expire_at_height": 100}
    
    handle_node_rpc(server, {"type": "STOR_GC", "tip_height": 105})
    assert server.db.delete_blob.call_count == 1

@patch("archivist.node_route.GRAFFITI.calc_proof_challenge")
@patch("archivist.node_route.GRAFFITI.hash_proof_chunk")
def test_stor_proof_run_kv(mock_hash, mock_chal, server):
    server.use_kv = True
    server.index["files"]["gid1"] = {"size_bytes": 5, "art_id": "art1"}
    
    mock_chal.return_value = {"offset": 0, "length": 5, "epoch": 1, "seed": "abc"}
    mock_hash.return_value = "hash123"
    
    server.db.get_final_bytes_range.return_value = b"hello"
    server.db.get_final_merkle_path.return_value = ["hashA", "hashB"]
    
    res = handle_node_rpc(server, {"type": "STOR_PROOF_RUN", "graffiti_id": "gid1", "tip_height": 100})
    assert res["status"] == "ok"
    assert res["hash"] == "hash123"
    assert res["chunk"] == base64.b64encode(b"hello").decode("ascii")
    assert res["path"] == ["hashA", "hashB"]

@patch("archivist.node_route.GRAFFITI.calc_proof_challenge")
@patch("archivist.node_route.GRAFFITI.hash_proof_chunk")
@patch("archivist.node_route.GRAFFITI.merkle_path_for_file")
def test_stor_proof_run_fs(mock_merkle, mock_hash, mock_chal, server, tmp_path):
    file_path = tmp_path / "gid1.bin"
    file_path.write_bytes(b"hello")
    
    server.index["files"]["gid1"] = {"size_bytes": 5, "art_id": "art1", "path": str(file_path)}
    
    mock_chal.return_value = {"offset": 0, "length": 5, "epoch": 1, "seed": "abc"}
    mock_hash.return_value = "hash123"
    mock_merkle.return_value = ["hashA", "hashB"]
    
    res = handle_node_rpc(server, {"type": "STOR_PROOF_RUN", "graffiti_id": "gid1", "tip_height": 100})
    assert res["status"] == "ok"
    assert res["hash"] == "hash123"
    assert res["chunk"] == base64.b64encode(b"hello").decode("ascii")

def test_stor_proof_run_missing(server):
    res = handle_node_rpc(server, {"type": "STOR_PROOF_RUN", "graffiti_id": "gid1"})
    assert res["status"] == "error"
    assert res["reason"] == "no_such"

    # Missing art id
    server.index["files"]["gid2"] = {"size_bytes": 5}
    res2 = handle_node_rpc(server, {"type": "STOR_PROOF_RUN", "graffiti_id": "gid2"})
    assert res2["status"] == "error"
    assert res2["reason"] == "missing_art_id"

def test_unknown_node_rpc(server):
    res = handle_node_rpc(server, {"type": "UNKNOWN"})
    assert res is None
