# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import json
import pytest
from unittest.mock import MagicMock, patch

from kremlin.services.graffiti_service import (
    _pick_endpoint,
    fetch_storers,
    _infer_cache_mime,
    select_upload_storers,
    build_upload_context,
    parse_amount_str,
    build_post_plan,
    build_comment_plan,
    _send_storage_request,
    filter_online_storers
)

def test_pick_endpoint():
    assert _pick_endpoint({"ip": "127.0.0.1", "port": 8080}) == ("127.0.0.1", 8080)
    assert _pick_endpoint({"url": "tcp://localhost:9090"}) == ("localhost", 9090)
    assert _pick_endpoint({"url": "localhost:9090"}) == ("localhost", 9090)
    assert _pick_endpoint({}) is None

def test_fetch_storers():
    rpc_call = MagicMock(return_value={"storers": [{"addr": "tsar1a", "port": 8080, "last_seen": 100}, {"addr": "tsar1b", "port": 9090, "last_seen": 200}]})
    storers = fetch_storers(rpc_call)
    assert len(storers) == 2
    # Should sort by last_seen descending
    assert storers[0]["addr"] == "tsar1b"
    assert storers[1]["addr"] == "tsar1a"
    
    # Test limit
    assert len(fetch_storers(rpc_call, limit=1)) == 1

def test_infer_cache_mime():
    assert _infer_cache_mime("image.jpg") == "image/jpeg"
    assert _infer_cache_mime("video.mp4") == "video/mp4"
    assert _infer_cache_mime("file.unknown") == "application/octet-stream"

def test_select_upload_storers():
    resp = {
        "storers": [
            {"addr": "a", "port": 80, "trusted": 1, "last_seen": 10},
            {"addr": "b", "port": 80, "trusted": 0, "last_seen": 20},
            {"addr": "c", "port": 0, "trusted": 1, "last_seen": 30} # Invalid port
        ]
    }
    with patch("kremlin.services.graffiti_service.CFG") as mock_cfg:
        mock_cfg.GRAFFITI_REPLICATION_R = 2
        storers = select_upload_storers(resp)
        assert len(storers) == 2
        # 'a' has higher trusted score
        assert storers[0]["addr"] == "a"
        assert storers[1]["addr"] == "b"

@patch("kremlin.services.graffiti_service.compute_art_id")
@patch("kremlin.services.graffiti_service.time.time")
def test_build_upload_context(mock_time, mock_compute):
    mock_compute.return_value = "art123"
    mock_time.return_value = 1000
    
    ctx = build_upload_context("sha", "tsar1creator")
    assert ctx["art_id"] == "art123"
    assert ctx["graffiti_id"] == "sha_1000"
    assert ctx["receipt_id"] == "rcpt_sha_1000"
    
    with pytest.raises(ValueError):
        build_upload_context("sha", "")

@patch("kremlin.services.graffiti_service.CFG")
def test_parse_amount_str(mock_cfg):
    mock_cfg.MAX_DECIMALS = 8
    mock_cfg.TSAR = 100_000_000
    
    assert parse_amount_str("1.5", 0) == 150_000_000
    assert parse_amount_str(" 2,5 ", 0) == 250_000_000
    assert parse_amount_str("", 100) == 100
    assert parse_amount_str(".5", 0) == 50_000_000
    
    with pytest.raises(ValueError):
        parse_amount_str("invalid", 0)
    with pytest.raises(ValueError):
        parse_amount_str("-1", 0)
    with pytest.raises(ValueError):
        parse_amount_str("0.000000001", 0)

@patch("kremlin.services.graffiti_service.build_opret_hex")
@patch("kremlin.services.graffiti_service.calc_comment_split")
@patch("kremlin.services.graffiti_service.build_comment_metadata")
@patch("kremlin.services.graffiti_service.derive_pool_address")
@patch("kremlin.services.graffiti_service.CFG")
def test_build_comment_plan(mock_cfg, mock_derive, mock_meta, mock_split, mock_opret):
    mock_cfg.GRAFFITI_COMMENT_MIN_FEE = 1000
    mock_cfg.MAX_DECIMALS = 8
    mock_cfg.TSAR = 100_000_000
    
    art = {"art_id": "art1", "creator": "tsar1creator"}
    mock_derive.return_value = "pool1"
    mock_opret.return_value = "opret123"
    mock_split.return_value = {"creator_total": 500, "storage": 500}
    
    plan = build_comment_plan(
        art=art,
        commenter_addr="tsar1commenter",
        base_amount_raw="0.00001",
        tip_amount_raw="0",
        comment_text="Nice art!"
    )
    
    assert plan["opret_hex"] == "opret123"
    assert plan["base_sats"] == 1000
    assert len(plan["outputs"]) == 2
    assert plan["outputs"][0]["address"] == "tsar1creator"

@patch("kremlin.services.graffiti_service.socket.create_connection")
def test_filter_online_storers(mock_conn):
    storers = [
        {"ip": "1.1.1.1", "port": 80},
        {"ip": "2.2.2.2", "port": 80},
    ]
    # first succeeds, second throws OSError
    mock_conn.side_effect = [MagicMock(), OSError("timeout")]
    
    online = filter_online_storers(storers)
    assert len(online) == 1
    assert online[0]["ip"] == "1.1.1.1"

@patch("kremlin.services.graffiti_service.os.path.isfile")
@patch("kremlin.services.graffiti_service.os.path.getsize")
@patch("kremlin.services.graffiti_service.mimetypes.guess_type")
@patch("kremlin.services.graffiti_service._sha256_file")
@patch("kremlin.services.graffiti_service._send_storage_request")
def test_upload_graffiti(mock_send, mock_sha, mock_mime, mock_size, mock_isfile):
    from kremlin.services.graffiti_service import upload_graffiti
    mock_isfile.return_value = True
    mock_size.return_value = 1000
    mock_mime.return_value = ("image/jpeg", None)
    mock_sha.return_value = "sha"
    
    # Mock init, put, and commit success
    mock_send.side_effect = [
        {"status": "ok", "chunk_size": 1024}, # init
        {"status": "ok"}, # put
        {"status": "ok"}, # commit
    ]
    
    # We also need to mock open to prevent real file reading
    from unittest.mock import mock_open
    with patch("builtins.open", mock_open(read_data=b"test data")):
        resp = upload_graffiti(
            storer_meta={"ip": "1.1.1.1", "port": 80},
            file_path="test.jpg",
            creator_addr="tsar1creator"
        )
    assert resp["status"] == "ok"
    assert resp["graffiti_id"] == "sha"

@patch("kremlin.services.graffiti_service.fetch_storers")
@patch("kremlin.services.graffiti_service._send_storage_request")
@patch("kremlin.services.graffiti_service._read_cached_graffiti_file")
@patch("kremlin.services.graffiti_service.os.makedirs")
def test_fetch_graffiti_file(mock_makedirs, mock_read_cache, mock_send, mock_fetch_storers):
    from kremlin.services.graffiti_service import fetch_graffiti_file
    mock_read_cache.return_value = None
    mock_fetch_storers.return_value = [{"ip": "1.1.1.1", "port": 80}]
    
    # Mock meta request and one-shot download
    mock_send.side_effect = [
        {"found": True, "graffiti_id": "gid", "meta": {"size_bytes": 100, "filename": "test.jpg", "mime": "image/jpeg"}},
        {"status": "ok", "data_b64": "YmFzZTY0ZGF0YQ==", "meta": {}}
    ]
    
    with patch("builtins.open", MagicMock()):
        resp = fetch_graffiti_file(MagicMock(), "art123")
    
    assert resp["status"] == "ok"
    assert resp["bytes"] == b"base64data"

@patch("kremlin.services.graffiti_service.socket.socket")
@patch("kremlin.services.graffiti_service.send_message")
@patch("kremlin.services.graffiti_service.recv_message")
@patch("kremlin.services.graffiti_service.CFG")
def test_send_storage_request(mock_cfg, mock_recv, mock_send, mock_sock):
    mock_cfg.RPC_TIMEOUT = 5
    mock_cfg.GRAFFITI_MAX_MSG_BYTES = 1024
    
    mock_recv.return_value = json.dumps({"status": "ok"}).encode("utf-8")
    
    resp = _send_storage_request("localhost", 8080, {"test": "data"})
    assert resp["status"] == "ok"
    mock_send.assert_called_once()
    mock_recv.assert_called_once()

    # test empty response
    mock_recv.return_value = b""
    resp2 = _send_storage_request("localhost", 8080, {"test": "data"})
    assert resp2["status"] == "error"

@patch("kremlin.services.graffiti_service.build_metadata")
@patch("kremlin.services.graffiti_service.build_opret_hex")
@patch("kremlin.services.graffiti_service.derive_pool_address")
@patch("kremlin.services.graffiti_service.calc_upload_fee_sats")
@patch("kremlin.services.graffiti_service.compute_art_id")
@patch("kremlin.services.graffiti_service.CFG")
def test_build_post_plan(mock_cfg, mock_art_id, mock_calc_fee, mock_derive, mock_opret, mock_meta):
    mock_cfg.TSAR = 100_000_000
    mock_art_id.return_value = "art_id"
    mock_calc_fee.return_value = 1000
    mock_derive.return_value = "pool"
    mock_opret.return_value = "opret"
    
    plan = build_post_plan(
        sha256_hex="sha",
        size_bytes=1000,
        mime="image/jpeg",
        creator_addr="tsar1c",
        storer_meta={"addr": "storer"},
        receipt_id="receipt"
    )
    
    assert plan["pool_addr"] == "pool"
    assert plan["fee_sats"] == 1000
    assert plan["opret_hex"] == "opret"
    assert plan["art_id"] == "art_id"

@patch("kremlin.services.graffiti_service.socket.socket")
@patch("kremlin.services.graffiti_service.send_message")
@patch("kremlin.services.graffiti_service.recv_message")
@patch("kremlin.services.graffiti_service.solve_pow")
def test_send_storage_request_pow(mock_solve_pow, mock_recv, mock_send, mock_socket):
    mock_solve_pow.return_value = {"nonce": 123}
    # First response: require pow
    # Second response: ok
    mock_recv.side_effect = [
        json.dumps({"reason": "pow_required", "pow_challenge": {"difficulty": 10}}).encode("utf-8"),
        json.dumps({"status": "ok"}).encode("utf-8")
    ]
    from kremlin.services.graffiti_service import _send_storage_request
    resp = _send_storage_request("localhost", 8080, {"test": "data"}, max_pow_retry=1)
    assert resp["status"] == "ok"
    assert mock_solve_pow.called

def test_sha256_file_and_cache(tmp_path):
    from kremlin.services.graffiti_service import _sha256_file, _find_cached_graffiti_path, _read_cached_graffiti_file, read_graffiti_file_info
    
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"hello world")
    
    # Test _sha256_file
    sha = _sha256_file(str(test_file))
    assert sha == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    
    # Test read_graffiti_file_info
    with patch("kremlin.services.graffiti_service.validate_graffiti_file", return_value="text/plain"), \
         patch("kremlin.services.graffiti_service.merkle_root_for_file", return_value=("mroot", 1)):
        info = read_graffiti_file_info(str(test_file))
        assert info["size"] == 11
        assert info["sha"] == sha
        
    # Test cache
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    
    # Create cached file
    cached_file = cache_dir / "art123.jpg"
    cached_file.write_bytes(b"image data")
    
    assert _find_cached_graffiti_path("art123", str(cache_dir)) == str(cached_file)
    
    cached_data = _read_cached_graffiti_file("art123", str(cache_dir))
    assert cached_data is not None
    assert cached_data["status"] == "ok"
    assert cached_data["bytes"] == b"image data"
    assert cached_data["meta"]["size_bytes"] == 10

    # Cache exceptions
    assert _find_cached_graffiti_path("art123", "non_existent_dir_12345") is None
    
    empty_file = cache_dir / "art456.jpg"
    empty_file.write_bytes(b"")
    assert _read_cached_graffiti_file("art456", str(cache_dir)) is None
    
    with patch("kremlin.services.graffiti_service.os.path.getsize", side_effect=OSError):
        assert _read_cached_graffiti_file("art123", str(cache_dir)) is None
    
    with patch("builtins.open", side_effect=OSError):
        assert _read_cached_graffiti_file("art123", str(cache_dir)) is None
    
@patch("kremlin.services.graffiti_service.fetch_storers")
@patch("kremlin.services.graffiti_service._send_storage_request")
@patch("kremlin.services.graffiti_service.os.makedirs")
@patch("kremlin.services.graffiti_service.CFG")
def test_fetch_graffiti_file_chunked(mock_cfg, mock_makedirs, mock_send, mock_fetch_storers, tmp_path):
    mock_cfg.GRAFFITI_MAX_MSG_BYTES = 2000
    mock_cfg.GRAFFITI_MAX_SIZE_BYTES = 10 * 1024 * 1024
    mock_cfg.STOR_GET_RL_IP_BURST = 5
    
    from kremlin.services.graffiti_service import fetch_graffiti_file
    mock_fetch_storers.return_value = [{"ip": "1.1.1.1", "port": 80}]
    
    cache_dir = str(tmp_path)
    
    # 1. Meta request: size is large (e.g. 10MB)
    # 2. Chunk 1
    # 3. Chunk 2 (eof=True)
    import base64
    chunk_data = base64.b64encode(b"a" * 1024).decode("ascii")
    mock_send.side_effect = [
        {"found": True, "graffiti_id": "gid", "meta": {"size_bytes": 2048, "filename": "test.jpg", "mime": "image/jpeg"}},
        {"status": "ok", "data_b64": chunk_data, "eof": False},
        {"status": "ok", "data_b64": chunk_data, "eof": True}
    ]
    
    with patch("kremlin.services.graffiti_service._read_cached_graffiti_file", return_value=None):
        resp = fetch_graffiti_file(MagicMock(), "art123", cache_dir=cache_dir)
        
    assert resp["status"] == "ok"
    assert len(resp["bytes"]) == 2048

def test_build_comment_plan_exceptions():
    from kremlin.services.graffiti_service import build_comment_plan
    with pytest.raises(ValueError, match="Pilih karya terlebih dahulu."):
        build_comment_plan(art=None, commenter_addr="tsar1", base_amount_raw="1", tip_amount_raw="0", comment_text="test")
        
    with pytest.raises(ValueError, match="Art ID tidak tersedia"):
        build_comment_plan(art={"dummy": 1}, commenter_addr="tsar1", base_amount_raw="1", tip_amount_raw="0", comment_text="test")
        
    with pytest.raises(ValueError, match="Pilih wallet untuk komentar"):
        build_comment_plan(art={"art_id": "1"}, commenter_addr="", base_amount_raw="1", tip_amount_raw="0", comment_text="test")
        
    with pytest.raises(ValueError, match="Teks komentar belum diisi"):
        build_comment_plan(art={"art_id": "1"}, commenter_addr="tsar1", base_amount_raw="1", tip_amount_raw="0", comment_text="")
        
    with pytest.raises(ValueError, match="Creator address is not available"):
        build_comment_plan(art={"art_id": "1"}, commenter_addr="tsar1", base_amount_raw="1", tip_amount_raw="0", comment_text="test")

@patch("kremlin.services.graffiti_service.os.path.isfile")
@patch("kremlin.services.graffiti_service.os.path.getsize")
@patch("kremlin.services.graffiti_service.mimetypes.guess_type")
@patch("kremlin.services.graffiti_service._sha256_file")
@patch("kremlin.services.graffiti_service._send_storage_request")
def test_upload_graffiti_with_merkle_and_art_id(mock_send, mock_sha, mock_mime, mock_size, mock_isfile):
    from kremlin.services.graffiti_service import upload_graffiti
    mock_isfile.return_value = True
    mock_size.return_value = 1000
    mock_mime.return_value = ("image/jpeg", None)
    mock_sha.return_value = "sha"
    
    mock_send.side_effect = [
        {"status": "ok", "chunk_size": 1024}, # init
        {"status": "ok"}, # put
        {"status": "ok"}, # commit
    ]
    
    from unittest.mock import mock_open
    with patch("builtins.open", mock_open(read_data=b"test data")):
        resp = upload_graffiti(
            storer_meta={"ip": "1.1.1.1", "port": 80},
            file_path="test.jpg",
            creator_addr="tsar1creator",
            art_id="art123",
            merkle_root="mroot123",
            merkle_chunk=1024,
            merkle_count=1
        )
    assert resp["status"] == "ok"
    # Ensure init payload included the extra fields
    init_call_args = mock_send.call_args_list[0][0]
    init_payload = init_call_args[2]
    assert init_payload["art_id"] == "art123"
    assert init_payload["mroot"] == "mroot123"
    assert init_payload["mchunk"] == 1024
    assert init_payload["mcount"] == 1

@patch("kremlin.services.graffiti_service.fetch_storers")
@patch("kremlin.services.graffiti_service._send_storage_request")
@patch("kremlin.services.graffiti_service.os.makedirs")
@patch("kremlin.services.graffiti_service.CFG")
def test_fetch_graffiti_file_chunked_errors(mock_cfg, mock_makedirs, mock_send, mock_fetch_storers, tmp_path):
    mock_cfg.GRAFFITI_MAX_MSG_BYTES = 2000
    mock_cfg.GRAFFITI_MAX_SIZE_BYTES = 10 * 1024 * 1024
    mock_cfg.STOR_GET_RL_IP_BURST = 5
    from kremlin.services.graffiti_service import fetch_graffiti_file
    mock_fetch_storers.return_value = [{"ip": "1.1.1.1", "port": 80}]
    
    # Test short read
    mock_send.side_effect = [
        {"found": True, "graffiti_id": "gid", "meta": {"size_bytes": 2048, "filename": "test.jpg", "mime": "image/jpeg"}},
        {"status": "ok", "data_b64": "aaaa", "eof": True}
    ]
    with patch("kremlin.services.graffiti_service._read_cached_graffiti_file", return_value=None):
        resp = fetch_graffiti_file(MagicMock(), "art_short", cache_dir=str(tmp_path))
        assert resp["status"] == "error"

    # Test bad chunk response
    mock_send.side_effect = [
        {"found": True, "graffiti_id": "gid", "meta": {"size_bytes": 2048, "filename": "test.jpg", "mime": "image/jpeg"}},
        "bad_response_string"
    ]
    with patch("kremlin.services.graffiti_service._read_cached_graffiti_file", return_value=None):
        resp = fetch_graffiti_file(MagicMock(), "art_bad", cache_dir=str(tmp_path))
        assert resp["status"] == "error"

