# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import time
import pytest
import base64
from unittest.mock import patch, MagicMock

from web.Backend.src.python import database_web as webdb

@pytest.fixture
def mock_store():
    store = MagicMock()
    with patch("web.Backend.src.python.database_web._open_store", return_value=store):
        yield store

def test_open_store():
    webdb._store = None
    with patch("web.Backend.src.python.database_web._native_open_storage") as mock_open:
        mock_open.return_value = "db"
        assert webdb._open_store() == "db"
        assert webdb._open_store() == "db" # cached

def test_cache_keys():
    assert webdb.make_cache_key("web", "prefix", "test") == "web:prefix:test"
    assert webdb.make_cache_key("web", None, "test") == "web:test"

def test_should_cache_error():
    assert webdb.should_cache_error("not_found") is True
    assert webdb.should_cache_error("height_out_of_range") is True
    assert webdb.should_cache_error("not found something") is True
    assert webdb.should_cache_error("other error") is False

def test_cache_ttl_for_error():
    assert webdb.cache_ttl_for_error("pow_required") == webdb.WEB_CACHE_ERROR_TTL_SHORT
    assert webdb.cache_ttl_for_error("rate limit exceeded") == webdb.WEB_CACHE_ERROR_TTL_SHORT
    assert webdb.cache_ttl_for_error("timeout") == webdb.WEB_CACHE_ERROR_TTL_SHORT
    assert webdb.cache_ttl_for_error("not_found") == webdb.WEB_CACHE_TTL_SEC
    assert webdb.cache_ttl_for_error("unknown_error") is None

def test_cache_set_get(mock_store):
    mock_store.get_bytes.return_value = None
    assert webdb.cache_get_json("key1") is None
    
    expired_entry = webdb._json_dumps({"ts": 0, "ttl": 10, "payload": "data"})
    mock_store.get_bytes.return_value = expired_entry
    assert webdb.cache_get_json("key2") is None
    
    valid_entry = webdb._json_dumps({"ts": int(time.time()), "ttl": 100, "payload": "data"})
    mock_store.get_bytes.return_value = valid_entry
    assert webdb.cache_get_json("key3", refresh_ttl=True) == "data"
    
    webdb.cache_set("key4", {"test": 123}, ttl_sec=50)

def test_block_storage(mock_store):
    webdb.save_blocks_permanent([{"height": 1, "hash": "A"}, "invalid", {"height": 2, "hash": "B"}])
    
    mock_store.get_bytes.return_value = webdb._json_dumps({"height": 1, "hash": "A"})
    assert webdb.get_block_from_storage(1)["hash"] == "A"
    
    def mock_get(db, k):
        h = int(k.decode("utf-8").split(":")[1])
        if h <= 2:
            return webdb._json_dumps({"height": h, "hash": "A"})
        return None
    mock_store.get_bytes.side_effect = mock_get
    
    res = webdb.get_block_range_from_storage(1, 5)
    assert len(res["items"]) == 2
    
    mock_store.iter_prefix.return_value = [(b"block:00000001", b""), (b"block:00000002", b"")]
    assert webdb.get_last_stored_height() == 2

def test_media_cache(mock_store):
    webdb._cache_media_error("art1", "not_found", 10)
    webdb._cache_media_ok_path("art2", {"mime": "image/jpeg"}, "/path/x.jpg", 100)
    
    mock_store.get_bytes.return_value = webdb._json_dumps({"ts": int(time.time()), "ttl": 100, "status": "ok"})
    assert webdb._load_media_entry("art2") is not None
    
    mock_store.get_bytes.return_value = None
    assert webdb._load_media_entry("art3") is None

def test_fetch_storers(mock_store):
    mock_store.get_bytes.return_value = None
    rpc_call = MagicMock(return_value={"storers": [{"addr": "127.0.0.1", "port": 8080, "last_seen": 10}]})
    res = webdb.fetch_storers(rpc_call, limit=1)
    assert len(res) == 1
    
    rpc_call_err = MagicMock(return_value={"error": "not_found"})
    assert len(webdb.fetch_storers(rpc_call_err)) == 0

@patch("web.Backend.src.python.database_web._send_storage_request")
@patch("web.Backend.src.python.database_web.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}])
def test_fetch_graffiti_file_network(mock_fetch, mock_send, mock_store, tmp_path):
    mock_store.get_bytes.return_value = None
    
    def send_effect(h, p, payload, *args, **kwargs):
        if not payload.get("include_data"):
            return {"status": "ok", "found": True, "meta": {"size_bytes": 10}}
        else:
            return {"status": "ok", "found": True, "data_b64": base64.b64encode(b"hello world").decode("utf-8")}
    
    mock_send.side_effect = send_effect
    res = webdb.fetch_graffiti_file(lambda p: None, "art4", cache_dir=str(tmp_path))
    assert res["status"] == "ok"
    assert "cache_path" in res

def test_prefetch_blocks(mock_store):
    mock_store.iter_prefix.return_value = [(b"block:00000001", b"")] # last = 1
    
    rpc_call = MagicMock(return_value={"height": 5, "items": [{"height": 2}, {"height": 3}]})
    webdb.prefetch_blocks(rpc_call)
    
    # Check prefetch threading
    with patch("web.Backend.src.python.database_web.prefetch_blocks") as mock_pb:
        webdb.start_prefetch_thread(rpc_call)
        time.sleep(0.1)
        webdb.stop_prefetch_thread()
        mock_pb.assert_called()

def test_receipt_cache(tmp_path):
    with patch("web.Backend.src.python.database_web.os.path.getmtime", return_value=time.time()):
        assert webdb.is_receipt_fresh("/does/not/exist", 100) is False
        
    f = tmp_path / "test.jpg"
    f.write_bytes(b"image")
    assert webdb.is_receipt_fresh(str(f), 100) is True
    assert webdb.is_receipt_fresh(str(f), -100) is False
    
    res = webdb.read_receipt_file(str(f), "txid")
    assert res["status"] == "success"

def test_chunked_download(mock_store, tmp_path):
    # Coverage for chunked download
    mock_store.get_bytes.return_value = None
    
    with patch("web.Backend.src.python.database_web.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}]):
        with patch("web.Backend.src.python.database_web._send_storage_request") as mock_send:
            def send_effect(h, p, payload, *args, **kwargs):
                if not payload.get("include_data"):
                    # Large file 20MB
                    return {"status": "ok", "found": True, "meta": {"size_bytes": 20 * 1024 * 1024}}
                else:
                    return {"status": "ok", "found": True, "data_b64": base64.b64encode(b"a" * payload["length"]).decode("utf-8")}
            mock_send.side_effect = send_effect
            
            res = webdb.fetch_graffiti_file(lambda p: None, "art5", cache_dir=str(tmp_path), max_bytes=50 * 1024 * 1024)
            assert res["status"] == "ok"
            assert "cache_path" in res

def test_prefetch_branches(mock_store):
    # Test last height
    mock_store.get_bytes.return_value = b"100"
    assert webdb.get_prefetch_last_height() == 100
    
    mock_store.get_bytes.side_effect = Exception("test")
    assert webdb.get_prefetch_last_height() == -1
    
    webdb.set_prefetch_last_height(200)

def test_receipt_cleanup_and_timer():
    with patch("threading.Timer") as mock_timer:
        webdb.schedule_receipt_deletion("tx1", 10)
        mock_timer.assert_called_once()
        
    with patch("os.path.exists", return_value=True):
        with patch("os.listdir", return_value=["tx1.jpg"]):
            with patch("os.path.getmtime", return_value=time.time() - 100):
                with patch("os.remove") as mock_remove:
                    webdb.cleanup_receipt_files(50)
                    mock_remove.assert_called()

def test_cache_media_exceptions(mock_store):
    mock_store.put_bytes.side_effect = Exception("err")
    webdb._cache_media_error("art_id", "reason")
    webdb._cache_media_ok_path("art_id", {}, "/path", 10)
    # Should swallow exception
    
    webdb.set_prefetch_last_height(10) # exception handled
    
    mock_store.get_bytes.side_effect = Exception("err")
    assert webdb.cache_get_json("key") is None
    webdb.cache_set("key", {})
    
def test_is_expired():
    # missing ttl
    assert webdb._is_expired({"ts": 0}) is True
    # ttl <= 0
    assert webdb._is_expired({"ts": 0, "ttl": -1}) is False
    
def test_prefetch_blocks_edge_cases(mock_store):
    mock_store.iter_prefix.return_value = [(b"block:00000001", b"")] # last = 1
    
    # 1. Fallback to GET_BLOCK_RANGE for tip height
    rpc1 = MagicMock(side_effect=[{"type": "GET_NETWORK_INFO"}, {"tip_height": 5}, {"items": [{"height": 2}]}])
    webdb.prefetch_blocks(rpc1)
    
    # 2. Resp has error
    rpc2 = MagicMock(return_value={"height": 5, "error": "some_err"})
    webdb.prefetch_blocks(rpc2)
    
    # 3. Items empty
    rpc3 = MagicMock(return_value={"height": 5, "items": []})
    webdb.prefetch_blocks(rpc3)
    
    # 4. Exception
    rpc4 = MagicMock(side_effect=Exception("network_fail"))
    webdb.prefetch_blocks(rpc4)

def test_fetch_graffiti_unknown_size_and_errors(mock_store, tmp_path):
    # test cached status != ok
    mock_store.get_bytes.return_value = webdb._json_dumps({"ts": int(time.time()), "ttl": 100, "status": "error", "reason": "banned"})
    assert webdb.fetch_graffiti_file(lambda p: None, "art6")["status"] == "error"
    
    # test cached status ok but no data
    mock_store.get_bytes.side_effect = [webdb._json_dumps({"ts": int(time.time()), "ttl": 100, "status": "ok"}), None]
    assert webdb._get_cached_graffiti_file("art7", None) is None
    
    # test write_cache_file exception
    webdb._write_cache_file("/invalid/dir", "art8", {}, b"data")
    
    mock_store.get_bytes.side_effect = None # reset
    mock_store.get_bytes.return_value = None # reset
    
    with patch("web.Backend.src.python.database_web.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}]):
        with patch("web.Backend.src.python.database_web._send_storage_request") as mock_send:
            
            # 1. Unknown size, one-shot
            def send_effect1(h, p, payload, *args, **kwargs):
                if not payload.get("include_data"):
                    return {"status": "ok", "found": True, "meta": {}} # no size
                else:
                    return {"status": "ok", "found": True, "data_b64": base64.b64encode(b"hello").decode("utf-8")}
            mock_send.side_effect = send_effect1
            assert webdb.fetch_graffiti_file(lambda p: None, "art_unknown", cache_dir=str(tmp_path))["status"] == "ok"
            
            # 2. Meta fetch bad response
            mock_send.side_effect = [None]
            assert webdb.fetch_graffiti_file(lambda p: None, "art_bad")["status"] == "error"
            
            # 3. Meta fetch not found
            mock_send.side_effect = [{"found": False}]
            assert webdb.fetch_graffiti_file(lambda p: None, "art_notfound")["status"] == "error"
            
            # 4. Chunked download failure (no data)
            def send_effect4(h, p, payload, *args, **kwargs):
                if not payload.get("include_data"):
                    return {"status": "ok", "found": True, "meta": {"size": 20*1024*1024}}
                elif payload.get("offset") == 0:
                    return {"status": "error", "reason": "some_err"}
            mock_send.side_effect = send_effect4
            assert webdb.fetch_graffiti_file(lambda p: None, "art_chunkfail", cache_dir=str(tmp_path))["status"] == "error"
            
            # 5. Chunked download exception (IOError)
            def send_effect5(h, p, payload, *args, **kwargs):
                if not payload.get("include_data"):
                    return {"status": "ok", "found": True, "meta": {"size": 20*1024*1024}}
                else:
                    return None # not a dict
            mock_send.side_effect = send_effect5
            assert webdb.fetch_graffiti_file(lambda p: None, "art_chunkexc", cache_dir=str(tmp_path))["status"] == "error"

def test_pick_endpoint():
    assert webdb._pick_endpoint({"ip": "1.2.3.4", "port": 80}) == ("1.2.3.4", 80)
    assert webdb._pick_endpoint({"url": "http://test.com:8080"}) == ("test.com", 8080)
    assert webdb._pick_endpoint({"url": "test.com"})[0] == "test.com"
    assert webdb._pick_endpoint({"invalid": "data"}) is None

def test_open_store_exceptions():
    with patch("web.Backend.src.python.database_web._store", None):
        with patch("web.Backend.src.python.database_web._native_open_storage", None):
            assert webdb._open_store() is None
        with patch("web.Backend.src.python.database_web._native_open_storage", side_effect=Exception("lmdb err")):
            assert webdb._open_store() is None

def test_block_storage_edge_cases(mock_store):
    # save_blocks_permanent edge cases
    webdb.save_blocks_permanent(None) # Not a list
    webdb.save_blocks_permanent(["not_a_dict"]) 
    webdb.save_blocks_permanent([{}]) # missing height
    
    mock_store.put_bytes.side_effect = Exception("err")
    webdb.save_blocks_permanent([{"height": 1}]) # exception swallowed
    
    # get_block_from_storage exception
    mock_store.get_bytes.side_effect = Exception("err")
    assert webdb.get_block_from_storage(1) is None
    
    # get_last_stored_height parse errors
    mock_store.iter_prefix.return_value = [(b"block:abc", b""), (b"block:", b"")]
    assert webdb.get_last_stored_height() == 0
    mock_store.iter_prefix.side_effect = Exception("err")
    assert webdb.get_last_stored_height() == -1

def test_path_traversal_sanitization():
    # Test receipt file name sanitization
    safe_path1 = webdb.get_receipt_file("../../../secret_file")
    assert ".." not in safe_path1
    assert "/" not in os.path.basename(safe_path1)
    assert "\\" not in os.path.basename(safe_path1)
    
    safe_path2 = webdb.get_receipt_file("subdir/txid_hash")
    assert "subdir" not in safe_path2
    
    # Test empty sanitization results
    assert webdb.get_receipt_file("../..") == ""
    
    # Test fetch_graffiti_file sanitization
    res = webdb.fetch_graffiti_file(lambda p: None, "../../..")
    assert res["status"] == "error"
    assert res["reason"] == "missing_art_id"

def test_prefetch_blocks_has_more(mock_store):
    mock_store.get_bytes.return_value = b"100"
    rpc_call = MagicMock(return_value={
        "height": 500,
        "items": [{"height": h} for h in range(101, 301)]
    })
    has_more = webdb.prefetch_blocks(rpc_call)
    assert has_more is True
    
    mock_store.get_bytes.return_value = b"100"
    rpc_call_no_more = MagicMock(return_value={
        "height": 250,
        "items": [{"height": h} for h in range(101, 251)]
    })
    has_more_no = webdb.prefetch_blocks(rpc_call_no_more)
    assert has_more_no is False

def test_history_book_cache(tmp_path):
    with patch("web.Backend.src.python.database_web.os.path.getmtime", return_value=time.time()):
        assert webdb.is_history_book_fresh("/does/not/exist", 100) is False
        
    f = tmp_path / "history_test.pdf"
    f.write_bytes(b"pdf_data")
    assert webdb.is_history_book_fresh(str(f), 100) is True
    assert webdb.is_history_book_fresh(str(f), -100) is False
    
    res = webdb.read_history_book_file(str(f), "tsar123")
    assert res["status"] == "success"
    assert res["data_url"].startswith("data:application/pdf;base64,")

def test_history_book_cleanup_and_timer():
    with patch("threading.Timer") as mock_timer:
        webdb.schedule_history_book_deletion("tsar123", 10)
        mock_timer.assert_called_once()
        
    with patch("os.path.exists", return_value=True):
        with patch("os.listdir", return_value=["history_123.pdf"]):
            with patch("os.path.getmtime", return_value=time.time() - 100):
                with patch("os.remove") as mock_remove:
                    webdb.cleanup_history_book_files(50)
                    mock_remove.assert_called()

def test_history_book_path_traversal():
    safe_path1 = webdb.get_history_book_file("../../../secret_file")
    assert ".." not in safe_path1
    assert "/" not in os.path.basename(safe_path1)
    
    assert webdb.get_history_book_file("../..") == ""
