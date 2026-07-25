# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest
from unittest.mock import patch, MagicMock

from web.Backend.src.python import web_rpc_client as rpc

@pytest.fixture
def mock_client():
    client = MagicMock()
    return client

def test_rpc_network(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        with patch("web.Backend.src.python.web_rpc_client._cache_set") as mock_set:
            def mock_send(c, p):
                if p["type"] == "GET_NETWORK_INFO":
                    return {"type": "NETWORK_INFO", "data": {"height": 10}}
                elif p["type"] == "GET_PEERS":
                    return {"peers": ["127.0.0.1:19000"]}
            
            with patch("web.Backend.src.python.web_rpc_client._rpc_send", side_effect=mock_send):
                res = rpc.rpc_network(mock_client)
                assert res["height"] == 10
                # Note: original code merges peers into the outer info, not data. We just check height.
                mock_set.assert_called_once()
                
            # Hit cache
            with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value={"height": 20}):
                res2 = rpc.rpc_network(mock_client)
                assert res2["height"] == 20

def test_rpc_block(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        with patch("web.Backend.src.python.web_rpc_client._rpc_send", return_value={"height": 10, "hash": "A"}):
            res = rpc.rpc_block(mock_client, "10")
            assert res["height"] == 10
            
        with patch("web.Backend.src.python.web_rpc_client._rpc_send", return_value={"height": 11, "hash": "B"}):
            res2 = rpc.rpc_block(mock_client, "B")
            assert res2["hash"] == "B"
            
        with patch("web.Backend.src.python.web_rpc_client._rpc_send", return_value={"error": "not_found"}):
            with patch("web.Backend.src.python.web_rpc_client._cache_set") as mock_set:
                res3 = rpc.rpc_block(mock_client, "12")
                assert res3["error"] == "not_found"
                mock_set.assert_called_once()

def test_rpc_block_range(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        # Storage hit
        with patch("web.Backend.src.python.web_rpc_client.webdb.get_block_range_from_storage", return_value={"items": [1,2], "has_more": False}):
            res = rpc.rpc_block_range(mock_client, {"start_height": 1, "limit": 2})
            assert len(res["items"]) == 2
            
        # Partial storage, fetch rest
        with patch("web.Backend.src.python.web_rpc_client.webdb.get_block_range_from_storage", return_value={"items": [1], "has_more": True}):
            with patch("web.Backend.src.python.web_rpc_client._rpc_send", return_value={"items": [2], "has_more": False}):
                with patch("web.Backend.src.python.web_rpc_client.webdb.save_blocks_permanent") as mock_save:
                    res2 = rpc.rpc_block_range(mock_client, {"start_height": 1, "limit": 2})
                    assert len(res2["items"]) == 2
                    mock_save.assert_called_once_with([2])
                    
        # Latest
        with patch("web.Backend.src.python.web_rpc_client._rpc_send", return_value={"items": [10, 9], "has_more": True}):
            res3 = rpc.rpc_block_range(mock_client, {"start_height": "latest", "limit": 2})
            assert len(res3["items"]) == 2

def test_rpc_address(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        def mock_send(c, p):
            if p["type"] == "GET_BALANCES":
                return {"items": {"addr1": {"spendable": 100}}}
            elif p["type"] == "GET_TOTAL_UTXO":
                return {"count": 5}
            elif p["type"] == "GET_TX_HISTORY":
                return {"items": [{"txid": "T1"}], "total": 1, "height": 100}
                
        with patch("web.Backend.src.python.web_rpc_client._rpc_send", side_effect=mock_send):
            res = rpc.rpc_address(mock_client, "addr1")
            assert res["spendable"] == 100
            assert res["utxo_count"] == 5
            assert len(res["history"]) == 1

def test_rpc_graffiti(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        def mock_send(c, p):
            if p["type"] == "GRAFFITI_GET_ART":
                return {"post": {"art_id": "art1"}}
            elif p["type"] == "GRAFFITI_GET_COMMENTS":
                return {"comments": [{"id": "c1"}]}
                
        with patch("web.Backend.src.python.web_rpc_client._rpc_send", side_effect=mock_send):
            res = rpc.rpc_graffiti(mock_client, "art1")
            assert res["post"]["art_id"] == "art1"
            assert len(res["comments"]) == 1

def test_rpc_graffiti_posts(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        with patch("web.Backend.src.python.web_rpc_client._rpc_send", return_value={"type": "GRAFFITI_GET_POSTS", "posts": [{"id": 1}]}):
            res = rpc.rpc_graffiti_posts(mock_client, {"limit": 10, "offset": 0})
            assert len(res["posts"]) == 1

def test_rpc_graffiti_file(mock_client):
    with patch("web.Backend.src.python.web_rpc_client.webdb.fetch_graffiti_file", return_value={"status": "ok", "cache_path": "/path"}):
        res = rpc.rpc_graffiti_file(mock_client, {"art_id": "art1"}, None)
        assert res["status"] == "ok"
        assert res["cache_path"] == "/path"
        
    with patch("web.Backend.src.python.web_rpc_client.webdb.fetch_graffiti_file", return_value=None):
        res2 = rpc.rpc_graffiti_file(mock_client, {"art_id": "art1"}, None)
        assert res2["status"] == "error"

def test_dispatch_rpc():
    with patch("web.Backend.src.python.web_rpc_client._get_client") as mock_get:
        mock_get.return_value = MagicMock()
        
        with patch("web.Backend.src.python.web_rpc_client.rpc_network", return_value={"net": 1}):
            assert rpc._dispatch_rpc("network", None, "127.0.0.1", 19000) == {"net": 1}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_block", return_value={"height": 1}):
            assert rpc._dispatch_rpc("block", {"height": 1}, "127.0.0.1", 19000) == {"height": 1}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_block_range", return_value={"items": []}):
            assert rpc._dispatch_rpc("block_range", {"limit": 10}, "127.0.0.1", 19000) == {"items": []}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_address", return_value={"spendable": 0}):
            assert rpc._dispatch_rpc("address", {"address": "a"}, "127.0.0.1", 19000) == {"spendable": 0}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_tx", return_value={"txid": "t"}):
            assert rpc._dispatch_rpc("tx", {"txid": "t"}, "127.0.0.1", 19000) == {"txid": "t"}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_graffiti", return_value={"post": {}}):
            assert rpc._dispatch_rpc("graffiti", {"art_id": "a"}, "127.0.0.1", 19000) == {"post": {}}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_graffiti_posts", return_value={"posts": []}):
            assert rpc._dispatch_rpc("graffiti_posts", {"limit": 10}, "127.0.0.1", 19000) == {"posts": []}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_graffiti_file", return_value={"status": "ok"}):
            assert rpc._dispatch_rpc("graffiti_file", {"art_id": "a"}, "127.0.0.1", 19000) == {"status": "ok"}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_receipt", return_value={"status": "ok"}):
            assert rpc._dispatch_rpc("receipt", {"txid": "r"}, "127.0.0.1", 19000) == {"status": "ok"}
            
        with patch("web.Backend.src.python.web_rpc_client.rpc_history_book", return_value={"status": "ok"}):
            assert rpc._dispatch_rpc("history_book", {"address": "a"}, "127.0.0.1", 19000) == {"status": "ok"}
            
        with patch("web.Backend.src.python.web_rpc_client.webdb.prefetch_blocks"):
            assert rpc._dispatch_rpc("prefetch_blocks", None, "127.0.0.1", 19000)["status"] == "ok"
            
        with patch("web.Backend.src.python.web_rpc_client.webdb.prefetch_blocks", side_effect=Exception("e")):
            assert rpc._dispatch_rpc("prefetch_blocks", None, "127.0.0.1", 19000)["status"] == "error"
            
        res_unk = rpc._dispatch_rpc("unknown", None, "127.0.0.1", 19000)
        assert res_unk["error"] == "unknown_op"

def test_rpc_receipt(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        with patch("web.Backend.src.python.web_rpc_client.rpc_tx", return_value={"txid": "T1"}):
            with patch("web.Backend.src.python.build_receipt.PaymentReceiptGenerator") as mock_gen:
                mock_inst = MagicMock()
                mock_inst.generate_receipt_base64.return_value = {"status": "success"}
                mock_gen.return_value = mock_inst
                
                res = rpc.rpc_receipt(mock_client, "T1")
                assert res["status"] == "success"

def test_parse_opts():
    assert rpc._parse_opts(None) == {}
    assert rpc._parse_opts('{"limit": 10}') == {"limit": 10}
    assert rpc._parse_opts("10, 20") == {"limit": 10, "offset": 20}
    
def test_parse_block_range_opts():
    assert rpc._parse_block_range_opts(None) == {}
    assert rpc._parse_block_range_opts('{"limit": 10}') == {"limit": 10}
    assert rpc._parse_block_range_opts("10, 20") == {"start_height": 10, "limit": 20}
    
def test_emit_worker():
    with patch("sys.stdout.write") as mock_write:
        rpc._emit_worker("req1", {"data": 1})
        mock_write.assert_called()

def test_worker_loop():
    input_data = [
        '{"id": "1", "op": "network", "host": "127.0.0.1", "port": 19000}\n',
        'invalid_json\n',
        '{"id": "2", "op": "unknown"}\n'
    ]
    with patch("sys.stdin", input_data):
        with patch("web.Backend.src.python.web_rpc_client._dispatch_rpc", return_value={"ok": True}) as mock_dispatch:
            with patch("web.Backend.src.python.web_rpc_client._emit_worker") as mock_emit:
                rpc._worker_loop()
                assert mock_dispatch.call_count == 2
                assert mock_emit.call_count == 2

def test_main():
    with patch("sys.argv", ["script.py", "network", "param", "127.0.0.1", "19000"]):
        with patch("web.Backend.src.python.web_rpc_client._dispatch_rpc", return_value={"ok": True}):
            with patch("web.Backend.src.python.web_rpc_client._emit") as mock_emit:
                rpc.main()
                mock_emit.assert_called_once_with({"ok": True})
                
    with patch("sys.argv", ["script.py", "worker"]):
        with patch("web.Backend.src.python.web_rpc_client._worker_loop") as mock_loop:
            rpc.main()
            mock_loop.assert_called_once()
            
    with patch("sys.argv", ["script.py"]):
        with patch("web.Backend.src.python.web_rpc_client._emit") as mock_emit:
            rpc.main()
            mock_emit.assert_called_once()

def test_client_cache():
    with patch("web.Backend.src.python.web_rpc_client.load_or_create_keypair_at", return_value=("id", "pub", "priv")):
        c1 = rpc._get_client("127.0.0.1", 19000)
        c2 = rpc._get_client("127.0.0.1", 19000)
        assert c1 is c2
        rpc._drop_client("127.0.0.1", 19000)
        c3 = rpc._get_client("127.0.0.1", 19000)
        assert c1 is not c3
        
def test_cache_policy():
    ok, ttl = rpc._cache_policy(None)
    assert not ok
    ok, ttl = rpc._cache_policy({"error": "not_found"})
    assert ok
    ok, ttl = rpc._cache_policy({"status": "error", "reason": "timeout"})
    assert ok
    assert ttl == rpc.webdb.WEB_CACHE_ERROR_TTL_SHORT

def test_exception_handling():
    with patch("sys.argv", ["script.py", "network", "param", "127.0.0.1", "19000"]):
        with patch("web.Backend.src.python.web_rpc_client._dispatch_rpc", side_effect=Exception("test_exc")):
            with patch("web.Backend.src.python.web_rpc_client._emit") as mock_emit:
                rpc.main()
                args, _ = mock_emit.call_args
                assert args[0]["error"] == "rpc_exception"

def test_rpc_receipt_race_condition(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value={"txid": "t1"}):
        with patch("web.Backend.src.python.web_rpc_client.webdb.is_receipt_fresh", return_value=True):
            with patch("web.Backend.src.python.web_rpc_client.webdb.read_receipt_file", side_effect=FileNotFoundError()):
                with patch("web.Backend.src.python.web_rpc_client.rpc_tx", return_value={"txid": "t1"}) as mock_tx:
                    with patch("web.Backend.src.python.build_receipt.PaymentReceiptGenerator") as mock_gen:
                        mock_inst = MagicMock()
                        mock_inst.generate_receipt_base64.return_value = {"status": "success", "regenerated": True}
                        mock_gen.return_value = mock_inst
                        
                        res = rpc.rpc_receipt(mock_client, "t1")
                        assert res["status"] == "success"
                        assert res.get("regenerated") is True
                        mock_tx.assert_called_once()

def test_rpc_history_book(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        with patch("web.Backend.src.python.web_rpc_client.rpc_address", return_value={"address": "tsar123", "balance": 10, "total_txs": 20}):
            with patch("web.Backend.src.python.build_history_book.HistoryBookGenerator") as mock_gen:
                mock_inst = MagicMock()
                mock_inst.generate_history_book_base64.return_value = {"status": "success"}
                mock_gen.return_value = mock_inst
                
                res = rpc.rpc_history_book(mock_client, "tsar123")
                assert res["status"] == "success"

def test_rpc_history_book_race_condition(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value={"address": "tsar1"}):
        with patch("web.Backend.src.python.web_rpc_client.webdb.is_history_book_fresh", return_value=True):
            with patch("web.Backend.src.python.web_rpc_client.webdb.read_history_book_file", side_effect=FileNotFoundError()):
                with patch("web.Backend.src.python.web_rpc_client.rpc_address", return_value={"address": "tsar1", "total_txs": 20}) as mock_addr:
                    with patch("web.Backend.src.python.build_history_book.HistoryBookGenerator") as mock_gen:
                        mock_inst = MagicMock()
                        mock_inst.generate_history_book_base64.return_value = {"status": "success", "regenerated": True}
                        mock_gen.return_value = mock_inst
                        
                        res = rpc.rpc_history_book(mock_client, "tsar1")
                        assert res["status"] == "success"
                        assert res.get("regenerated") is True
                        mock_addr.assert_called_once()

def test_rpc_history_book_insufficient_txs(mock_client):
    with patch("web.Backend.src.python.web_rpc_client._cache_get", return_value=None):
        with patch("web.Backend.src.python.web_rpc_client.rpc_address", return_value={"address": "tsar123", "total_txs": 5, "history": []}):
            res = rpc.rpc_history_book(mock_client, "tsar123")
            assert res["status"] == "error"
            assert "requires at least 20 transactions" in res["message"]


