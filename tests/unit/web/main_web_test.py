# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest
from unittest.mock import patch, MagicMock

from web.Backend.src.python import main_web


def test_parse_opts():
    assert main_web._parse_opts(None) == {}
    assert main_web._parse_opts('{"limit": 10}') == {"limit": 10}
    assert main_web._parse_opts("10, 20") == {"limit": 10, "offset": 20}


def test_parse_block_range_opts():
    assert main_web._parse_block_range_opts(None) == {}
    assert main_web._parse_block_range_opts('{"limit": 10}') == {"limit": 10}
    assert main_web._parse_block_range_opts("10, 20") == {"start_height": 10, "limit": 20}


def test_dispatch_rpc():
    with patch("web.Backend.src.python.main_web._get_client") as mock_get:
        mock_get.return_value = MagicMock()
        
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_network", return_value={"net": 1}):
            assert main_web._dispatch_rpc("network", None, "127.0.0.1", 19000) == {"net": 1}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_block", return_value={"height": 1}):
            assert main_web._dispatch_rpc("block", {"height": 1}, "127.0.0.1", 19000) == {"height": 1}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_block_range", return_value={"items": []}):
            assert main_web._dispatch_rpc("block_range", {"limit": 10}, "127.0.0.1", 19000) == {"items": []}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_address", return_value={"spendable": 0}):
            assert main_web._dispatch_rpc("address", {"address": "a"}, "127.0.0.1", 19000) == {"spendable": 0}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_tx", return_value={"txid": "t"}):
            assert main_web._dispatch_rpc("tx", {"txid": "t"}, "127.0.0.1", 19000) == {"txid": "t"}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_graffiti", return_value={"post": {}}):
            assert main_web._dispatch_rpc("graffiti", {"art_id": "a"}, "127.0.0.1", 19000) == {"post": {}}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_graffiti_posts", return_value={"posts": []}):
            assert main_web._dispatch_rpc("graffiti_posts", {"limit": 10}, "127.0.0.1", 19000) == {"posts": []}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_graffiti_file", return_value={"status": "ok"}):
            assert main_web._dispatch_rpc("graffiti_file", {"art_id": "a"}, "127.0.0.1", 19000) == {"status": "ok"}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_receipt", return_value={"status": "ok"}):
            assert main_web._dispatch_rpc("receipt", {"txid": "r"}, "127.0.0.1", 19000) == {"status": "ok"}
            
        with patch("web.Backend.src.python.logic_web.rpc_handlers.rpc_history_book", return_value={"status": "ok"}):
            assert main_web._dispatch_rpc("history_book", {"address": "a"}, "127.0.0.1", 19000) == {"status": "ok"}
            
        with patch("web.Backend.src.python.logic_web.db_blocks.prefetch_blocks"):
            assert main_web._dispatch_rpc("prefetch_blocks", None, "127.0.0.1", 19000)["status"] == "ok"
            
        with patch("web.Backend.src.python.logic_web.db_blocks.prefetch_blocks", side_effect=Exception("e")):
            assert main_web._dispatch_rpc("prefetch_blocks", None, "127.0.0.1", 19000)["status"] == "error"
            
        res_unk = main_web._dispatch_rpc("unknown", None, "127.0.0.1", 19000)
        assert res_unk["error"] == "unknown_op"


def test_emit_worker():
    with patch("sys.stdout.write") as mock_write:
        main_web._emit_worker("req1", {"data": 1})
        mock_write.assert_called()


def test_worker_loop():
    input_data = [
        '{"id": "1", "op": "network", "host": "127.0.0.1", "port": 19000}\n',
        'invalid_json\n',
        '{"id": "2", "op": "unknown"}\n'
    ]
    with patch("sys.stdin", input_data):
        with patch("web.Backend.src.python.main_web._dispatch_rpc", return_value={"ok": True}) as mock_dispatch:
            with patch("web.Backend.src.python.main_web._emit_worker") as mock_emit:
                main_web._worker_loop()
                assert mock_dispatch.call_count == 2
                assert mock_emit.call_count == 2


def test_main():
    with patch("sys.argv", ["script.py", "network", "param", "127.0.0.1", "19000"]):
        with patch("web.Backend.src.python.main_web._dispatch_rpc", return_value={"ok": True}):
            with patch("web.Backend.src.python.main_web._emit") as mock_emit:
                main_web.main()
                mock_emit.assert_called_once_with({"ok": True})
                
    with patch("sys.argv", ["script.py", "worker"]):
        with patch("web.Backend.src.python.main_web._worker_loop") as mock_loop:
            main_web.main()
            mock_loop.assert_called_once()
            
    with patch("sys.argv", ["script.py"]):
        with patch("web.Backend.src.python.main_web._emit") as mock_emit:
            main_web.main()
            mock_emit.assert_called_once()


def test_exception_handling():
    with patch("sys.argv", ["script.py", "network", "param", "127.0.0.1", "19000"]):
        with patch("web.Backend.src.python.main_web._dispatch_rpc", side_effect=Exception("test_exc")):
            with patch("web.Backend.src.python.main_web._emit") as mock_emit:
                main_web.main()
                args, _ = mock_emit.call_args
                assert args[0]["error"] == "rpc_exception"
