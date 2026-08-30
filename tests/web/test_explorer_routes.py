# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import tempfile
from unittest.mock import patch
from web.Backend.src.routes.explorer_routes import (
    ExplorerRoutes,
    parse_range_header,
    resolve_cache_path,
    infer_media_type,
    touch_file,
    cleanup_graffiti_cache,
    is_art_id,
)
from web.Backend.src.services.explorer_service import ExplorerService


def testis_art_id():
    assert is_art_id("graf" + "0" * 60) is True
    assert is_art_id("graf" + "a" * 60) is True
    assert is_art_id("graf" + "0" * 59) is False
    assert is_art_id("tsar" + "0" * 60) is False
    assert is_art_id("") is False
    assert is_art_id(None) is False


def testparse_range_header():
    assert parse_range_header(None, 1000) is None
    assert parse_range_header("", 1000) is None
    assert parse_range_header("invalid", 1000) == {"invalid": True}
    assert parse_range_header("bytes=100-50", 1000) == {"invalid": True}
    assert parse_range_header("bytes=1500-2000", 1000) == {"invalid": True}

    assert parse_range_header("bytes=0-499", 1000) == {"start": 0, "end": 499}
    assert parse_range_header("bytes=500-", 1000) == {"start": 500, "end": 999}
    assert parse_range_header("bytes=0-1500", 1000) == {"start": 0, "end": 999}


def testresolve_cache_path():
    assert resolve_cache_path(None) is None
    assert resolve_cache_path(123) is None
    # Path traversal attack should return None
    assert resolve_cache_path("../../etc/passwd") is None
    assert resolve_cache_path("..\\..\\windows\\system32") is None


def testinfer_media_type():
    assert infer_media_type({"mime": "application/pdf"}, None) == "application/pdf"
    assert infer_media_type({"mime_type": "video/mp4"}, None) == "video/mp4"
    assert infer_media_type({"mime": "image/jpeg"}, None) == "image/jpeg"
    assert infer_media_type(None, "sample.pdf") == "application/pdf"
    assert infer_media_type(None, "sample.mp4") == "video/mp4"
    assert infer_media_type(None, "sample.jpg") == "image/jpeg"
    assert infer_media_type(None, "sample.bin") == "application/octet-stream"


def test_touch_and_cleanup_cache():
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("test")
        tmp_name = f.name
    try:
        touch_file(tmp_name)
        cleanup_graffiti_cache()
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_explorer_routes_handlers():
    svc = ExplorerService("127.0.0.1", 19000)
    routes = ExplorerRoutes(svc, "127.0.0.1", 19000)

    # 1. Receipt
    assert routes.handle_receipt({})[0] == 400
    assert routes.handle_receipt({"txid": "invalid"})[0] == 400
    hex64 = "0" * 64
    with patch.object(svc, "get_receipt", return_value={"status": "success", "receipt": "ok"}):
        code, resp = routes.handle_receipt({"txid": hex64})
        assert code == 200
        assert resp["status"] == "ok"

    # 2. History Book
    assert routes.handle_history_book({})[0] == 400
    assert routes.handle_history_book({"address": "invalid"})[0] == 400
    addr = "tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    with patch.object(svc, "get_history_book", return_value={"status": "success", "data": {}}):
        code, resp = routes.handle_history_book({"address": addr})
        assert code == 200

    # 3. Network
    with patch.object(svc, "get_network", return_value={"peers": 5}):
        code, resp = routes.handle_network()
        assert code == 200
        assert resp["data"]["peers"] == 5

    # 4. Blocks
    with patch.object(svc, "get_block_range", return_value={"items": []}):
        code, resp = routes.handle_blocks({"limit": "10", "start": "100", "prefer_database": "true"})
        assert code == 200

    # 5. Block
    assert routes.handle_block("invalid_id")[0] == 400
    with patch.object(svc, "get_block", return_value={"height": 1}):
        code, resp = routes.handle_block("1")
        assert code == 200

    # 6. Tx
    assert routes.handle_tx("invalid_txid")[0] == 400
    with patch.object(svc, "get_tx", return_value={"txid": hex64}):
        code, resp = routes.handle_tx(hex64)
        assert code == 200

    # 7. Address
    assert routes.handle_address("invalid_addr")[0] == 400
    with patch.object(svc, "get_address", return_value={"balance": 10}):
        code, resp = routes.handle_address(addr)
        assert code == 200

    # 8. Graffiti Detail
    assert routes.handle_graffiti_detail("invalid_art_id")[0] == 400
    art_id = "graf" + "0" * 60
    with patch.object(svc, "get_graffiti", return_value=None):
        assert routes.handle_graffiti_detail(art_id)[0] == 404
    with patch.object(svc, "get_graffiti", return_value={"art_id": art_id}):
        code, resp = routes.handle_graffiti_detail(art_id)
        assert code == 200

    # 9. Graffiti List
    with patch.object(svc, "get_graffiti_posts", return_value={"items": []}):
        code, resp = routes.handle_graffiti_list({"limit": "10", "offset": "0"})
        assert code == 200

    # 10. Search
    assert routes.handle_search({})[0] == 400
    with patch.object(svc, "search", return_value={"kind": "unknown", "data": None}):
        assert routes.handle_search({"q": "none"})[0] == 404
    with patch.object(svc, "search", return_value={"kind": "block", "data": {"height": 1}}):
        code, resp = routes.handle_search({"q": "1"})
        assert code == 200
        assert resp["kind"] == "block"

    # 11. Prefetch blocks
    with patch("web.Backend.src.core.main_web.dispatch_rpc") as mock_dispatch:
        code, resp = routes.handle_prefetch_blocks()
        assert code == 200
        assert resp["status"] == "ok"
