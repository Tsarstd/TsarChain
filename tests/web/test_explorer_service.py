# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from unittest.mock import patch
from web.Backend.src.services.explorer_service import ExplorerService


def test_pick():
    svc = ExplorerService()
    assert svc._pick(None, "a") is None
    assert svc._pick({}, "a") is None
    assert svc._pick({"a": 1}, "a") == 1
    assert svc._pick({"b": 2}, "a", "b") == 2
    assert svc._pick({"_meta": {"c": 3}}, "c") == 3
    assert svc._pick({"a": None, "_meta": {"a": 4}}, "a") == 4


def test_decode_comment_hex():
    svc = ExplorerService()
    assert svc._decode_comment_hex(None) == ""
    assert svc._decode_comment_hex("") == ""
    # "hello" in hex is 68656c6c6f
    assert svc._decode_comment_hex("68656c6c6f") == "hello"
    assert svc._decode_comment_hex("invalid-hex") == ""


def test_normalize_block():
    svc = ExplorerService()
    assert svc._normalize_block(None) is None
    assert svc._normalize_block({"error": "not found"}) is None
    assert svc._normalize_block({"status": "error"}) is None
    assert svc._normalize_block({"found": False}) is None

    blk = {
        "height": 10,
        "hash": "00" * 32,
        "transactions": [
            {"txid": "tx1", "inputs": [{"txid": "prev", "vout": 0}], "outputs": [{"amount": 50}]}
        ],
        "comments": [
            {"author": "alice", "comment_hex": "68656c6c6f"}
        ]
    }
    norm = svc._normalize_block(blk)
    assert norm is not None
    assert norm["height"] == 10
    assert norm["hash"] == "00" * 32
    assert len(norm["transactions"]) == 1
    assert norm["transactions"][0]["txid"] == "tx1"
    assert norm["comments"][0]["comment_text"] == "hello"


def test_normalize_block_summary():
    svc = ExplorerService()
    assert svc._normalize_block_summary(None) is None
    summary = {
        "height": 5,
        "hash": "11" * 32,
        "transactions": ["tx1", "tx2"],
        "graffiti_posts": 2,
        "graffiti_comments": 3,
    }
    norm = svc._normalize_block_summary(summary)
    assert norm["height"] == 5
    assert norm["tx_count"] == 2
    assert norm["graffiti_posts"] == 2
    assert norm["graffiti_comments"] == 3
    assert norm["graffiti_count"] == 5


def test_normalize_tx():
    svc = ExplorerService()
    assert svc._normalize_tx(None) is None
    assert svc._normalize_tx({"error": "tx not found"}) is None

    tx = {
        "txid": "tx100",
        "confirmations": 6,
        "vin": [{"txid": "00" * 32, "vout": 0, "amount": 50}],
        "vout": [{"vout": 0, "amount": 50, "address": "tsar1addr", "event": {"type": "payout"}}]
    }
    norm = svc._normalize_tx(tx)
    assert norm is not None
    assert norm["txid"] == "tx100"
    assert norm["status"] == "confirmed"
    assert norm["is_coinbase"] is True
    assert len(norm["inputs"]) == 1
    assert len(norm["outputs"]) == 1
    assert norm["outputs"][0]["event"] == "payout"


def test_normalize_address():
    svc = ExplorerService()
    assert svc._normalize_address(None) is None
    addr_info = {
        "address": "tsar1abc",
        "utxos": [{"amount": 10.5}, {"amount": 4.5}],
        "history": ["tx1", "tx2", "tx3"]
    }
    norm = svc._normalize_address(addr_info)
    assert norm["balance"] == 15.0
    assert norm["utxo_count"] == 2
    assert norm["total_txs"] == 3


def test_normalize_graffiti():
    svc = ExplorerService()
    assert svc._normalize_graffiti_post(None) is None
    post = {"art_id": "graf" + "0" * 60, "title": "My Art"}
    norm_post = svc._normalize_graffiti_post(post)
    assert norm_post["preview_url"] == f"/api/graffiti/{post['art_id']}/media"

    detail = {
        "post": post,
        "comments": [{"comment_hex": "68656c6c6f"}]
    }
    norm_detail = svc._normalize_graffiti_detail(detail)
    assert norm_detail is not None
    assert norm_detail["comments"][0]["comment_text"] == "hello"


def test_explorer_service_search():
    svc = ExplorerService("127.0.0.1", 19000)

    # 1. Unknown
    res = svc.search("random")
    assert res["kind"] == "unknown"
    assert res["data"] is None

    # 2. Block height
    with patch.object(svc, "get_block", return_value={"height": 100, "hash": "00" * 32}):
        res = svc.search("100")
        assert res["kind"] == "block"
        assert res["data"]["height"] == 100

    # 3. Address
    with patch.object(svc, "get_address", return_value={"address": "tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqq"}):
        res = svc.search("tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqq")
        assert res["kind"] == "address"
        assert res["data"]["address"] == "tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqq"

    # 4. Hash64 - tx match
    hex64 = "ab" * 32
    with patch.object(svc, "get_tx", return_value={"txid": hex64}):
        res = svc.search(hex64)
        assert res["kind"] == "tx"
        assert res["data"]["txid"] == hex64

    # 5. Hash64 - tx fails, block matches
    with patch.object(svc, "get_tx", return_value={"error": "not found"}):
        with patch.object(svc, "get_block", return_value={"hash": hex64}):
            res = svc.search(hex64)
            assert res["kind"] == "block"
            assert res["data"]["hash"] == hex64
