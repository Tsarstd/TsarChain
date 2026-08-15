# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import pytest
from unittest.mock import patch, MagicMock

from tsarchain.contracts.graffiti_registry import GraffitiRegistry
from tsarchain.utils import config as CFG

# Helper for testing KV behavior
@pytest.fixture
def mock_kv():
    with patch("tsarchain.contracts.graffiti_registry.iter_prefix") as m_iter, \
         patch("tsarchain.contracts.graffiti_registry.batch") as m_batch:
        yield m_iter, m_batch

def test_init_kv_empty(mock_kv):
    m_iter, _ = mock_kv
    m_iter.return_value = []
    reg = GraffitiRegistry()
    m_iter.assert_called_once_with("graffiti", b"")
    assert "proofs" in reg.data

def test_init_kv_with_data(mock_kv):
    from tsarchain.contracts.graffiti_registry import serialize_post_binary
    m_iter, _ = mock_kv
    post_bytes = serialize_post_binary({"art_id": "art1", "stats": {}})
    m_iter.return_value = [(b"p:art1", post_bytes)]
    reg = GraffitiRegistry()
    assert "art1" in reg.data["posts"]

def test_init_kv_with_other_keys(mock_kv):
    m_iter, _ = mock_kv
    m_iter.return_value = [(b"other:key", b"{}")]
    reg = GraffitiRegistry()
    assert reg.data == {"posts": {}, "comments": {}, "payouts": {}, "proofs": {}}

def test_flush_kv(mock_kv):
    _, m_batch = mock_kv
    m_b = MagicMock()
    m_batch.return_value.__enter__.return_value = m_b
    reg = GraffitiRegistry()
    reg.data["posts"]["art1"] = {"stats": {}}
    reg._flush()
    m_batch.assert_called_once_with("graffiti")
    m_b.put.assert_called_once()

def test_record_post(mock_kv):
    reg = GraffitiRegistry()
    # First post
    reg.record_post("art1", {"title": "hello"}, "tx1", 100, "pool1", 1000, block_hash="hash1")
    post = reg.get_post("art1")
    assert post is not None
    assert post["title"] == "hello"
    assert post["txid"] == "tx1"
    assert post["block_height"] == 100
    assert post["pool_address"] == "pool1"
    assert post["amount_paid"] == 1000
    assert post["block_hash"] == "hash1"
    assert post["stats"]["pool_balance"] == 1000
    
    # Duplicate post (should return early)
    reg.record_post("art1", {"title": "world"}, "tx1", 100, "pool1", 1000)
    post2 = reg.get_post("art1")
    assert post2["title"] == "hello"  # Not updated
    
    # Update post with different txid (although realistically unlikely for same art_id, testing code paths)
    reg.record_post("art1", {"title": "world"}, "tx2", 101, "pool1", 500)
    post3 = reg.get_post("art1")
    assert post3["title"] == "world"
    assert post3["stats"]["pool_balance"] == 500 # 0 + 500 (since new entry is created from meta)

def test_get_post_not_found(mock_kv):
    reg = GraffitiRegistry()
    assert reg.get_post("art2") is None

def test_record_comment(mock_kv):
    reg = GraffitiRegistry()
    reg.record_post("art1", {}, "tx_post", 100, "pool1", 1000)
    
    meta = {"comment": "nice", "commenter": "alice", "amount": 200, "tip": 50, "ts": 12345}
    reg.record_comment("art1", meta, "tx_comment1", 101, 100, 100)
    
    post = reg.get_post("art1")
    assert post["stats"]["creator_paid"] == 100
    assert post["stats"]["storage_paid"] == 100
    assert post["stats"]["pool_balance"] == 1100
    assert post["stats"]["comments"] == 1
    
    comments = reg.list_comments("art1")
    assert len(comments) == 1
    assert comments[0]["txid"] == "tx_comment1"
    assert comments[0]["comment"] == "nice"
    assert comments[0]["commenter"] == "alice"
    assert comments[0]["amount"] == 200
    assert comments[0]["tip"] == 50
    assert comments[0]["creator_paid"] == 100
    assert comments[0]["storage_paid"] == 100
    assert comments[0]["ts"] == 12345
    
    # Duplicate comment
    reg.record_comment("art1", meta, "tx_comment1", 101, 100, 100)
    assert len(reg.list_comments("art1")) == 1

def test_record_comment_no_post(mock_kv):
    reg = GraffitiRegistry()
    meta = {"comment": "nice", "amount": 200}
    reg.record_comment("art2", meta, "tx_comment2", 101, 100, 100)
    assert len(reg.list_comments("art2")) == 1
    assert reg.get_post("art2") is None # Post is still None

def test_record_payout(mock_kv):
    reg = GraffitiRegistry()
    reg.record_post("art1", {}, "tx_post", 100, "pool1", 1000)
    
    reg.record_payout("art1", {"addr1": 200, "addr2": 300}, "tx_payout1", 102, epoch=1)
    
    post = reg.get_post("art1")
    assert post["stats"]["pool_balance"] == 500 # 1000 - 500
    assert post["stats"]["last_paid_epoch"] == 1
    
    payouts = reg.list_payouts("art1")
    assert len(payouts) == 1
    assert payouts[0]["amount"] == 500
    assert payouts[0]["epoch"] == 1
    
    # Duplicate payout
    reg.record_payout("art1", {"addr1": 200}, "tx_payout1", 102)
    assert len(reg.list_payouts("art1")) == 1
    
    # Payout with pool_balance provided
    reg.record_payout("art1", {"addr1": 100}, "tx_payout2", 103, pool_balance=900)
    assert reg.get_post("art1")["stats"]["pool_balance"] == 900
    
    # Duplicate payout with pool_balance provided
    reg.record_payout("art1", {"addr1": 100}, "tx_payout2", 103, pool_balance=1000)
    assert reg.get_post("art1")["stats"]["pool_balance"] == 1000

def test_record_payout_no_post(mock_kv):
    reg = GraffitiRegistry()
    reg.record_payout("art_nonexistent", {"addr1": 100}, "tx1", 100)
    assert len(reg.list_payouts("art_nonexistent")) == 0

def test_set_pool_balance(mock_kv):
    reg = GraffitiRegistry()
    reg.record_post("art1", {}, "tx_post", 100, "pool1", 1000)
    reg.set_pool_balance("art1", 2000)
    assert reg.get_post("art1")["stats"]["pool_balance"] == 2000
    reg.set_pool_balance("art1", -50)
    assert reg.get_post("art1")["stats"]["pool_balance"] == 0
    
    # Test on nonexistent post
    reg.set_pool_balance("art2", 2000)
    assert reg.get_post("art2") is None

def test_record_proof(mock_kv):
    reg = GraffitiRegistry()
    reg.record_proof("art1", "storer1", 1, 0, 100, "hash1", height=101, seed="seed1")
    proof = reg.get_proof("art1", "storer1", 1)
    assert proof is not None
    assert proof["storer"] == "storer1"
    assert proof["epoch"] == 1
    assert proof["offset"] == 0
    assert proof["length"] == 100
    assert proof["hash"] == "hash1"
    assert proof["height"] == 101
    assert proof["seed"] == "seed1"
    assert "ts" in proof
    
    # Update same proof
    reg.record_proof("art1", "storer1", 1, 0, 100, "hash2", height=102, seed="seed2")
    proof2 = reg.get_proof("art1", "storer1", 1)
    assert proof2["hash"] == "hash2"
    assert proof2["height"] == 102
    
    # Add new proof for different epoch
    reg.record_proof("art1", "storer1", 2, 0, 100, "hash3")
    assert reg.get_latest_proof_epoch("art1", "storer1") == 2
    
    # Invalid inputs
    reg.record_proof("", "storer1", 1, 0, 100, "hash")
    reg.record_proof("art1", "", 1, 0, 100, "hash")

def test_get_proof(mock_kv):
    reg = GraffitiRegistry()
    assert reg.get_proof("art1", "storer1", 1) is None
    assert reg.get_proof("", "storer1", 1) is None
    reg.record_proof("art1", "storer1", 1, 0, 100, "hash1")
    assert reg.get_proof("art1", "storer2", 1) is None
    assert reg.get_proof("art1", "storer1", 2) is None

def test_get_latest_proof(mock_kv):
    reg = GraffitiRegistry()
    assert reg.get_latest_proof("art1") is None
    assert reg.get_latest_proof_epoch("art1") == -1
    
    # Record proofs for multiple storers and epochs
    reg.record_proof("art1", "storer1", 1, 0, 100, "hash1")
    reg.record_proof("art1", "storer2", 2, 0, 100, "hash2")
    
    latest = reg.get_latest_proof("art1")
    assert latest["storer"] == "storer2"
    assert latest["epoch"] == 2
    assert reg.get_latest_proof_epoch("art1") == 2
    
    latest_s1 = reg.get_latest_proof("art1", "storer1")
    assert latest_s1["storer"] == "storer1"
    assert latest_s1["epoch"] == 1
    assert reg.get_latest_proof_epoch("art1", "storer1") == 1
    
    assert reg.get_latest_proof("art1", "storer3") is None
    assert reg.get_latest_proof_epoch("art1", "storer3") == -1

def test_list_payouts(mock_kv):
    reg = GraffitiRegistry()
    assert reg.list_payouts("art1") == []
    assert reg.list_payouts("") == []
    
    reg.record_post("art1", {}, "tx_post", 100, "pool1", 1000)
    reg.record_payout("art1", {"addr1": 100}, "tx1", 101, epoch=1)
    reg.record_payout("art1", {"addr1": 100}, "tx2", 102, epoch=2)
    
    payouts = reg.list_payouts("art1")
    assert len(payouts) == 2
    assert payouts[0]["txid"] == "tx2" # Sorted by block_height reverse
    assert payouts[1]["txid"] == "tx1"
    
    assert len(reg.list_payouts("art1", limit=1)) == 1
    assert len(reg.list_payouts("art1", limit=0)) == 2 # limit 0 is ignored

def test_list_posts(mock_kv):
    reg = GraffitiRegistry()
    assert reg.list_posts() == []
    
    reg.record_post("art1", {}, "tx1", 100, "pool1", 1000)
    reg.record_post("art2", {}, "tx2", 101, "pool2", 2000)
    reg.record_post("art3", {}, "tx3", 102, "pool3", 3000)
    
    posts = reg.list_posts()
    assert len(posts) == 3
    assert posts[0]["art_id"] == "art3"
    assert posts[1]["art_id"] == "art2"
    assert posts[2]["art_id"] == "art1"
    
    assert len(reg.list_posts(limit=2)) == 2
    assert reg.list_posts(limit=2)[0]["art_id"] == "art3"
    
    assert len(reg.list_posts(offset=1)) == 2
    assert reg.list_posts(offset=1)[0]["art_id"] == "art2"
    
    assert len(reg.list_posts(limit=1, offset=1)) == 1
    assert reg.list_posts(limit=1, offset=1)[0]["art_id"] == "art2"
    
    assert len(reg.list_posts(limit=0)) == 3
    assert len(reg.list_posts(offset=-1)) == 3

def test_list_comments(mock_kv):
    reg = GraffitiRegistry()
    assert reg.list_comments("art1") == []
    assert reg.list_comments("") == []
    
    reg.record_comment("art1", {"comment": "first"}, "tx1", 101, 100, 100)
    reg.record_comment("art1", {"comment": "second"}, "tx2", 102, 100, 100)
    
    comments = reg.list_comments("art1")
    assert len(comments) == 2
    assert comments[0]["txid"] == "tx2"
    assert comments[1]["txid"] == "tx1"
    
    assert len(reg.list_comments("art1", limit=1)) == 1
    assert len(reg.list_comments("art1", limit=0)) == 2
