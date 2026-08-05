# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import Mock, patch
from tsarchain.network.rpc.user_rpc.common import (
    verify_chat_signatures,
    identity_from_msg,
    summarize_block,
    allow_rpc_with_pow,
    _norm_identity,
    _subnet_key
)

def test_norm_identity():
    assert _norm_identity(None) is None
    assert _norm_identity("") is None
    assert _norm_identity("  ") is None
    assert _norm_identity("Alice ") == "alice"
    assert _norm_identity(["Bob", "Charlie"]) == "bob"
    assert _norm_identity([]) is None
    assert _norm_identity([""]) is None

def test_subnet_key():
    assert _subnet_key("192.168.1.100") == "192.168.1"
    assert _subnet_key("10.0.0.1") == "10.0.0"
    assert _subnet_key("invalid_ip") is None
    assert _subnet_key("127.0.0") is None

def test_identity_from_msg():
    assert identity_from_msg(None) is None
    assert identity_from_msg("not_a_dict") is None
    assert identity_from_msg({}) is None
    
    assert identity_from_msg({"wallet_addr": "addr1"}) == "addr1"
    assert identity_from_msg({"creator_addr": "addr_c"}) == "addr_c"
    assert identity_from_msg({"from_addr": "addr_f"}) == "addr_f"
    assert identity_from_msg({"from": " addr2 "}) == "addr2"
    assert identity_from_msg({"address": "addr3"}) == "addr3"
    assert identity_from_msg({"addr": "addr4"}) == "addr4"
    assert identity_from_msg({"sender": "addr5"}) == "addr5"
    assert identity_from_msg({"node_id": "addr6"}) == "addr6"

    assert identity_from_msg({"addresses": ["addr7", "addr8"]}) == "addr7"
    assert identity_from_msg({"addresses": []}) is None
    assert identity_from_msg({"addresses": "not_list"}) is None

    assert identity_from_msg({"data": {"from_addr": "addr9"}}) == "addr9"
    assert identity_from_msg({"data": {"addr": "addr10"}}) == "addr10"
    assert identity_from_msg({"data": "not_dict"}) is None
    
    assert identity_from_msg({"unknown": "test"}) is None

@patch("tsarchain.network.rpc.user_rpc.common.batch_verify_der_low_s")
def test_verify_chat_signatures(mock_batch_verify):
    # Empty tasks
    assert verify_chat_signatures([]) == {}

    # Invalid tasks (missing fields or empty payload)
    res = verify_chat_signatures([
        ("l1", "", b"pl", "sig"),
        ("l2", "pub", None, "sig"),
        ("l3", "pub", b"", "sig"),
        ("l4", "pub", b"pl", ""),
        ("l5", None, b"pl", "sig"),
    ])
    assert res == {"l1": False, "l2": False, "l3": False, "l4": False, "l5": False}
    mock_batch_verify.assert_not_called()

    # Valid tasks
    tasks = [
        ("t1", "02"*33, b"hello", "30"*35),
        ("t2", "03"*33, b"world", "30"*35)
    ]
    mock_batch_verify.return_value = [True, False]
    
    res = verify_chat_signatures(tasks)
    assert res == {"t1": True, "t2": False}
    mock_batch_verify.assert_called_once()
    args, kwargs = mock_batch_verify.call_args
    assert kwargs["enforce_low_s"] is True
    assert kwargs["parallel"] is False
    assert len(args[0]) == 2 # two triples

def test_summarize_block():
    mock_network = Mock()
    mock_network.bhash_hex.return_value = "block_hash_123"
    
    mock_block = Mock()
    mock_block.height = 100
    mock_block.timestamp = 1234567890
    
    mock_tx = Mock()
    mock_tx.block_id = 999
    
    mock_tx_out1 = Mock(script_pubkey=b"normal_spk")
    mock_tx_out2 = Mock(script_pubkey=b"graffiti_post")
    mock_tx_out3 = Mock(script_pubkey=b"graffiti_comment")
    mock_tx_out4 = Mock(script_pubkey=b"graffiti_payout")
    mock_tx_out5 = Mock(script_pubkey=b"graffiti_other")
    mock_tx_out6 = Mock(script_pubkey=None)
    del mock_tx_out6.script_pubkey # remove entirely
    
    mock_tx.outputs = [mock_tx_out1, mock_tx_out2, mock_tx_out3, mock_tx_out4, mock_tx_out5, mock_tx_out6]
    
    # Another tx with no outputs
    mock_tx2 = Mock()
    mock_tx2.outputs = None
    
    mock_block.transactions = [mock_tx, mock_tx2]
    
    with patch("tsarchain.network.rpc.user_rpc.common.GRAFFITI.parse_from_script") as mock_parse:
        def side_effect(spk):
            if spk == b"normal_spk":
                return None
            if spk == b"graffiti_post":
                return {"event": "post"}
            if spk == b"graffiti_comment":
                return {"event": "comment"}
            if spk == b"graffiti_payout":
                return {"event": "payout"}
            if spk == b"graffiti_other":
                return {"event": "unknown"}
            return None
        mock_parse.side_effect = side_effect
        
        res = summarize_block(mock_network, mock_block)
        
        assert res["height"] == 100
        assert res["hash"] == "block_hash_123"
        assert res["block_id"] == 999
        assert res["timestamp"] == 1234567890
        assert res["tx_count"] == 2
        assert res["graffiti_posts"] == 1
        assert res["graffiti_comments"] == 1
        assert res["graffiti_payouts"] == 1
        assert res["graffiti_count"] == 3

    mock_block_empty = Mock()
    mock_block_empty.transactions = []
    with pytest.raises(IndexError):
        summarize_block(mock_network, mock_block_empty)

@patch("tsarchain.network.rpc.user_rpc.common.verify_pow")
@patch("tsarchain.network.rpc.user_rpc.common.issue_pow")
def test_allow_rpc_with_pow(mock_issue_pow, mock_verify_pow):
    mock_network = Mock()
    mock_network.tb_node_allow.return_value = True
    
    # 1. pow_obj provided and valid
    mock_verify_pow.return_value = True
    allowed, err = allow_rpc_with_pow(
        mock_network,
        scope="test_scope",
        table={},
        ip="192.168.1.1",
        identity="alice",
        key_label="lbl",
        burst=10,
        window_s=60,
        backoff_s=0,
        pow_obj={"nonce": 123},
        difficulty=5
    )
    assert allowed is True
    assert err is None
    
    # 2. pow_obj provided but invalid, token bucket allows
    mock_verify_pow.return_value = False
    allowed, err = allow_rpc_with_pow(
        mock_network,
        scope="test_scope",
        table={},
        ip="192.168.1.1",
        identity="alice",
        key_label="lbl",
        burst=10,
        window_s=60,
        backoff_s=0,
        pow_obj={"nonce": 123},
        difficulty=5
    )
    assert allowed is True
    assert err is None
    
    # 3. pow_obj invalid/None, token bucket denies, issue new pow
    mock_network.tb_node_allow.return_value = False
    mock_issue_pow.return_value = "pow_chal"
    
    allowed, err = allow_rpc_with_pow(
        mock_network,
        scope="test_scope",
        table={},
        ip="192.168.1.1",
        identity="alice",
        key_label="lbl",
        burst=10,
        window_s=60,
        backoff_s=10,
        pow_obj=None,
        difficulty=5
    )
    assert allowed is False
    assert err["error"] == "pow_required"
    assert err["pow_challenge"] == "pow_chal"
    assert err["retry_after"] == 10
    
    # 4. backoff throws Exception (should be caught and passed)
    mock_network.tb_node_allow.return_value = False
    mock_network.backoff.side_effect = Exception("backoff error")
    allowed, err = allow_rpc_with_pow(
        mock_network,
        scope="test_scope",
        table={},
        ip="192.168.1.1",
        identity="alice",
        key_label="lbl",
        burst=10,
        window_s=60,
        backoff_s=10,
        pow_obj=None,
        difficulty=5
    )
    assert allowed is False
    
    # 5. verify_pow throws Exception (should be caught and passed, and proceed to tb_allow)
    mock_verify_pow.side_effect = Exception("pow error")
    mock_network.tb_node_allow.return_value = True
    allowed, err = allow_rpc_with_pow(
        mock_network,
        scope="test_scope",
        table={},
        ip="192.168.1.1",
        identity="alice",
        key_label="lbl",
        burst=10,
        window_s=60,
        backoff_s=0,
        pow_obj={"nonce": 123},
        difficulty=5
    )
    assert allowed is True
    
    # 6. empty ip and identity
    mock_network.tb_node_allow.return_value = True
    allowed, err = allow_rpc_with_pow(
        mock_network,
        scope="test_scope",
        table={},
        ip="",
        identity=None,
        key_label="lbl",
        burst=10,
        window_s=60,
        backoff_s=0,
        pow_obj=None,
        difficulty=5
    )
    assert allowed is True

    # 7. No backoff_s, denied by bucket
    mock_network.tb_node_allow.return_value = False
    allowed, err = allow_rpc_with_pow(
        mock_network,
        scope="test_scope",
        table={},
        ip="192.168.1.1",
        identity="alice",
        key_label="lbl",
        burst=10,
        window_s=60,
        backoff_s=0,
        pow_obj=None,
        difficulty=5
    )
    assert allowed is False
    assert err["retry_after"] == 1 # default max(1, 0)
