# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import pytest
from unittest.mock import Mock, patch

from kremlin.services.explorer_providers import get_explorer_providers

@pytest.fixture
def mock_rpc_client():
    client = Mock()
    client.send.return_value = {}
    return client

@pytest.fixture
def providers(mock_rpc_client):
    return get_explorer_providers(mock_rpc_client)

def test_get_info_normalization(mock_rpc_client, providers):
    mock_rpc_client.send.return_value = {
        "net_id": "tsar-mainnet",
        "tip_height": 100,
        "tip_target": 500,
        "network_hashrate": 1000,
        "genesis_hash": "0000abc",
        "tip_hash": "1234def",
    }
    
    prov_get_info = providers["get_info"]
    info = prov_get_info()
    
    mock_rpc_client.send.assert_called_once_with({"type": "GET_NETWORK_INFO"})
    assert info["network"] == "tsar-mainnet"
    assert info["height"] == 100
    assert info["difficulty"] == 500
    assert info["hashrate"] == 1000
    assert info["genesis"] == "0000abc"
    assert info["tip"] == "1234def"

def test_get_info_not_dict(mock_rpc_client, providers):
    mock_rpc_client.send.return_value = "error_string"
    assert providers["get_info"]() == {}

def test_get_block_by_height(mock_rpc_client, providers):
    mock_rpc_client.send.return_value = {"block_data": "data"}
    prov_get_block = providers["get_block"]
    
    blk = prov_get_block("123")
    mock_rpc_client.send.assert_called_once_with({"type": "GET_BLOCK", "height": 123})
    assert blk["height"] == 123
    assert blk["block_data"] == "data"

def test_get_block_by_hash(mock_rpc_client, providers):
    mock_rpc_client.send.return_value = {"block_data": "data"}
    prov_get_block = providers["get_block"]
    
    hash_str = "a" * 64
    blk = prov_get_block(hash_str)
    mock_rpc_client.send.assert_called_once_with({"type": "GET_BLOCK", "hash": hash_str})
    assert blk["hash"] == hash_str
    assert blk["block_data"] == "data"

def test_get_block_invalid(mock_rpc_client, providers):
    prov_get_block = providers["get_block"]
    assert prov_get_block("invalid_hash_or_height") == {"error": "not_found"}

def test_get_tx_detail_success(mock_rpc_client, providers):
    mock_rpc_client.send.return_value = {
        "tx": {
            "id": "tx123",
            "vin": [{"txid": "0"*64}],
            "vout": [{"value": 50}]
        }
    }
    prov_get_tx = providers["get_tx"]
    tx = prov_get_tx("tx123")
    
    assert tx["txid"] == "tx123"
    assert len(tx["inputs"]) == 1
    assert tx["inputs"][0]["txid"] == "0"*64
    assert len(tx["outputs"]) == 1
    assert tx["is_coinbase"] is True

def test_get_tx_fallback_endpoints(mock_rpc_client, providers):
    # Simulate GET_TX_DETAIL failing, then GET_TX failing, then GET_TRANSACTION succeeding
    responses = [
        {"error": "not found"},
        {"error": "not found"},
        {"transaction": {"hash": "tx123", "inputs": [{"txid": "1"*64}], "outputs": []}}
    ]
    mock_rpc_client.send.side_effect = responses
    prov_get_tx = providers["get_tx"]
    
    tx = prov_get_tx("tx123")
    assert tx["txid"] == "tx123"
    assert tx["is_coinbase"] is False
    assert mock_rpc_client.send.call_count == 3

def test_get_tx_not_found(mock_rpc_client, providers):
    mock_rpc_client.send.return_value = {"error": "not found"}
    prov_get_tx = providers["get_tx"]
    assert prov_get_tx("tx123") == {"error": "not_found"}

def test_get_address_balances_and_utxos(mock_rpc_client, providers):
    def side_effect(payload):
        if payload["type"] == "GET_BALANCES":
            return {"spendable": 100, "immature": 50, "pending": 10}
        elif payload["type"] == "GET_UTXOS":
            return {"utxos": {"txid1:0": {"amount": 100}}}
        elif payload["type"] == "GET_TX_HISTORY":
            return [{"txid": "tx1"}, {"txid": "tx2"}]
        return {}
    
    mock_rpc_client.send.side_effect = side_effect
    prov_get_address = providers["get_address"]
    
    addr_info = prov_get_address("tsar1abc")
    assert addr_info["address"] == "tsar1abc"
    assert addr_info["spendable"] == 100
    assert addr_info["immature"] == 50
    assert addr_info["pending"] == 10
    assert len(addr_info["utxos"]) == 1
    assert addr_info["utxos"][0]["txid"] == "txid1"
    assert addr_info["utxos"][0]["amount"] == 100
    assert len(addr_info["history"]) == 2

def test_get_address_fallback_spendable(mock_rpc_client, providers):
    # If balances are 0 but UTXOs exist, it should sum up UTXOs
    def side_effect(payload):
        if payload["type"] == "GET_BALANCES":
            return {}
        elif payload["type"] == "GET_UTXOS":
            return [{"txid": "tx1", "amount": 25}, {"txid": "tx2", "amount": 75}]
        elif payload["type"] == "GET_TX_HISTORY":
            return []
        return {}
    
    mock_rpc_client.send.side_effect = side_effect
    prov_get_address = providers["get_address"]
    
    addr_info = prov_get_address("tsar1xyz")
    assert addr_info["spendable"] == 100

def test_simple_providers(mock_rpc_client, providers):
    # Test mempool
    providers["get_mempool"]()
    mock_rpc_client.send.assert_called_with({"type": "GET_MEMPOOL"})
    
    # Test graffiti
    providers["get_graffiti"]("art123")
    mock_rpc_client.send.assert_called_with({"type": "GRAFFITI_GET_ART", "art_id": "art123"})
    
    # Test graffiti comments
    providers["get_graffiti_comments"]("art123")
    mock_rpc_client.send.assert_called_with({"type": "GRAFFITI_GET_COMMENTS", "art_id": "art123"})

@patch("kremlin.services.explorer_providers.fetch_graffiti_file")
def test_fetch_graffiti_file(mock_fetch, mock_rpc_client, providers):
    mock_fetch.return_value = {"status": "ok"}
    prov_fetch_graffiti = providers["fetch_graffiti_file"]
    
    post_data = {"art_id": "art123", "storer": "tsar1storer"}
    res = prov_fetch_graffiti(post=post_data, art_id="art123")
    
    assert res == {"status": "ok"}
    
    # Ensure fetch_graffiti_file was called with _rpc callable, art_id, and storer_addr
    args, kwargs = mock_fetch.call_args
    assert callable(args[0])
    assert args[1] == "art123"
    assert kwargs["storer_addr"] == "tsar1storer"
    
    # Verify the callable passed is actually bound to rpc_client.send
    rpc_callable = args[0]
    rpc_callable({"test": 1})
    mock_rpc_client.send.assert_called_with({"test": 1})
