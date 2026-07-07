# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
from collections import deque
from unittest.mock import patch

from tsarchain.network.node_logic.ratelimit import (
    _subnet_key,
    _rl_prune,
    _hit,
    _would_allow,
    is_banned,
    ban_ip,
    ban_peer,
    allow_handshake,
    _handshake_hits_ip,
    _handshake_hits_id,
    _handshake_hits_subnet,
    _temp_ban_ip,
    _temp_ban_id,
)

@pytest.fixture(autouse=True)
def reset_globals():
    _handshake_hits_ip.clear()
    _handshake_hits_id.clear()
    _handshake_hits_subnet.clear()
    _temp_ban_ip.clear()
    _temp_ban_id.clear()

def test_subnet_key():
    assert _subnet_key("192.168.1.10") == "192.168.1"
    assert _subnet_key("10.0.0.1") == "10.0.0"
    assert _subnet_key("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:0db8:85a3:0000"
    assert _subnet_key("invalid") == "invalid"

def test_rl_prune():
    table = {"key": deque([10.0, 15.0, 20.0])}
    _rl_prune(table, "key", 5.0, 21.0)
    assert list(table["key"]) == [20.0]
    
    _rl_prune(table, "key", 0.5, 21.0)
    assert "key" not in table

def test_hit():
    table = {}
    assert _hit(table, "key", 5.0, 2, 10.0) is True
    assert _hit(table, "key", 5.0, 2, 11.0) is True
    assert _hit(table, "key", 5.0, 2, 12.0) is False  # len=3, burst=2
    # Prune
    assert _hit(table, "key", 1.0, 2, 20.0) is True

def test_would_allow():
    table = {}
    assert _would_allow(table, "key", 5.0, 2, 10.0) is True
    table["key"] = deque([10.0, 11.0])
    assert _would_allow(table, "key", 5.0, 2, 12.0) is False
    assert _would_allow(table, "key", 1.0, 2, 20.0) is True

def test_is_banned():
    assert is_banned("127.0.0.1") is False
    
    _temp_ban_ip["192.168.1.10"] = 20.0
    assert is_banned("192.168.1.10", 15.0) is True
    assert is_banned("192.168.1.10", 25.0) is False
    
    _temp_ban_id["node1"] = 20.0
    assert is_banned("192.168.1.11", 15.0, node_id="node1") is True
    assert is_banned("192.168.1.11", 25.0, node_id="node1") is False

def test_ban_peer():
    ban_peer("127.0.0.1", 10.0)
    assert "127.0.0.1" not in _temp_ban_ip
    
    with patch("tsarchain.network.node_logic.ratelimit.time.time", return_value=10.0):
        ban_peer("192.168.1.10", 15.0, node_id="node1")
    assert _temp_ban_ip["192.168.1.10"] == 25.0
    assert _temp_ban_id["node1"] == 25.0
    
def test_ban_ip():
    with patch("tsarchain.network.node_logic.ratelimit.time.time", return_value=10.0):
        ban_ip("192.168.1.10", 15.0)
    assert _temp_ban_ip["192.168.1.10"] == 25.0

@patch("tsarchain.network.node_logic.ratelimit.CFG")
def test_allow_handshake_local(mock_cfg):
    assert allow_handshake("127.0.0.1", 10.0) is True

@patch("tsarchain.network.node_logic.ratelimit.verify_pow")
@patch("tsarchain.network.node_logic.ratelimit.CFG")
def test_allow_handshake_pow(mock_cfg, mock_pow):
    mock_pow.return_value = True
    assert allow_handshake("192.168.1.10", 10.0, pow_proof={"nonce": "123"}) is True

@patch("tsarchain.network.node_logic.ratelimit.CFG")
def test_allow_handshake_precheck(mock_cfg):
    mock_cfg.HANDSHAKE_RL_PER_IP_BURST = 10
    mock_cfg.HANDSHAKE_RL_PER_IP_WINDOW_S = 10.0
    mock_cfg.HANDSHAKE_RL_SUBNET_BURST = 20
    mock_cfg.HANDSHAKE_RL_SUBNET_WINDOW_S = 10.0
    mock_cfg.HANDSHAKE_RL_PER_NODE_BURST = 5
    mock_cfg.HANDSHAKE_RL_PER_NODE_WINDOW_S = 10.0
    mock_cfg.CGNAT_IP_BURST_MULT = 1.0
    
    assert allow_handshake("192.168.1.10", 10.0, precheck=True) is True

@patch("tsarchain.network.node_logic.ratelimit.CFG")
def test_allow_handshake_normal(mock_cfg):
    mock_cfg.HANDSHAKE_RL_PER_IP_BURST = 2
    mock_cfg.HANDSHAKE_RL_PER_IP_WINDOW_S = 10.0
    mock_cfg.HANDSHAKE_RL_SUBNET_BURST = 100
    mock_cfg.HANDSHAKE_RL_SUBNET_WINDOW_S = 10.0
    mock_cfg.HANDSHAKE_RL_PER_NODE_BURST = 5
    mock_cfg.HANDSHAKE_RL_PER_NODE_WINDOW_S = 10.0
    mock_cfg.CGNAT_IP_BURST_MULT = 1.0
    mock_cfg.TEMP_BAN_SECONDS = 60.0
    
    assert allow_handshake("192.168.1.10", 10.0) is True
    assert allow_handshake("192.168.1.10", 10.0) is True
    assert allow_handshake("192.168.1.10", 10.0) is False # hit subnet/ip limits
    
    # Check that IP got banned
    assert _temp_ban_ip.get("192.168.1.10", 0.0) > 0.0

@patch("tsarchain.network.node_logic.ratelimit.CFG")
def test_allow_handshake_id_hit(mock_cfg):
    mock_cfg.HANDSHAKE_RL_PER_IP_BURST = 100
    mock_cfg.HANDSHAKE_RL_PER_IP_WINDOW_S = 10.0
    mock_cfg.HANDSHAKE_RL_SUBNET_BURST = 100
    mock_cfg.HANDSHAKE_RL_SUBNET_WINDOW_S = 10.0
    mock_cfg.HANDSHAKE_RL_PER_NODE_BURST = 1
    mock_cfg.HANDSHAKE_RL_PER_NODE_WINDOW_S = 10.0
    mock_cfg.CGNAT_IP_BURST_MULT = 1.0
    mock_cfg.TEMP_BAN_SECONDS = 60.0
    
    assert allow_handshake("192.168.1.10", 10.0, node_id="nid1") is True
    assert allow_handshake("192.168.1.11", 10.0, node_id="nid1") is False # hit node_id limits
    
    assert _temp_ban_id.get("nid1", 0.0) > 0.0
