# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
import threading
from unittest.mock import patch, MagicMock


from tsarchain.network.rpc.user_rpc.category.networking import (
    ping,
    get_peers,
    stor_list
    )


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------

@pytest.fixture
def mock_network():
    net = MagicMock()
    net.rl_ip = {}  # rate-limit table (dict)
    net.peers = {"192.168.1.1:38169", "192.168.1.2:38170"}
    net.storage_peers = {
        ("10.0.0.1", 8080): {
            "addr": "10.0.0.1",
            "ip": "10.0.0.1",
            "port": 8080,
            "last_seen": 1000,
            "alive": True,
            "url": "https://store1.example",
        },
        ("10.0.0.2", 8081): {
            "addr": "10.0.0.2",
            "ip": "10.0.0.2",
            "port": 8081,
            "last_seen": 2000,
            "alive": False,
            "url": "",
        },
        # Duplicate address with better port
        ("10.0.0.1", 9999): {
            "addr": "10.0.0.1",
            "ip": "10.0.0.1",
            "port": 9999,
            "last_seen": 1500,
            "alive": True,
            "url": "https://store2.example",
        },
    }
    net.lock = threading.Lock()
    net.tb_node_allow = MagicMock(return_value=True)
    net.backoff = MagicMock()
    return net


@pytest.fixture
def mock_cm_allow(monkeypatch):
    with patch("tsarchain.network.rpc.user_rpc.category.networking.CM.allow_rpc_with_pow") as mock_allow:
        yield mock_allow


@pytest.fixture
def mock_config():
    with patch("tsarchain.network.rpc.user_rpc.category.networking.CFG") as mock_cfg:
        # Provide default values used in the calls
        mock_cfg.PING_RL_IP_BURST = 5
        mock_cfg.PING_RL_IP_WINDOW_S = 10
        mock_cfg.PING_RL_BACKOFF_S = 30
        mock_cfg.GET_PEERS_RL_IP_BURST = 5
        mock_cfg.GET_PEERS_RL_IP_WINDOW_S = 10
        mock_cfg.GET_PEERS_RL_BACKOFF_S = 30
        mock_cfg.STOR_LIST_RL_IP_BURST = 4
        mock_cfg.STOR_LIST_RL_WINDOW_S = 10
        mock_cfg.STOR_LIST_RL_BACKOFF_S = 8
        mock_cfg.RPC_POW_DIFFICULTY_READ = 12
        mock_cfg.DEBUG_BENCHMARKS = False   # default off
        yield mock_cfg


# ----------------------------------------------------------------------
# Tests for ping()
# ----------------------------------------------------------------------

def test_ping_ok(mock_network, mock_cm_allow, mock_config):
    """ping: allow_rpc returns True -> PONG response."""
    mock_cm_allow.return_value = (True, None)

    result = ping(
        mock_network,
        message={},
        pow_obj=None,
        base_identity="id123",
        addr=("127.0.0.1", 38169),
        mtype="PING",
        client_ip="127.0.0.1",
        is_miner_sender=lambda: False,
    )

    assert result == {"type": "PONG"}

    # Verify allow_rpc_with_pow called with correct params
    mock_cm_allow.assert_called_once_with(
        mock_network,
        scope="rpc:ping",
        table=mock_network.rl_ip,
        ip="127.0.0.1",
        identity="id123",
        key_label="ping",
        burst=mock_config.PING_RL_IP_BURST,
        window_s=mock_config.PING_RL_IP_WINDOW_S,
        backoff_s=mock_config.PING_RL_BACKOFF_S,
        pow_obj=None,
        difficulty=int(mock_config.RPC_POW_DIFFICULTY_READ),
    )


def test_ping_pow_required(mock_network, mock_cm_allow, mock_config):
    """ping: allow_rpc returns False -> returns pow challenge."""
    expected_pow_resp = {"error": "pow_required", "retry_after": 30, "pow_challenge": "challenge"}
    mock_cm_allow.return_value = (False, expected_pow_resp)

    result = ping(
        mock_network,
        message={},
        pow_obj={"nonce": "bad"},
        base_identity="id123",
        addr=("127.0.0.1", 38169),
        mtype="PING",
        client_ip="127.0.0.1",
        is_miner_sender=lambda: False,
    )

    assert result == expected_pow_resp


# ----------------------------------------------------------------------
# Tests for get_peers()
# ----------------------------------------------------------------------

def test_get_peers_miner_true(mock_network, mock_cm_allow, mock_config):
    """get_peers: miner sender -> returns full peer list."""
    mock_cm_allow.return_value = (True, None)

    result = get_peers(
        mock_network,
        message={},
        pow_obj=None,
        base_identity="id123",
        addr=("127.0.0.1", 38169),
        mtype="GET_PEERS",
        client_ip="127.0.0.1",
        is_miner_sender=lambda: True,
    )

    assert result == {"type": "PEERS", "peers": list(mock_network.peers)}

    mock_cm_allow.assert_called_once_with(
        mock_network,
        scope="rpc:get_peers",
        table=mock_network.rl_ip,
        ip="127.0.0.1",
        identity="id123",
        key_label="get_peers",
        burst=mock_config.GET_PEERS_RL_IP_BURST,
        window_s=mock_config.GET_PEERS_RL_IP_WINDOW_S,
        backoff_s=mock_config.GET_PEERS_RL_BACKOFF_S,
        pow_obj=None,
        difficulty=int(mock_config.RPC_POW_DIFFICULTY_READ),
    )


def test_get_peers_miner_false(mock_network, mock_cm_allow, mock_config):
    """get_peers: non-miner sender -> returns empty peer list."""
    mock_cm_allow.return_value = (True, None)

    result = get_peers(
        mock_network,
        message={},
        pow_obj=None,
        base_identity="id123",
        addr=("127.0.0.1", 38169),
        mtype="GET_PEERS",
        client_ip="127.0.0.1",
        is_miner_sender=lambda: False,
    )

    assert result == {"type": "PEERS", "peers": []}


def test_get_peers_pow_required(mock_network, mock_cm_allow, mock_config):
    """get_peers: allow_rpc fails -> returns pow challenge."""
    expected_pow_resp = {"error": "pow_required", "retry_after": 30, "pow_challenge": "challenge"}
    mock_cm_allow.return_value = (False, expected_pow_resp)

    result = get_peers(
        mock_network,
        message={},
        pow_obj={"nonce": "bad"},
        base_identity="id123",
        addr=("127.0.0.1", 38169),
        mtype="GET_PEERS",
        client_ip="127.0.0.1",
        is_miner_sender=lambda: False,
    )

    assert result == expected_pow_resp


# ----------------------------------------------------------------------
# Tests for stor_list()
# ----------------------------------------------------------------------

def test_stor_list_ok(mock_network, mock_cm_allow, mock_config):
    """stor_list: success -> returns STOR_LIST with items."""
    mock_cm_allow.return_value = (True, None)

    result = stor_list(
        mock_network,
        message={},
        pow_obj=None,
        base_identity="id123",
        client_ip="127.0.0.1",
    )

    # Expected items: built from storage_peers with dedup by address
    expected_items = [
        {
            "addr": "10.0.0.1",
            "url": "https://store2.example",   # better port wins
            "ip": "10.0.0.1",
            "port": 9999,
            "last_seen": 1500,
            "alive": True,
        },
        {
            "addr": "10.0.0.2",
            "url": "",
            "ip": "10.0.0.2",
            "port": 8081,
            "last_seen": 2000,
            "alive": False,
        },
    ]
    # Order may vary, compare as sets or sorted
    assert result["type"] == "STOR_LIST"
    assert sorted(result["storers"], key=lambda x: x["addr"]) == sorted(expected_items, key=lambda x: x["addr"])

    mock_cm_allow.assert_called_once_with(
        mock_network,
        scope="rpc:stor_list",
        table=mock_network.rl_ip,
        ip="127.0.0.1",
        identity="id123",
        key_label="stor_list",
        burst=mock_config.STOR_LIST_RL_IP_BURST,
        window_s=mock_config.STOR_LIST_RL_WINDOW_S,
        backoff_s=mock_config.STOR_LIST_RL_BACKOFF_S,
        pow_obj=None,
        difficulty=int(mock_config.RPC_POW_DIFFICULTY_READ),
    )


def test_stor_list_empty(mock_network, mock_cm_allow, mock_config):
    """stor_list: no storage peers -> empty list."""
    mock_network.storage_peers = {}
    mock_cm_allow.return_value = (True, None)

    result = stor_list(
        mock_network,
        message={},
        pow_obj=None,
        base_identity="id123",
        client_ip="127.0.0.1",
    )

    assert result == {"type": "STOR_LIST", "storers": []}


def test_stor_list_pow_required(mock_network, mock_cm_allow, mock_config):
    """stor_list: allow_rpc fails -> returns pow challenge."""
    expected_pow_resp = {"error": "pow_required", "retry_after": 8, "pow_challenge": "challenge"}
    mock_cm_allow.return_value = (False, expected_pow_resp)

    result = stor_list(
        mock_network,
        message={},
        pow_obj={"nonce": "bad"},
        base_identity="id123",
        client_ip="127.0.0.1",
    )

    assert result == expected_pow_resp


def test_stor_list_with_bad_entries(mock_network, mock_cm_allow, mock_config):
    """stor_list: skip entries that are not dicts."""
    # Add a non-dict entry
    mock_network.storage_peers[("1.2.3.4", 1234)] = "not a dict"
    mock_cm_allow.return_value = (True, None)

    result = stor_list(
        mock_network,
        message={},
        pow_obj=None,
        base_identity="id123",
        client_ip="127.0.0.1",
    )

    # Should not include the bad entry
    assert len(result["storers"]) == 2  # only the two valid ones
    # Ensure the bad entry didn't cause errors