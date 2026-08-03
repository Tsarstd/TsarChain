# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import socket
import pytest
from unittest.mock import MagicMock, patch

from tsarchain.utils import config as CFG
from tsarchain.network.node_logic.peers import normalize_peer
from tsarchain.network.node import Network
from tsarchain.network.node_logic.server_node import start_server
from tsarchain.network.node_logic.rpc_client import _connect_socket as rpc_client_connect
from archivist.connect import _connect_socket as archivist_connect
from kremlin.services.rpc_kremlin import _connect_socket as kremlin_connect


def test_normalize_peer_ipv6_and_ipv4():
    # IPv4 tuple
    assert normalize_peer(None, ("192.168.1.8", 38169)) == ("192.168.1.8", 38169)
    # IPv4-mapped IPv6 tuple
    assert normalize_peer(None, ("::ffff:192.168.1.8", 38169)) == ("192.168.1.8", 38169)
    # IPv6 tuple
    assert normalize_peer(None, ("2001:db8:85a3::8a2e:370:7334", 38169)) == (
        "2001:db8:85a3::8a2e:370:7334",
        38169,
    )
    # Bracketed IPv6 string
    assert normalize_peer(None, "[2001:db8:85a3::8a2e:370:7334]:38169") == (
        "2001:db8:85a3::8a2e:370:7334",
        38169,
    )
    # Standard IPv4 string
    assert normalize_peer(None, "192.168.1.8:38169") == ("192.168.1.8", 38169)


def test_is_local_address_ipv6():
    assert Network._is_local_address("::1") is True
    assert Network._is_local_address("[::1]") is True
    assert Network._is_local_address("127.0.0.1") is True
    assert Network._is_local_address("fe80::1%16") is True


@patch("tsarchain.network.node_logic.server_node.socket.socket")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
def test_start_server_ipv6_mode_true(mock_allow, mock_socket):
    mock_allow.return_value = True
    mock_sock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_inst

    mock_node = MagicMock()
    mock_node.port = 38169
    mock_node._stop.is_set.side_effect = [False, True]
    mock_sock_inst.accept.side_effect = Exception("Stop")

    with patch.object(CFG, "IPV6_MODE", True):
        start_server(mock_node)

    # Check AF_INET6 socket creation and bind to ::
    mock_socket.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM)
    mock_sock_inst.bind.assert_called_once_with(("::", 38169))


@patch("tsarchain.network.node_logic.server_node.socket.socket")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
def test_start_server_ipv6_mode_false(mock_allow, mock_socket):
    mock_allow.return_value = True
    mock_sock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_inst

    mock_node = MagicMock()
    mock_node.port = 38169
    mock_node._stop.is_set.side_effect = [False, True]
    mock_sock_inst.accept.side_effect = Exception("Stop")

    with patch.object(CFG, "IPV6_MODE", False):
        start_server(mock_node)

    # Check AF_INET socket creation and bind to 0.0.0.0
    mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_sock_inst.bind.assert_called_once_with(("0.0.0.0", 38169))


@patch("tsarchain.network.node_logic.rpc_client.socket.getaddrinfo")
@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
def test_rpc_client_connect_socket_ipv6_mode_true(mock_socket, mock_getaddrinfo):
    mock_getaddrinfo.return_value = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 38169, 0, 0))
    ]
    mock_sock_inst = MagicMock()
    mock_socket.return_value = mock_sock_inst

    with patch.object(CFG, "IPV6_MODE", True):
        s = rpc_client_connect(("2001:db8::1", 38169), timeout=2.0)

    assert s == mock_sock_inst
    mock_socket.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM, 6)
    mock_sock_inst.connect.assert_called_once_with(("2001:db8::1", 38169, 0, 0))


@patch("tsarchain.network.node_logic.rpc_client.socket.socket")
def test_rpc_client_connect_socket_ipv6_mode_false(mock_socket):
    mock_sock_inst = MagicMock()
    mock_socket.return_value = mock_sock_inst

    with patch.object(CFG, "IPV6_MODE", False):
        s = rpc_client_connect(("192.168.1.8", 38169), timeout=2.0)

    assert s == mock_sock_inst
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_sock_inst.connect.assert_called_once_with(("192.168.1.8", 38169))
