# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from tsarchain.network.node_logic.server_node import start_server, _handle_connection


class MockNode:
    def __init__(self):
        self._stop = threading.Event()
        self.port = 8333
        self.lock = threading.RLock()
        self.inbound_peers = set()
        self._inbound_ips = {}
        self.peer_scores = {}
        self.node_id = "mock_node_id"
        self.pubkey = "mock_pubkey"
        self.privkey = "mock_privkey"
        self.peer_pubkeys = {}
        self.node_ctx = {"test": "context"}

    def get_pinned(self, *args):
        return None

    def set_pinned(self, *args):
        pass


@pytest.fixture
def mock_node():
    return MockNode()


# ---------------------------------------------------------
# start_server tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.server_node.socket.socket")
@patch("tsarchain.network.node_logic.server_node.threading.Thread")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_start_server_success(mock_cfg, mock_allow, mock_thread, mock_socket, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.MAX_INBOUND_PEERS = 100
    mock_cfg.MAX_INBOUND_PER_IP = 10
    mock_allow.return_value = True

    mock_sock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_inst
    
    # We simulate 1 successful accept, then set _stop to True to break the loop
    def mock_accept():
        if mock_node._stop.is_set():
            raise Exception("Stop")
        mock_node._stop.set()  # Stop on next iter
        return MagicMock(), ("127.0.0.1", 12345)
        
    mock_sock_inst.accept.side_effect = mock_accept
    
    start_server(mock_node)
    
    mock_sock_inst.bind.assert_called_once_with(("0.0.0.0", 8333))
    mock_sock_inst.listen.assert_called_once()
    mock_thread.assert_called_once()


@patch("tsarchain.network.node_logic.server_node.socket.socket")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_start_server_handshake_deny(mock_cfg, mock_allow, mock_socket, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_allow.return_value = False

    mock_sock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_inst
    
    mock_conn = MagicMock()
    def mock_accept():
        if mock_node._stop.is_set():
            raise Exception("Stop")
        mock_node._stop.set()
        return mock_conn, ("127.0.0.1", 12345)
        
    mock_sock_inst.accept.side_effect = mock_accept
    
    start_server(mock_node)
    
    mock_conn.close.assert_called_once()


@patch("tsarchain.network.node_logic.server_node.socket.socket")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_start_server_inbound_full(mock_cfg, mock_allow, mock_socket, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.MAX_INBOUND_PEERS = 1
    mock_cfg.MAX_INBOUND_PER_IP = 10
    mock_allow.return_value = True

    mock_node.inbound_peers.add(("192.168.1.10", 1234))

    mock_sock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_inst
    
    mock_conn = MagicMock()
    def mock_accept():
        if mock_node._stop.is_set():
            raise Exception("Stop")
        mock_node._stop.set()
        return mock_conn, ("127.0.0.1", 12345)
        
    mock_sock_inst.accept.side_effect = mock_accept
    
    start_server(mock_node)
    
    mock_conn.close.assert_called_once()


@patch("tsarchain.network.node_logic.server_node.socket.socket")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_start_server_inbound_ip_full(mock_cfg, mock_allow, mock_socket, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.MAX_INBOUND_PEERS = 100
    mock_cfg.MAX_INBOUND_PER_IP = 1
    mock_allow.return_value = True

    mock_node._inbound_ips["127.0.0.1"] = 1

    mock_sock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_inst
    
    mock_conn = MagicMock()
    def mock_accept():
        if mock_node._stop.is_set():
            raise Exception("Stop")
        mock_node._stop.set()
        return mock_conn, ("127.0.0.1", 12345)
        
    mock_sock_inst.accept.side_effect = mock_accept
    
    start_server(mock_node)
    
    mock_conn.close.assert_called_once()


# ---------------------------------------------------------
# _handle_connection tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.server_node.sniff_first_json_frame")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_handle_connection_sniff_deny(mock_cfg, mock_allow, mock_sniff, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_sniff.return_value = (b"", {"from": "test", "pow": "123"})
    mock_allow.return_value = False
    
    mock_conn = MagicMock()
    _handle_connection(mock_node, mock_conn, ("127.0.0.1", 12345))
    
    mock_conn.close.assert_called_once()
    assert ("127.0.0.1", 12345) not in mock_node.inbound_peers


@patch("tsarchain.network.node_logic.server_node.sniff_first_json_frame")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.ban_ip")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_handle_connection_not_dict_ban(mock_cfg, mock_ban, mock_allow, mock_sniff, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_sniff.return_value = (b"", "not_a_dict")
    mock_allow.return_value = True
    
    mock_conn = MagicMock()
    _handle_connection(mock_node, mock_conn, ("127.0.0.1", 12345))
    
    mock_ban.assert_called_once_with("127.0.0.1", mock_cfg.BAN_MALICIOUS_RPC)
    mock_conn.close.assert_called_once()


@patch("tsarchain.network.node_logic.server_node.sniff_first_json_frame")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.SecureChannel")
@patch("tsarchain.network.node_logic.server_node.process_message")
@patch("tsarchain.network.node_logic.server_node.build_envelope")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_handle_connection_p2p_secure(mock_cfg, mock_build_env, mock_process, mock_channel, mock_allow, mock_sniff, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.ENVELOPE_REQUIRED = False
    mock_sniff.return_value = (b"", {"type": "P2P_HS1"})
    mock_allow.return_value = True
    
    mock_chan_inst = MagicMock()
    mock_channel.return_value = mock_chan_inst
    
    # Send one payload, then None to break loop
    mock_chan_inst.recv.side_effect = [json.dumps({"test": "data"}).encode("utf-8"), None]
    
    mock_process.return_value = {"status": "ok"}
    mock_build_env.return_value = {"env": "yes"}
    
    mock_conn = MagicMock()
    _handle_connection(mock_node, mock_conn, ("127.0.0.1", 12345))
    
    mock_chan_inst.hs_server_from_obj.assert_called_once()
    mock_process.assert_called_once()
    mock_build_env.assert_called_once()
    mock_chan_inst.send.assert_called_once_with(json.dumps({"env": "yes"}).encode("utf-8"))
    mock_conn.close.assert_called_once()


@patch("tsarchain.network.node_logic.server_node.sniff_first_json_frame")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.process_message")
@patch("tsarchain.network.node_logic.server_node.build_envelope")
@patch("tsarchain.network.node_logic.server_node.send_message")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_handle_connection_legacy_rpc(mock_cfg, mock_send, mock_build_env, mock_process, mock_allow, mock_sniff, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.P2P_ENC_REQUIRED = False
    mock_cfg.ENVELOPE_REQUIRED = False
    mock_sniff.return_value = (b"", {"type": "HELLO"})
    mock_allow.return_value = True
    
    mock_process.return_value = {"status": "ok"}
    mock_build_env.return_value = {"env": "yes"}
    
    mock_conn = MagicMock()
    _handle_connection(mock_node, mock_conn, ("127.0.0.1", 12345))
    
    mock_process.assert_called_once()
    mock_send.assert_called_once()
    mock_conn.close.assert_called_once()


@patch("tsarchain.network.node_logic.server_node.sniff_first_json_frame")
@patch("tsarchain.network.node_logic.server_node.allow_handshake")
@patch("tsarchain.network.node_logic.server_node.process_message")
@patch("tsarchain.network.node_logic.server_node.is_envelope")
@patch("tsarchain.network.node_logic.server_node.verify_and_unwrap")
@patch("tsarchain.network.node_logic.server_node.build_envelope")
@patch("tsarchain.network.node_logic.server_node.send_message")
@patch("tsarchain.network.node_logic.server_node.CFG")
def test_handle_connection_legacy_rpc_envelope(mock_cfg, mock_send, mock_build_env, mock_verify, mock_is_env, mock_process, mock_allow, mock_sniff, mock_node):
    mock_cfg.BUFFER_SIZE = 8192
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.P2P_ENC_REQUIRED = False
    mock_cfg.ENVELOPE_REQUIRED = False
    
    msg_dict = {"from": "nid", "pubkey": "pub", "data": "test"}
    mock_sniff.return_value = (b"", msg_dict)
    mock_allow.return_value = True
    mock_is_env.return_value = True
    mock_verify.return_value = {"type": "HELLO"}
    
    mock_process.return_value = {"status": "ok", "drop": True}
    mock_build_env.return_value = {"env": "yes"}
    
    mock_conn = MagicMock()
    _handle_connection(mock_node, mock_conn, ("127.0.0.1", 12345))
    
    mock_verify.assert_called_once()
    mock_process.assert_called_once()
    mock_send.assert_called_once()
    mock_conn.close.assert_called_once()
    assert mock_node.peer_pubkeys["nid"] == "pub"
