# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import json
import pytest
from unittest.mock import patch, MagicMock

from archivist.connect import create_keypair, _scan_nodes, NodeDirectory, RPC

@patch("archivist.connect.save_node_key")
def test_create_keypair(mock_save, tmp_path):
    path = str(tmp_path / "key.json")
    with patch("archivist.connect.load_node_key"):
        node_id, pub, priv = create_keypair(path)
    assert node_id is not None
    assert pub is not None
    assert priv is not None
    assert priv is not None

@patch("archivist.connect._load_stor_peer_keys")
@patch("archivist.connect._save_stor_peer_keys")
@patch("archivist.connect.socket.socket")
@patch("archivist.connect.SecureChannel")
def test_scan_nodes(mock_channel, mock_sock, mock_save, mock_load, tmp_path):
    # Mocking create_keypair implicitly via patching CFG
    mock_s = MagicMock()
    mock_sock.return_value.__enter__.return_value = mock_s
    
    chan_inst = MagicMock()
    mock_channel.return_value = chan_inst
    chan_inst.recv.return_value = json.dumps({"type": "PONG"}).encode("utf-8")
    
    with patch("archivist.connect.create_keypair", return_value=("id1", "0"*64, "0"*64)):
        with patch("archivist.connect.CFG.PORT_START", 1234):
            with patch("archivist.connect.CFG.PORT_END", 1234):
                with patch("archivist.connect.CFG.ENVELOPE_REQUIRED", False):
                    with patch("archivist.connect.load_node_key", return_value={"id": "x", "pubkey": "0"*64, "privkey": "0"*64}):
                        nodes = _scan_nodes(manual_nodes=[("10.0.0.1", 5000)])
                        assert len(nodes) > 0

def test_node_directory():
    d = NodeDirectory(ttl=60)
    with patch("archivist.connect._scan_nodes") as mock_scan:
        mock_scan.return_value = [("127.0.0.1", 1234)]
        
        nodes = d.get_nodes()
        assert nodes == [("127.0.0.1", 1234)]
        assert mock_scan.call_count == 1
        
        # Test cache
        nodes2 = d.get_nodes()
        assert nodes2 == [("127.0.0.1", 1234)]
        assert mock_scan.call_count == 1
        
        # Test mark good
        d.mark_good(("10.0.0.1", 5555))
        nodes3 = d.get_nodes()
        assert nodes3[0] == ("10.0.0.1", 5555)

@patch("archivist.connect.create_keypair", return_value=("id", "0"*64, "0"*64))
def test_rpc_init(mock_cp):
    rpc = RPC()
    assert rpc.node is None
    assert rpc.trusted is False
    
    rpc.set_address_override(None)
    assert rpc.address == rpc._default_address
    
    with pytest.raises(ValueError):
        rpc.set_address_override("bc1qtest")

@patch("archivist.connect.create_keypair", return_value=("id", "0"*64, "0"*64))
@patch("archivist.connect.socket.socket")
@patch("archivist.connect.SecureChannel")
def test_rpc_connect(mock_chan, mock_sock, mock_cp):
    rpc = RPC()
    
    mock_s = MagicMock()
    mock_sock.return_value.__enter__.return_value = mock_s
    chan_inst = MagicMock()
    mock_chan.return_value = chan_inst
    
    chan_inst.recv.side_effect = [
        json.dumps({"type": "HELLO_OK"}).encode("utf-8"),
        json.dumps({"type": "PONG"}).encode("utf-8")
    ]
    
    rpc.set_address_override(None)
    res = rpc.connect("127.0.0.1", 1234)
    assert res is True
    assert rpc.node == ("127.0.0.1", 1234)

@patch("archivist.connect.create_keypair", return_value=("id", "0"*64, "0"*64))
@patch("archivist.connect.socket.socket")
@patch("archivist.connect.SecureChannel")
def test_rpc_call(mock_chan, mock_sock, mock_cp):
    rpc = RPC()
    rpc.node = ("127.0.0.1", 1234)
    rpc.set_address_override(None)
    
    mock_s = MagicMock()
    mock_sock.return_value.__enter__.return_value = mock_s
    chan_inst = MagicMock()
    mock_chan.return_value = chan_inst
    
    chan_inst.recv.return_value = json.dumps({"type": "RESPONSE", "data": 123}).encode("utf-8")
    
    res = rpc.call({"type": "REQUEST"})
    assert res["type"] == "RESPONSE"
    assert res["data"] == 123
    
    # Test timeout / no response
    chan_inst.recv.return_value = b""
    assert rpc.call({"type": "REQUEST"}) is None

def test_load_save_stor_peer_keys(tmp_path):
    import archivist.connect as conn
    with patch("archivist.connect.kv_enabled", return_value=False):
        with patch("archivist.connect.CFG.ARCHIV_PEER_KEYS", str(tmp_path / "peers.json")):
            conn._save_stor_peer_keys({"peer1": "key1"})
            
            # Load successfully
            loaded = conn._load_stor_peer_keys()
            assert loaded["peer1"] == "key1"
            
            # Save None payload
            conn._save_stor_peer_keys(None)

@patch("archivist.connect.create_keypair", return_value=("id", "0"*64, "0"*64))
def test_rpc_send_recv(mock_cp):
    rpc = RPC()
    rpc.sock = MagicMock()
    
    with patch("archivist.connect.send_message") as mock_send:
        rpc._send({"type": "TEST"})
        assert mock_send.call_count == 1
        
    with patch("archivist.connect.recv_message") as mock_recv:
        mock_recv.return_value = json.dumps({"type": "TEST_RECV"}).encode("utf-8")
        res = rpc._recv()
        assert res["type"] == "TEST_RECV"
        
        mock_recv.return_value = b""
        assert rpc._recv() is None
