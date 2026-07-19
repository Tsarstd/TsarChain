# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import json
from unittest.mock import MagicMock, patch

from kremlin.services.rpc_kremlin import (
    _mk_extra,
    _throttle,
    NodeClient,
)

def test_mk_extra():
    extra = _mk_extra("peer1", "RPC1", "req1")
    assert extra == {"peer": "peer1", "rpc": "RPC1", "req": "req1"}
    
    extra_default = _mk_extra()
    assert extra_default == {"peer": "-", "rpc": "-", "req": "-"}

@patch("kremlin.services.rpc_kremlin.time.time")
def test_throttle(mock_time):
    mock_time.return_value = 100.0
    # First time should pass
    assert _throttle("test_key", 10.0) is True
    # Second time immediately should fail
    mock_time.return_value = 105.0
    assert _throttle("test_key", 10.0) is False
    # Third time after interval should pass
    mock_time.return_value = 111.0
    assert _throttle("test_key", 10.0) is True

def test_node_client_dir():
    dir_obj = NodeClient._Dir(ttl=10)
    
    # Empty dir
    assert dir_obj.get() == []
    
    # Set and get
    with patch("kremlin.services.rpc_kremlin.time.time", return_value=100.0):
        dir_obj.set([("127.0.0.1", 8080), ("127.0.0.2", 8080)])
        
    with patch("kremlin.services.rpc_kremlin.time.time", return_value=105.0):
        assert len(dir_obj.get()) == 2
        
    # Expired
    with patch("kremlin.services.rpc_kremlin.time.time", return_value=115.0):
        assert dir_obj.get() == []
        
    # Mark good
    with patch("kremlin.services.rpc_kremlin.time.time", return_value=100.0):
        dir_obj.set([("127.0.0.1", 8080), ("127.0.0.2", 8080)])
        dir_obj.mark_good(("127.0.0.2", 8080))
        nodes = dir_obj.get()
        assert nodes[0] == ("127.0.0.2", 8080)

def test_node_client_init():
    user_ctx = {"node_id": "node1", "pubkey": "pub1", "privkey": "priv1"}
    client = NodeClient(MagicMock(), user_ctx)
    assert client.user_id == "node1"
    assert client.user_pub == "pub1"
    assert client.user_priv == "priv1"

@patch("kremlin.services.rpc_kremlin.CFG")
@patch("kremlin.services.rpc_kremlin.socket.socket")
@patch("kremlin.services.rpc_kremlin.SecureChannel")
def test_node_client_scan(mock_secure_channel, mock_socket, mock_cfg):
    mock_cfg.PORT_START = 8080
    mock_cfg.PORT_END = 8082
    mock_cfg.BOOTSTRAP_NODES = [("127.0.0.1", 8080)]
    mock_cfg.CONNECT_TIMEOUT_SCAN = 1
    mock_cfg.ENVELOPE_REQUIRED = False
    
    user_ctx = {"node_id": "test", "pubkey": "02" + "01"*32, "privkey": "01"*32, "net_id": "testnet"}
    client = NodeClient(mock_cfg, user_ctx)
    
    mock_chan = MagicMock()
    mock_chan.recv.return_value = json.dumps({"type": "PONG"}).encode("utf-8")
    mock_secure_channel.return_value = mock_chan
    
    found = client.scan(start=8080, end=8082, manual_nodes=[("127.0.0.2", 8081)])
    assert ("127.0.0.1", 8080) in found
    assert ("127.0.0.2", 8081) in found

@patch("kremlin.services.rpc_kremlin.time.time")
@patch("kremlin.services.rpc_kremlin.time.sleep")
@patch("kremlin.services.rpc_kremlin.CFG")
def test_node_client_pace(mock_cfg, mock_sleep, mock_time):
    mock_cfg.WALLET_RPC_MIN_INTERVAL = 1.0
    client = NodeClient(mock_cfg, {})
    
    client._last_send_ts = 100.0
    mock_time.side_effect = [100.5, 101.5] # wait = 101.0 - 100.5 = 0.5
    
    client._pace()
    mock_sleep.assert_called_once_with(0.5)

@patch("kremlin.services.rpc_kremlin.CFG")
@patch("kremlin.services.rpc_kremlin.socket.socket")
@patch("kremlin.services.rpc_kremlin.SecureChannel")
@patch("kremlin.services.rpc_kremlin.is_envelope")
def test_node_client_try_send_one(mock_is_env, mock_secure_channel, mock_socket, mock_cfg):
    mock_cfg.ENVELOPE_REQUIRED = False
    user_ctx = {"node_id": "test", "pubkey": "02" + "01"*32, "privkey": "01"*32, "net_id": "testnet"}
    client = NodeClient(mock_cfg, user_ctx)
    
    mock_chan = MagicMock()
    mock_chan.recv.return_value = json.dumps({"status": "ok"}).encode("utf-8")
    mock_secure_channel.return_value = mock_chan
    mock_is_env.return_value = False
    
    resp = client._try_send_one(("127.0.0.1", 8080), {"type": "TEST"})
    assert resp == {"status": "ok"}

@patch("kremlin.services.rpc_kremlin.CFG")
def test_node_client_send(mock_cfg):
    client = NodeClient(mock_cfg, {})
    
    # Case 1: no peers
    with patch.object(client.dir, "get", return_value=[]), \
         patch.object(client, "scan", return_value=[]):
        resp = client.send({"type": "TEST"})
        assert resp == {"error": "No peers"}
        
    # Case 2: peers exist, get response
    with patch.object(client.dir, "get", return_value=[("127.0.0.1", 8080)]), \
         patch.object(client, "_try_send_one", return_value={"status": "ok"}):
        resp = client.send({"type": "TEST"})
        assert resp == {"status": "ok"}

    # Case 3: peers exist, no response
    with patch.object(client.dir, "get", return_value=[("127.0.0.1", 8080)]), \
         patch.object(client, "scan", return_value=[("127.0.0.1", 8080)]), \
         patch.object(client, "_try_send_one", return_value=None):
        resp = client.send({"type": "TEST"})
        assert resp == {"error": "No response from any node"}

@patch("kremlin.services.rpc_kremlin.threading.Thread")
def test_node_client_send_async(mock_thread):
    client = NodeClient(MagicMock(), {})
    cb = MagicMock()
    client.send_async({"type": "TEST"}, cb)
    
    mock_thread.assert_called_once()
    # verify it was called as a daemon thread
    args, kwargs = mock_thread.call_args
    assert kwargs["daemon"] is True

@patch("kremlin.services.rpc_kremlin.CFG")
@patch("kremlin.services.rpc_kremlin.socket.socket")
@patch("kremlin.services.rpc_kremlin.SecureChannel")
@patch("kremlin.services.rpc_kremlin.send_message")
@patch("kremlin.services.rpc_kremlin.recv_message")
def test_node_client_scan_fallback_and_envelope(mock_recv, mock_send, mock_secure_channel, mock_socket, mock_cfg):
    mock_cfg.PORT_START = 8080
    mock_cfg.PORT_END = 8080
    mock_cfg.BOOTSTRAP_NODES = [("127.0.0.1", 8080)]
    mock_cfg.CONNECT_TIMEOUT_SCAN = 1
    mock_cfg.ENVELOPE_REQUIRED = False
    mock_cfg.P2P_ENC_REQUIRED = False
    
    user_ctx = {"node_id": "test", "pubkey": "02" + "01"*32, "privkey": "01"*32, "net_id": "testnet"}
    client = NodeClient(mock_cfg, user_ctx)
    
    # 1. Fallback to plaintext PONG when SecureChannel raises
    mock_secure_channel.side_effect = Exception("Handshake failed")
    mock_recv.return_value = json.dumps({"type": "PONG"}).encode("utf-8")
    
    found = client.scan(start=8080, end=8080, manual_nodes=[])
    assert ("127.0.0.1", 8080) in found
    mock_send.assert_called_once()
    
    # 2. SecureChannel works, returns an envelope, is_envelope=True, verify_and_unwrap returns PONG
    mock_secure_channel.side_effect = None
    mock_chan = MagicMock()
    mock_chan.recv.return_value = json.dumps({"sig": "abcd", "payload": "xyz"}).encode("utf-8") # pseudo envelope
    mock_secure_channel.return_value = mock_chan
    
    with patch("kremlin.services.rpc_kremlin.is_envelope", return_value=True), \
         patch("kremlin.services.rpc_kremlin.verify_and_unwrap", return_value={"type": "PONG"}):
        found = client.scan(start=8080, end=8080, manual_nodes=[])
        assert ("127.0.0.1", 8080) in found
        
    # 3. SecureChannel works, envelope verify fails, ENVELOPE_REQUIRED=False
    with patch("kremlin.services.rpc_kremlin.is_envelope", return_value=True), \
         patch("kremlin.services.rpc_kremlin.verify_and_unwrap", side_effect=Exception("Bad sig")):
        found = client.scan(start=8080, end=8080, manual_nodes=[])
        assert ("127.0.0.1", 8080) in found

@patch("kremlin.services.rpc_kremlin.CFG")
@patch("kremlin.services.rpc_kremlin.socket.socket")
@patch("kremlin.services.rpc_kremlin.SecureChannel")
@patch("kremlin.services.rpc_kremlin.send_message")
@patch("kremlin.services.rpc_kremlin.recv_message")
def test_node_client_try_send_one_fallback_and_envelope(mock_recv, mock_send, mock_secure_channel, mock_socket, mock_cfg):
    user_ctx = {"node_id": "test", "pubkey": "02" + "01"*32, "privkey": "01"*32, "net_id": "testnet"}
    client = NodeClient(mock_cfg, user_ctx)
    peer = ("127.0.0.1", 8080)
    mock_cfg.ENVELOPE_REQUIRED = False
    mock_cfg.P2P_ENC_REQUIRED = False
    
    # 1. Fallback to plaintext
    mock_secure_channel.side_effect = Exception("Handshake failed")
    mock_recv.return_value = json.dumps({"status": "ok"}).encode("utf-8")
    
    with patch("kremlin.services.rpc_kremlin.is_envelope", return_value=False):
        resp = client._try_send_one(peer, {"type": "TEST"})
        assert resp == {"status": "ok"}
        
    # 2. Valid envelope
    mock_secure_channel.side_effect = None
    mock_chan = MagicMock()
    mock_chan.recv.return_value = json.dumps({"sig": "abcd", "payload": "xyz"}).encode("utf-8")
    mock_secure_channel.return_value = mock_chan
    
    with patch("kremlin.services.rpc_kremlin.is_envelope", return_value=True), \
         patch("kremlin.services.rpc_kremlin.verify_and_unwrap", return_value={"status": "env_ok"}):
        resp = client._try_send_one(peer, {"type": "TEST"})
        assert resp == {"status": "env_ok"}
        
    # 3. Invalid envelope, not required
    mock_cfg.ENVELOPE_REQUIRED = False
    with patch("kremlin.services.rpc_kremlin.is_envelope", return_value=True), \
         patch("kremlin.services.rpc_kremlin.verify_and_unwrap", side_effect=Exception("Bad sig")):
        resp = client._try_send_one(peer, {"type": "TEST"})
        assert resp == {"sig": "abcd", "payload": "xyz"}

