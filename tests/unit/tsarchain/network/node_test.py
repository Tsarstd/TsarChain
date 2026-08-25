# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
import socket
from unittest.mock import MagicMock, patch

from tsarchain.network.node import Network

@pytest.fixture
def mock_cfg():
    with patch("tsarchain.network.node.CFG") as m_cfg:
        m_cfg.PORT_START = 8000
        m_cfg.PORT_END = 8005
        m_cfg.DEFAULT_NET_ID = "testnet"
        m_cfg.BOOTSTRAP_NODES = [("1.1.1.1", 8000)]
        m_cfg.BOOTSTRAP_NODE = ("1.1.1.1", 8000)
        m_cfg.PEER_SCORE_START = 100
        yield m_cfg

@pytest.fixture
def mock_socket():
    with patch("tsarchain.network.node.socket.socket") as m_sock:
        mock_instance = MagicMock()
        m_sock.return_value.__enter__.return_value = mock_instance
        yield m_sock

@pytest.fixture
def mock_broadcast():
    with patch("tsarchain.network.node.Broadcast") as m_bcast:
        mock_instance = MagicMock()
        m_bcast.return_value = mock_instance
        yield m_bcast

@pytest.fixture
def mock_deps():
    with patch("tsarchain.network.node.load_or_create_keypair_at") as m_keys, \
         patch("tsarchain.network.node.load_peer_keys") as m_load_peer, \
         patch("tsarchain.network.node.storage_registry.init_storage_registry") as m_stor, \
         patch("tsarchain.network.node.chat_state.init_chat_state") as m_chat, \
         patch("tsarchain.network.node.threading.Thread") as m_thread, \
         patch("tsarchain.network.node.rpc_client.prefetch_rpc_connections") as m_prefetch:
         
        m_keys.return_value = ("nid1", "00" * 33, "00" * 32)
        m_load_peer.return_value = {"nid1": "00" * 33}
        
        mock_thread_instance = MagicMock()
        mock_thread_instance.is_alive.return_value = True
        m_thread.return_value = mock_thread_instance
        
        yield {
            "keys": m_keys,
            "load_peer": m_load_peer,
            "stor": m_stor,
            "chat": m_chat,
            "thread": m_thread,
            "prefetch": m_prefetch
        }

def test_network_init_success(mock_cfg, mock_socket, mock_broadcast, mock_deps):
    # Ensure active_ports is clean
    Network.active_ports.clear()
    
    net = Network()
    net.start()
    
    assert net.port == 8000
    assert net.port in Network.active_ports
    
    # Broadcast is initialized properly
    mock_broadcast.assert_called_once()
    assert net.broadcast.port == 8000
    assert net.node_id == "nid1"
    
    # Threads started
    assert mock_deps["thread"].call_count == 3
    for call in mock_deps["thread"].return_value.start.call_args_list:
        pass # just checking they were called, we have 3 threads so start() called 3 times
    assert mock_deps["thread"].return_value.start.call_count == 3
    
    # Check encode wrapper for broadcast
    encoded = net.broadcast._encode({"test": 1})
    assert isinstance(encoded, dict)

def test_network_init_no_ports(mock_cfg, mock_socket, mock_deps, mock_broadcast):
    Network.active_ports.clear()
    
    # Fill active_ports to cover 'continue' at line 246
    Network.active_ports.add(8000)
    
    # Make bind raise OSError for remaining ports
    mock_socket.return_value.__enter__.return_value.bind.side_effect = OSError("port in use")
    
    with pytest.raises(RuntimeError, match="No available ports"):
        Network()

def test_network_init_no_bootstrap(mock_cfg, mock_socket, mock_deps, mock_broadcast):
    Network.active_ports.clear()
    # A generator is truthy, so it bypasses `or (CFG.BOOTSTRAP_NODE,)`
    # and when converted to tuple, results in empty `()`
    mock_cfg.BOOTSTRAP_NODES = (x for x in [])
    mock_cfg.BOOTSTRAP_NODE = None
    
    with pytest.raises(ValueError, match="No valid bootstrap peers configured"):
        Network()

def test_network_init_self_bootstrap(mock_cfg, mock_socket, mock_deps, mock_broadcast):
    Network.active_ports.clear()
    # Mock _is_self_bootstrap to True
    with patch.object(Network, "_is_self_bootstrap", return_value=True):
        net = Network()
        # If it's self bootstrap, persistent_peers shouldn't contain self
        assert len(net.persistent_peers) == 0

def test_network_init_prefetch_exception(mock_cfg, mock_socket, mock_broadcast, mock_deps):
    Network.active_ports.clear()
    mock_deps["prefetch"].side_effect = Exception("rpc error")
    
    # Shouldn't raise
    net = Network()
    net.start()
    assert net.port == 8000

def test_network_shutdown(mock_cfg, mock_socket, mock_broadcast, mock_deps):
    Network.active_ports.clear()
    net = Network()
    net.start()
    
    mock_sock = MagicMock()
    net._server_sock = mock_sock
    
    net.shutdown()
    
    assert net._stop.is_set()
    mock_sock.close.assert_called_once()
    assert net.port not in Network.active_ports
    net.broadcast.shutdown.assert_called_once()
    
    # threads joined
    assert mock_deps["thread"].return_value.join.call_count == 3

def test_pinned_keys(mock_cfg, mock_socket, mock_broadcast, mock_deps):
    Network.active_ports.clear()
    net = Network()
    
    assert net.get_pinned("nid1") == "00" * 33
    
    with patch("tsarchain.network.node.save_peer_keys") as m_save:
        # Update existing
        net.set_pinned("nid1", "pub2")
        assert net.get_pinned("nid1") == "pub2"
        m_save.assert_called_once_with(net.peer_pubkeys)
        
        m_save.reset_mock()
        # Update same (no change)
        net.set_pinned("nid1", "pub2")
        m_save.assert_not_called()

def test_is_local_address():
    # True cases
    assert Network._is_local_address("127.0.0.1") is True
    assert Network._is_local_address("localhost") is True
    assert Network._is_local_address("::1") is True
    
    # False cases
    assert Network._is_local_address("") is False
    assert Network._is_local_address(None) is False
    assert Network._is_local_address("   ") is False
    
    # Mock socket getaddrinfo and gethostbyname_ex to test IP matching
    with patch("tsarchain.network.node.socket.getaddrinfo") as m_info, \
         patch("tsarchain.network.node.socket.gethostbyname_ex") as m_ex, \
         patch("tsarchain.network.node.socket.gethostname") as m_hn, \
         patch("tsarchain.network.node.socket.getfqdn") as m_fqdn:
         
        def mock_getaddrinfo(host, *args, **kwargs):
            if host is None:
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.168.1.50', 0))]
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.168.1.100', 0))]
            
        m_info.side_effect = mock_getaddrinfo
        
        # Local IPs have something else
        m_ex.return_value = ('hostname', [], ['192.168.1.50'])
        
        assert Network._is_local_address("192.168.1.100") is False
        
        # Now make local IPs include target
        m_ex.return_value = ('hostname', [], ['192.168.1.100'])
        assert Network._is_local_address("192.168.1.100") is True

        # Test target empty info
        m_info.side_effect = lambda host, *args, **kwargs: []
        assert Network._is_local_address("192.168.1.100") is False

def test_is_self_bootstrap(mock_cfg, mock_socket, mock_broadcast, mock_deps):
    Network.active_ports.clear()
    net = Network()
    
    with patch.object(Network, "_is_local_address", return_value=True):
        assert net._is_self_bootstrap("127.0.0.1", net.port) is True
        assert net._is_self_bootstrap("127.0.0.1", 9999) is False

def test_wrappers(mock_cfg, mock_socket, mock_broadcast, mock_deps):
    Network.active_ports.clear()
    net = Network()
    
    with patch("tsarchain.network.node.peers.penalize_peer") as m_pen:
        net.penalize_peer("peer", 10)
        m_pen.assert_called_once_with(net, "peer", 10)
        
    with patch("tsarchain.network.node.peers.reward_peer") as m_rew:
        net.reward_peer("peer", 5)
        m_rew.assert_called_once_with(net, "peer", 5)
        
    with patch("tsarchain.network.node.peers.publish_block") as m_pub:
        net.publish_block("block", force=False)
        m_pub.assert_called_once_with(net, "block", exclude=None, force=False)
        
    with patch("tsarchain.network.node.peers.normalize_peer") as m_norm:
        net.normalize_peer("peer")
        m_norm.assert_called_once_with(net, "peer")
        
    with patch("tsarchain.network.node.sync.request_sync") as m_req_sync:
        net.request_sync(fast=True)
        m_req_sync.assert_called_once_with(net, fast=True)
        
    with patch("tsarchain.network.node.sync.sync_with_peers") as m_sync_p:
        net.sync_with_peers()
        m_sync_p.assert_called_once_with(net)
        
    with patch("tsarchain.network.node.sync.is_caught_up") as m_caught:
        net.is_caught_up(freshness=5.0)
        m_caught.assert_called_once_with(net, freshness=5.0, height_slack=0)
        
    with patch("tsarchain.network.node.sync.get_best_peer_height") as m_best:
        net.get_best_peer_height()
        m_best.assert_called_once_with(net)
        
    with patch("tsarchain.network.node.sync.handle_block_gap") as m_gap:
        net.handle_block_gap("block", "origin")
        m_gap.assert_called_once_with(net, "block", "origin")
        
    with patch("tsarchain.network.node.rpc_client.rpc_request") as m_rpc:
        net.rpc_request("peer", {"payload": 1}, timeout=2.0)
        m_rpc.assert_called_once_with(net, "peer", {"payload": 1}, 2.0)
        
    with patch("tsarchain.network.node.rpc_client.request_mempool_inline") as m_mem_in:
        net.request_mempool_inline("peer", force=True)
        m_mem_in.assert_called_once_with(net, "peer", force=True)
        
    with patch("tsarchain.network.node.rpc_client.request_mempool_snapshot") as m_mem_snap:
        net.request_mempool_snapshot("peer", force=True)
        m_mem_snap.assert_called_once_with(net, "peer", force=True)


def test_network_handler_proxy_delegation(mock_cfg, mock_socket, mock_broadcast, mock_deps):
    Network.active_ports.clear()
    net = Network()

    # Network dynamically delegates to handlers (chat, history, explorer, tx, guard)
    assert callable(net.chat_handler.get_prekey_bundle)
    assert callable(net.get_prekey_bundle)
    
    # Sub-handlers via NetworkHandlerProxy can access Network attributes
    assert net.chat_handler.port == 8000
    assert net.chat_handler.node_id == "nid1"
    
    # Non-existent attribute raises AttributeError
    with pytest.raises(AttributeError):
        _ = net.non_existent_attr_123
    with pytest.raises(AttributeError):
        _ = net.chat_handler.non_existent_attr_123

