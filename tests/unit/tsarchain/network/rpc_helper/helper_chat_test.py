# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import collections
import threading
import pytest
from unittest.mock import MagicMock, Mock, patch, ANY

from tsarchain.network.rpc_helper.chat import ChatHandler
from tsarchain.utils import config as CFG

# ---------------------- Dummy class to host the mixin ----------------------
class DummyNode(ChatHandler):
    def __init__(self):
        super().__init__(self)
        self.node_ctx = {}
        self.pubkey = "test_pubkey"
        self.privkey = "test_privkey"
        self.node_id = "test_node"
        self.peers = [("127.0.0.1", 9000)]
        self.broadcast = Mock()
        self.broadcast._broadcast = Mock()
        self.chat_lock = threading.Lock()
        self.chat_mailbox = {}
        self.chat_global_count = 0
        self.chat_seen_mid = {}
        self.chat_seen_max = 100
        self.backoff_until = {}
        self.chat_gc_last = 0
        self.get_pinned = Mock(return_value=None)
        self.set_pinned = Mock()


# ---------------------- Fixtures ----------------------
@pytest.fixture
def node():
    """Return a DummyNode instance with ChatHandler."""
    return DummyNode()


@pytest.fixture
def mock_config(monkeypatch):
    """Mock all config flags and constants used."""
    monkeypatch.setattr("tsarchain.network.rpc_helper.chat.CFG", Mock(
        ENFORCE_HELLO_PUBKEY=False,
        ENVELOPE_REQUIRED=False,
        P2P_ENC_REQUIRED=False,
        CHAT_TTL_S=60,
        CHAT_MAILBOX_MAX=10,
        CHAT_GLOBAL_QUEUE_MAX=100,
    ))


@pytest.fixture
def mock_time(monkeypatch):
    """Mock time.time to return controllable values."""
    mock_time = Mock()
    mock_time.return_value = 1000.0
    monkeypatch.setattr("tsarchain.network.rpc_helper.chat.time.time", mock_time)
    return mock_time


# ---------------------- Tests ----------------------

class TestSendToPeer:

    def test_send_to_peer_valid_no_encryption(self, node, monkeypatch):
        """Test _send_to_peer when encryption is not required."""
        monkeypatch.setattr("tsarchain.network.rpc_helper.chat.CFG.P2P_ENC_REQUIRED", False)

        mock_socket_instance = Mock()
        with patch('socket.socket') as mock_socket_class:
            mock_socket_class.return_value.__enter__.return_value = mock_socket_instance

            mock_build = Mock(return_value={"test": "env"})
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.build_envelope", mock_build)

            mock_send = Mock()
            mock_recv = Mock(return_value=b"ok")
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.send_message", mock_send)
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.recv_message", mock_recv)

            payload = {"type": "TEST"}
            node._send_to_peer(("192.168.1.1", 8000), payload)

        mock_socket_instance.connect.assert_called_with(("192.168.1.1", 8000))
        mock_build.assert_called_once_with(payload, node.node_ctx, extra={"pubkey": node.pubkey})
        mock_send.assert_called_once_with(mock_socket_instance, ANY)
        mock_recv.assert_called_once_with(mock_socket_instance, timeout=1)

    def test_send_to_peer_valid_with_encryption(self, node, monkeypatch):
        """Test _send_to_peer when encryption is required."""
        monkeypatch.setattr("tsarchain.network.rpc_helper.chat.CFG.P2P_ENC_REQUIRED", True)

        mock_socket_instance = Mock()
        with patch('socket.socket') as mock_socket_class:
            mock_socket_class.return_value.__enter__.return_value = mock_socket_instance

            mock_chan = Mock()
            mock_chan.handshake = Mock()
            mock_chan.send = Mock()
            mock_chan.recv = Mock(return_value=b"ok")
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.SecureChannel", Mock(return_value=mock_chan))

            mock_build = Mock(return_value={"test": "env"})
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.build_envelope", mock_build)

            payload = {"type": "TEST"}
            node._send_to_peer(("192.168.1.1", 8000), payload)

        mock_socket_instance.connect.assert_called_with(("192.168.1.1", 8000))
        mock_build.assert_called_once()
        mock_chan.handshake.assert_called_once()
        mock_chan.send.assert_called_once_with(ANY)
        mock_chan.recv.assert_called_once_with(1)

    def test_send_to_peer_invalid_peer(self, node):
        """Test _send_to_peer raises ValueError for bad peer tuple."""
        with pytest.raises(ValueError, match="bad peer"):
            node._send_to_peer(("only_one",), {})
        with pytest.raises(ValueError, match="bad peer"):
            node._send_to_peer(("a", "b", "c"), {})

    def test_send_to_peer_enforce_hello_pubkey(self, node, monkeypatch):
        """Test that env gets pubkey when ENFORCE_HELLO_PUBKEY is True."""
        monkeypatch.setattr("tsarchain.network.rpc_helper.chat.CFG.ENFORCE_HELLO_PUBKEY", True)
        monkeypatch.setattr("tsarchain.network.rpc_helper.chat.CFG.P2P_ENC_REQUIRED", False)

        mock_socket_instance = Mock()
        with patch('socket.socket') as mock_socket_class:
            mock_socket_class.return_value.__enter__.return_value = mock_socket_instance

            mock_build = Mock(return_value={"test": "env"})
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.build_envelope", mock_build)

            mock_send = Mock()
            mock_recv = Mock(return_value=b"ok")
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.send_message", mock_send)
            monkeypatch.setattr("tsarchain.network.rpc_helper.chat.recv_message", mock_recv)

            node._send_to_peer(("192.168.1.1", 8000), {"type": "TEST"})

        mock_build.assert_called_once_with({"type": "TEST"}, node.node_ctx, extra={"pubkey": node.pubkey})


class TestRelayPresence:

    def test_relay_presence_hops_ge_2(self, node):
        """If hops >= 2, function returns without broadcasting."""
        pres = {"hops": 2}
        node._relay_presence(pres, exclude=None)
        node.broadcast._broadcast.assert_not_called()

    def test_relay_presence_hops_lt_2(self, node):
        """If hops < 2, relay increments and broadcasts."""
        pres = {"hops": 0, "data": "hello"}
        node._relay_presence(pres, exclude="exclude_peer")
        expected = {"type": "CHAT_PRESENCE", "hops": 1, "data": "hello"}
        node.broadcast._broadcast.assert_called_once_with(node.peers, expected, exclude="exclude_peer")

    def test_relay_presence_no_hops(self, node):
        """If hops not present, treat as 0."""
        pres = {"data": "hello"}
        node._relay_presence(pres)
        expected = {"type": "CHAT_PRESENCE", "hops": 1, "data": "hello"}
        node.broadcast._broadcast.assert_called_once_with(node.peers, expected, exclude=None)

    def test_relay_presence_async(self, node, monkeypatch):
        """_relay_presence_async should start a daemon thread."""
        mock_thread = Mock()
        monkeypatch.setattr("tsarchain.network.rpc_helper.chat.threading.Thread", mock_thread)

        node._relay_presence_async({"hops": 0}, exclude="some")
        mock_thread.assert_called_once_with(target=node._relay_presence, args=({"hops": 0}, "some"), daemon=True)
        mock_thread.return_value.start.assert_called_once()


class TestMailbox:

    def test_mailbox_put_success(self, node, mock_time):
        """Put item when not full."""
        addr = "addr1"
        item = "msg"
        ttl = 10
        per_max = 5
        global_max = 10
        result = node._mailbox_put(addr, item, ttl, per_max, global_max)
        assert result is True
        assert addr in node.chat_mailbox
        dq = node.chat_mailbox[addr]
        assert len(dq) == 1
        exp, stored = dq[0]
        assert exp == 1000 + ttl
        assert stored == item
        assert node.chat_global_count == 1

    def test_mailbox_put_expired_prune(self, node):
        """Prune expired items before adding."""
        addr = "addr1"
        dq = collections.deque([(900, "old")])  # expired at 900, current time 1000
        node.chat_mailbox[addr] = dq
        node.chat_global_count = 1

        result = node._mailbox_put(addr, "new", 10, 5, 10)
        assert result is True
        assert len(dq) == 1
        assert dq[0][1] == "new"
        assert node.chat_global_count == 1  # removed old, added new -> net 1

    def test_mailbox_put_per_addr_full(self, node):
        """Fail when per-address limit reached."""
        addr = "addr1"
        per_max = 2
        for i in range(per_max):
            node._mailbox_put(addr, f"msg{i}", 10, per_max, 10)
        result = node._mailbox_put(addr, "extra", 10, per_max, 10)
        assert result is False
        assert len(node.chat_mailbox[addr]) == per_max
        assert node.chat_global_count == per_max

    def test_mailbox_put_global_full(self, node):
        """Fail when global queue limit reached."""
        addr1 = "addr1"
        addr2 = "addr2"
        global_max = 2
        node._mailbox_put(addr1, "msg1", 10, 10, global_max)
        node._mailbox_put(addr2, "msg2", 10, 10, global_max)
        result = node._mailbox_put("addr3", "msg3", 10, 10, global_max)
        assert result is False
        assert node.chat_global_count == 2

    def test_mailbox_pull(self, node):
        """Pull items from mailbox."""
        addr = "addr1"
        node._mailbox_put(addr, "msg1", 10, 10, 10)
        node._mailbox_put(addr, "msg2", 10, 10, 10)
        result = node._mailbox_pull(addr, 1)
        assert len(result) == 1
        assert result[0] == "msg1"
        dq = node.chat_mailbox[addr]
        assert len(dq) == 1
        assert dq[0][1] == "msg2"
        assert node.chat_global_count == 1  # one removed

    def test_mailbox_pull_expired_pruned(self, node, mock_time):
        """Pull should prune expired items and not return them."""
        addr = "addr1"
        dq = collections.deque([(900, "old"), (1100, "new")])
        node.chat_mailbox[addr] = dq
        node.chat_global_count = 2
        result = node._mailbox_pull(addr, 2)
        assert result == ["new"]
        assert len(dq) == 0
        assert node.chat_global_count == 0

    def test_mailbox_pull_empty(self, node):
        """Pull from empty mailbox returns empty list."""
        result = node._mailbox_pull("nonexistent", 5)
        assert result == []

    def test_enqueue_rcpt(self, node):
        """_enqueue_rcpt should call _mailbox_put with correct item."""
        node._mailbox_put = Mock(return_value=True)
        node._enqueue_rcpt("to_addr", "delivered", "mid123", "from_user", "to_user", 123456)
        expected_item = {
            "type": "CHAT_RCPT",
            "rcpt": "delivered",
            "msg_id": "mid123",
            "from": "from_user",
            "to": "to_user",
            "ts": 123456,
        }
        node._mailbox_put.assert_called_once_with(
            "to_addr", expected_item, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX
        )


class TestDedupMid:

    def test_dedup_mid_new(self, node):
        """New msg_id returns False and stores it."""
        addr = "addr1"
        msg_id = "123"
        assert node._dedup_mid(addr, msg_id) is False
        assert addr in node.chat_seen_mid
        dq, st = node.chat_seen_mid[addr]
        assert msg_id in st
        assert len(dq) == 1
        assert dq[0] == msg_id

    def test_dedup_mid_duplicate(self, node):
        """Duplicate msg_id returns True."""
        addr = "addr1"
        msg_id = "123"
        node._dedup_mid(addr, msg_id)  # first
        assert node._dedup_mid(addr, msg_id) is True

    def test_dedup_mid_maxlen_eviction(self, node):
        """When deque maxlen reached, oldest is discarded."""
        node.chat_seen_max = 2
        addr = "addr1"
        node._dedup_mid(addr, "1")
        node._dedup_mid(addr, "2")
        node._dedup_mid(addr, "3")
        dq, st = node.chat_seen_mid[addr]
        assert "1" not in st
        assert "2" in st
        assert "3" in st
        assert len(dq) == 2

    def test_dedup_mid_none(self, node):
        """msg_id None should return False and not store."""
        assert node._dedup_mid("addr", None) is False
        assert "addr" not in node.chat_seen_mid


class TestGcMailboxes:

    def test_gc_mailboxes_not_due(self, node, mock_time):
        """If last GC was less than 30s ago, skip."""
        node.chat_gc_last = 980  # current 1000, diff 20
        node._gc_mailboxes()
        assert node.chat_mailbox == {}
        assert node.backoff_until == {}
        assert node.chat_gc_last == 980

    def test_gc_mailboxes_due(self, node, mock_time):
        """GC removes expired items and cleans empty deques."""
        node.chat_gc_last = 900  # diff 100 > 30
        dq1 = collections.deque([(950, "old"), (1100, "new")])
        dq2 = collections.deque([(950, "old2")])  # all expired
        node.chat_mailbox["addr1"] = dq1
        node.chat_mailbox["addr2"] = dq2
        node.chat_global_count = 3
        node.backoff_until["peer1"] = 900  # expired
        node.backoff_until["peer2"] = 1100  # not expired
        node._gc_mailboxes()

        assert len(node.chat_mailbox["addr1"]) == 1
        assert node.chat_mailbox["addr1"][0][1] == "new"
        assert "addr2" not in node.chat_mailbox
        assert node.chat_global_count == 1
        assert "peer1" not in node.backoff_until
        assert "peer2" in node.backoff_until
        assert node.chat_gc_last == 1000

    def test_gc_mailboxes_removes_empty_deque(self, node):
        """If a deque becomes empty after pruning, remove the key."""
        node.chat_gc_last = 900
        dq = collections.deque([(950, "old")])  # expired
        node.chat_mailbox["addr"] = dq
        node.chat_global_count = 1
        node._gc_mailboxes()
        assert "addr" not in node.chat_mailbox
        assert node.chat_global_count == 0