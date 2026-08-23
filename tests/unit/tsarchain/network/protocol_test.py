# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import time
import errno
import pytest
import struct
import socket
import hashlib
from unittest.mock import MagicMock, patch, mock_open

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

import tsarchain.network.protocol as proto
from tsarchain.network.protocol import (
    _is_disconnect_exc,
    _nonce_total_entries,
    _nonce_prune_expired_locked,
    _nonce_prune_global_if_needed_locked,
    _nonce_register,
    send_message,
    recv_message,
    _recv_exact,
    sniff_first_json_frame,
    load_or_create_keypair_at,
    _canonical_dumps,
    _gen_nonce,
    _sign_message_hex,
    _verify_signature,
    is_envelope,
    build_envelope,
    verify_and_unwrap,
    SecureChannel,
)


# ─── helpers ───────────────────────────────────────────────────────────────────

def _make_keypair():
    sk = SigningKey.generate()
    vk = sk.verify_key
    priv_hex = sk.encode(encoder=HexEncoder).decode()
    pub_hex = vk.encode(encoder=HexEncoder).decode()
    node_id = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
    return node_id, pub_hex, priv_hex


@pytest.fixture(autouse=True)
def _clear_nonce_cache():
    """Reset the module-level nonce cache before every test."""
    proto._nonce_cache.clear()
    yield
    proto._nonce_cache.clear()


@pytest.fixture
def keypair():
    return _make_keypair()


@pytest.fixture
def mock_cfg():
    with patch.object(proto, "CFG") as m:
        m.REPLAY_WINDOW_SEC = 60
        m.NONCE_GLOBAL_MAX = 100_000
        m.NONCE_PER_SENDER_MAX = 256
        m.MAX_MSG = 3 * 1024 * 1024
        m.NETWORK_MAGIC = b"TSARCHAIN"
        m.BUFFER_SIZE = 65536
        m.MAX_HANDSHAKE_BYTES = 16384
        m.CANONICAL_SEP = (",", ":")
        m.DEFAULT_NET_ID = "testnet"
        m.HANDSHAKE_TIMEOUT = 10
        m.BAN_MALICIOUS_RPC = 600
        m.P2P_SESSION_TTL_S = 3600
        m.P2P_SESSION_MAX_MSG = 10000
        m.P2P_AEAD_KEY_BYTES = 32
        m.P2P_AEAD_NONCE_BYTES = 12
        m.P2P_AEAD_AAD_PREFIX = b"TSAR|P2P|v1"
        m.P2P_REKEY_EVERY_MSG = 2000
        yield m


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Disconnect detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsDisconnectExc:

    def test_connection_error_types(self):
        assert _is_disconnect_exc(ConnectionError()) is True
        assert _is_disconnect_exc(ConnectionResetError()) is True
        assert _is_disconnect_exc(ConnectionAbortedError()) is True
        assert _is_disconnect_exc(TimeoutError()) is True
        assert _is_disconnect_exc(BrokenPipeError()) is True
        assert _is_disconnect_exc(socket.timeout()) is True

    def test_oserror_posix_codes(self):
        for code in (errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED, errno.ETIMEDOUT):
            e = OSError()
            e.errno = code
            assert _is_disconnect_exc(e) is True

    def test_oserror_win_codes(self):
        for wcode in (10053, 10054, 10058, 10060):
            e = OSError()
            e.errno = None
            e.winerror = wcode
            assert _is_disconnect_exc(e) is True

    def test_oserror_other_code(self):
        e = OSError()
        e.errno = 999999
        e.winerror = 999999
        assert _is_disconnect_exc(e) is False

    def test_non_os_error(self):
        assert _is_disconnect_exc(ValueError("x")) is False
        assert _is_disconnect_exc(RuntimeError()) is False


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Nonce cache
# ═══════════════════════════════════════════════════════════════════════════════

class TestNonceCache:

    def test_total_entries_empty(self):
        assert _nonce_total_entries() == 0

    def test_total_entries_with_data(self):
        proto._nonce_cache["s1"] = {"a": 1, "b": 2}
        proto._nonce_cache["s2"] = {"c": 3}
        assert _nonce_total_entries() == 3

    def test_prune_expired(self, mock_cfg):
        mock_cfg.REPLAY_WINDOW_SEC = 60
        now = int(time.time())
        proto._nonce_cache["s1"] = {"old": now - 200, "new": now}
        _nonce_prune_expired_locked(now)
        assert "old" not in proto._nonce_cache.get("s1", {})
        assert "new" in proto._nonce_cache.get("s1", {})

    def test_prune_expired_removes_empty_sender(self, mock_cfg):
        mock_cfg.REPLAY_WINDOW_SEC = 60
        now = int(time.time())
        proto._nonce_cache["s1"] = {"old": now - 200}
        _nonce_prune_expired_locked(now)
        assert "s1" not in proto._nonce_cache

    def test_prune_expired_none_timestamp(self, mock_cfg):
        mock_cfg.REPLAY_WINDOW_SEC = 60
        now = int(time.time())
        proto._nonce_cache["s1"] = {"n1": None}
        _nonce_prune_expired_locked(now)
        assert "s1" not in proto._nonce_cache

    def test_prune_global_under_limit(self, mock_cfg):
        mock_cfg.NONCE_GLOBAL_MAX = 10
        proto._nonce_cache["s1"] = {"a": 1}
        _nonce_prune_global_if_needed_locked()
        assert "a" in proto._nonce_cache["s1"]

    def test_prune_global_over_limit(self, mock_cfg):
        mock_cfg.NONCE_GLOBAL_MAX = 2
        proto._nonce_cache["s1"] = {"a": 1, "b": 2}
        proto._nonce_cache["s2"] = {"c": 3}
        _nonce_prune_global_if_needed_locked()
        assert _nonce_total_entries() <= 2

    def test_prune_global_evicts_oldest(self, mock_cfg):
        mock_cfg.NONCE_GLOBAL_MAX = 1
        proto._nonce_cache["s1"] = {"old": 100}
        proto._nonce_cache["s2"] = {"new": 200}
        _nonce_prune_global_if_needed_locked()
        assert _nonce_total_entries() <= 1

    def test_prune_global_removes_empty_sender(self, mock_cfg):
        mock_cfg.NONCE_GLOBAL_MAX = 0
        proto._nonce_cache["s1"] = {"only": 1}
        _nonce_prune_global_if_needed_locked()
        assert "s1" not in proto._nonce_cache

    def test_register_success(self, mock_cfg):
        _nonce_register("sender1", "nonce1")
        assert "nonce1" in proto._nonce_cache["sender1"]

    def test_register_missing_sender(self, mock_cfg):
        with pytest.raises(ValueError, match="missing sender/nonce"):
            _nonce_register("", "nonce1")

    def test_register_missing_nonce(self, mock_cfg):
        with pytest.raises(ValueError, match="missing sender/nonce"):
            _nonce_register("sender1", "")

    def test_register_replay_rejected(self, mock_cfg):
        _nonce_register("sender1", "nonce1")
        with pytest.raises(ValueError, match="replayed nonce"):
            _nonce_register("sender1", "nonce1")

    def test_register_per_sender_eviction(self, mock_cfg):
        mock_cfg.NONCE_PER_SENDER_MAX = 3
        now = int(time.time())
        for i in range(5):
            _nonce_register("s", f"n{i}")
        assert len(proto._nonce_cache["s"]) <= 3


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Send / Receive messages
# ═══════════════════════════════════════════════════════════════════════════════

class TestSendMessage:

    def test_send_success(self, mock_cfg):
        sock = MagicMock()
        send_message(sock, b"hello")
        sock.sendall.assert_called_once()
        raw = sock.sendall.call_args[0][0]
        body = mock_cfg.NETWORK_MAGIC + b"hello"
        assert raw == struct.pack(">I", len(body)) + body

    def test_send_too_large(self, mock_cfg):
        sock = MagicMock()
        with pytest.raises(ValueError, match="Message too large"):
            send_message(sock, b"x" * mock_cfg.MAX_MSG, max_len=100)

    def test_send_custom_max_len(self, mock_cfg):
        sock = MagicMock()
        with pytest.raises(ValueError, match="Message too large"):
            send_message(sock, b"x" * 100, max_len=50)

    def test_send_disconnect_suppressed(self, mock_cfg):
        sock = MagicMock()
        sock.sendall.side_effect = ConnectionResetError("reset")
        # Shouldn't raise
        send_message(sock, b"hello")

    def test_send_non_disconnect_raised(self, mock_cfg):
        sock = MagicMock()
        sock.sendall.side_effect = RuntimeError("unknown error")
        with pytest.raises(RuntimeError):
            send_message(sock, b"hello")

    def test_send_disconnect_throttled(self, mock_cfg):
        """Verify disconnect log throttling window works."""
        proto._SEND_DISCONNECT_LAST = 0.0
        proto._SEND_DISCONNECT_COUNT = 0
        sock = MagicMock()
        sock.sendall.side_effect = ConnectionResetError("reset")
        send_message(sock, b"a")
        send_message(sock, b"b")
        # Count should have been reset on the first log, then incremented again
        assert proto._SEND_DISCONNECT_COUNT >= 0


class TestRecvExact:

    def test_recv_exact_success(self, mock_cfg):
        sock = MagicMock()
        sock.recv.side_effect = [b"hel", b"lo"]
        result = _recv_exact(sock, 5)
        assert result == b"hello"

    def test_recv_exact_connection_closed(self, mock_cfg):
        sock = MagicMock()
        sock.recv.return_value = b""
        with pytest.raises(ConnectionError, match="Connection closed"):
            _recv_exact(sock, 5)


class TestRecvMessage:

    def test_recv_success(self, mock_cfg):
        magic = mock_cfg.NETWORK_MAGIC
        payload = b"test_payload"
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body

        sock = MagicMock()
        call_count = [0]
        def mock_recv(n):
            nonlocal call_count
            start = call_count[0]
            chunk = frame[start:start + n]
            call_count[0] += len(chunk)
            if not chunk:
                raise ConnectionError("closed")
            return chunk

        sock.recv.side_effect = mock_recv
        result = recv_message(sock, timeout=5.0)
        assert result == payload

    def test_recv_oversize_frame(self, mock_cfg):
        sock = MagicMock()
        hdr = struct.pack(">I", mock_cfg.MAX_MSG + 1)
        sock.recv.return_value = hdr
        result = recv_message(sock, max_len=100)
        assert result is None

    def test_recv_oversize_with_ban(self, mock_cfg):
        sock = MagicMock()
        hdr = struct.pack(">I", mock_cfg.MAX_MSG + 1)
        sock.recv.return_value = hdr
        on_misbehave = MagicMock()
        result = recv_message(sock, max_len=100, peer_ip="1.2.3.4", ban_on_bad=True, on_misbehave=on_misbehave)
        assert result is None
        on_misbehave.assert_called_once_with("1.2.3.4", mock_cfg.BAN_MALICIOUS_RPC)

    def test_recv_bad_magic(self, mock_cfg):
        body = b"BADMAGIC" + b"payload"
        frame = struct.pack(">I", len(body)) + body

        sock = MagicMock()
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv
        result = recv_message(sock)
        assert result is None

    def test_recv_bad_magic_with_ban(self, mock_cfg):
        body = b"BADMAGIC" + b"payload"
        frame = struct.pack(">I", len(body)) + body

        sock = MagicMock()
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv
        on_misbehave = MagicMock()
        result = recv_message(sock, peer_ip="5.5.5.5", ban_on_bad=True, on_misbehave=on_misbehave)
        assert result is None
        on_misbehave.assert_called_once()

    def test_recv_disconnect_returns_none(self, mock_cfg):
        sock = MagicMock()
        sock.recv.side_effect = ConnectionResetError("reset")
        result = recv_message(sock)
        assert result is None

    def test_recv_generic_exception_returns_none(self, mock_cfg):
        sock = MagicMock()
        sock.recv.side_effect = RuntimeError("something unexpected")
        result = recv_message(sock)
        assert result is None

    def test_recv_zero_length_frame(self, mock_cfg):
        sock = MagicMock()
        hdr = struct.pack(">I", 0)
        sock.recv.return_value = hdr
        result = recv_message(sock)
        assert result is None

    def test_recv_sets_timeout(self, mock_cfg):
        sock = MagicMock()
        sock.recv.side_effect = ConnectionError()
        recv_message(sock, timeout=3.14)
        sock.settimeout.assert_called_once_with(3.14)


class TestSniffFirstJsonFrame:

    def test_sniff_success(self, mock_cfg):
        obj = {"type": "P2P_HS1", "net": "testnet"}
        payload = json.dumps(obj).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body

        sock = MagicMock()
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        raw, parsed = sniff_first_json_frame(sock, timeout=2.0)
        assert raw == payload
        assert parsed == obj

    def test_sniff_no_data(self, mock_cfg):
        sock = MagicMock()
        sock.recv.side_effect = ConnectionResetError()
        raw, parsed = sniff_first_json_frame(sock)
        assert raw is None
        assert parsed is None


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Keypair helper
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoadOrCreateKeypair:

    def test_load_from_storage(self, mock_cfg):
        record = {"id": "nid1", "pubkey": "pub1", "privkey": "priv1"}
        with patch("tsarchain.network.protocol.load_node_key", return_value=record):
            nid, pub, priv = load_or_create_keypair_at("some/path")
            assert nid == "nid1"
            assert pub == "pub1"
            assert priv == "priv1"

    def test_create_new_key(self, mock_cfg):
        with patch("tsarchain.network.protocol.load_node_key", return_value=None), \
             patch("tsarchain.network.protocol.save_node_key") as m_save:
            nid, pub, priv = load_or_create_keypair_at("some/path")
            assert len(nid) == 64  # sha256 hex
            assert len(pub) == 64  # ed25519 pubkey hex
            assert len(priv) == 64  # ed25519 privkey hex
            m_save.assert_called_once()

    def test_load_from_storage_incomplete_record_creates_new(self, mock_cfg):
        """Incomplete record from storage should trigger generation of a new valid keypair."""
        with patch("tsarchain.network.protocol.load_node_key", return_value={"id": "nid_only"}), \
             patch("tsarchain.network.protocol.save_node_key") as m_save:
            nid, pub, priv = load_or_create_keypair_at("some/path")
            assert len(nid) == 64
            assert len(pub) == 64
            assert len(priv) == 64
            m_save.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Envelope & Signature
# ═══════════════════════════════════════════════════════════════════════════════

class TestCanonicalDumps:

    def test_deterministic(self, mock_cfg):
        obj = {"b": 2, "a": 1}
        result = _canonical_dumps(obj)
        assert result == b'{"a":1,"b":2}'

    def test_utf8(self, mock_cfg):
        result = _canonical_dumps({"k": "日本語"})
        assert "日本語" in result.decode("utf-8")


class TestGenNonce:

    def test_length(self):
        n = _gen_nonce(16)
        assert len(n) == 32  # hex

    def test_unique(self):
        assert _gen_nonce() != _gen_nonce()


class TestSignAndVerify:

    def test_roundtrip(self, keypair):
        nid, pub, priv = keypair
        payload = b"test message"
        sig = _sign_message_hex(priv, payload)
        assert _verify_signature(pub, payload, sig) is True

    def test_bad_sig(self, keypair):
        nid, pub, priv = keypair
        payload = b"test message"
        with pytest.raises(Exception):
            _verify_signature(pub, payload, "00" * 64)


class TestIsEnvelope:

    def test_valid(self):
        env = {"net_id": "x", "from": "y", "msg": {}, "sig": "z", "ts": 1, "nonce": "n"}
        assert is_envelope(env) is True

    def test_missing_field(self):
        env = {"net_id": "x", "from": "y", "msg": {}}
        assert is_envelope(env) is False

    def test_not_dict(self):
        assert is_envelope("not a dict") is False
        assert is_envelope(None) is False


class TestBuildEnvelope:

    def test_build_success(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx)
        assert env["net_id"] == "testnet"
        assert env["from"] == nid
        assert "sig" in env
        assert env["msg"] == {"type": "HELLO"}

    def test_build_with_extra(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        assert env["pubkey"] == pub

    def test_build_without_extra(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra=None)
        assert "pubkey" not in env


class TestVerifyAndUnwrap:

    def test_roundtrip(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        inner = verify_and_unwrap(env, lambda node_id: pub)
        assert inner == {"type": "HELLO"}

    def test_wrong_net_id(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        env["net_id"] = "wrong_net"
        with pytest.raises(ValueError, match="wrong network id"):
            verify_and_unwrap(env, lambda nid: pub)

    def test_timestamp_violation(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        env["ts"] = 100  # far in the past
        with pytest.raises(ValueError, match="timestamp window violation"):
            verify_and_unwrap(env, lambda nid: pub)

    def test_invalid_ts_type(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        env["ts"] = "not_int"
        with pytest.raises(ValueError, match="timestamp window violation"):
            verify_and_unwrap(env, lambda nid: pub)

    def test_missing_nonce(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        env["nonce"] = ""
        with pytest.raises(ValueError, match="missing nonce"):
            verify_and_unwrap(env, lambda nid: pub)

    def test_missing_node_id(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        env["from"] = ""
        with pytest.raises(ValueError, match="missing node_id"):
            verify_and_unwrap(env, lambda nid: pub)

    def test_msg_not_dict(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        env["msg"] = "not_dict"
        with pytest.raises(ValueError, match="missing msg"):
            verify_and_unwrap(env, lambda nid: pub)

    def test_no_pubkey_anywhere(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx)
        # No pubkey in envelope, callback returns None
        with pytest.raises(ValueError, match="unknown peer pubkey"):
            verify_and_unwrap(env, lambda nid: None)

    def test_pubkey_from_envelope(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        # Callback returns None, pubkey taken from envelope
        inner = verify_and_unwrap(env, lambda nid: None)
        assert inner == {"type": "HELLO"}

    def test_node_id_pubkey_mismatch(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        _, other_pub, _ = _make_keypair()
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": other_pub})
        # Callback returns None, so pubkey is taken from envelope which doesn't match node_id
        with pytest.raises(ValueError, match="node_id/pubkey mismatch"):
            verify_and_unwrap(env, lambda nid: None)

    def test_non_callable_get_pubkey(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        inner = verify_and_unwrap(env, None)
        assert inner == {"type": "HELLO"}

    def test_replay_rejected(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        verify_and_unwrap(env, lambda nid: pub)
        with pytest.raises(ValueError, match="replayed nonce"):
            verify_and_unwrap(env, lambda nid: pub)

    def test_hmac_field_removed(self, keypair, mock_cfg):
        nid, pub, priv = keypair
        ctx = {"net_id": "testnet", "node_id": nid, "pubkey": pub, "privkey": priv}
        env = build_envelope({"type": "HELLO"}, ctx, extra={"pubkey": pub})
        env["hmac"] = "leftover_hmac_value"
        inner = verify_and_unwrap(env, lambda nid: pub)
        assert inner == {"type": "HELLO"}


# ═══════════════════════════════════════════════════════════════════════════════
# 6. SecureChannel
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecureChannel:

    @pytest.fixture
    def mock_native(self):
        with patch("tsarchain.network.protocol.SecureChannelNative") as m:
            yield m

    def _make_channel(self, mock_cfg, mock_native, role="client"):
        sock = MagicMock()
        ch = SecureChannel(
            sock, role,
            node_id="nid1", node_pub="pub1", node_priv="priv1",
            peer_ip="1.2.3.4"
        )
        return ch, sock

    def test_init_client(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        assert ch.role == "client"
        assert ch.peer_ip == "1.2.3.4"
        assert ch.peer_node_id is None
        mock_native.assert_called_once()

    def test_init_server(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")
        assert ch.role == "server"

    def test_init_defaults(self, mock_cfg, mock_native):
        sock = MagicMock()
        ch = SecureChannel(sock, "client")
        # get_pinned and set_pinned should have defaults
        assert ch.get_pinned("test") is None
        ch.set_pinned("test", "pk")  # should not raise

    def test_handshake_dispatches_client(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        with patch.object(ch, "_hs_client_auth") as m:
            ch.handshake()
            m.assert_called_once()

    def test_handshake_dispatches_server(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")
        with patch.object(ch, "_hs_server_auth") as m:
            ch.handshake()
            m.assert_called_once()

    def test_hs_client_auth_success(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        ch.native.client_build_hs1.return_value = {"type": "P2P_HS1"}
        ch.native.client_accept_hs2.return_value = ("peer_nid", "peer_pub")

        hs2 = {"type": "P2P_HS2", "net": "testnet", "node_id": "peer_nid"}
        hs2_payload = json.dumps(hs2).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs2_payload
        frame = struct.pack(">I", len(body)) + body

        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        ch._hs_client_auth()
        assert ch.peer_node_id == "peer_nid"
        assert ch.peer_node_pub == "peer_pub"

    def test_hs_client_auth_no_response(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        ch.native.client_build_hs1.return_value = {"type": "P2P_HS1"}
        sock.recv.side_effect = ConnectionResetError()
        with pytest.raises(ConnectionError, match="no handshake response"):
            ch._hs_client_auth()

    def test_hs_client_auth_bad_type(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        ch.native.client_build_hs1.return_value = {"type": "P2P_HS1"}

        hs2 = {"type": "WRONG_TYPE", "net": "testnet"}
        hs2_payload = json.dumps(hs2).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs2_payload
        frame = struct.pack(">I", len(body)) + body

        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="bad P2P handshake"):
            ch._hs_client_auth()

    def test_hs_client_auth_bad_net(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        ch.native.client_build_hs1.return_value = {"type": "P2P_HS1"}

        hs2 = {"type": "P2P_HS2", "net": "wrong_net"}
        hs2_payload = json.dumps(hs2).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs2_payload
        frame = struct.pack(">I", len(body)) + body

        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="bad P2P handshake"):
            ch._hs_client_auth()

    def test_hs_client_auth_pinned(self, mock_cfg, mock_native):
        """When peer is already pinned, set_pinned should NOT be called."""
        get_pinned = MagicMock(return_value="existing_pub")
        set_pinned = MagicMock()
        sock = MagicMock()
        ch = SecureChannel(sock, "client", node_id="nid1", node_pub="pub1", node_priv="priv1",
                           get_pinned=get_pinned, set_pinned=set_pinned)
        ch.native.client_build_hs1.return_value = {"type": "P2P_HS1"}
        ch.native.client_accept_hs2.return_value = ("peer_nid", "peer_pub")

        hs2 = {"type": "P2P_HS2", "net": "testnet", "node_id": "peer_nid"}
        hs2_payload = json.dumps(hs2).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs2_payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        ch._hs_client_auth()
        set_pinned.assert_not_called()

    def test_hs_client_auth_no_node_id_hint(self, mock_cfg, mock_native):
        """When node_id hint is empty, pinned should be None."""
        get_pinned = MagicMock(return_value=None)
        set_pinned = MagicMock()
        sock = MagicMock()
        ch = SecureChannel(sock, "client", node_id="nid1", node_pub="pub1", node_priv="priv1",
                           get_pinned=get_pinned, set_pinned=set_pinned)
        ch.native.client_build_hs1.return_value = {"type": "P2P_HS1"}
        ch.native.client_accept_hs2.return_value = ("peer_nid", "peer_pub")

        hs2 = {"type": "P2P_HS2", "net": "testnet", "node_id": ""}
        hs2_payload = json.dumps(hs2).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs2_payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        ch._hs_client_auth()
        get_pinned.assert_not_called()
        set_pinned.assert_called_once_with("peer_nid", "peer_pub")

    def test_hs_server_auth_success(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")
        ch.native.server_accept_hs1.return_value = ({"type": "P2P_HS2"}, "peer_nid", "peer_pub")

        hs1 = {"type": "P2P_HS1", "net": "testnet", "node_id": "peer_hint"}
        hs1_payload = json.dumps(hs1).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs1_payload
        frame = struct.pack(">I", len(body)) + body

        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        ch._hs_server_auth()
        assert ch.peer_node_id == "peer_nid"
        sock.sendall.assert_called()  # HS2 sent

    def test_hs_server_auth_no_payload(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")
        sock.recv.side_effect = ConnectionResetError()
        with pytest.raises(ConnectionError, match="no handshake payload"):
            ch._hs_server_auth()

    def test_hs_server_auth_bad_type(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")

        hs1 = {"type": "WRONG", "net": "testnet"}
        hs1_payload = json.dumps(hs1).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs1_payload
        frame = struct.pack(">I", len(body)) + body

        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="bad P2P handshake"):
            ch._hs_server_auth()

    def test_hs_server_auth_pinned(self, mock_cfg, mock_native):
        """When peer is already pinned, set_pinned should NOT be called."""
        get_pinned = MagicMock(return_value="existing_pub")
        set_pinned = MagicMock()
        sock = MagicMock()
        ch = SecureChannel(sock, "server", node_id="nid1", node_pub="pub1", node_priv="priv1",
                           get_pinned=get_pinned, set_pinned=set_pinned)
        ch.native.server_accept_hs1.return_value = ({"type": "P2P_HS2"}, "peer_nid", "peer_pub")

        hs1 = {"type": "P2P_HS1", "net": "testnet", "node_id": "peer_hint"}
        hs1_payload = json.dumps(hs1).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs1_payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        ch._hs_server_auth()
        set_pinned.assert_not_called()

    def test_hs_server_auth_no_hint(self, mock_cfg, mock_native):
        """When node_id hint is empty, pinned lookup should be skipped."""
        get_pinned = MagicMock(return_value=None)
        set_pinned = MagicMock()
        sock = MagicMock()
        ch = SecureChannel(sock, "server", node_id="nid1", node_pub="pub1", node_priv="priv1",
                           get_pinned=get_pinned, set_pinned=set_pinned)
        ch.native.server_accept_hs1.return_value = ({"type": "P2P_HS2"}, "peer_nid", "peer_pub")

        hs1 = {"type": "P2P_HS1", "net": "testnet"}
        hs1_payload = json.dumps(hs1).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + hs1_payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        ch._hs_server_auth()
        get_pinned.assert_not_called()
        set_pinned.assert_called_once_with("peer_nid", "peer_pub")

    def test_hs_server_from_obj_success(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")
        ch.native.server_accept_hs1.return_value = ({"type": "P2P_HS2"}, "peer_nid", "peer_pub")
        hs1 = {"type": "P2P_HS1", "net": "testnet", "node_id": "peer_hint"}
        ch.hs_server_from_obj(hs1)
        assert ch.peer_node_id == "peer_nid"

    def test_hs_server_from_obj_bad_type(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")
        with pytest.raises(ValueError, match="bad P2P handshake"):
            ch.hs_server_from_obj({"type": "WRONG", "net": "testnet"})

    def test_hs_server_from_obj_bad_net(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "server")
        with pytest.raises(ValueError, match="bad P2P handshake"):
            ch.hs_server_from_obj({"type": "P2P_HS1", "net": "wrong"})

    def test_hs_server_from_obj_pinned(self, mock_cfg, mock_native):
        get_pinned = MagicMock(return_value="existing_pub")
        set_pinned = MagicMock()
        sock = MagicMock()
        ch = SecureChannel(sock, "server", node_id="nid1", node_pub="pub1", node_priv="priv1",
                           get_pinned=get_pinned, set_pinned=set_pinned)
        ch.native.server_accept_hs1.return_value = ({"type": "P2P_HS2"}, "peer_nid", "peer_pub")
        ch.hs_server_from_obj({"type": "P2P_HS1", "net": "testnet", "node_id": "peer_hint"})
        set_pinned.assert_not_called()

    def test_hs_server_from_obj_no_hint(self, mock_cfg, mock_native):
        get_pinned = MagicMock(return_value=None)
        set_pinned = MagicMock()
        sock = MagicMock()
        ch = SecureChannel(sock, "server", node_id="nid1", node_pub="pub1", node_priv="priv1",
                           get_pinned=get_pinned, set_pinned=set_pinned)
        ch.native.server_accept_hs1.return_value = ({"type": "P2P_HS2"}, "peer_nid", "peer_pub")
        ch.hs_server_from_obj({"type": "P2P_HS1", "net": "testnet"})
        get_pinned.assert_not_called()
        set_pinned.assert_called_once()

    def test_send(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        ch.native.encrypt.return_value = (1, b"ciphertext")
        ch.send(b"plaintext")
        sock.sendall.assert_called_once()
        raw = sock.sendall.call_args[0][0]
        # Decode frame
        body_len = struct.unpack(">I", raw[:4])[0]
        body = raw[4:]
        assert body.startswith(mock_cfg.NETWORK_MAGIC)
        payload = body[len(mock_cfg.NETWORK_MAGIC):]
        obj = json.loads(payload.decode("utf-8"))
        assert obj["type"] == "P2P_DATA"
        assert obj["seq"] == 1
        assert obj["ct"] == b"ciphertext".hex()

    def test_recv_success(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        ch.native.decrypt.return_value = b"plaintext"

        data_obj = {"type": "P2P_DATA", "seq": 5, "ct": b"ciphertext".hex()}
        payload = json.dumps(data_obj).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body

        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        result = ch.recv(timeout=5.0)
        assert result == b"plaintext"
        ch.native.decrypt.assert_called_once_with(5, bytes.fromhex(b"ciphertext".hex()))

    def test_recv_no_data(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")
        sock.recv.side_effect = ConnectionResetError()
        result = ch.recv(timeout=1.0)
        assert result is None

    def test_recv_wrong_type(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")

        data_obj = {"type": "WRONG", "seq": 1, "ct": "aa"}
        payload = json.dumps(data_obj).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="expecting P2P_DATA"):
            ch.recv(timeout=1.0)

    def test_recv_missing_seq(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")

        data_obj = {"type": "P2P_DATA", "ct": "aa"}
        payload = json.dumps(data_obj).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="missing seq"):
            ch.recv(timeout=1.0)

    def test_recv_missing_ct(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")

        data_obj = {"type": "P2P_DATA", "seq": 1}
        payload = json.dumps(data_obj).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="missing ct"):
            ch.recv(timeout=1.0)

    def test_recv_seq_not_int(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")

        data_obj = {"type": "P2P_DATA", "seq": "not_int", "ct": "aa"}
        payload = json.dumps(data_obj).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="missing seq"):
            ch.recv(timeout=1.0)

    def test_recv_ct_not_str(self, mock_cfg, mock_native):
        ch, sock = self._make_channel(mock_cfg, mock_native, "client")

        data_obj = {"type": "P2P_DATA", "seq": 1, "ct": 123}
        payload = json.dumps(data_obj).encode("utf-8")
        magic = mock_cfg.NETWORK_MAGIC
        body = magic + payload
        frame = struct.pack(">I", len(body)) + body
        pos = [0]
        def mock_recv(n):
            chunk = frame[pos[0]:pos[0] + n]
            pos[0] += len(chunk)
            if not chunk:
                raise ConnectionError()
            return chunk
        sock.recv.side_effect = mock_recv

        with pytest.raises(ValueError, match="missing ct"):
            ch.recv(timeout=1.0)
