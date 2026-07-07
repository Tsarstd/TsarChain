# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
import time
from unittest.mock import MagicMock, patch, ANY

from kremlin.security.chat.triple_xdh import ChatManager
from tsarchain.utils import config as CFG

# ---------- Constants ----------
# X25519 private/public keys: 32 bytes -> 64 hex chars
VALID_CHAT_PRIV_HEX = "00" * 32
VALID_CHAT_PUB_HEX = "00" * 32          # 64 hex for X25519

VALID_SPEND_PUB_HEX = "02" + "00" * 32  # 2 + 64 = 66 chars

# ---------- Fixtures ----------

@pytest.fixture
def mock_common():
    with patch("kremlin.security.chat.triple_xdh.COM") as mock:
        mock.canon.side_effect = lambda x: x.strip().lower()
        mock.hkdf.return_value = b"fake_hkdf_output"
        mock.hkdf_ck.return_value = (b"new_ck", b"new_mk")
        mock.hkdf_rk.return_value = (b"new_rk", b"new_ck")
        mock.build_aad_bytes.return_value = b"fake_aad"
        mock.pack.return_value = b"packed_text"
        mock.unpack.return_value = "unpacked_text"
        mock.sign.return_value = "00" * 64
        mock.pub_hex_from_priv.return_value = VALID_SPEND_PUB_HEX
        mock.ec_priv_from_hex.return_value = b"\x00" * 32
        mock.load_or_create_chat_dh_key.return_value = (VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX)
        mock.get_prekey_inventory.return_value = {"opk_queue": "5", "created": str(int(time.time()))}
        mock.rotate_signed_prekey.return_value = None
        mock.add_one_time_prekeys.return_value = None
        mock.get_prekey_bundle_local.return_value = {
            "ik": VALID_CHAT_PRIV_HEX,
            "spk": VALID_CHAT_PRIV_HEX,
            "sig": "00" * 64,
            "opk": VALID_CHAT_PRIV_HEX,
        }
        mock.ensure_signed_prekey.return_value = None
        mock.consume_opk_priv.return_value = VALID_CHAT_PRIV_HEX
        mock.get_local_prekeys_for_recv.return_value = {"spk_sk": VALID_CHAT_PRIV_HEX}
        mock.load_chat_session.return_value = None
        mock.store_chat_session.return_value = None
        mock.delete_chat_session.return_value = None
        yield mock


@pytest.fixture
def mock_wallet():
    with patch("kremlin.security.chat.triple_xdh.Wallet") as mock:
        mock.unlock.return_value = {"private_key": VALID_CHAT_PRIV_HEX}
        yield mock


@pytest.fixture
def mock_rpc():
    return MagicMock()


@pytest.fixture
def mock_password_prompt():
    return MagicMock(return_value="test_password")


@pytest.fixture
def chat_manager(mock_rpc, mock_password_prompt):
    with patch.object(CFG, "CHAT_SESSION_DIR", "/tmp/chat_sessions"):
        mgr = ChatManager(
            rpc_send=mock_rpc,
            password_prompt_cb=mock_password_prompt,
            key_ttl_sec=3600,
        )
        # Reset internal caches
        mgr.priv_cache = {}
        mgr.pub_cache = {}
        mgr._chat_dh_cache = {}
        mgr._pwd_cache = {}
        mgr._last_prekey_publish = {}
        mgr._last_inventory_check = {}
        mgr._prekey_bundle_cache = {}
        mgr._sessions = {}
        mgr._pending_used_opk = {}
        mgr._registered_addrs = set()
        # Mock internal methods to avoid side effects
        mgr._ensure_prekey_inventory = MagicMock()
        mgr._can_publish_prekeys = MagicMock(wraps=mgr._can_publish_prekeys)
        return mgr


# ---------- Tests ----------

def test_init(chat_manager):
    assert chat_manager.key_ttl_sec == 3600
    assert chat_manager.priv_cache == {}
    assert chat_manager.pub_cache == {}
    assert chat_manager._sessions == {}
    assert chat_manager._registered_addrs == set()
    assert chat_manager.on_partner_key_changed is None
    assert chat_manager.on_partner_presence is None


def test_get_priv_for_chat_miss_prompt(chat_manager, mock_wallet):
    addr = "bob@example.com"
    result = chat_manager.get_priv_for_chat(addr)
    assert result == VALID_CHAT_PRIV_HEX
    mock_wallet.unlock.assert_called_once_with("test_password", addr)
    assert addr in chat_manager.priv_cache
    assert chat_manager.priv_cache[addr][0] == VALID_CHAT_PRIV_HEX


def test_try_unlock_success(chat_manager, mock_wallet):
    addr = "charlie@example.com"
    priv, err = chat_manager.try_unlock(addr)
    assert priv == VALID_CHAT_PRIV_HEX
    assert err is None
    assert addr in chat_manager.priv_cache
    assert addr in chat_manager._pwd_cache


def test_try_unlock_cancelled(chat_manager, mock_wallet):
    chat_manager.password_prompt_cb = MagicMock(return_value=None)
    addr = "dave@example.com"
    priv, err = chat_manager.try_unlock(addr)
    assert priv is None
    assert err == "cancelled"
    mock_wallet.unlock.assert_not_called()


def test_lookup_pub_cache_hit(chat_manager):
    addr = "eve@example.com"
    pub = "pub_cached"
    chat_manager.pub_cache[addr] = pub
    cb = MagicMock()
    chat_manager.lookup_pub(addr, cb)
    cb.assert_called_once_with(pub)
    # No RPC call should be made
    chat_manager.rpc_send.assert_not_called()


def test_lookup_pub_cache_miss(chat_manager):
    addr = "frank@example.com"
    cb = MagicMock()
    chat_manager.lookup_pub(addr, cb)
    # RPC call should be sent
    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    assert payload["type"] == "CHAT_LOOKUP_PUB"
    assert payload["address"] == addr

    # Simulate RPC response
    resp = {"type": "CHAT_PUBKEY", "pubkey": "pub_from_rpc", "last_seen": 12345}
    cb_rpc(resp)
    cb.assert_called_once_with("pub_from_rpc")
    assert chat_manager.pub_cache[addr] == "pub_from_rpc"
    assert chat_manager.presence_ts[addr] == 12345


def test_ensure_session_bad_signature(chat_manager, mock_wallet, mock_common):
    me = "alice@example.com"
    peer = "bob@example.com"
    cb = MagicMock()

    # Ensure we have a chat DH key
    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))

    with patch("kremlin.security.chat.triple_xdh.ec.EllipticCurvePublicKey") as mock_ec:
        mock_vk = MagicMock()
        mock_vk.verify = MagicMock(side_effect=Exception("bad signature"))
        mock_ec.from_encoded_point.return_value = mock_vk

        chat_manager.ensure_session(me, peer, cb)

        # Trigger RPC response
        chat_manager.rpc_send.assert_called_once()
        args, kwargs = chat_manager.rpc_send.call_args
        payload, cb_rpc = args
        bundle_resp = {
            "type": "CHAT_PREKEY_BUNDLE",
            "bundle": {
                "ik": "ik_hex",
                "spk": "spk_hex",
                "opk": "opk_hex",
                "spend_pub": VALID_SPEND_PUB_HEX,
                "sig": "sig_hex",
            }
        }
        cb_rpc(bundle_resp)

        cb.assert_called_once_with("bundle_spk_verify_failed")
        # No session should be created
        assert (me, peer) not in chat_manager._sessions


def test_poll_receive_message(chat_manager, mock_common):
    me = "alice@example.com"
    n = 5
    on_items = MagicMock()
    on_done = MagicMock()

    # Mock get_priv_for_chat to succeed
    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)

    # Mock session handling: return an existing session for the sender
    mock_sess = MagicMock()
    mock_sess.decrypt.return_value = b"Hello Alice"
    chat_manager._get_session = MagicMock(return_value=mock_sess)

    # Mock _ensure_prekey_inventory to do nothing
    chat_manager._ensure_prekey_inventory = MagicMock()

    # Call poll
    chat_manager.poll(me, n, on_items, on_done)

    # Should send CHAT_PULL RPC
    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    assert payload["type"] == "CHAT_PULL"
    assert payload["address"] == me

    # Simulate response with one message
    items_resp = {
        "type": "CHAT_ITEMS",
        "items": [
            {
                "type": "CHAT_ITEM",
                "from": "bob@example.com",
                "from_pub": "eph_hex",
                "from_static": "static_hex",
                "msg_id": 123,
                "ts": 12345,
                "enc": {"nonce": "nonce", "ct": "ct"},
                "ratchet_pn": 0,
                "ratchet_n": 0,
            }
        ]
    }
    cb_rpc(items_resp)

    on_items.assert_called_once_with([
        {
            "type": "chat",
            "from": "bob@example.com",
            "text": "unpacked_text",  # because mock_common.unpack returns that
            "msg_id": 123,
            "ts": 12345,
            "to": me,
        }
    ])
    on_done.assert_called_once_with(items_resp)
    # Decrypt should have been called with the header
    mock_sess.decrypt.assert_called_once()


def test_publish_prekeys_cooldown(chat_manager):
    addr = "alice@example.com"
    chat_manager._last_prekey_publish[addr] = time.time()  # just now
    chat_manager._can_publish_prekeys.return_value = False
    on_done = MagicMock()
    chat_manager.publish_prekeys(addr, on_done)
    on_done.assert_called_once_with({"skipped": "cooldown"})
    # No RPC call should be made
    chat_manager.rpc_send.assert_not_called()


def test_session_persistence(chat_manager, mock_common):
    me = "alice@example.com"
    peer = "bob@example.com"
    key = (me, peer)

    # Mock load_chat_session to return a serialized session
    mock_common.load_chat_session.return_value = {
        "rk": "00"*32,
        "cks": "00"*32,
        "ckr": "00"*32,
        "dhs": "dhs_serialized",
        "dhr": "dhr_hex",
        "ns": 0,
        "nr": 0,
        "pn": 0,
        "skipped": {},
        "my_identity": "my_id",
        "their_identity": "their_id",
        "my_static_hex": "static_hex",
        "needs_send_rotation": False,
    }

    # Patch RatchetSession.from_dict to return a mock
    with patch("kremlin.security.chat.triple_xdh.RatchetSession") as mock_rs:
        mock_session = MagicMock()
        mock_rs.from_dict.return_value = mock_session

        sess = chat_manager._get_session(me, peer)
        assert sess == mock_session
        # Should be stored in memory
        assert key in chat_manager._sessions

        # Now test persistence on send_message (via _persist_session)
        chat_manager._persist_session(me, peer, mock_session)
        mock_common.store_chat_session.assert_called_once_with(me, peer, ANY, ANY)


# --- X3DH Handshake ---
def test_ensure_session_success_without_opk(chat_manager, mock_common):
    me, peer = "alice@example.com", "bob@example.com"
    cb = MagicMock()

    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))

    with patch("kremlin.security.chat.triple_xdh.ec.EllipticCurvePublicKey") as mock_ec:
        mock_vk = MagicMock()
        mock_vk.verify = MagicMock(return_value=None)
        mock_ec.from_encoded_point.return_value = mock_vk

        with patch("kremlin.security.chat.triple_xdh.x25519.X25519PrivateKey") as mock_x:
            mock_eph = MagicMock()
            mock_eph.public_key.return_value.public_bytes.return_value.hex.return_value = "eph_pub_hex"
            mock_x.generate.return_value = mock_eph

            mock_priv = MagicMock()
            mock_priv.exchange.return_value = b"dh_secret" * 4
            mock_x.from_private_bytes.return_value = mock_priv

            with patch("kremlin.security.chat.triple_xdh.HKDF") as mock_hkdf:
                mock_hkdf.return_value.derive.return_value = b"root_key_32_bytes"
                with patch("kremlin.security.chat.triple_xdh.RatchetSession") as mock_rs:
                    mock_session = MagicMock()
                    mock_rs.init_as_initiator.return_value = mock_session

                    chat_manager.ensure_session(me, peer, cb)

                    chat_manager.rpc_send.assert_called_once()
                    args, kwargs = chat_manager.rpc_send.call_args
                    payload, cb_rpc = args
                    bundle_resp = {
                        "type": "CHAT_PREKEY_BUNDLE",
                        "bundle": {
                            "ik": VALID_CHAT_PRIV_HEX,
                            "spk": VALID_CHAT_PRIV_HEX,
                            "spend_pub": VALID_SPEND_PUB_HEX,
                            "sig": "00" * 64,
                        }
                    }
                    cb_rpc(bundle_resp)

                    assert (me, peer) in chat_manager._sessions
                    assert chat_manager._sessions[(me, peer)] == mock_session
                    mock_common.store_chat_session.assert_called_once()
                    cb.assert_called_once_with(None)
                    assert (me, peer) not in chat_manager._pending_used_opk


def test_ensure_session_success_with_opk(chat_manager, mock_common):
    me, peer = "alice@example.com", "bob@example.com"
    cb = MagicMock()

    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))

    with patch("kremlin.security.chat.triple_xdh.ec.EllipticCurvePublicKey") as mock_ec:
        mock_vk = MagicMock()
        mock_vk.verify = MagicMock(return_value=None)
        mock_ec.from_encoded_point.return_value = mock_vk

        with patch("kremlin.security.chat.triple_xdh.x25519.X25519PrivateKey") as mock_x:
            mock_eph = MagicMock()
            mock_eph.public_key.return_value.public_bytes.return_value.hex.return_value = "eph_pub_hex"
            mock_x.generate.return_value = mock_eph

            mock_priv = MagicMock()
            mock_priv.exchange.return_value = b"dh_secret" * 4
            mock_x.from_private_bytes.return_value = mock_priv

            with patch("kremlin.security.chat.triple_xdh.HKDF") as mock_hkdf:
                mock_hkdf.return_value.derive.return_value = b"root_key_32_bytes"
                with patch("kremlin.security.chat.triple_xdh.RatchetSession") as mock_rs:
                    mock_session = MagicMock()
                    mock_rs.init_as_initiator.return_value = mock_session

                    chat_manager.ensure_session(me, peer, cb)

                    chat_manager.rpc_send.assert_called_once()
                    args, kwargs = chat_manager.rpc_send.call_args
                    payload, cb_rpc = args
                    bundle_resp = {
                        "type": "CHAT_PREKEY_BUNDLE",
                        "bundle": {
                            "ik": VALID_CHAT_PRIV_HEX,
                            "spk": VALID_CHAT_PRIV_HEX,
                            "opk": VALID_CHAT_PRIV_HEX,
                            "spend_pub": VALID_SPEND_PUB_HEX,
                            "sig": "00" * 64,
                        }
                    }
                    cb_rpc(bundle_resp)

                    assert (me, peer) in chat_manager._sessions
                    assert chat_manager._pending_used_opk[(me, peer)] == VALID_CHAT_PRIV_HEX
                    cb.assert_called_once_with(None)


def test_ensure_session_bundle_missing_spend_pub(chat_manager):
    me, peer = "alice@example.com", "bob@example.com"
    cb = MagicMock()
    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))

    chat_manager.ensure_session(me, peer, cb)
    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    bundle_resp = {
        "type": "CHAT_PREKEY_BUNDLE",
        "bundle": {"ik": VALID_CHAT_PRIV_HEX, "spk": VALID_CHAT_PRIV_HEX, "sig": "00"*64}  # no spend_pub
    }
    cb_rpc(bundle_resp)
    cb.assert_called_once_with("bundle_missing_spend_pub")


def test_ensure_session_bundle_missing_sig(chat_manager):
    me, peer = "alice@example.com", "bob@example.com"
    cb = MagicMock()
    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))

    chat_manager.ensure_session(me, peer, cb)
    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    bundle_resp = {
        "type": "CHAT_PREKEY_BUNDLE",
        "bundle": {"ik": VALID_CHAT_PRIV_HEX, "spk": VALID_CHAT_PRIV_HEX, "spend_pub": VALID_SPEND_PUB_HEX}  # no sig
    }
    cb_rpc(bundle_resp)
    cb.assert_called_once_with("bundle_missing_spk_sig")


# --- Sending Messages ---
def test_send_message_success_existing_session(chat_manager, mock_common):
    frm, to = "alice@example.com", "bob@example.com"
    text = "Hello Bob"
    on_queued = MagicMock()
    on_result = MagicMock()

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._ensure_registered = MagicMock(side_effect=lambda addr, cb: cb(None))

    mock_sess = MagicMock()
    mock_sess.encrypt.return_value = {
        "ratchet": {"eph_pub": "00" * 32, "static_pub": "00" * 32, "pn": 0, "n": 0},
        "enc": {"nonce": "00" * 24, "ct": "00" * 32}
    }
    chat_manager._get_session = MagicMock(return_value=mock_sess)
    chat_manager._ensure_prekey_inventory = MagicMock()

    chat_manager.send_message(frm, to, text, on_queued, on_result)

    chat_manager._ensure_registered.assert_called_once_with(frm, ANY)
    mock_sess.encrypt.assert_called_once_with(b"packed_text", frm, to, ANY, ANY)

    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    assert payload["type"] == "CHAT_SEND"
    assert payload["from"] == frm
    assert payload["to"] == to
    on_queued.assert_called_once()
    cb_rpc({"status": "ok"})
    on_result.assert_called_once_with({"status": "ok", "msg_id": ANY, "to": to, "from": frm})


def test_send_message_new_session_created(chat_manager, mock_common):
    frm, to = "alice@example.com", "bob@example.com"
    text = "Hello"
    on_queued = MagicMock()
    on_result = MagicMock()

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._ensure_registered = MagicMock(side_effect=lambda addr, cb: cb(None))
    chat_manager._ensure_prekey_inventory = MagicMock()

    # No session initially
    chat_manager._get_session = MagicMock(return_value=None)

    # Mock ensure_session to create a session and call callback
    def ensure_session_side_effect(me, peer, cb):
        mock_sess = MagicMock()
        mock_sess.encrypt.return_value = {
            "ratchet": {"eph_pub": "00" * 32, "static_pub": "00" * 32, "pn": 0, "n": 0},
            "enc": {"nonce": "00" * 24, "ct": "00" * 32}
        }
        chat_manager._sessions[(me, peer)] = mock_sess
        cb(None)

    chat_manager.ensure_session = MagicMock(side_effect=ensure_session_side_effect)

    # Override _get_session to return the session after creation
    def get_session_side_effect(me, peer):
        return chat_manager._sessions.get((me, peer))
    chat_manager._get_session = MagicMock(side_effect=get_session_side_effect)

    chat_manager.send_message(frm, to, text, on_queued, on_result)

    chat_manager.ensure_session.assert_called_once_with(frm, to, ANY)
    sess = chat_manager._sessions.get((frm, to))
    assert sess is not None
    sess.encrypt.assert_called_once()
    chat_manager.rpc_send.assert_called_once()


def test_send_message_unlock_failed(chat_manager):
    frm, to = "alice@example.com", "bob@example.com"
    chat_manager.get_priv_for_chat = MagicMock(return_value=None)
    on_queued = MagicMock()
    on_result = MagicMock()

    chat_manager.send_message(frm, to, "hi", on_queued, on_result)
    on_result.assert_called_once_with({"status": "unlock_failed"})
    chat_manager.rpc_send.assert_not_called()


# --- Polling ---
def test_poll_with_receipt_item(chat_manager, mock_common):
    me = "alice@example.com"
    n = 5
    on_items = MagicMock()
    on_done = MagicMock()

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._ensure_prekey_inventory = MagicMock()
    chat_manager.poll(me, n, on_items, on_done)

    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    items_resp = {
        "type": "CHAT_ITEMS",
        "items": [
            {
                "type": "CHAT_RCPT",
                "rcpt": "bob@example.com",
                "msg_id": 456,
                "from": "bob",
                "to": me,
                "ts": 12345,
            }
        ]
    }
    cb_rpc(items_resp)

    on_items.assert_called_once_with([
        {
            "type": "rcpt",
            "rcpt": "bob@example.com",
            "msg_id": 456,
            "from": "bob",
            "to": me,
            "ts": 12345,
        }
    ])
    on_done.assert_called_once_with(items_resp)


def test_poll_decrypt_failure(chat_manager, mock_common):
    me = "alice@example.com"
    on_items = MagicMock()
    on_done = MagicMock()

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._ensure_prekey_inventory = MagicMock()
    mock_sess = MagicMock()
    mock_sess.decrypt.return_value = None  # decryption fails
    chat_manager._get_session = MagicMock(return_value=mock_sess)

    chat_manager.poll(me, 5, on_items, on_done)
    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    items_resp = {
        "type": "CHAT_ITEMS",
        "items": [
            {
                "type": "CHAT_ITEM",
                "from": "bob@example.com",
                "from_pub": "eph",
                "from_static": "static",
                "msg_id": 123,
                "ts": 12345,
                "enc": {"nonce": "n", "ct": "c"},
                "ratchet_pn": 0,
                "ratchet_n": 0,
            }
        ]
    }
    cb_rpc(items_resp)

    # No item should be output
    on_items.assert_called_once_with([])
    on_done.assert_called_once_with(items_resp)


def test_poll_auto_register_when_not_registered(chat_manager, mock_common):
    me = "alice@example.com"
    on_items = MagicMock()
    on_done = MagicMock()

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._ensure_prekey_inventory = MagicMock()
    chat_manager._ensure_registered = MagicMock(side_effect=lambda addr, cb: cb(None))

    chat_manager.poll(me, 5, on_items, on_done)

    # First RPC call for CHAT_PULL
    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload1, cb1 = args
    assert payload1["type"] == "CHAT_PULL"

    # Simulate response: not_registered
    cb1({"type": "CHAT_NONE", "error": "not_registered"})

    # _ensure_registered should have been called, which triggers another CHAT_PULL
    assert chat_manager.rpc_send.call_count == 2
    args2, kwargs2 = chat_manager.rpc_send.call_args_list[1]
    payload2, cb2 = args2
    assert payload2["type"] == "CHAT_PULL"

    # Now send a proper response
    cb2({"type": "CHAT_ITEMS", "items": []})
    on_items.assert_called_once_with([])
    on_done.assert_called_once_with({"type": "CHAT_ITEMS", "items": []})


# --- Registration ---
def test_register_success(chat_manager, mock_common):
    addr = "alice@example.com"
    on_done = MagicMock()

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))
    mock_common.get_prekey_bundle_local.return_value = {
        "ik": VALID_CHAT_PRIV_HEX, "spk": VALID_CHAT_PRIV_HEX, "sig": "00"*64, "opk": VALID_CHAT_PRIV_HEX
    }
    mock_common.sign.return_value = "00"*64

    chat_manager.register(addr, on_done)

    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb = args
    assert payload["type"] == "CHAT_REGISTER"
    assert payload["address"] == addr
    assert payload["chat_pub"] == VALID_CHAT_PUB_HEX

    cb({"type": "CHAT_REGISTERED"})
    assert chat_manager.pub_cache[addr] == VALID_CHAT_PUB_HEX
    assert addr in chat_manager._registered_addrs
    on_done.assert_called_once_with({"type": "CHAT_REGISTERED"})


def test_ensure_registered_success(chat_manager):
    addr = "alice@example.com"
    cb = MagicMock()

    chat_manager._registered_addrs = set()
    chat_manager.register = MagicMock(side_effect=lambda addr, on_done: on_done({"type": "CHAT_REGISTERED"}))

    chat_manager._ensure_registered(addr, cb)
    chat_manager.register.assert_called_once_with(addr, ANY)
    cb.assert_called_once_with(None)
    assert addr in chat_manager._registered_addrs


# --- Publishing Prekeys ---
def test_publish_prekeys_success(chat_manager, mock_common):
    addr = "alice@example.com"
    on_done = MagicMock()

    chat_manager._can_publish_prekeys.return_value = True
    mock_common.get_prekey_bundle_local.return_value = {
        "ik": VALID_CHAT_PRIV_HEX, "spk": VALID_CHAT_PRIV_HEX, "sig": "", "opk": VALID_CHAT_PRIV_HEX
    }
    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    mock_common.sign.return_value = "00"*64

    chat_manager.publish_prekeys(addr, on_done)

    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb = args
    assert payload["type"] == "CHAT_PUBLISH_PREKEYS"
    assert payload["address"] == addr
    assert payload["spk"] == VALID_CHAT_PRIV_HEX
    assert payload["sig"] == "00"*64

    assert addr in chat_manager._last_prekey_publish
    assert addr in chat_manager._prekey_bundle_cache

    cb({"status": "ok"})
    on_done.assert_called_once_with({"status": "ok"})


def test_publish_prekeys_uses_cache(chat_manager, mock_common):
    addr = "alice@example.com"
    on_done = MagicMock()
    chat_manager._can_publish_prekeys.return_value = True

    cached_bundle = {
        "ik": "00" * 32,
        "spk": "00" * 32,
        "sig": "00" * 64,
        "opk": "00" * 32,
    }
    chat_manager._prekey_bundle_cache[addr] = (cached_bundle, time.time())

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    mock_common.sign.return_value = "00" * 64
    mock_common.pub_hex_from_priv.return_value = VALID_SPEND_PUB_HEX
    mock_common.ec_priv_from_hex.return_value = b"\x00" * 32

    chat_manager.publish_prekeys(addr, on_done)

    mock_common.ensure_signed_prekey.assert_not_called()
    mock_common.sign.assert_called_once()
    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb = args
    assert payload["ik"] == cached_bundle["ik"]
    assert payload["spk"] == cached_bundle["spk"]
    assert payload["opk"] == cached_bundle["opk"]
    assert payload["sig"] == "00" * 64


# --- SAS ---
def test_sas(chat_manager):
    chat_manager.expected_pub_or_lookup = MagicMock(side_effect=lambda addr: {
        "alice@example.com": "a"*64,
        "bob@example.com": "b"*64
    }.get(addr, ""))

    sas = chat_manager.sas("alice@example.com", "bob@example.com")
    assert len(sas) == 6
    assert all(c in "🐙🦊🐼🐧🐯🐸🦁🐵🦄🐺🐤🦉🐢🐬🦒🐳" for c in sas)


# --- Partner Callbacks ---
def test_lookup_pub_triggers_presence_callback(chat_manager):
    addr = "bob@example.com"
    chat_manager.on_partner_key_changed = MagicMock()
    chat_manager.on_partner_presence = MagicMock()
    chat_manager.pub_cache = {}

    cb = MagicMock()
    chat_manager.lookup_pub(addr, cb)

    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb_rpc = args
    assert payload["type"] == "CHAT_LOOKUP_PUB"

    resp = {"type": "CHAT_PUBKEY", "pubkey": "new_pub", "last_seen": 999}
    cb_rpc(resp)
    chat_manager.on_partner_presence.assert_called_once_with(addr, 999)
    chat_manager.on_partner_key_changed.assert_not_called()


# --- Read Receipt ---
def test_send_read_receipt(chat_manager, mock_common):
    sender = "bob@example.com"
    reader = "alice@example.com"
    msg_id = 123
    on_result = MagicMock()

    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager.send_read_receipt(sender, reader, msg_id, on_result)

    chat_manager.rpc_send.assert_called_once()
    args, kwargs = chat_manager.rpc_send.call_args
    payload, cb = args
    assert payload["type"] == "CHAT_READ"
    assert payload["sender"] == sender
    assert payload["reader"] == reader
    assert payload["msg_id"] == msg_id
    assert "read_sig" in payload

    cb({"status": "ok"})
    on_result.assert_called_once_with({"status": "ok"})


# --- Caching ---
def test_priv_cache_expiry(chat_manager, mock_wallet):
    addr = "alice@example.com"
    chat_manager.priv_cache[addr] = ("old_priv", time.time() - 10)
    chat_manager._pwd_cache[addr] = ("old_pwd", time.time() - 10)

    chat_manager.password_prompt_cb = MagicMock(return_value="new_password")

    priv = chat_manager.get_priv_for_chat(addr)
    mock_wallet.unlock.assert_called_once_with("new_password", addr)
    assert priv == VALID_CHAT_PRIV_HEX
    assert chat_manager.priv_cache[addr][0] == VALID_CHAT_PRIV_HEX
    assert chat_manager._pwd_cache[addr][0] == "new_password"


def test_pwd_cache_used(chat_manager):
    addr = "alice@example.com"
    chat_manager._pwd_cache[addr] = ("cached_pwd", time.time() + 100)
    chat_manager.password_prompt_cb = MagicMock()

    with patch("kremlin.security.chat.triple_xdh.Wallet") as mock_wallet:
        mock_wallet.unlock.return_value = {"private_key": "priv_from_cached_pwd"}
        priv = chat_manager.get_priv_for_chat(addr)
        chat_manager.password_prompt_cb.assert_not_called()
        mock_wallet.unlock.assert_called_once_with("cached_pwd", addr)
        assert priv == "priv_from_cached_pwd"

# --- New tests to increase coverage ---
def test_poll_x3dh_responder_bootstrap(chat_manager, mock_common):
    me = "alice@example.com"
    on_items = MagicMock()
    on_done = MagicMock()
    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    
    chat_manager._get_session = MagicMock(return_value=None)
    
    with patch.object(chat_manager, "_ensure_prekey_inventory"):
        chat_manager.poll(me, 5, on_items, on_done)
    
    with patch("kremlin.security.chat.triple_xdh.x25519.X25519PrivateKey") as mock_x_priv, \
         patch("kremlin.security.chat.triple_xdh.x25519.X25519PublicKey") as mock_x_pub, \
         patch("kremlin.security.chat.triple_xdh.HKDF") as mock_hkdf, \
         patch("kremlin.security.chat.triple_xdh.RatchetSession") as mock_rs:
        
        mock_hkdf.return_value.derive.return_value = b"root_key_32_bytes"
        mock_sess = MagicMock()
        mock_sess.decrypt.return_value = b"responder_packed_text"
        mock_rs.init_as_responder.return_value = mock_sess
        
        args, kwargs = chat_manager.rpc_send.call_args
        _, cb_rpc = args
        items_resp = {
            "type": "CHAT_ITEMS",
            "items": [
                {
                    "type": "CHAT_ITEM",
                    "from": "bob@example.com",
                    "from_pub": "00"*32,
                    "from_static": "00"*32,
                    "used_opk": "00"*32,
                    "msg_id": 123,
                    "ts": 12345,
                    "enc": {"nonce": "nonce", "ct": "ct"},
                    "ratchet_pn": 0,
                    "ratchet_n": 0,
                }
            ]
        }
        cb_rpc(items_resp)
        
        mock_rs.init_as_responder.assert_called_once()
        on_items.assert_called_once()

def test_ensure_prekey_inventory_refill_and_rotate(chat_manager, mock_common):
    # Unmock the method for this test
    chat_manager._ensure_prekey_inventory = chat_manager.__class__._ensure_prekey_inventory.__get__(chat_manager, chat_manager.__class__)
    addr = "alice@example.com"
    chat_manager._last_inventory_check.pop(addr, None)
    
    mock_common.get_prekey_inventory.side_effect = [
        {"created": str(int(time.time()) - 99999999), "opk_queue": 0},
        {"created": str(int(time.time())), "opk_queue": 100}
    ]
    
    with patch.object(chat_manager, "publish_prekeys") as mock_publish:
        chat_manager._ensure_prekey_inventory(addr, force=True)
        mock_common.rotate_signed_prekey.assert_called_once()
        assert mock_common.add_one_time_prekeys.call_count > 0
        mock_publish.assert_called_once()

def test_ensure_session_invalid_spend_pub(chat_manager, mock_common):
    me, peer = "alice@example.com", "bob@example.com"
    cb = MagicMock()
    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))
    chat_manager.ensure_session(me, peer, cb)
    args, _ = chat_manager.rpc_send.call_args
    cb_rpc = args[1]
    
    cb_rpc({"type": "CHAT_PREKEY_BUNDLE", "bundle": {"spk": "00", "sig": "00"}})
    cb.assert_called_with("bundle_missing_spend_pub")
    
    cb_rpc({"type": "CHAT_PREKEY_BUNDLE", "bundle": {"spend_pub": "invalid", "spk": "00", "sig": "00"}})
    cb.assert_called_with("bundle_invalid_spend_pub")
    
    cb_rpc({"type": "UNKNOWN_RESP"})
    cb.assert_called_with("no_bundle")

def test_send_message_errors(chat_manager, mock_common):
    frm, to = "alice@example.com", "bob@example.com"
    on_queued = MagicMock()
    on_result = MagicMock()
    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._ensure_registered = MagicMock(side_effect=lambda addr, cb: cb(None))
    
    mock_sess = MagicMock()
    mock_sess.encrypt.side_effect = Exception("enc err")
    chat_manager._get_session = MagicMock(return_value=mock_sess)
    chat_manager.send_message(frm, to, "hello", on_queued, on_result)
    on_result.assert_called_with({"status": "encrypt_failed", "reason": "enc err"})
    
    chat_manager._ensure_registered = MagicMock(side_effect=lambda addr, cb: cb("register_failed_err"))
    chat_manager.send_message(frm, to, "hello", on_queued, on_result)
    on_result.assert_called_with({"status": "register_failed", "reason": "register_failed_err"})

    chat_manager._ensure_registered = MagicMock(side_effect=lambda addr, cb: cb(None))
    chat_manager._get_session = MagicMock(return_value=None)
    chat_manager.ensure_session = MagicMock(side_effect=lambda frm, to, cb: cb("ensure_fail"))
    chat_manager.send_message(frm, to, "hello", on_queued, on_result)
    on_result.assert_called_with({"status": "sess_error", "reason": "ensure_fail"})

    chat_manager.ensure_session = MagicMock(side_effect=lambda frm, to, cb: cb(None))
    chat_manager.send_message(frm, to, "hello", on_queued, on_result)
    on_result.assert_called_with({"status": "sess_missing"})

    mock_sess2 = MagicMock()
    mock_sess2.encrypt.return_value = {"enc": {"nonce": "invalid_hex", "ct": "00"}, "ratchet": {"pn": 0, "n": 0}}
    chat_manager._get_session = MagicMock(return_value=mock_sess2)
    chat_manager.ensure_session = MagicMock(side_effect=lambda frm, to, cb: cb(None))
    chat_manager.send_message(frm, to, "hello", on_queued, on_result)
    on_result.assert_called_with({"status": "ratchet_header_invalid"})

def test_register_error_handling(chat_manager, mock_common):
    addr = "alice@example.com"
    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    chat_manager._get_chat_dh = MagicMock(return_value=(VALID_CHAT_PRIV_HEX, VALID_CHAT_PUB_HEX))
    
    cb = MagicMock()
    chat_manager.register(addr, cb)
    args, _ = chat_manager.rpc_send.call_args
    cb_rpc = args[1]
    
    cb_rpc(None)
    cb.assert_called_with(None)
    
    cb_rpc({"error": "rate_limited", "type": "CHAT_REGISTER"})
    cb.assert_called_with({"error": "rate_limited", "type": "CHAT_REGISTER"})

def test_ensure_registered_error_handling(chat_manager):
    addr = "alice@example.com"
    cb = MagicMock()
    chat_manager.register = MagicMock(side_effect=lambda addr, on_done: on_done({"error": "err", "type": "CHAT_REGISTER"}))
    chat_manager._ensure_registered(addr, cb)
    cb.assert_called_with("register_failed")

def test_publish_prekeys_error_handling(chat_manager, mock_common):
    addr = "alice@example.com"
    chat_manager._can_publish_prekeys.return_value = True
    chat_manager.get_priv_for_chat = MagicMock(return_value=VALID_CHAT_PRIV_HEX)
    
    cb = MagicMock()
    chat_manager.publish_prekeys(addr, cb)
    args, _ = chat_manager.rpc_send.call_args
    cb_rpc = args[1]
    
    cb_rpc({"error": "failed"})
    assert addr not in chat_manager._last_prekey_publish
    cb.assert_called_with({"error": "failed"})

def test_get_priv_for_chat_empty_pwd(chat_manager):
    addr = "alice@example.com"
    chat_manager._pwd_cache_get = MagicMock(return_value=None)
    chat_manager.password_prompt_cb = MagicMock(return_value="")
    assert chat_manager.get_priv_for_chat(addr) is None

def test_get_chat_dh_cache_hit(chat_manager):
    addr = "alice@example.com"
    chat_manager._chat_dh_cache[addr] = ("sk", "pk", time.time() + 100)
    sk, pk = chat_manager._get_chat_dh(addr)
    assert sk == "sk"
    assert pk == "pk"

def test_expected_pub_or_lookup_miss(chat_manager):
    addr = "alice@example.com"
    with patch.object(chat_manager, "lookup_pub") as mock_lookup:
        chat_manager.expected_pub_or_lookup(addr)
        mock_lookup.assert_called_once()
        
def test_ensure_session_fast_path(chat_manager):
    me, peer = "alice@example.com", "bob@example.com"
    chat_manager._get_session = MagicMock(return_value=MagicMock())
    cb = MagicMock()
    chat_manager.ensure_session(me, peer, cb)
    cb.assert_called_with(None)
    chat_manager.rpc_send.assert_not_called()

def test_delete_session(chat_manager, mock_common):
    chat_manager._delete_session("a", "b")
    mock_common.delete_chat_session.assert_called_once_with("a", "b")