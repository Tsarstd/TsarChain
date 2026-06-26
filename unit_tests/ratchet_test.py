# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: Signal-X3DH; Signal-DoubleRatchet; RFC7748-X25519; RFC5869-HKDF

import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidTag

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_ROOT = os.path.join(PROJECT_ROOT, "src")
for path in (PROJECT_ROOT, SRC_ROOT):
    if path not in sys.path:
        sys.path.append(path)

from kremlin.security.chat.double_ratchet import RatchetSession  # noqa: E402
from tsarchain.utils import config as CFG


def _derive_root_key():
    """Simulate X3DH derivation used by wallet."""
    IKs = x25519.X25519PrivateKey.generate()
    IKr = x25519.X25519PrivateKey.generate()
    SPKs = x25519.X25519PrivateKey.generate()
    EPh = x25519.X25519PrivateKey.generate()

    secret = b"".join(
        [
            IKs.exchange(SPKs.public_key()),
            EPh.exchange(IKr.public_key()),
            EPh.exchange(SPKs.public_key()),
        ]
    )
    rk = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"tsar:x3dh:v1",
    ).derive(secret)
    return (IKs, IKr, SPKs, EPh, rk)


def _build_sessions():
    IKs, IKr, SPKs, EPh, rk = _derive_root_key()
    chatA = x25519.X25519PrivateKey.generate()
    chatB = x25519.X25519PrivateKey.generate()
    chatA_hex = chatA.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    chatB_hex = chatB.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    spk_hex = SPKs.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    eph_hex = EPh.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    initiator = RatchetSession.init_as_initiator(
        rk,
        chatA_hex,
        chatB_hex,
        EPh,
        spk_hex,
        my_static_hex=chatA_hex,
    )
    responder = RatchetSession.init_as_responder(
        rk,
        chatB_hex,
        chatA_hex,
        eph_hex,
        my_ratchet_priv=SPKs,
        my_static_hex=chatB_hex,
    )
    return initiator, responder


@pytest.mark.parametrize("rounds", [4, 8])
def test_double_ratchet_roundtrip(rounds):
    alice, bob = _build_sessions()

    for idx in range(rounds):
        payload = f"message-{idx}".encode()
        if idx % 2 == 0:
            packet = alice.encrypt(payload, "a", "b", idx + 1, idx + 100)
            decrypted = bob.decrypt(packet["enc"], "a", "b", idx + 1, idx + 100, packet["ratchet"])
            assert decrypted == payload
        else:
            packet = bob.encrypt(payload, "b", "a", idx + 1, idx + 100)
            decrypted = alice.decrypt(packet["enc"], "b", "a", idx + 1, idx + 100, packet["ratchet"])
            assert decrypted == payload


def test_out_of_order_delivery_and_skipped_keys():
    alice, bob = _build_sessions()

    first_packet = alice.encrypt(b"first", "a", "b", 1, 10)
    second_packet = alice.encrypt(b"second", "a", "b", 2, 11)

    decrypted_second = bob.decrypt(second_packet["enc"], "a", "b", 2, 11, second_packet["ratchet"])
    assert decrypted_second == b"second"

    decrypted_first = bob.decrypt(first_packet["enc"], "a", "b", 1, 10, first_packet["ratchet"])
    assert decrypted_first == b"first"


def test_session_serialisation_roundtrip():
    alice, bob = _build_sessions()

    # exchange a message so that internal counters change
    packet = alice.encrypt(b"ping", "a", "b", 1, 10)
    assert bob.decrypt(packet["enc"], "a", "b", 1, 10, packet["ratchet"]) == b"ping"

    serial = alice.to_dict()
    restored = RatchetSession.from_dict(serial)
    assert restored.to_dict() == serial
    
def test_max_skipped_keys():
    """Ensure that `store_skipped` does not exceed the limit and discards the oldest items."""
    alice, bob = _build_sessions()
    
    # Send more than CFG.CHAT_RATCHET_MAX_SKIP messages.
    # For example, 210 messages (10 above the 200 limit)
    total_msgs = CFG.CHAT_RATCHET_MAX_SKIP + 10
    packets = []
    for i in range(total_msgs):
        packets.append(alice.encrypt(f"msg-{i}".encode(), "a", "b", i, 100 + i))

    # Bob receives the last message first (index total_msgs-1)
    last_packet = packets[-1]
    dec = bob.decrypt(
        last_packet["enc"], "a", "b", total_msgs-1, 100 + total_msgs - 1, last_packet["ratchet"]
    )
    assert dec == f"msg-{total_msgs-1}".encode()

    max_skip = CFG.CHAT_RATCHET_MAX_SKIP
    assert len(bob.skipped) <= max_skip
    
    first_packet = packets[0]
    with pytest.raises(Exception):
        bob.decrypt(
            first_packet["enc"], "a", "b", 0, 100, first_packet["ratchet"]
        )
    
    recent_idx = total_msgs - 5
    recent_packet = packets[recent_idx]
    dec_recent = bob.decrypt(
        recent_packet["enc"], "a", "b", recent_idx, 100 + recent_idx, recent_packet["ratchet"]
    )
    assert dec_recent == f"msg-{recent_idx}".encode()

def test_decrypt_corrupt_ciphertext():
    """Ensure that decryption with corrupted ciphertext or nonce throws an exception."""
    alice, bob = _build_sessions()
    packet = alice.encrypt(b"hello", "a", "b", 1, 10)

    enc_corrupt = dict(packet["enc"])
    enc_corrupt["ct"] = enc_corrupt["ct"][:-2] + "00"  # change 1 byte

    with pytest.raises(InvalidTag):
        bob.decrypt(enc_corrupt, "a", "b", 1, 10, packet["ratchet"])

def test_rotate_and_out_of_order_with_skipped():
    """
    Scenario:
    1. Alice sends 3 messages (n=0, 1, 2) to Bob.
    2. Bob receives only message n=2 (skipping n=0, 1).
    3. Bob sends back 1 message (triggering a rotation at Bob's end).
    4. Alice receives the reply, then sends a new message (triggering a rotation at Alice's end).
    5. Bob receives Alice's new message.
    6. Bob then receives Alice's old message (n=0)—requiring the use of the skipped key from the initial chain.
    """
    alice, bob = _build_sessions()

    # 1. Alice send 3 message
    packets = []
    for i in range(3):
        packets.append(alice.encrypt(f"a-{i}".encode(), "a", "b", i, 100+i))

    # 2. Bob only receives the second message (n=2).
    dec2 = bob.decrypt(packets[2]["enc"], "a", "b", 2, 102, packets[2]["ratchet"])
    assert dec2 == b"a-2"

    # 3. Bob sends back (will rotate the send chain at Bob's end due to `needs_send_rotation`)
    bob_reply = bob.encrypt(b"b-reply", "b", "a", 999, 200)

    # 4. Alice receives a reply and then sends a new message (rotation at Alice's end)
    alice.decrypt(bob_reply["enc"], "b", "a", 999, 200, bob_reply["ratchet"])
    alice_new = alice.encrypt(b"a-new", "a", "b", 3, 300)

    # 5. Bob receives a new message from Alice (this will trigger a rotation on Bob's end)
    dec_new = bob.decrypt(alice_new["enc"], "a", "b", 3, 300, alice_new["ratchet"])
    assert dec_new == b"a-new"

    # 6. Bob now receives Alice's old message (n=0) — must use the skipped key
    #    Previously, upon receiving n=2, Bob stored the skipped keys for n=0 and n=1
    #    using dh_hex = alice.DHs.public_key() (which remains the same).
    dec0 = bob.decrypt(packets[0]["enc"], "a", "b", 0, 100, packets[0]["ratchet"])
    assert dec0 == b"a-0"

def test_serialization_with_skipped_keys():
    """Ensure that skipped keys remain intact after serialization/deserialization."""
    alice, bob = _build_sessions()
    # For skipped keys: send 3 messages, receive only the 2nd message.
    packets = []
    for i in range(3):
        packets.append(alice.encrypt(f"msg-{i}".encode(), "a", "b", i, 100+i))
    bob.decrypt(packets[2]["enc"], "a", "b", 2, 102, packets[2]["ratchet"])
    # Now bob.skipped contains 2 entries (n=0 and n=1).

    serial = bob.to_dict()
    restored = RatchetSession.from_dict(serial)

    assert restored.skipped == bob.skipped
    assert restored.to_dict() == serial
    dec0 = restored.decrypt(packets[0]["enc"], "a", "b", 0, 100, packets[0]["ratchet"])
    assert dec0 == b"msg-0"
