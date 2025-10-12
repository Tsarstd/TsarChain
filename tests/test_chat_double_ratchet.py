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

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_ROOT = os.path.join(PROJECT_ROOT, "src")
for path in (PROJECT_ROOT, SRC_ROOT):
    if path not in sys.path:
        sys.path.append(path)

from tsarchain.wallet.chat_security import RatchetSession  # noqa: E402


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
