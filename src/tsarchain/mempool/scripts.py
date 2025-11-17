# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md.

from __future__ import annotations

from typing import TYPE_CHECKING
from ecdsa import VerifyingKey, SECP256k1

from ..utils import helpers as H
from ..utils.helpers import hash256, is_p2wpkh_script, serialize_tx_for_txid

if TYPE_CHECKING:
    from ..core.tx import Tx

__all__ = [
    "is_p2pkh_script",
    "decompress_pubkey33",
    "vk_from_pubkey_bytes",
    "extract_p2pkh_scriptsig",
    "get_utxo_script_bytes",
    "p2wpkh_script_code_from_spk",
    "legacy_sighash",
]


def is_p2pkh_script(spk: bytes) -> bool:
    return (
        isinstance(spk, (bytes, bytearray))
        and len(spk) == 25
        and spk[0] == 0x76
        and spk[1] == 0xA9
        and spk[2] == 0x14
        and spk[23] == 0x88
        and spk[24] == 0xAC
    )


def decompress_pubkey33(pub33: bytes) -> bytes:
    if not (len(pub33) == 33 and pub33[0] in (2, 3)):
        raise ValueError("Invalid compressed pubkey")

    x = int.from_bytes(pub33[1:], "big")
    y_sq = (pow(x, 3, H.SECP256K1_P) + 7) % H.SECP256K1_P
    y = pow(y_sq, (H.SECP256K1_P + 1) // 4, H.SECP256K1_P)

    if (y & 1) != (pub33[0] & 1):
        y = H.SECP256K1_P - y
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def vk_from_pubkey_bytes(pubkey: bytes) -> VerifyingKey:
    if len(pubkey) == 33 and pubkey[0] in (2, 3):
        raw = decompress_pubkey33(pubkey)
        return VerifyingKey.from_string(raw, curve=SECP256k1)

    if len(pubkey) == 65 and pubkey[0] == 4:
        return VerifyingKey.from_string(pubkey[1:], curve=SECP256k1)

    if len(pubkey) == 64:
        return VerifyingKey.from_string(pubkey, curve=SECP256k1)

    raise ValueError("Unsupported pubkey format")


def extract_p2pkh_scriptsig(script_sig_bytes: bytes):
    if not script_sig_bytes or len(script_sig_bytes) < 2:
        raise ValueError("scriptSig too short")

    i = 0
    L1 = script_sig_bytes[i]
    i += 1
    if i + L1 > len(script_sig_bytes):
        raise ValueError("Bad sig length in scriptSig")

    sig_all = script_sig_bytes[i : i + L1]
    i += L1
    if len(sig_all) < 2:
        raise ValueError("Bad DER+hashtype")

    sighash_type = sig_all[-1]
    sig_der = sig_all[:-1]

    if i >= len(script_sig_bytes):
        raise ValueError("Missing pubkey push")

    L2 = script_sig_bytes[i]
    i += 1
    if i + L2 > len(script_sig_bytes):
        raise ValueError("Bad pubkey length in scriptSig")

    pubkey = script_sig_bytes[i : i + L2]
    return sig_der, sighash_type, pubkey


def get_utxo_script_bytes(utxo_entry) -> bytes:
    # dict with tx_out object
    if isinstance(utxo_entry, dict):
        tx_out = utxo_entry.get("tx_out")
        if tx_out is not None:
            if hasattr(tx_out, "script_pubkey") and hasattr(
                tx_out.script_pubkey, "serialize"
            ):
                try:
                    return tx_out.script_pubkey.serialize()
                except Exception:
                    pass

            # tx_out dict
            if isinstance(tx_out, dict) and "script_pubkey" in tx_out:
                spk = tx_out["script_pubkey"]
                if isinstance(spk, (bytes, bytearray)):
                    return bytes(spk)
                if isinstance(spk, str):
                    try:
                        return bytes.fromhex(spk)
                    except Exception:
                        pass

        # flat dict
        if "script_pubkey" in utxo_entry:
            spk = utxo_entry["script_pubkey"]
            if isinstance(spk, (bytes, bytearray)):
                return bytes(spk)
            if isinstance(spk, str):
                try:
                    return bytes.fromhex(spk)
                except Exception:
                    pass

    # object level (namedtuple/dataclass)
    if hasattr(utxo_entry, "tx_out") and hasattr(utxo_entry.tx_out, "script_pubkey"):
        spk_obj = utxo_entry.tx_out.script_pubkey
        if hasattr(spk_obj, "serialize"):
            try:
                return spk_obj.serialize()
            except Exception:
                pass

        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)

    if hasattr(utxo_entry, "script_pubkey"):
        spk_obj = utxo_entry.script_pubkey
        if hasattr(spk_obj, "serialize"):
            try:
                return spk_obj.serialize()
            except Exception:
                pass

        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)

    raise ValueError("script_pubkey not found in UTXO entry")


def p2wpkh_script_code_from_spk(spk_bytes: bytes) -> bytes:
    if not is_p2wpkh_script(spk_bytes):
        raise ValueError("Not a P2WPKH script")

    pkhash = spk_bytes[2:22]
    return b"\x19\x76\xa9\x14" + pkhash + b"\x88\xac"


def legacy_sighash(tx: "Tx", vin_index: int, script_code: bytes, sighash_type: int) -> bytes:
    orig_scripts = [tin.script_sig for tin in tx.inputs]
    try:
        for tin in tx.inputs:
            tin.script_sig = H.Script([])
        tx.inputs[vin_index].script_sig = H.Script.deserialize(script_code)
        preimage = serialize_tx_for_txid(tx) + int(sighash_type).to_bytes(4, "little")
        return hash256(preimage)

    finally:
        for tin, orig in zip(tx.inputs, orig_scripts):
            tin.script_sig = orig
