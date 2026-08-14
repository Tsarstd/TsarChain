# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE.

from __future__ import annotations

from bech32 import bech32_encode, convertbits
from ..utils import config as CFG
from ..utils.helpers import Script

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.scripts")

__all__ = ["get_utxo_script_bytes", "extract_script_bytes", "script_to_address"]


def extract_script_bytes(spk) -> bytes | None:
    if spk is None:
        return None
    if hasattr(spk, "serialize"):
        return spk.serialize()
    if isinstance(spk, Script):
        return spk.serialize()
    if isinstance(spk, (bytes, bytearray)):
        return bytes(spk)
    if isinstance(spk, str):
        try:
            return bytes.fromhex(spk)
        except ValueError:
            return None
    return None


def script_to_address(script) -> str | None:
    b = extract_script_bytes(script)
    if not b:
        return None
    if len(b) == 22 and b[0] == 0x00 and b[1] == 0x14:
        data = [0] + list(convertbits(b[2:], 8, 5, True))
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    if len(b) == 34 and b[0] == 0x00 and b[1] == 0x20:
        data = [0] + list(convertbits(b[2:], 8, 5, True))
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    return None


def get_utxo_script_bytes(utxo_entry) -> bytes:
    if isinstance(utxo_entry, Script):
        return utxo_entry.serialize()

    if isinstance(utxo_entry, dict):
        tx_out = utxo_entry.get("tx_out")
        if tx_out is not None:
            if hasattr(tx_out, "script_pubkey"):
                res = extract_script_bytes(tx_out.script_pubkey)
                if res is not None: return res
            elif isinstance(tx_out, dict):
                res = extract_script_bytes(tx_out.get("script_pubkey"))
                if res is not None: return res
        
        res = extract_script_bytes(utxo_entry.get("script_pubkey"))
        if res is not None: return res

    else:
        if hasattr(utxo_entry, "tx_out") and hasattr(utxo_entry.tx_out, "script_pubkey"):
            res = extract_script_bytes(utxo_entry.tx_out.script_pubkey)
            if res is not None: return res
        
        if hasattr(utxo_entry, "script_pubkey"):
            res = extract_script_bytes(utxo_entry.script_pubkey)
            if res is not None: return res
            
    raise ValueError("script_pubkey not found in UTXO entry")