# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md.

from __future__ import annotations

from ..utils.helpers import Script

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.scripts")

__all__ = ["get_utxo_script_bytes",]

def get_utxo_script_bytes(utxo_entry) -> bytes:
    # dict with tx_out object
    if isinstance(utxo_entry, dict):
        tx_out = utxo_entry.get("tx_out")
        if tx_out is not None:
            if hasattr(tx_out, "script_pubkey") and hasattr(
                tx_out.script_pubkey, "serialize"
            ):
                return tx_out.script_pubkey.serialize()

            # tx_out dict
            if isinstance(tx_out, dict) and "script_pubkey" in tx_out:
                spk = tx_out["script_pubkey"]
            if isinstance(spk, (bytes, bytearray)):
                return bytes(spk)
            if isinstance(spk, str):
                return bytes.fromhex(spk)
            if isinstance(spk, Script):
                return spk.serialize()

        # flat dict
        if "script_pubkey" in utxo_entry:
            spk = utxo_entry["script_pubkey"]
            if isinstance(spk, (bytes, bytearray)):
                return bytes(spk)
            if isinstance(spk, str):
                return bytes.fromhex(spk)
            if isinstance(spk, Script):
                return spk.serialize()

    # object level (namedtuple/dataclass)
    if hasattr(utxo_entry, "tx_out") and hasattr(utxo_entry.tx_out, "script_pubkey"):
        spk_obj = utxo_entry.tx_out.script_pubkey
        if hasattr(spk_obj, "serialize"):
            return spk_obj.serialize()
        if isinstance(spk_obj, Script):
            return spk_obj.serialize()
        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)

    if hasattr(utxo_entry, "script_pubkey"):
        spk_obj = utxo_entry.script_pubkey
        if hasattr(spk_obj, "serialize"):
            return spk_obj.serialize()
        if isinstance(spk_obj, Script):
            return spk_obj.serialize()
        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)

    if isinstance(utxo_entry, Script):
        return utxo_entry.serialize()

    raise ValueError("script_pubkey not found in UTXO entry")
