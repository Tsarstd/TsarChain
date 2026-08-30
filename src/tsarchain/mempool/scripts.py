# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE.

from __future__ import annotations

from ..utils.helpers import extract_script_bytes, script_to_address
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.scripts")

__all__ = ["get_utxo_script_bytes", "extract_script_bytes", "script_to_address"]


def get_utxo_script_bytes(utxo_entry) -> bytes:
    res = extract_script_bytes(utxo_entry)
    if res is not None:
        return res
    raise ValueError("script_pubkey not found in UTXO entry")