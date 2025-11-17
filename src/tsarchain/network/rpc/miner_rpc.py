# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

from typing import TYPE_CHECKING, Any, Optional

from ...utils import config as CFG

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc(miner_rpc)")

if TYPE_CHECKING:
    from ..node import Network

__all__ = ["handle_miner_rpc"]


def handle_miner_rpc(self: "Network", message: dict[str, Any], addr: Optional[tuple], mtype: str) -> dict | None:
    """Handle miner-to-miner RPC messages."""
    if mtype == "HELLO":
        return self._handle_hello(message, addr)

    if mtype == "NEW_BLOCK":
        self.broadcast.receive_block(message, addr, self.peers)
        return {"status": "ok"}

    if mtype == "GET_FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"type": "SYNC_REDIRECT", "reason": "full_sync_disabled"}
        return self._handle_get_full_sync(message, addr)

    if mtype == "GET_HEADERS":
        return self._handle_get_headers(message, addr)

    if mtype == "GET_BLOCKS":
        return self._handle_get_blocks(message, addr)

    if mtype in ("HEADERS", "BLOCKS"):
        return {"status": "ok"}

    if mtype == "FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"status": "ignored", "reason": "full_sync_disabled"}
        return self._handle_full_sync(message, addr)

    if mtype == "CHAIN":
        if self._validate_incoming_chain(message):
            return {"status": "ok"}
        return None

    if mtype == "MEMPOOL":
        self.broadcast.receive_mempool(message)
        return {"status": "mempool received"}

    return None
