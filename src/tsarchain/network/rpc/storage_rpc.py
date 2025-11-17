# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from typing import TYPE_CHECKING, Any, Optional

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc(storage_rpc)")

if TYPE_CHECKING:
    from ..node import Network


__all__ = ["handle_storage_rpc"]


def handle_storage_rpc(self: "Network", message: dict[str, Any], addr: Optional[tuple], mtype: str) -> dict | None:

    if mtype == "GRAFFITI_GET_PAYOUTS":
        art_id = str(message.get("art_id") or "").strip().lower()
        if not art_id:
            return {"type": "GRAFFITI_GET_PAYOUTS", "payouts": []}
        limit = int(message.get("limit", 100) or 100)
        limit = max(1, min(limit, 500))
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        payouts = reg.list_payouts(art_id, limit) if reg else []
        return {"type": "GRAFFITI_GET_PAYOUTS", "art_id": art_id, "payouts": payouts}

    elif mtype == "GRAFFITI_POOL_PAYOUT":
        art_id = str(message.get("art_id") or "").strip().lower()
        try:
            amount = int(message.get("amount", 0))
        except Exception:
            amount = 0
        recipient = str(message.get("recipient") or "").strip().lower() or "storage"
        txid = str(message.get("txid") or "").strip() or "offchain"
        if not art_id or amount <= 0:
            return {"error": "bad_request"}
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        if not reg:
            return {"error": "registry_unavailable"}
        post = reg.get_post(art_id)
        if not post:
            return {"error": "unknown_art_id"}
        stats = post.setdefault("stats", {})
        pool_balance = int(stats.get("pool_balance", 0))
        if pool_balance < amount:
            return {"error": "insufficient_pool_balance", "pool_balance": pool_balance}
        height = getattr(getattr(self.broadcast, "blockchain", None), "height", 0)
        reg.record_payout(art_id, {recipient: amount}, txid, height)
        return {"status": "ok", "art_id": art_id, "pool_balance": int(stats.get("pool_balance", 0))}

    return None

