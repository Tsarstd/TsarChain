# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE.

from __future__ import annotations

from ..core.tx import Tx

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.mempool.orphan')

__all__ = ["OrphanPoolMixin"]

class OrphanPoolMixin:

    def recheck_orphans(self) -> int:
        if not self._orphan_pool:
            return 0
        retry_items = list(self._orphan_pool.items())
        self._orphan_pool = {}
        self._orphan_missing = {}
        added = 0
        for _, tx_dict in retry_items:
            tx_obj = Tx.from_dict(tx_dict)
            if self.add_valid_tx(tx_obj):
                added += 1
            else:
                reason = self.last_error_reason or ""
                if reason.startswith(("prevout_missing ", "orphan_waiting ")):
                    missing = reason.split(" ", 1)[1].strip()
                    self._queue_orphan(tx_obj, missing)
        return added


    def _queue_orphan(self, tx_obj: Tx, missing_key: str) -> None:
        tx_dict = tx_obj.to_dict(include_txid=True)
        txid_hex = tx_dict.get("txid")
        if not txid_hex and getattr(tx_obj, "txid", None):
            txid_hex = tx_obj.txid.hex()
            tx_dict["txid"] = txid_hex
        if not txid_hex:
            return
        key = txid_hex.lower()
        self._orphan_pool[key] = tx_dict
        self._orphan_missing[key] = missing_key.lower()