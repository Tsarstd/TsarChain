# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations
from typing import Optional

# ---------------- Local Project ----------------
from ..storage.utxo import UTXODB

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.utxo_validate')

class UTXOMixin:
    def _ensure_utxodb(self) -> Optional[UTXODB]:
        if self.in_memory:
            return None
        if self._utxodb is None:
            self._utxodb = UTXODB()
            self._utxo_dirty = False
            self._utxo_last_flush_height = self.height
            self._utxo_synced = False
        if not self._utxo_synced:
            self._sync_utxo_store(force=True)
        return self._utxodb

    def get_utxo_store(self) -> Optional[UTXODB]:
        return self._ensure_utxodb()

    def _mark_utxo_dirty(self) -> None:
        if self.in_memory:
            return
        self._utxo_dirty = True

    def _maybe_flush_utxo(self, *, force: bool = False) -> None:
        if self.in_memory:
            return
        store = self._ensure_utxodb()
        if store is None:
            return
        current_height = self.height
        if force:
            did_flush = store.flush(force=True)
        else:
            if not self._utxo_dirty:
                return
            if self._utxo_last_flush_height >= 0 and (current_height - self._utxo_last_flush_height) < self._utxo_flush_interval:
                return
            did_flush = store.flush()
        if did_flush:
            self._utxo_dirty = False
            self._utxo_last_flush_height = current_height

    def _sync_utxo_store(self, *, force: bool = False) -> None:
        if self.in_memory or self._utxodb is None:
            return
        if self._utxo_synced and not force:
            return
        try:
            if self.chain:
                self._utxodb.rebuild_from_chain(self.chain)
            else:
                self._utxodb.utxos.clear()
                self._utxodb.flush(force=True)
        except Exception:
            log.exception("[_sync_utxo_store] Failed to rebuild UTXO snapshot")
            return
        self._utxo_dirty = False
        self._utxo_last_flush_height = self.height
        self._utxo_synced = True
