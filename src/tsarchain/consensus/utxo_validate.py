# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations
from typing import Optional

# ---------------- Local Project ----------------
from ..storage.utxo import UTXODB
from ..utils import config as CFG
from .genesis import GENESIS_HASH

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.utxo_validate')

class UTXOMixin:
    def _ensure_utxodb(self) -> Optional[UTXODB]:
        if self.in_memory:
            mem_store = getattr(self, "_in_memory_utxodb", None)
            tip_state = getattr(self, "_in_memory_utxo_tip", -1)
            if mem_store is None:
                mem_store = UTXODB(persist=False)
                self._in_memory_utxodb = mem_store
                self._in_memory_utxo_tip = -1
            if tip_state != self.height:
                # rebuild in-place (broadcast/mempool) stay valid
                try:
                    mem_store.utxos.clear()
                    mem_store._dirty = False
                    mem_store._dirty_keys.clear()
                    mem_store._removed_keys.clear()
                    mem_store._rewrite_all = False
                    mem_store.rebuild_from_chain(self.chain)
                except Exception:
                    log.exception("[_ensure_utxodb] failed to rebuild in-memory UTXO store")
                self._in_memory_utxo_tip = self.height
            return mem_store
        
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
        # Saat genesis lock dan chain kosong, hindari flush paksa yang bisa mengosongkan DB yang sudah ada
        if (not self.chain) and not force and GENESIS_HASH is not None and not CFG.ALLOW_AUTO_GENESIS:
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
            if not self.chain:
                # Hindari mengosongkan UTXO saat chain belum termuat (mis. saat genesis lock menunggu sync)
                if getattr(self._utxodb, "utxos", None):
                    log.warning("[_sync_utxo_store] Chain kosong; skip clear_db agar snapshot UTXO tidak hilang")
                    self._utxo_synced = True
                    self._utxo_dirty = False
                    self._utxo_last_flush_height = self.height
                    return
                self._utxodb.utxos.clear()
                self._utxodb.flush(force=True)
            else:
                self._utxodb.rebuild_from_chain(self.chain)
        except Exception:
            log.exception("[_sync_utxo_store] Failed to rebuild UTXO snapshot")
            return
        self._utxo_dirty = False
        self._utxo_last_flush_height = self.height
        self._utxo_synced = True
