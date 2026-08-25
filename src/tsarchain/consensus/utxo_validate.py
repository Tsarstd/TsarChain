# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
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

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .blockchain import Blockchain

class UTXOValidator:
    def __init__(self, blockchain: "Blockchain"):
        self.blockchain = blockchain


    def ensure_utxodb(self) -> Optional[UTXODB]:
        if self.blockchain._utxodb is None:
            self.blockchain._utxodb = UTXODB()
            self.blockchain._utxo_dirty = False
            self.blockchain._utxo_last_flush_height = self.blockchain.height
            if self.blockchain._utxodb.utxos:
                self.blockchain._utxo_synced = True
            else:
                self.blockchain._utxo_synced = False
        if not self.blockchain._utxo_synced:
            self._sync_utxo_store(force=True)
        return self.blockchain._utxodb


    def mark_utxo_dirty(self) -> None:
        self.blockchain._utxo_dirty = True


    def maybe_flush_utxo(self, *, force: bool = False) -> None:
        store = self.ensure_utxodb()
        if store is None:
            return
        # Saat genesis lock dan chain kosong, hindari flush paksa yang bisa mengosongkan DB yang sudah ada
        if (not self.blockchain.chain) and not force:
            return
        current_height = self.blockchain.height
        if force:
            did_flush = store.flush(force=True)
        else:
            if not self.blockchain._utxo_dirty:
                return
            if self.blockchain._utxo_last_flush_height >= 0 and (current_height - self.blockchain._utxo_last_flush_height) < CFG.UTXO_FLUSH_INTERVAL:
                return
            did_flush = store.flush()
        if did_flush:
            self.blockchain._utxo_dirty = False
            self.blockchain._utxo_last_flush_height = current_height


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _sync_utxo_store(self, *, force: bool = False) -> None:
        if self.blockchain._utxodb is None:
            return
        if self.blockchain._utxo_synced and not force:
            return
        if not self.blockchain.chain:
            # Hindari mengosongkan UTXO saat chain belum termuat (mis. saat genesis lock menunggu sync)
            if self.blockchain._utxodb.utxos:
                log.warning("[_sync_utxo_store] Chain kosong; skip clear_db agar snapshot UTXO tidak hilang")
                self.blockchain._utxo_synced = True
                self.blockchain._utxo_dirty = False
                self.blockchain._utxo_last_flush_height = self.blockchain.height
                return
            self.blockchain._utxodb.utxos.clear()
            self.blockchain._utxodb.flush(force=True)
        else:
            self.blockchain._utxodb.rebuild_from_chain(self.blockchain.chain)
        self.blockchain._utxo_dirty = False
        self.blockchain._utxo_last_flush_height = self.blockchain.height
        self.blockchain._utxo_synced = True