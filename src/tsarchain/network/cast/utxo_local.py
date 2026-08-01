# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import time
from typing import Optional

from .base import BroadcastHandlerProxy
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.utxo_local")


class UTXOLocalHandler(BroadcastHandlerProxy):
    
    def maybe_flush_local_utxo(self, height: Optional[int], *, force: bool = False) -> None:
        if self._utxo_shared:
            return

        if force:
            if self.utxodb.flush(force=True):
                log.info("[maybe_flush_local_utxo] forced flush at height=%s", height)
                if height is not None:
                    self._utxo_last_flush_height = height
            return

        if height is None:
            return

        if self._utxo_last_flush_height < 0 or (height - self._utxo_last_flush_height) >= CFG.UTXO_FLUSH_INTERVAL:
            if self.utxodb.flush():
                self._utxo_last_flush_height = height
                log.info(
                    "[maybe_flush_local_utxo] flushed at height=%s interval=%s",
                    height,
                    CFG.UTXO_FLUSH_INTERVAL,
                )


    def rebuild_utxo_from_chain_locked(self):
        if self._utxo_shared:
            log.info("[rebuild_utxo_from_chain_locked] shared UTXO store detected; skipping local rebuild")
            return
    
        rebuild_start = time.time()
        self.utxodb.rebuild_from_chain(self.blockchain.chain)
        self.maybe_flush_local_utxo(self.blockchain.height, force=True)
        self._clean_mempool_after_chain_replace()
        log.info(
            "[rebuild_utxo_from_chain_locked] rebuilt local store in %.2fs",
            time.time() - rebuild_start,
        )


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _clean_mempool_after_chain_replace(self):
        current_mempool = self.mempool.get_all_txs()
        new_mempool = []
        in_chain = set()
        for block in self.blockchain.chain:
            for block_tx in block.transactions:
                in_chain.add(block_tx.txid.hex() if getattr(block_tx, "txid", None) else "")

        for tx in current_mempool:
            if tx.txid.hex() not in in_chain:
                new_mempool.append(tx)

        if hasattr(self.mempool, "save_pool"):
            self.mempool.save_pool(new_mempool)
        else:
            self.mempool.clear()
            for tx in new_mempool:
                self.mempool.add_tx(tx)
            self.mempool.flush()


__all__ = ["UTXOLocalHandler"]
