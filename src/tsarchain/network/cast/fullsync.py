# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import time
import secrets
from typing import Any, Dict, Tuple

from ...core.tx import Tx
from ...utils import helpers as H
from ...utils import config as CFG
from .base import BroadcastHandlerProxy
from ...consensus.blockchain import Blockchain

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.fullsync")


class FullSyncHandler(BroadcastHandlerProxy):
    def build_full_sync_payload(self) -> Tuple[Dict[str, Any], int, int, int]:
        start = time.time()
        chain_data, utxo_dict, state_view, mempool_data = self._snapshot_components()
        payload = {
            "type": "FULL_SYNC",
            "data": {
                "chain": chain_data,
                "utxos": utxo_dict,
                "state": state_view,
                "mempool": mempool_data,
            },
            "ts": int(time.time()),
            "nonce": secrets.token_hex(16),
        }
        log.info(
            "[broadcast.build_full_sync_payload] totals blocks=%d utxos=%d mempool=%d assembled in %.2fs",
            len(chain_data),
            len(utxo_dict),
            len(mempool_data),
            time.time() - start,
        )
        return payload, len(chain_data), len(utxo_dict), len(mempool_data)


    def receive_full_sync(self, payload: dict):
        if not CFG.ENABLE_FULL_SYNC:
            return False
        try:
            incoming = payload.get("chain") or []
            if not isinstance(incoming, list) or not incoming:
                return False

            if not self.validate_incoming_chain({"data": incoming}):
                return False

            current_list = [b.to_dict() for b in self.blockchain.chain]
            if not self._is_incoming_chain_better(incoming, current_list):
                return False

            new_chain = Blockchain.from_dict(incoming)
            
            with self.lock:
                replace_start = time.time()
                self.blockchain.replace_with(new_chain)
                log.info(
                    "[full-sync-recv] chain replace applied in %.2fs (blocks=%d)",
                    time.time() - replace_start,
                    len(incoming),
                )
                
                utxo_start = time.time()
                self.rebuild_utxo_from_chain_locked()
                log.info(
                    "[full-sync-recv] utxo/mempool rebuild finished in %.2fs",
                    time.time() - utxo_start,
                )
                
                added = self._apply_mempool_from_sync(payload.get("mempool"))
                self.last_sync_time = time.time()

            log.info(
                "[full-sync-recv] Applied snapshot (blocks=%d, height=%s, mempool_added=%d)",
                len(incoming),
                self.blockchain.height,
                added,
            )
            return True

        except Exception:
            log.exception("[receive_full_sync] Error receiving full sync")
            return False


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _snapshot_components(self):
        snapshot_start = time.time()
        chain_lock = getattr(self.blockchain, "lock", None)
        if chain_lock:
            chain_lock.acquire()
        try:
            chain_objects = list(self.blockchain.chain)
        finally:
            if chain_lock:
                chain_lock.release()
        with self.lock:
            state_view = dict(self.state)
            
        mempool_objects = self.mempool.get_all_txs()  
        chain_data = []
        for block in chain_objects:
            chain_data.append(block.to_dict())
            
        mempool_data = []
        for tx in mempool_objects:
            mempool_data.append(tx.to_dict())
            
        if CFG.KV_BACKEND == "lmdb":
            utxo_dict = H.kv_load_utxo_dict_native(limit=CFG.KV_ITER_CHUNK)
        else:
            utxo_dict = self.utxodb.to_dict()
            
        duration = time.time() - snapshot_start
        log.info(
            "[broadcast.snapshot] chain=%d utxos=%d mempool=%d in %.2fs",
            len(chain_data),
            len(utxo_dict),
            len(mempool_data),
            duration,
        )
        return chain_data, utxo_dict, state_view, mempool_data


    def _is_incoming_chain_better(self, incoming, current_list):
        if not current_list:
            return True
        cw_local = self.calc_chainwork_from_list(current_list)
        cw_remote = self.calc_chainwork_from_list(incoming)
        h_local = self.blockchain.height
        h_remote = incoming[-1].get("height", len(incoming) - 1)
        tip_local = current_list[-1]["hash"]
        tip_remote = incoming[-1].get("hash", "")
        
        if h_remote > h_local:
            return True
        if h_remote < h_local:
            return False
        if cw_remote > cw_local:
            return True
        if cw_remote < cw_local:
            return False
        return tip_remote < tip_local


    def _apply_mempool_from_sync(self, pool):
        added = 0
        if not isinstance(pool, list) or not pool:
            return 0
        for tx_data in pool:
            tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
            if self.mempool.add_valid_tx(tx):
                added += 1
        if added:
            log.info("[receive_full_sync] Mempool updated: %s new transactions", added)
            self.mempool.flush()
        return added


__all__ = ["FullSyncHandler"]
