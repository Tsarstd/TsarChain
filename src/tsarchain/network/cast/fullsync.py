# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import time
from typing import Any, Dict, Tuple

from ...consensus.blockchain import Blockchain
from ...core.tx import Tx
from ...utils import config as CFG


from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.fullsync")


class FullSyncMixin:
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
            
        try:
            mempool_objects = self.mempool.get_all_txs()
        except Exception:
            mempool_objects = []
            
        chain_data = []
        for block in chain_objects:
            try:
                chain_data.append(block.to_dict())
            except Exception:
                continue
            
        mempool_data = []
        for tx in mempool_objects:
            try:
                mempool_data.append(tx.to_dict())
            except Exception:
                continue
            
        try:
            utxo_dict = self.utxodb.to_dict()
        except Exception:
            utxo_dict = {}
            
        duration = time.time() - snapshot_start
        log.info(
            "[broadcast.snapshot] chain=%d utxos=%d mempool=%d in %.2fs",
            len(chain_data),
            len(utxo_dict),
            len(mempool_data),
            duration,
        )
        return chain_data, utxo_dict, state_view, mempool_data

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
        }
        log.info(
            "[broadcast.build_full_sync_payload] totals blocks=%d utxos=%d mempool=%d assembled in %.2fs",
            len(chain_data),
            len(utxo_dict),
            len(mempool_data),
            time.time() - start,
        )
        return payload, len(chain_data), len(utxo_dict), len(mempool_data)

    def send_full_sync(self, peer: Tuple[str, int]):
        try:
            payload, blocks_cnt, utxo_cnt, mempool_cnt = self.build_full_sync_payload()
            send_start = time.time()
            sent = self._send(peer, payload)
            elapsed = time.time() - send_start
            try:
                log.info(
                    "[full-sync-send] Snapshot to %s (%d blocks, %d utxos, %d mempool tx) status=%s elapsed=%.2fs",
                    peer,
                    blocks_cnt,
                    utxo_cnt,
                    mempool_cnt,
                    "ok" if sent else "failed",
                    elapsed,
                )
            except Exception:
                pass
        except Exception as e:
            log.exception(f"[send_full_sync] Error sending full sync to {peer}: {e}")

    def receive_full_sync(self, payload: dict):
        if not CFG.ENABLE_FULL_SYNC:
            return False
        try:
            incoming = payload.get("chain") or []
            if not isinstance(incoming, list) or not incoming:
                return False

            if not self._validate_incoming_chain({"data": incoming}):
                return False

            current_list = [b.to_dict() for b in self.blockchain.chain]
            cw_local = self._calc_chainwork_from_list(current_list)
            cw_remote = self._calc_chainwork_from_list(incoming)
            h_local = self.blockchain.height
            h_remote = incoming[-1].get("height", len(incoming) - 1)
            tip_local = current_list[-1]["hash"] if current_list else ""
            tip_remote = incoming[-1].get("hash", "")

            def is_better():
                if h_remote > h_local:
                    return True
                if h_remote < h_local:
                    return False
                if cw_remote > cw_local:
                    return True
                if cw_remote < cw_local:
                    return False
                return tip_remote < tip_local

            if not is_better() and self.blockchain.chain:
                return False

            new_chain = Blockchain.from_dict(incoming)
            added = 0

            with self.lock:
                replace_start = time.time()
                self.blockchain.replace_with(new_chain)
                log.info(
                    "[full-sync-recv] chain replace applied in %.2fs (blocks=%d)",
                    time.time() - replace_start,
                    len(incoming),
                )
                
                utxo_start = time.time()
                self._rebuild_utxo_from_chain_locked()
                log.info(
                    "[full-sync-recv] utxo/mempool rebuild finished in %.2fs",
                    time.time() - utxo_start,
                )
                
                pool = payload.get("mempool") or []
                if isinstance(pool, list) and pool:
                    for tx_data in pool:
                        try:
                            tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
                            if self.mempool.add_valid_tx(tx):
                                added += 1
                        except Exception:
                            log.exception("[receive_full_sync] Error adding tx from mempool during full sync")
                            
                    if added:
                        log.info("[receive_full_sync] Mempool updated: %s new transactions", added)
                        try:
                            self.mempool.flush()
                        except Exception:
                            log.exception("[receive_full_sync] Failed to flush mempool after update")

                self.last_sync_time = time.time()
            try:
                log.info(
                    "[full-sync-recv] Applied snapshot (blocks=%d, height=%s, mempool_added=%d)",
                    len(incoming),
                    self.blockchain.height,
                    added,
                )
            except Exception:
                pass
            return True

        except Exception:
            log.exception("[receive_full_sync] Error receiving full sync")
            return False


__all__ = ["FullSyncMixin"]
