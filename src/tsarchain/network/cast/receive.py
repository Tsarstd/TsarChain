# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from typing import Any, Dict, Set, Tuple

from ...consensus.blockchain import Blockchain
from ...core.block import Block
from ...core.tx import Tx
from ...storage.utxo import UTXODB
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.receive")


class ReceiveMixin:
    def receive_chain(self, message: Dict[str, Any]) -> bool:
        try:
            if not self._validate_incoming_chain(message):
                return False

            incoming_chain_data = message["data"]
            incoming_chain = Blockchain.from_dict(incoming_chain_data)

            with self.lock:
                current_height = self.blockchain.height
                incoming_height = incoming_chain.height

                current_list = [blk.to_dict() for blk in self.blockchain.chain]
                incoming_list = incoming_chain_data
                cw_local = self._calc_chainwork_from_list(current_list)
                cw_remote = self._calc_chainwork_from_list(incoming_list)
                tip_local = current_list[-1]["hash"] if current_list else ""
                tip_remote = incoming_list[-1]["hash"] if incoming_list else ""

                def is_better():
                    if incoming_height > current_height:
                        return True
                    if incoming_height < current_height:
                        return False
                    if cw_remote > cw_local:
                        return True
                    if cw_remote < cw_local:
                        return False
                    return tip_remote < tip_local

                if is_better():
                    self.blockchain.replace_with(incoming_chain)
                    self._rebuild_utxo_from_chain_locked()
                    return True

                return False

        except Exception:
            log.exception("[receive_chain] Error receiving chain")
            return False

    def receive_block(self, message: Dict[str, Any], addr, peers: Set[Tuple[str, int]]) -> bool:
        block_id = None
        inflight = False
        accepted = False
        try:
            block_data = message.get("data")
            if not block_data:
                return False

            block = Block.deserialize_block(block_data)
            block_id = block.hash().hex()

            origin_port = message.get("port")
            origin = (addr[0], origin_port) if origin_port else None

            with self.lock:
                if block_id in self.seen_blocks or block_id in self._processing_blocks:
                    return True
                self._processing_blocks.add(block_id)
                inflight = True

            last = self.blockchain.get_last_block()
            potential_fork = False
            if last:
                tip_h = last.hash()
                if block.height > last.height + 1:
                    handled = False
                    if self.network:
                        try:
                            self.network.handle_block_gap(block, origin)
                            handled = True
                        except Exception:
                            log.exception("[receive_block] Network handle_block_gap failed")
                    if not handled and CFG.ENABLE_FULL_SYNC:
                        targets = [origin] if origin else list(peers)
                        for p in targets:
                            try:
                                self._request_full_sync(p)
                            except Exception:
                                log.exception("[receive_block] Full sync request to %s failed", p)
                    return False
                if block.prev_block_hash != tip_h:
                    potential_fork = True

            if not potential_fork:
                if not self.blockchain.validate_block(block):
                    reason = getattr(self.blockchain, "_last_block_validation_error", None)
                    if reason:
                        log.warning(
                            "[receive_block] Invalid block received ... block=%s peer=%s reason=%s",
                            block_id[:12],
                            f"{addr[0]}:{origin_port or 0}",
                            reason,
                        )
                    else:
                        log.warning(
                            "[receive_block] Invalid block received ... block=%s peer=%s",
                            block_id[:12],
                            f"{addr[0]}:{origin_port or 0}",
                        )
                    if reason and isinstance(reason, str) and reason.startswith("prevout_missing"):
                        try:
                            if self.network:
                                target = origin if origin else (next(iter(peers)) if peers else None)
                                if target:
                                    self.network._request_full_sync(target, force=True)
                                else:
                                    self.network.request_sync(fast=True)
                        except Exception:
                            log.exception("[receive_block] Failed to trigger full sync after prevout missing")
                    return False

            old_tip = None
            try:
                ok = self.blockchain.add_block(block)
            except ValueError:
                if potential_fork:
                    old_tip = self.blockchain.swap_tip_if_better(block)
                    ok = old_tip is not None
                else:
                    ok = False
            if not ok:
                log.warning("[receive_block] Block at height %s rejected by add_block", block.height)
                if potential_fork:
                    targets = [origin] if origin else list(peers)
                    for p in targets:
                        try:
                            prev_flag = CFG.ENABLE_FULL_SYNC
                            CFG.ENABLE_FULL_SYNC = True
                            self._request_full_sync(p)
                        except Exception:
                            log.exception("[receive_block] Fallback full sync request to %s failed", p)
                        finally:
                            CFG.ENABLE_FULL_SYNC = prev_flag
                return False

            accepted = True

            try:
                removal_candidates: list[str] = []
                for tx in (block.transactions[1:] or []):
                    txid = getattr(tx, "txid", None)
                    if not txid:
                        continue
                    removal_candidates.append(txid.hex() if isinstance(txid, (bytes, bytearray)) else str(txid))
                if removal_candidates:
                    try:
                        removed = self.mempool.remove_many(removal_candidates)
                        missing = len(removal_candidates) - removed
                        if missing > 0:
                            log.debug(
                                "[receive_block] %s mempool tx already absent when pruning confirmed set",
                                missing,
                            )
                    except AttributeError:
                        fail_rm = 0
                        for txid in removal_candidates:
                            try:
                                if not self.mempool.remove_tx(txid):
                                    fail_rm += 1
                            except Exception:
                                fail_rm += 1
                        if fail_rm:
                            log.warning(
                                "[receive_block] %s tx failed to remove from mempool after block addition",
                                fail_rm,
                            )
                try:
                    self.mempool.flush()
                except Exception:
                    log.exception("[receive_block] Error flushing mempool after block acceptance")

                if old_tip:
                    try:
                        for tx in (old_tip.transactions[1:] or []):
                            try:
                                self.mempool.add_valid_tx(tx)
                            except Exception:
                                pass
                    except Exception:
                        log.exception("[receive_block] Error requeueing transactions from orphaned tip")
                try:
                    self.mempool.flush()
                except Exception:
                    log.exception("[receive_block] Failed to flush mempool after block handling")
            except Exception:
                log.exception("[receive_block] Error updating mempool after block acceptance")

            if not self._utxo_shared:
                try:
                    self.utxodb.update(block.transactions, block.height, autosave=False)
                    self._maybe_flush_local_utxo(block.height)
                except Exception:
                    log.exception("[receive_block] Error updating UTXO after block acceptance")

            try:
                recovered = self.mempool.recheck_orphans() if hasattr(self.mempool, "recheck_orphans") else 0
                if recovered:
                    log.info("[receive_block] Revalidated %s orphan mempool txs", recovered)
            except Exception:
                log.exception("[receive_block] Error rechecking orphan mempool txs after block")

            with self.lock:
                self.seen_blocks.add(block_id)

            try:
                self.broadcast_block(block, peers, exclude=origin, force=True)
            except Exception:
                log.exception("[receive_block] Error broadcasting new block to peers")

            return True
        except Exception:
            log.exception("[receive_block] Error processing incoming block")
            return False
        finally:
            if inflight and block_id:
                with self.lock:
                    self._processing_blocks.discard(block_id)
                    if not accepted:
                        self.seen_blocks.discard(block_id)
                    return accepted

    def receive_tx(self, message: Dict[str, Any], addr, peers: Set[Tuple[str, int]]) -> bool:
        try:
            tx_data = message["data"]
            tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
            tx_id = tx.txid.hex()

            with self.lock:
                if tx_id in self.seen_txs:
                    return False
                self.seen_txs.add(tx_id)

            try:
                is_valid = self.mempool.add_valid_tx(tx)
            except Exception:
                log.exception("[receive_tx] Error validating/adding incoming TX")
                return False

            if is_valid:
                self.broadcast_tx(tx, peers)
                return True
            else:
                return False
        except Exception:
            log.exception("[receive_tx] Error processing incoming TX")
            return False

    def receive_utxos(self, message: Dict[str, Any]):
        try:
            utxo_data = message.get("data", {})
            if utxo_data and not self.blockchain.chain:
                self.utxodb = UTXODB.from_dict(utxo_data)
                self._utxo_shared = False
                self._utxo_last_flush_height = -1
                if not self.blockchain.in_memory:
                    self.utxodb.flush(force=True)
            else:
                if utxo_data:
                    log.warning("[receive_utxos] Ignoring UTXO snapshot since we have a non-empty chain")
        except Exception:
            log.exception("[receive_utxos] Error updating UTXO DB")

    def receive_state(self, message: Dict[str, Any]):
        try:
            self.state = message.get("data", {})
        except Exception:
            log.exception("[receive_state] Error updating state")

    def receive_mempool(self, message: Dict[str, Any]):
        try:
            txs_data = message.get("data", [])
            added_count = 0
            for tx_data in txs_data:
                try:
                    tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
                    if self.mempool.add_valid_tx(tx):
                        added_count += 1
                except Exception:
                    log.exception("[receive_mempool] Error adding tx from mempool snapshot")
            try:
                rechecked = self.mempool.recheck_orphans() if hasattr(self.mempool, "recheck_orphans") else 0
                if rechecked:
                    added_count += rechecked
                    log.debug("[receive_mempool] Revalidated %s orphan transactions", rechecked)
            except Exception:
                log.exception("[receive_mempool] Error rechecking orphan transactions")
            if added_count:
                log.info("[receive_mempool] Mempool updated: %s new transactions", added_count)
                try:
                    self.mempool.flush()
                except Exception:
                    log.exception("[receive_mempool] Failed to flush mempool after update")
        except Exception:
            log.exception("[receive_mempool] Error updating mempool")


__all__ = ["ReceiveMixin"]
