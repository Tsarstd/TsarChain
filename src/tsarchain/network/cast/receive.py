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
from ...utils.helpers import native_validate_block_txs, native_validate_block_txs_compact

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.receive")


class ReceiveMixin:
    @staticmethod
    def _native_script_hex(candidate) -> str | None:
        if candidate is None:
            return None
        if hasattr(candidate, "serialize"):
            try:
                return candidate.serialize().hex()
            except Exception:
                log.exception("[_native_script_hex] unexpected error")
                return None
        if isinstance(candidate, (bytes, bytearray)):
            return bytes(candidate).hex()
        if isinstance(candidate, str):
            return candidate.lower()
        script_attr = getattr(candidate, "script_pubkey", None)
        if script_attr is not None:
            return ReceiveMixin._native_script_hex(script_attr)
        return None

    @staticmethod
    def _native_script_bytes(candidate) -> bytes | None:
        if candidate is None:
            return None
        if hasattr(candidate, "serialize"):
            return candidate.serialize()
        if isinstance(candidate, (bytes, bytearray)):
            return bytes(candidate)
        if isinstance(candidate, str):
            return bytes.fromhex(candidate)
        script_attr = getattr(candidate, "script_pubkey", None)
        if script_attr is not None:
            return ReceiveMixin._native_script_bytes(script_attr)
        return None

    def _normalize_native_prevout(self, entry, key_desc: str):
        candidate = entry
        if isinstance(candidate, dict):
            tx_out = candidate.get("tx_out") or candidate
        else:
            tx_out = getattr(candidate, "tx_out", None) or candidate

        script_bytes = self._native_script_bytes(tx_out)
        if script_bytes is None and isinstance(candidate, dict):
            script_bytes = self._native_script_bytes(candidate.get("script_pubkey"))
        if script_bytes is None:
            return None

        if isinstance(tx_out, dict):
            amount_val = tx_out.get("amount")
        elif hasattr(tx_out, "amount"):
            amount_val = getattr(tx_out, "amount", None)
        else:
            amount_val = getattr(candidate, "amount", None)
        amount_int = int(amount_val if amount_val is not None else 0)

        if isinstance(candidate, dict):
            is_cb = bool(candidate.get("is_coinbase", False))
            born = int(candidate.get("block_height", candidate.get("height", 0)))
        else:
            is_cb = bool(getattr(candidate, "is_coinbase", False))
            born = int(getattr(candidate, "block_height", getattr(candidate, "height", 0)) or 0)

        return amount_int, script_bytes, is_cb, born

    def _build_native_prevout_snapshot(self, block: Block):
        lookup = getattr(self.utxodb, "lookup_entry", None)
        if not callable(lookup):
            return None

        txs = getattr(block, "transactions", []) or []
        if not txs:
            return {}

        snapshot: dict[str, dict] = {}
        utxo_items: list[tuple] = []
        processed_txids: set[str] = set()

        def _txid_lower(value) -> str | None:
            if value is None:
                return None
            if isinstance(value, (bytes, bytearray)):
                return bytes(value).hex().lower()
            return str(value).lower()

        for tx in txs:
            txid_lower = _txid_lower(getattr(tx, "txid", None))
            if getattr(tx, "is_coinbase", False):
                if txid_lower:
                    processed_txids.add(txid_lower)
                continue

            for tx_input in getattr(tx, "inputs", []) or []:
                prev_txid_lower = _txid_lower(getattr(tx_input, "txid", None) or getattr(tx_input, "prev_tx", None))
                if prev_txid_lower is None:
                    return None
                prev_index = int(getattr(tx_input, "vout", getattr(tx_input, "prev_index", 0)))
                if prev_txid_lower in processed_txids:
                    continue
                snap_key = f"{prev_txid_lower}:{prev_index}"
                if snap_key in snapshot:
                    continue
                entry = lookup(prev_txid_lower, prev_index)
                if entry is None:
                    return None
                normalized = self._normalize_native_prevout(entry, snap_key)
                if normalized is None:
                    return None
                amount_int, script_bytes, is_cb, born = normalized
                snapshot[snap_key] = {
                    "amount": amount_int,
                    "script_pubkey": script_bytes,
                    "is_coinbase": is_cb,
                    "block_height": born,
                }
                txid_b = bytes.fromhex(prev_txid_lower)
                utxo_items.append((txid_b, int(prev_index), amount_int, script_bytes, is_cb, born))

            if txid_lower:
                processed_txids.add(txid_lower)

        return snapshot, utxo_items

    def _native_precheck_block(self, block: Block) -> bool:
        snapshot = self._build_native_prevout_snapshot(block)
        if snapshot is None:
            return True
        if isinstance(snapshot, tuple) and len(snapshot) == 2:
            snapshot_dict, utxo_items = snapshot
        else:
            snapshot_dict, utxo_items = snapshot, None

        opts = {
            "coinbase_maturity": int(CFG.COINBASE_MATURITY),
            "max_sigops_per_tx": int(CFG.MAX_SIGOPS_PER_TX),
            "max_sigops_per_block": int(CFG.MAX_SIGOPS_PER_BLOCK),
            "enforce_low_s": True,
        }
        try:
            if utxo_items is not None:
                tx_payloads = []
                for tx in getattr(block, "transactions", []) or []:
                    version = int(getattr(tx, "version", 1))
                    locktime = int(getattr(tx, "locktime", 0))
                    inputs_payload = []
                    for tx_input in getattr(tx, "inputs", []) or []:
                        prev_txid_b = getattr(tx_input, "txid", None) or getattr(tx_input, "prev_tx", None)
                        if isinstance(prev_txid_b, str):
                            prev_txid_b = bytes.fromhex(prev_txid_b)
                        if not isinstance(prev_txid_b, (bytes, bytearray)) or len(prev_txid_b) != 32:
                            raise ValueError("txid_missing")
                        prev_index = int(getattr(tx_input, "vout", getattr(tx_input, "prev_index", 0)))
                        seq = int(getattr(tx_input, "sequence", 0xffffffff))
                        wit_vec = []
                        for w in getattr(tx_input, "witness", None) or []:
                            if isinstance(w, (bytes, bytearray)):
                                wit_vec.append(bytes(w))
                            elif isinstance(w, str):
                                wit_vec.append(bytes.fromhex(w))
                            else:
                                raise ValueError("witness_invalid")
                        inputs_payload.append((bytes(prev_txid_b), prev_index, seq, wit_vec))
                    outputs_payload = []
                    for tx_out in getattr(tx, "outputs", []) or []:
                        amt = int(getattr(tx_out, "amount", tx_out.get("amount") if isinstance(tx_out, dict) else 0))
                        spk_obj = getattr(tx_out, "script_pubkey", tx_out.get("script_pubkey") if isinstance(tx_out, dict) else None)
                        spk_bytes = self._native_script_bytes(spk_obj)
                        if spk_bytes is None:
                            raise ValueError("spk_missing")
                        outputs_payload.append((amt, spk_bytes))
                    txid_b = getattr(tx, "txid", None)
                    if isinstance(txid_b, str):
                        txid_b = bytes.fromhex(txid_b)
                    if not isinstance(txid_b, (bytes, bytearray)) or len(txid_b) != 32:
                        raise ValueError("txid_missing")
                    tx_payloads.append((version, locktime, inputs_payload, outputs_payload, bytes(txid_b), bool(getattr(tx, "is_coinbase", False))))
                    
                if tx_payloads is not None:
                    ok, reason, fees = native_validate_block_txs_compact(
                        tx_payloads,
                        utxo_items,
                        int(getattr(block, "height", 0) or 0),
                        opts,
                    )
                else:
                    ok, reason, fees = native_validate_block_txs(
                        block.to_dict(),
                        snapshot_dict,
                        int(getattr(block, "height", 0) or 0),
                        opts,
                    )
            else:
                ok, reason, fees = native_validate_block_txs(
                    block.to_dict(),
                    snapshot_dict,
                    int(getattr(block, "height", 0) or 0),
                    opts,
                )
        except Exception:
            log.exception("[_native_precheck_block] unexpected error")
            log.debug("[native-precheck] validator failed; falling back", exc_info=True)
            return True

        if not ok:
            blk_label = block.hash().hex()[:12]
            log.warning("[native-precheck] block %s rejected (%s)", blk_label, reason or "unknown")
            return False

        if isinstance(fees, (list, tuple)):
            block._native_fee_hint = [int(f) for f in fees]  # type: ignore[attr-defined]
        return True

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
                        self.network.handle_block_gap(block, origin)
                        handled = True
                    if not handled and CFG.ENABLE_FULL_SYNC:
                        targets = [origin] if origin else list(peers)
                        for p in targets:
                            self._request_full_sync(p)
                    return False
                if block.prev_block_hash != tip_h:
                    potential_fork = True

            if not potential_fork:
                if not self._native_precheck_block(block):
                    return False
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
                        if self.network:
                            target = origin if origin else (next(iter(peers)) if peers else None)
                            if target:
                                self.network._request_full_sync(target, force=True)
                            else:
                                self.network.request_sync(fast=True)
                    return False

            old_tip = None
            ok = self.blockchain.add_block(block)
            if not ok:
                log.warning("[receive_block] Block at height %s rejected by add_block", block.height)
                if potential_fork:
                    targets = [origin] if origin else list(peers)
                    for p in targets:
                        CFG.ENABLE_FULL_SYNC = True
                        self._request_full_sync(p)
                return False
            
            accepted = True
            removal_candidates: list[str] = []
            for tx in (block.transactions[1:] or []):
                txid = getattr(tx, "txid", None)
                if not txid:
                    continue
                removal_candidates.append(txid.hex() if isinstance(txid, (bytes, bytearray)) else str(txid))
                
            if removal_candidates:
                removed = self.mempool.remove_many(removal_candidates)
                missing = len(removal_candidates) - removed
                if missing > 0:
                    log.debug(
                        "[receive_block] %s mempool tx already absent when pruning confirmed set",
                        missing,
                    )
            self.mempool.flush()

            if old_tip:
                for tx in (old_tip.transactions[1:] or []):
                    self.mempool.add_valid_tx(tx)
            self.mempool.flush()

            if not self._utxo_shared:
                blk_hash = block.hash().hex()
                self.utxodb.update(block.transactions, block.height, block_hash=blk_hash, autosave=False)
                self._maybe_flush_local_utxo(block.height)

            recovered = self.mempool.recheck_orphans() if hasattr(self.mempool, "recheck_orphans") else 0
            if recovered:
                log.info("[receive_block] Revalidated %s orphan mempool txs", recovered)

            with self.lock:
                self.seen_blocks.add(block_id)

            self.broadcast_block(block, peers, exclude=origin, force=True)

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
            phase = str(message.get("phase") or "fluff").strip().lower()

            use_dandelion = False
            dpp = getattr(self, "dandelion", None)
            use_dandelion = bool(dpp and dpp.enabled(len(peers)))
            is_stem = use_dandelion and phase == "stem"
            if not is_stem:
                with self.lock:
                    if tx_id in self.seen_txs:
                        return False
                    self.seen_txs.add(tx_id)

            is_valid = self.mempool.add_valid_tx(tx)

            if is_valid:
                if is_stem:
                    handled = self.dandelion.handle_inbound_stem(tx, tx_id, peers, origin=addr)
                    if not handled:
                        # fallback to fluff if handler declines
                        self._broadcast_tx_fluff(tx, tx_id, peers)
                else:
                    self._broadcast_tx_fluff(tx, tx_id, peers)
                return True
            else:
                return False
        except Exception:
            log.exception("[receive_tx] Error processing incoming TX")
            return False

    def receive_utxos(self, message: Dict[str, Any]):
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

    def receive_state(self, message: Dict[str, Any]):
        self.state = message.get("data", {})

    def receive_mempool(self, message: Dict[str, Any]):
        try:
            if self.network and hasattr(self.network, "is_caught_up"):
                if not self.network.is_caught_up(freshness=20.0, height_slack=0):
                    setattr(self.network, "_pending_mempool_pull", True)
                    self.network.request_sync(fast=True)
                    return
            if int(getattr(self.blockchain, "height", -1)) < 0:
                setattr(self.network, "_pending_mempool_pull", True)
                self.network.request_sync(fast=True)
                return

            txs_data = message.get("data", [])
            added_count = 0
            for tx_data in txs_data:
                tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
                if self.mempool.add_valid_tx(tx):
                    added_count += 1
            rechecked = self.mempool.recheck_orphans() if hasattr(self.mempool, "recheck_orphans") else 0
            if rechecked:
                added_count += rechecked
                log.debug("[receive_mempool] Revalidated %s orphan transactions", rechecked)
            if added_count:
                log.info("[receive_mempool] Mempool updated: %s new transactions", added_count)
                self.mempool.flush()
        except Exception:
            log.exception("[receive_mempool] Error updating mempool")


__all__ = ["ReceiveMixin"]
