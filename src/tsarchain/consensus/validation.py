# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: Merkle

from __future__ import annotations

import time
from typing import Optional
from bech32 import bech32_encode, convertbits

# ---------------- Local Project ----------------
from ..core.block import Block
from ..storage.utxo import UTXODB
from ..utils import config as CFG
from ..utils.helpers import bits_to_target, merkle_root
from ..utils import helpers as H
from ..contracts import graffiti as GRAFFITI
from ..contracts.graffiti_registry import GraffitiRegistry
from .genesis import GENESIS_HASH

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.validation')

class ValidationMixin:
# =============================================================================
# 1. VALIDATION PROCESSING
# =============================================================================
    def _compute_txids_for_block(self, block: Block) -> bool:
        try:
            txs = getattr(block, "transactions", []) or []
            for tx in txs:
                raw_no_witness = self._serialize_tx_cached(tx, include_witness=False)
                if raw_no_witness is None:
                    self._last_block_validation_error = "tx_serialize_failed"
                    return False
                txid_bytes = H.hash256(raw_no_witness)
                existing = getattr(tx, "txid", None)
                existing_bytes = None
                if isinstance(existing, (bytes, bytearray)):
                    existing_bytes = bytes(existing)
                elif isinstance(existing, str):
                    try:
                        existing_bytes = bytes.fromhex(existing)
                    except Exception:
                        existing_bytes = None
                if existing_bytes is not None and existing_bytes != txid_bytes:
                    self._last_block_validation_error = "txid_mismatch"
                    return False
                try:
                    setattr(tx, "_cached_txid_bytes", txid_bytes)
                    setattr(tx, "_cached_raw_tx_nowit", raw_no_witness)
                    setattr(tx, "txid", txid_bytes)
                    setattr(tx, "txid_hex", txid_bytes.hex())
                except Exception:
                    pass
            return True
        except Exception:
            self._last_block_validation_error = "txid_compute_failed"
            return False

    def validate_block(self, block: Block) -> bool:
        try:
            if not all([block.height is not None, block.prev_block_hash, block.transactions]):
                return False

            if not self._validate_pow(block):
                return False

            if not self._compute_txids_for_block(block):
                return False

            if not self._validate_merkle(block):
                return False

            if not self._ensure_unique_txids(block):
                return False

            if not self._check_block_limits(block):
                return False

            store = None
            utxo_view = None
            state_token = None
            with self.lock:
                if not self._validate_chain_context_locked(block):
                    return False
                store = self._ensure_utxodb() or UTXODB()
                if not callable(getattr(store, "lookup_entry", None)):
                    try:
                        utxo_view = getattr(store, "utxos", None)
                        if utxo_view is None:
                            utxo_view = store.load_utxo_set()
                    except Exception:
                        utxo_view = None
                state_token = self._chain_state_token_locked()

            if not self._check_sigops_budget(block, store, utxo_view):
                return False

            if block.height > 0 and not self._validate_transactions(block, store):
                return False

            with self.lock:
                if state_token != self._chain_state_token_locked():
                    self._last_block_validation_error = "chain_state_changed_during_validation"
                    return False
                self._last_block_validation_error = None

            return True

        except Exception:
            log.exception("[validate_block] Unexpected error during block validation")
            return False
    
    def _validate_pow(self, block: Block) -> bool:
        try:
            header_hash = block.hash()
            target = bits_to_target(block.bits)
            return int.from_bytes(header_hash, "big") <= int(target)
        except Exception:
            return False

    def _validate_merkle(self, block: Block) -> bool:
        try:
            computed = merkle_root(block.transactions)
            header_mr = getattr(block, "merkle_root", None)
            if isinstance(header_mr, str):
                header_mr = bytes.fromhex(header_mr)
            return computed == header_mr
        except Exception:
            return False

    def _validate_transactions(self, block: Block, utxo_store: UTXODB | None = None) -> bool:
        store = utxo_store or self._ensure_utxodb() or UTXODB()

        self._last_block_validation_error = "validation_failed"
        txs = getattr(block, "transactions", [])
        if not txs:
            self._last_block_validation_error = "empty_block_transactions"
            return False

        cb = txs[0]
        if not getattr(cb, "is_coinbase", False):
            self._last_block_validation_error = "missing_coinbase"
            return False
        if any(getattr(t, "is_coinbase", False) for t in txs[1:]):
            self._last_block_validation_error = "duplicate_coinbase"
            return False

        spend_height = int(getattr(block, "height", 0))

        # Guardrail: ensure each tx serializes and is not absurdly large
        for tx in txs:
            try:
                raw_full = self._serialize_tx_cached(tx, include_witness=True)
            except Exception:
                self._last_block_validation_error = "tx_serialize_failed"
                return False
            if raw_full is None:
                self._last_block_validation_error = "tx_serialize_failed"
                return False
            if len(raw_full) > int(CFG.MAX_BLOCK_BYTES):
                self._last_block_validation_error = "tx_too_large"
                return False

        # Graffiti rule: maximum one POST per block; if there is a POST, the block_id must match its art_id.
        graffiti_posts = 0
        first_art_id = None
        reg = getattr(store, "_graffiti_registry", None)
        if reg is None:
            reg = GraffitiRegistry()

        def _spk_to_address(spk_obj) -> str | None:
            try:
                if hasattr(spk_obj, "serialize"):
                    spk_bytes = spk_obj.serialize()
                elif isinstance(spk_obj, (bytes, bytearray)):
                    spk_bytes = bytes(spk_obj)
                elif isinstance(spk_obj, str):
                    spk_bytes = bytes.fromhex(spk_obj)
                else:
                    return None
                if len(spk_bytes) == 22 and spk_bytes[0] == 0x00 and spk_bytes[1] == 0x14:
                    prog = spk_bytes[2:]
                    data = [0] + list(convertbits(prog, 8, 5, True))
                    return bech32_encode(CFG.ADDRESS_PREFIX, data)
                if len(spk_bytes) == 34 and spk_bytes[0] == 0x00 and spk_bytes[1] == 0x20:
                    prog = spk_bytes[2:]
                    data = [0] + list(convertbits(prog, 8, 5, True))
                    return bech32_encode(CFG.ADDRESS_PREFIX, data)
            except Exception:
                return None
            return None

        for tx in txs[1:]:  # skip coinbase
            for tx_out in getattr(tx, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                try:
                    meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                except Exception:
                    meta = None
                if not meta:
                    continue
                if str(meta.get("event", "")).upper() != "POST":
                    continue
                graffiti_posts += 1
                if not first_art_id:
                    sha_hex = meta.get("sha256")
                    creator = meta.get("creator")
                    art_id = meta.get("art_id")
                    if not art_id and sha_hex and creator:
                        try:
                            art_id = GRAFFITI.compute_art_id(sha_hex, creator)
                        except Exception:
                            art_id = None
                    first_art_id = (art_id or "").strip().lower() if art_id else None
        if graffiti_posts > 1:
            self._last_block_validation_error = "too_many_graffiti_posts"
            return False

        cb_block_id = None
        try:
            cb_block_id = getattr(cb, "block_id", None)
            if isinstance(cb_block_id, str):
                cb_block_id = cb_block_id.strip().lower()
        except Exception:
            cb_block_id = None
        if graffiti_posts == 1 and first_art_id:
            if not cb_block_id or cb_block_id.strip().lower() != first_art_id:
                self._last_block_validation_error = "block_id_mismatch_graffiti"
                return False

        # Graffiti payout validation: enforce epoch monotonic + payout shortfall/overdraw checks.
        for tx in txs[1:]:
            # Map outputs by address for quick lookup
            paymap: dict[str, int] = {}
            for out in getattr(tx, "outputs", []) or []:
                addr = _spk_to_address(getattr(out, "script_pubkey", None))
                if not addr:
                    continue
                try:
                    amt = int(getattr(out, "amount", 0))
                except Exception:
                    amt = 0
                if amt <= 0:
                    continue
                paymap[addr.strip().lower()] = paymap.get(addr.strip().lower(), 0) + amt

            for out in getattr(tx, "outputs", []) or []:
                spk = getattr(out, "script_pubkey", None)
                try:
                    meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                except Exception:
                    meta = None
                if not meta or str(meta.get("event", "")).upper() != "PAYOUT":
                    continue
                art_id = str(meta.get("art_id") or "").strip().lower()
                if not art_id:
                    self._last_block_validation_error = "payout_bad_art_id"
                    return False
                post = reg.get_post(art_id) if reg else None
                if not post:
                    self._last_block_validation_error = "payout_unknown_art"
                    return False
                stats = post.get("stats") or {}
                pool_balance = int(stats.get("pool_balance", 0))
                last_epoch = int(stats.get("last_paid_epoch", -1))
                try:
                    epoch = int(meta.get("epoch", -1))
                except Exception:
                    epoch = -1
                if epoch >= 0 and epoch <= last_epoch:
                    self._last_block_validation_error = "payout_epoch_rewind"
                    return False
                # Proof gating: require latest proof epoch >= payout epoch when epoch is provided
                if epoch >= 0:
                    latest_proof = reg.get_latest_proof_epoch(art_id)
                    if latest_proof < epoch:
                        # Allow inline proof metadata in payout OP_RETURN to satisfy gating for stateless peers.
                        proof_epoch = None
                        try:
                            proof_epoch = int(meta.get("proof_epoch", -1))
                        except Exception:
                            proof_epoch = None
                        if proof_epoch is None or proof_epoch < 0:
                            try:
                                proof_height = int(meta.get("proof_height", meta.get("height", -1)))
                            except Exception:
                                proof_height = -1
                            if proof_height >= 0:
                                try:
                                    proof_epoch = GRAFFITI.compute_proof_epoch(proof_height)
                                except Exception:
                                    proof_epoch = None
                        if proof_epoch is None or proof_epoch < epoch:
                            self._last_block_validation_error = "payout_missing_proof"
                            return False
                        
                recs = meta.get("recipients") or []
                if not isinstance(recs, list) or not recs:
                    self._last_block_validation_error = "payout_no_recipients"
                    return False
                total_req = 0
                for rec in recs:
                    addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
                    try:
                        amt_req = int(rec.get("amount", 0))
                    except Exception:
                        amt_req = 0
                    if not addr or amt_req <= 0:
                        self._last_block_validation_error = "payout_bad_recipient"
                        return False
                    total_req += amt_req
                    paid = paymap.get(addr, 0)
                    if paid < amt_req:
                        self._last_block_validation_error = "payout_shortfall"
                        return False
                if total_req > pool_balance:
                    self._last_block_validation_error = "payout_exceeds_pool"
                    return False

        def _script_to_bytes(spk_obj):
            if spk_obj is None:
                return None
            if isinstance(spk_obj, dict):
                spk_obj = spk_obj.get("script_pubkey", spk_obj.get("script"))
            if isinstance(spk_obj, (bytes, bytearray)):
                return bytes(spk_obj)
            if isinstance(spk_obj, str):
                try:
                    return bytes.fromhex(spk_obj)
                except Exception:
                    return None
            script_attr = getattr(spk_obj, "script_pubkey", None)
            if script_attr is not None:
                spk_obj = script_attr
            if hasattr(spk_obj, "serialize"):
                try:
                    return spk_obj.serialize()
                except Exception:
                    return None
            if hasattr(spk_obj, "to_bytes"):
                try:
                    return bytes(spk_obj.to_bytes())
                except Exception:
                    return None
            return None

        def _txid_hex(value):
            if value is None:
                return None
            if isinstance(value, (bytes, bytearray)):
                return value.hex()
            return str(value)

        store_lookup = getattr(store, "lookup_entry", None)
        utxo_view = None
        if not callable(store_lookup):
            try:
                utxo_view = getattr(store, "utxos", None)
                if utxo_view is None:
                    utxo_view = store.load_utxo_set()
            except Exception:
                try:
                    utxo_view = store.load_utxo_set()
                except Exception:
                    log.exception("[_validate_transactions] Cannot load fallback UTXO view")
                    self._last_block_validation_error = "utxo_view_unavailable"
                    return False

        def _legacy_lookup(snapshot_map, prev_txid_hex: str, prev_index: int):
            if not isinstance(snapshot_map, dict):
                return None
            key = f"{prev_txid_hex}:{int(prev_index)}"
            entry = snapshot_map.get(key) or snapshot_map.get(key.lower())
            if entry is not None:
                return entry
            try:
                entry = snapshot_map.get(key.encode("utf-8"))
                if entry is not None:
                    return entry
            except Exception:
                pass
            bucket = snapshot_map.get(prev_txid_hex) or snapshot_map.get(prev_txid_hex.lower())
            if isinstance(bucket, dict) and int(prev_index) in bucket:
                return bucket[int(prev_index)]
            tuple_key = (prev_txid_hex, int(prev_index))
            if tuple_key in snapshot_map:
                return snapshot_map[tuple_key]
            try:
                tuple_b = (bytes.fromhex(prev_txid_hex), int(prev_index))
            except ValueError:
                tuple_b = None
            if tuple_b and tuple_b in snapshot_map:
                return snapshot_map[tuple_b]
            lookup_key_ci = key.lower()
            if len(snapshot_map) <= 2048:
                for candidate_key, candidate_value in snapshot_map.items():
                    try:
                        if isinstance(candidate_key, str) and candidate_key.lower() == lookup_key_ci:
                            return candidate_value
                        if isinstance(candidate_key, tuple) and len(candidate_key) == 2:
                            txid_part, vout_part = candidate_key
                            if int(vout_part) != int(prev_index):
                                continue
                            if isinstance(txid_part, (bytes, bytearray)):
                                txid_cmp = txid_part.hex().lower()
                            else:
                                txid_cmp = str(txid_part).lower()
                            if txid_cmp == prev_txid_hex.lower():
                                return snapshot_map[candidate_key]
                    except Exception:
                        continue
            return None

        def _resolve_prevout(prev_txid_hex: str, prev_index: int):
            if callable(store_lookup):
                try:
                    return store_lookup(prev_txid_hex, prev_index)
                except Exception:
                    return None
            return _legacy_lookup(utxo_view, prev_txid_hex, prev_index)

        def _normalize_snapshot_entry(entry, key_desc: str):
            candidate = entry
            if isinstance(candidate, dict):
                tx_out = candidate.get("tx_out") or candidate
            else:
                tx_out = getattr(candidate, "tx_out", None) or candidate
            script_bytes = _script_to_bytes(tx_out)
            if script_bytes is None and isinstance(candidate, dict):
                script_bytes = _script_to_bytes(candidate.get("script_pubkey"))
            if script_bytes is None:
                log.debug("[native_snapshot] entry %s missing script", key_desc)
                return None
            if isinstance(tx_out, dict):
                amount_val = tx_out.get("amount")
            elif hasattr(tx_out, "amount"):
                amount_val = getattr(tx_out, "amount", None)
            else:
                amount_val = getattr(candidate, "amount", None)
            try:
                amt = int(amount_val if amount_val is not None else 0)
            except Exception:
                log.debug("[native_snapshot] entry %s amount invalid (%s)", key_desc, amount_val)
                return None
            if isinstance(candidate, dict):
                is_cb = bool(candidate.get("is_coinbase", False))
                born = int(candidate.get("block_height", candidate.get("height", 0)))
            else:
                is_cb = bool(getattr(candidate, "is_coinbase", False))
                born = int(getattr(candidate, "block_height", getattr(candidate, "height", 0)) or 0)
            return {
                "amount": amt,
                "script_pubkey": script_bytes,
                "is_coinbase": is_cb,
                "block_height": born,
            }

        processed_txids = set()
        snapshot: dict[str, dict] = {}
        for tx in txs:
            txid_hex = _txid_hex(getattr(tx, "txid", None))
            if txid_hex is None and hasattr(tx, "compute_txid"):
                try:
                    tx.compute_txid()
                    txid_hex = _txid_hex(getattr(tx, "txid", None))
                except Exception:
                    txid_hex = None
            txid_lower = txid_hex.lower() if txid_hex else None
            if getattr(tx, "is_coinbase", False):
                if txid_lower:
                    processed_txids.add(txid_lower)
                continue
            for tx_input in getattr(tx, "inputs", []) or []:
                prev_txid_hex = _txid_hex(getattr(tx_input, "txid", None) or getattr(tx_input, "prev_tx", None))
                if prev_txid_hex is None:
                    self._last_block_validation_error = "tx_input_missing_prev_txid"
                    return False
                try:
                    prev_index = int(getattr(tx_input, "vout", getattr(tx_input, "prev_index", 0)))
                except Exception:
                    self._last_block_validation_error = "tx_input_invalid_prev_index"
                    return False
                if prev_txid_hex.lower() in processed_txids:
                    continue
                snap_key = f"{prev_txid_hex.lower()}:{prev_index}"
                if snap_key in snapshot:
                    continue
                entry = _resolve_prevout(prev_txid_hex.lower(), prev_index)
                if entry is None:
                    self._last_block_validation_error = f"prevout_missing {prev_txid_hex}:{prev_index}"
                    return False
                normalized = _normalize_snapshot_entry(entry, snap_key)
                if normalized is None:
                    self._last_block_validation_error = "native_snapshot_invalid_entry"
                    return False
                snapshot[snap_key] = normalized
            if txid_lower:
                processed_txids.add(txid_lower)

        def _build_block_payload_compact(tx_list, snapshot_dict):
            tx_payloads = []
            for tx in tx_list:
                try:
                    compact = H.tx_to_compact_tuple(tx)
                    tx_payloads.append(compact)
                except Exception:
                    return None

            utxo_items = []
            for key, entry in snapshot_dict.items():
                try:
                    if isinstance(key, bytes):
                        key = key.decode("utf-8")
                    if ":" not in key:
                        continue
                    txid_hex, vout_str = key.split(":", 1)
                    txid_b = bytes.fromhex(txid_hex)
                    vout_i = int(vout_str)
                    utxo_items.append((
                        txid_b,
                        vout_i,
                        int(entry.get("amount", 0)),
                        bytes(entry.get("script_pubkey", b"")),
                        bool(entry.get("is_coinbase", False)),
                        int(entry.get("block_height", 0)),
                    ))
                except Exception:
                    continue
            return tx_payloads, utxo_items

        opts = {
            "coinbase_maturity": int(CFG.COINBASE_MATURITY),
            "max_sigops_per_tx": int(CFG.MAX_SIGOPS_PER_TX),
            "max_sigops_per_block": int(CFG.MAX_SIGOPS_PER_BLOCK),
            "enforce_low_s": True,
        }
        payload_txs, payload_utxo = _build_block_payload_compact(txs, snapshot) or (None, None)
        try:
            if payload_txs is not None and payload_utxo is not None:
                ok, reason, fees = H.native_validate_block_txs_compact(
                    payload_txs,
                    payload_utxo,
                    spend_height,
                    opts,
                )
            else:
                ok, reason, fees = H.native_validate_block_txs(
                    block.to_dict(),
                    snapshot,
                    spend_height,
                    opts,
                )
        except Exception:
            log.exception("[_validate_transactions] Native block validator failed")
            self._last_block_validation_error = "native_validation_failed"
            return False

        if not ok:
            self._last_block_validation_error = reason or "native_validation_failed"
            return False

        fees_list = []
        if isinstance(fees, (list, tuple)):
            if len(fees) != max(len(txs) - 1, 0):
                self._last_block_validation_error = "fee_mismatch"
                return False
            for tx_obj, fee_val in zip(txs[1:], fees):
                fee_int = int(fee_val)
                fees_list.append(fee_int)
                try:
                    tx_obj.fee = fee_int
                except Exception:
                    setattr(tx_obj, "fee", fee_int)
        else:
            fees_list = [int(getattr(t, "fee", 0)) for t in txs[1:]]

        minted_before = self._cumulative_supply_until(block.height)
        base = self._scheduled_reward(block.height)
        reward = min(max(0, base), max(0, CFG.MAX_SUPPLY - minted_before))
        total_fee = sum(fees_list)
        expected_cb = reward + total_fee

        actual_cb = sum(int(o.amount) for o in getattr(cb, "outputs", []))
        if actual_cb != expected_cb:
            self._last_block_validation_error = f"coinbase_amount_mismatch expected={expected_cb} actual={actual_cb}"
            return False

        self._last_block_validation_error = None
        return True


# =============================================================================
# 2. HELPER
# =============================================================================
    def _serialize_tx_cached(self, tx, *, include_witness: bool) -> bytes | None:
        """
        Cache serialize_tx hasil untuk menghindari hashing/serialisasi berulang
        pada jalur panas validasi.
        """
        attr = "_cached_raw_tx_w" if include_witness else "_cached_raw_tx_nowit"
        buf = getattr(tx, attr, None)
        if isinstance(buf, (bytes, bytearray)):
            return bytes(buf)
        try:
            raw = H.serialize_tx(tx, include_witness=include_witness)
        except Exception:
            return None
        try:
            setattr(tx, attr, raw)
        except Exception:
            pass
        return raw

    def _estimate_block_size(self, block: Block) -> Optional[int]:
        try:
            size = 80  # header
            for tx in block.transactions or []:
                cached = getattr(tx, "_cached_raw_tx_w", None)
                if isinstance(cached, (bytes, bytearray)):
                    size += len(cached); continue
                if hasattr(tx, 'serialize') and callable(getattr(tx, 'serialize', None)):
                    try:
                        raw = tx.serialize()
                        size += len(raw if isinstance(raw, (bytes, bytearray)) else bytes.fromhex(raw))
                        continue
                    except Exception:
                        pass
                if hasattr(tx, 'raw') and isinstance(getattr(tx, 'raw'), (bytes, bytearray)):
                    size += len(tx.raw); continue
                if hasattr(tx, 'size_bytes'):
                    v = tx.size_bytes
                    if callable(v): size += int(v()); 
                    else: size += int(v); continue
                return None
            return int(size)
        except Exception:
            return None

    def _count_block_sigops(self, block: Block) -> Optional[int]:
        total = 0
        try:
            for tx in block.transactions or []:
                if hasattr(tx, 'sigops_count') and callable(getattr(tx, 'sigops_count', None)):
                    total += int(tx.sigops_count()); continue
                if hasattr(tx, 'count_sigops') and callable(getattr(tx, 'count_sigops', None)):
                    total += int(tx.count_sigops()); continue
                return None
            return total
        except Exception:
            return None

    def _chain_state_token_locked(self):
        tip_hash = self.chain[-1].hash() if self.chain else None
        return (self.height, tip_hash)

    def _validate_chain_context_locked(self, block: Block) -> bool:
        expected_height = self.height + 1 if self.chain else 0
        if block.height != expected_height:
            return False
        if self.chain and block.prev_block_hash != self.chain[-1].hash():
            return False
        if not self.chain and (block.height != 0 or block.prev_block_hash != CFG.ZERO_HASH):
            return False
        if not self.chain and block.height == 0 and GENESIS_HASH is not None:
            if block.hash() != GENESIS_HASH:
                return False
        mtp = self.median_time_past(CFG.MTP_WINDOWS)
        if block.timestamp < mtp:
            return False
        if block.timestamp > int(time.time()) + CFG.FUTURE_DRIFT:
            return False
        if self.chain:
            parent_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)
            if block.timestamp + int(CFG.TARGET_BLOCK_TIME) < parent_ts:
                return False
        if not self._validate_difficulty(block):
            return False
        return True

    def _ensure_unique_txids(self, block: Block) -> bool:
        try:
            seen_txids = set()
            for tx in (block.transactions or []):
                if hasattr(tx, 'compute_txid') and (getattr(tx, 'txid', None) is None):
                    try:
                        tx.compute_txid()
                    except Exception:
                        return False
                txid_b = getattr(tx, 'txid', None)
                if not isinstance(txid_b, (bytes, bytearray)):
                    try:
                        txid_b = bytes.fromhex(txid_b) if isinstance(txid_b, str) else None
                    except Exception:
                        txid_b = None
                if txid_b is None:
                    return False
                if txid_b in seen_txids:
                    return False
                seen_txids.add(txid_b)
            return True
        except Exception:
            return False

    def _check_block_limits(self, block: Block) -> bool:
        try:
            txs_ex_coinbase = max(0, (len(block.transactions) or 0) - 1)
            if txs_ex_coinbase > CFG.MAX_TXS_PER_BLOCK:
                return False
            est_size = self._estimate_block_size(block)
            if est_size is not None and est_size > CFG.MAX_BLOCK_BYTES:
                return False
            return True
        except Exception:
            return False

    def _entry_script_bytes(self, entry) -> bytes | None:
        candidate = entry
        if isinstance(candidate, dict):
            tx_out = candidate.get("tx_out") or candidate
        else:
            tx_out = getattr(candidate, "tx_out", None) or candidate
        spk = None
        if isinstance(tx_out, dict):
            spk = tx_out.get("script_pubkey")
        elif hasattr(tx_out, "script_pubkey"):
            spk = tx_out.script_pubkey
        if spk is None and isinstance(candidate, dict):
            spk = candidate.get("script_pubkey")
        if spk is None:
            return None
        if hasattr(spk, "serialize"):
            try:
                return spk.serialize()
            except Exception:
                return None
        if isinstance(spk, (bytes, bytearray)):
            return bytes(spk)
        if isinstance(spk, str):
            try:
                return bytes.fromhex(spk)
            except Exception:
                return None
        return None

    def _check_sigops_budget(self, block: Block, store: UTXODB, utxo_view) -> bool:
        lookup_fn = getattr(store, "lookup_entry", None)

        def _utxo_lookup(txid_b: bytes, vout_i: int):
            entry = None
            if callable(lookup_fn):
                try:
                    entry = lookup_fn(txid_b.hex(), int(vout_i))
                except Exception:
                    entry = None
            elif isinstance(utxo_view, dict):
                key = f"{txid_b.hex()}:{int(vout_i)}"
                entry = utxo_view.get(key) or utxo_view.get(key.lower())
            if entry is None:
                return None
            return self._entry_script_bytes(entry)

        try:
            total_sigops = 0
            for tx in (block.transactions or []):
                if getattr(tx, "is_coinbase", False):
                    continue
                if hasattr(tx, "sigops_count"):
                    so = int(tx.sigops_count(_utxo_lookup))
                else:
                    so = len(getattr(tx, "inputs", []))
                if so > int(CFG.MAX_SIGOPS_PER_TX):
                    return False
                total_sigops += so
            if total_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
                return False
            return True
        except Exception:
            est_sigops = self._count_block_sigops(block)
            if est_sigops is not None and est_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
                return False
            return True

