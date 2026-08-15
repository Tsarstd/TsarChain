# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: Merkle

from __future__ import annotations

import time
import threading

from typing import Optional
from typing import TYPE_CHECKING
from bech32 import bech32_encode, convertbits

# ---------------- Local Project ----------------
from ..core.block import Block
from ..utils import helpers as H
from ..storage.utxo import UTXODB
from .genesis import GENESIS_HASH
from ..utils import config as CFG
from ..utils.benchmarks import benchmark
from ..contracts import graffiti as GRAFFITI
from ..utils.helpers import bits_to_target, merkle_root
from ..contracts.graffiti_registry import GraffitiRegistry

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.consensus.validation")

if TYPE_CHECKING:
    from .blockchain import Blockchain

class BlockValidator:
    def __init__(self, blockchain: "Blockchain"):
        self.blockchain = blockchain

    _pow_light_warmed = False
    _pow_warm_next_epoch: int | None = None
    _pow_warm_lock = threading.Lock()
    _pow_epoch_warmed: set[int] = set()

    # =============================================================================
    # 1. VALIDATION PROCESSING
    # =============================================================================

    @benchmark(label="validate_block", threshold_ms=200.0)
    def validate_block(self, block: Block) -> bool:
        try:
            # 1. Check Field Completeness
            if not all([block.height is not None, block.prev_block_hash, block.transactions]):
                self.blockchain._last_block_validation_error = "block_missing_fields"
                return False

            # 2. Warm-up POW
            b_height = int(getattr(block, "height", 0))
            self._warm_pow_context(b_height)
            self._ensure_warm(b_height)

            if not self.__class__._pow_light_warmed and CFG.POW_ALGO == "randomx":
                H.pow_hash_verify_light(block.header(), height=block.height)
            else:
                self.__class__._pow_light_warmed = True

            # 3. Main Block Validation Set
            validation_steps = [
                (self._validate_pow, "pow_invalid"),
                (self.compute_txids_for_block, None),
                (self._validate_merkle, "merkle_mismatch"),
                (self._ensure_unique_txids, "duplicate_or_missing_txid"),
                (self._check_block_limits, "block_limits_exceeded"),
            ]

            for validate_func, err_msg in validation_steps:
                if not validate_func(block):
                    self.blockchain._last_block_validation_error = err_msg or self.blockchain._last_block_validation_error
                    return False

            # 4. State & Chain Context Validation
            with self.blockchain.lock:
                if not self._validate_chain_context_locked(block):
                    self.blockchain._last_block_validation_error = "chain_context_invalid"
                    return False
                
                store = self.blockchain.ensure_utxodb() or UTXODB()
                has_lookup = callable(getattr(store, "lookup_entry", None))
                utxo_view = getattr(store, "utxos", None) if not has_lookup else None
                utxo_view = store.load_utxo_set() if (not has_lookup and utxo_view is None) else utxo_view
                state_token = self._chain_state_token_locked()

            # 5. Additional Validation Related to Store/UTXO
            if not self._check_sigops_budget(block, store, utxo_view):
                self.blockchain._last_block_validation_error = "sigops_limit_exceeded"
                return False

            if block.height > 0 and not self._validate_transactions(block, store):
                return False

            # 6. Finalization
            with self.blockchain.lock:
                if state_token != self._chain_state_token_locked():
                    self.blockchain._last_block_validation_error = "chain_state_changed_during_validation"
                    return False
                self.blockchain._last_block_validation_error = None
            return True

        except Exception:
            self.blockchain._last_block_validation_error = "unexpected_validation_error"
            log.exception("[validate_block] Unexpected error during block validation")
            return False


    def compute_txids_for_block(self, block: Block) -> bool:
        txs = getattr(block, "transactions", []) or []
        for tx in txs:
            raw_no_witness = self._serialize_tx_cached(tx, include_witness=False)
            if raw_no_witness is None:
                self.blockchain._last_block_validation_error = "tx_serialize_failed"
                return False
            txid_bytes = H.hash256(raw_no_witness)
            existing = getattr(tx, "txid", None)
            existing_bytes = None
            if isinstance(existing, (bytes, bytearray)):
                existing_bytes = bytes(existing)

            elif isinstance(existing, str):
                existing_bytes = bytes.fromhex(existing)

            if existing_bytes is not None and existing_bytes != txid_bytes:
                self.blockchain._last_block_validation_error = "txid_mismatch"
                return False

            setattr(tx, "_cached_txid_bytes", txid_bytes)
            setattr(tx, "_cached_raw_tx_nowit", raw_no_witness)
            setattr(tx, "txid", txid_bytes)
            setattr(tx, "txid_hex", txid_bytes.hex())
        return True


    # =============================================================================
    # INTERNAL METHOD
    # =============================================================================


    def _warm_pow_context(self, height: int):  # pre-warm for next epoch
        if CFG.POW_ALGO != "randomx":
            return
        epoch_blocks = max(1, int(CFG.RANDOMX_KEY_EPOCH_BLOCKS))
        if epoch_blocks <= 0:
            return
        # pre-warm next epoch key near boundary
        next_epoch = (height // epoch_blocks) + 1
        with self._pow_warm_lock:
            if getattr(self.__class__, "_pow_warm_next_epoch", None) == next_epoch or getattr(self, "_pow_warm_next_epoch", None) == next_epoch:
                return
            self.__class__._pow_warm_next_epoch = next_epoch
            self._pow_warm_next_epoch = next_epoch

        def _worker():
            key = H.pow_key_for_height(next_epoch * epoch_blocks)
            # dummy header to prime dataset
            dummy_hdr = b"\x00" * 80
            H.pow_hash_verify_light(dummy_hdr, key_hint=key)
            log.info("[pow_warm] warmed epoch=%s", next_epoch)

        t = threading.Thread(target=_worker, name="pow-warm", daemon=True)
        t.start()


    def _ensure_warm(self, height: int):  # ensure epoch
        if CFG.POW_ALGO != "randomx":
            return
        epoch_blocks = max(1, int(CFG.RANDOMX_KEY_EPOCH_BLOCKS))
        if epoch_blocks <= 0:
            return
        epoch = max(0, int(height) // epoch_blocks)
        with self._pow_warm_lock:
            if epoch in self.__class__._pow_epoch_warmed:
                return
            self.__class__._pow_epoch_warmed.add(epoch)

        key = H.pow_key_for_height(epoch * epoch_blocks)
        dummy_hdr = b"\x00" * 80
        H.pow_hash_verify_light(dummy_hdr, key_hint=key)
        log.info("[pow_warm] ensured epoch=%s ready", epoch)


    def _validate_pow(self, block: Block) -> bool: 
        header_hash = block.hash()
        target = bits_to_target(block.bits)
        return int.from_bytes(header_hash, "big") <= int(target)


    def _validate_merkle(self, block: Block) -> bool: 
        computed = merkle_root(block.transactions)
        header_mr = getattr(block, "merkle_root", None)
        if isinstance(header_mr, str):
            header_mr = bytes.fromhex(header_mr)
        return computed == header_mr


    def _validate_transactions(self, block: Block, utxo_store: UTXODB | None = None) -> bool: 
        store = utxo_store or self.blockchain.ensure_utxodb() or UTXODB()
        self.blockchain._last_block_validation_error = "validation_failed"
        txs = getattr(block, "transactions", [])
        if not txs:
            self.blockchain._last_block_validation_error = "empty_block_transactions"
            return False

        cb = txs[0]
        if not getattr(cb, "is_coinbase", False):
            self.blockchain._last_block_validation_error = "missing_coinbase"
            return False
        if any(getattr(t, "is_coinbase", False) for t in txs[1:]):
            self.blockchain._last_block_validation_error = "duplicate_coinbase"
            return False

        spend_height = int(getattr(block, "height", 0))

        if not self._validate_tx_guardrails(txs, spend_height):
            return False

        if not self._validate_graffiti_rules(txs, cb, store):
            return False

        return self._validate_transactions_payload(block, txs, spend_height, cb, store)


    def _validate_tx_guardrails(self, txs, block_height: int) -> bool: 
        for tx in txs:
            raw_full = self._serialize_tx_cached(tx, include_witness=True)
            if raw_full is None:
                self.blockchain._last_block_validation_error = "tx_serialize_failed"
                return False
            if len(raw_full) > int(CFG.MAX_BLOCK_BYTES):
                self.blockchain._last_block_validation_error = "tx_too_large"
                return False
            try:
                weight, vsize, _base_size, _total_size = H.compute_tx_weight_vsize(tx)
            except Exception:
                log.exception(
                    "[_validate_tx_guardrails] weight_calc_failed txid=%s height=%s",
                    getattr(tx, "txid", None),
                    block_height,
                )
                self.blockchain._last_block_validation_error = "tx_weight_calc_failed"
                return False

            vin = len(getattr(tx, "inputs", []))
            vout = len(getattr(tx, "outputs", []))
            if vsize > int(CFG.MAX_TX_VSIZE):
                self.blockchain._last_block_validation_error = "tx_vsize_exceeds_limit"
                return False
            if vsize < int(CFG.MIN_TX_VSIZE):
                self.blockchain._last_block_validation_error = "tx_vsize_below_min"
                return False
            if weight > int(CFG.MAX_TX_WEIGHT):
                self.blockchain._last_block_validation_error = "tx_weight_exceeds_limit"
                return False
            if weight < int(CFG.MIN_TX_WEIGHT):
                self.blockchain._last_block_validation_error = "tx_weight_below_min"
                return False
            if vin > int(CFG.MAX_TX_INPUTS):
                self.blockchain._last_block_validation_error = "tx_inputs_exceed_limit"
                return False
            if vout > int(CFG.MAX_TX_OUTPUTS):
                self.blockchain._last_block_validation_error = "tx_outputs_exceed_limit"
                return False

            for tx_out in getattr(tx, "outputs", []):
                if not self._validate_graffiti_output(
                    getattr(tx_out, "script_pubkey", None)
                ):
                    return False
        return True


    def _validate_graffiti_rules(self, txs, cb, store) -> bool: 
        reg = getattr(store, "_graffiti_registry", None)
        if reg is None:
            reg = GraffitiRegistry()
            
        if not self._validate_graffiti_posts(txs, cb):
            return False
            
        if not self._validate_graffiti_payouts(txs, reg):
            return False
            
        return True


    def _validate_graffiti_posts(self, txs, cb) -> bool: #NOSONAR
        graffiti_posts = 0
        first_art_id = None
        for tx in txs[1:]:  # skip coinbase
            for tx_out in getattr(tx, "outputs", []):
                spk = getattr(tx_out, "script_pubkey", None)
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if not meta or str(meta.get("event", "")).upper() != "POST":
                    continue

                art_id = str(meta.get("art_id") or "").strip().lower()
                if not art_id:
                    sha_hex = str(meta.get("sha256") or "").strip().lower()
                    creator = str(meta.get("creator") or "").strip().lower()
                    art_id = GRAFFITI.compute_art_id(sha_hex, creator) if sha_hex and creator else ""
                if not art_id:
                    continue

                try:
                    pool_addr = GRAFFITI.derive_pool_address(art_id)
                    min_fee = int(GRAFFITI.calc_upload_fee_sats(int(meta.get("size") or 0)))
                except Exception:
                    continue

                paid = sum(
                    int(getattr(out, "amount", 0))
                    for out in getattr(tx, "outputs", []) or []
                    if (self._spk_to_address(getattr(out, "script_pubkey", None)) if getattr(out, "script_pubkey", None) is not None else getattr(out, "address", None)) == pool_addr
                )
                if paid < min_fee:
                    continue

                graffiti_posts += 1
                if not first_art_id:
                    first_art_id = art_id

        if graffiti_posts > 1:
            self.blockchain._last_block_validation_error = "too_many_graffiti_posts"
            return False

        cb_block_id = getattr(cb, "block_id", None)
        if isinstance(cb_block_id, str):
            cb_block_id = cb_block_id.strip().lower()
        if graffiti_posts == 1 and first_art_id:
            if not cb_block_id or cb_block_id.strip().lower() != first_art_id:
                self.blockchain._last_block_validation_error = "block_id_mismatch_graffiti"
                return False
        return True


    def _validate_graffiti_payouts(self, txs, reg) -> bool: 
        for tx in txs[1:]:
            paymap: dict[str, int] = {}
            for out in getattr(tx, "outputs", []):
                addr = self._spk_to_address(getattr(out, "script_pubkey", None))
                if not addr:
                    continue
                amt = int(getattr(out, "amount", 0))
                if amt > 0:
                    paymap[addr.strip().lower()] = paymap.get(addr.strip().lower(), 0) + amt

            for out in getattr(tx, "outputs", []):
                spk = getattr(out, "script_pubkey", None)
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if not meta or str(meta.get("event", "")).upper() != "PAYOUT":
                    continue
                if not self._validate_single_payout(meta, paymap, reg):
                    return False
        return True


    def _validate_single_payout(self, meta: dict, paymap: dict[str, int], reg) -> bool: 
        art_id = str(meta.get("art_id") or "").strip().lower()
        if not art_id:
            self.blockchain._last_block_validation_error = "payout_bad_art_id"
            return False
        post = reg.get_post(art_id) if reg else None
        if not post:
            self.blockchain._last_block_validation_error = "payout_unknown_art"
            return False
        
        stats = post.get("stats") or {}
        pool_balance = int(stats.get("pool_balance", 0))
        last_epoch = int(stats.get("last_paid_epoch", -1))
        epoch = int(meta.get("epoch", -1))

        if epoch >= 0 and epoch <= last_epoch:
            self.blockchain._last_block_validation_error = "payout_epoch_rewind"
            return False

        if epoch >= 0 and not self._validate_payout_proof(meta, epoch, art_id, reg):
            return False

        recs = meta.get("recipients") or []
        if not isinstance(recs, list) or not recs:
            self.blockchain._last_block_validation_error = "payout_no_recipients"
            return False
            
        total_req = 0
        for rec in recs:
            addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
            amt_req = int(rec.get("amount", 0))
            if not addr or amt_req <= 0:
                self.blockchain._last_block_validation_error = "payout_bad_recipient"
                return False
            total_req += amt_req
            if paymap.get(addr, 0) < amt_req:
                self.blockchain._last_block_validation_error = "payout_shortfall"
                return False
                
        if total_req > pool_balance:
            self.blockchain._last_block_validation_error = "payout_exceeds_pool"
            return False
            
        return True


    def _validate_payout_proof(self, meta: dict, epoch: int, art_id: str, reg) -> bool: 
        latest_proof = reg.get_latest_proof_epoch(art_id)
        if latest_proof < epoch:
            proof_epoch = int(meta.get("proof_epoch", -1))
            if proof_epoch < 0:
                proof_height = int(meta.get("proof_height", meta.get("height", -1)))
                if proof_height >= 0:
                    proof_epoch = GRAFFITI.compute_proof_epoch(proof_height)
            if proof_epoch is None or proof_epoch < epoch:
                self.blockchain._last_block_validation_error = "payout_missing_proof"
                return False
        return True


    def _validate_transactions_payload(self, block, txs, spend_height, cb, store) -> bool: 
        snapshot = self._prepare_tx_snapshot(txs, store)
        if snapshot is None:
            return False

        opts = {
            "coinbase_maturity": int(CFG.COINBASE_MATURITY),
            "max_sigops_per_tx": int(CFG.MAX_SIGOPS_PER_TX),
            "max_sigops_per_block": int(CFG.MAX_SIGOPS_PER_BLOCK),
            "max_tx_vsize": int(CFG.MAX_TX_VSIZE),
            "min_tx_vsize": int(CFG.MIN_TX_VSIZE),
            "max_tx_weight": int(CFG.MAX_TX_WEIGHT),
            "min_tx_weight": int(CFG.MIN_TX_WEIGHT),
            "max_tx_inputs": int(CFG.MAX_TX_INPUTS),
            "max_tx_outputs": int(CFG.MAX_TX_OUTPUTS),
            "enforce_low_s": True,
        }

        payload_txs, payload_utxo = self._build_block_payload_compact(txs, snapshot) or (None, None)
        if payload_txs is not None and payload_utxo is not None:
            ok, reason, fees = H.native_validate_block_txs_compact(
                payload_txs, payload_utxo, spend_height, opts
            )
        else:
            ok, reason, fees = H.native_validate_block_txs(
                block.to_dict(), snapshot, spend_height, opts
            )

        if not ok:
            self.blockchain._last_block_validation_error = reason or "native_validation_failed"
            return False

        return self._verify_block_fees_and_rewards(block, txs, cb, fees)


    def _prepare_tx_snapshot(self, txs, store) -> dict | None: #NOSONAR
        store_lookup = getattr(store, "lookup_entry", None)
        utxo_view = None
        if not callable(store_lookup):
            utxo_view = getattr(store, "utxos", None)
            if utxo_view is None:
                utxo_view = store.load_utxo_set()

        processed_txids = set()
        snapshot: dict[str, dict] = {}
        for tx in txs:
            txid_hex = self._txid_hex(getattr(tx, "txid", None))
            if txid_hex is None and hasattr(tx, "compute_txid"):
                tx.compute_txid()
                txid_hex = self._txid_hex(getattr(tx, "txid", None))
            txid_lower = txid_hex.lower() if txid_hex else None

            if getattr(tx, "is_coinbase", False):
                if txid_lower:
                    processed_txids.add(txid_lower)
                continue

            for tx_input in getattr(tx, "inputs", []):
                prev_txid_hex = self._txid_hex(
                    getattr(tx_input, "txid", None) or getattr(tx_input, "prev_tx", None)
                )
                if prev_txid_hex is None:
                    self.blockchain._last_block_validation_error = "tx_input_missing_prev_txid"
                    return None
                prev_index = int(getattr(tx_input, "vout", getattr(tx_input, "prev_index", 0)))
                if prev_txid_hex.lower() in processed_txids:
                    continue
                snap_key = f"{prev_txid_hex.lower()}:{prev_index}"
                if snap_key in snapshot:
                    continue
                entry = self._resolve_prevout(store_lookup, utxo_view, prev_txid_hex.lower(), prev_index)
                if entry is None:
                    self.blockchain._last_block_validation_error = f"prevout_missing {prev_txid_hex}:{prev_index}"
                    return None
                normalized = self._normalize_snapshot_entry(entry, snap_key)
                if normalized is None:
                    self.blockchain._last_block_validation_error = "native_snapshot_invalid_entry"
                    return None
                snapshot[snap_key] = normalized

            if txid_lower:
                processed_txids.add(txid_lower)
        return snapshot


    def _verify_block_fees_and_rewards(self, block, txs, cb, fees) -> bool: 
        fees_list = []
        if isinstance(fees, (list, tuple)):
            if len(fees) != max(len(txs) - 1, 0):
                self.blockchain._last_block_validation_error = "fee_mismatch"
                return False
            for tx_obj, fee_val in zip(txs[1:], fees):
                fee_int = int(fee_val)
                fees_list.append(fee_int)
                tx_obj.fee = fee_int
        else:
            fees_list = [int(getattr(t, "fee", 0)) for t in txs[1:]]

        minted_before = self.blockchain.cumulative_supply_until(block.height)
        base = self.blockchain.scheduled_reward(block.height)
        reward = min(max(0, base), max(0, CFG.MAX_SUPPLY - minted_before))
        total_fee = sum(fees_list)
        expected_cb = reward + total_fee

        actual_cb = sum(int(o.amount) for o in getattr(cb, "outputs", []))
        if actual_cb != expected_cb:
            self.blockchain._last_block_validation_error = f"coinbase_amount_mismatch expected={expected_cb} actual={actual_cb}"
            return False

        return True


    def _serialize_tx_cached(self, tx, *, include_witness: bool) -> bytes | None: 
        """
        Cache the result of serialize_tx to avoid repeated hashing/serialization
        in the validation hot path.
        """
        attr = "_cached_raw_tx_w" if include_witness else "_cached_raw_tx_nowit"
        buf = getattr(tx, attr, None)
        if isinstance(buf, (bytes, bytearray)):
            return bytes(buf)
        raw = H.serialize_tx(tx, include_witness=include_witness)
        setattr(tx, attr, raw)
        return raw


    def _estimate_block_size(self, block: Block) -> Optional[int]: 
        size = 80  # header
        for tx in block.transactions or []:
            tx_size = self._estimate_tx_size(tx)
            if tx_size is None:
                return None
            size += tx_size
        return int(size)


    def _estimate_tx_size(self, tx) -> Optional[int]: 
        cached = getattr(tx, "_cached_raw_tx_w", None)
        if isinstance(cached, (bytes, bytearray)):
            return len(cached)
        
        if hasattr(tx, "serialize") and callable(getattr(tx, "serialize", None)):
            try:
                raw = tx.serialize()
                return len(raw if isinstance(raw, (bytes, bytearray)) else bytes.fromhex(raw))
            except Exception:
                log.exception("[_estimate_block_size] tx.serialize failed")
                
        if hasattr(tx, "raw") and isinstance(getattr(tx, "raw"), (bytes, bytearray)):
            return len(tx.raw)
            
        if hasattr(tx, "size_bytes"):
            v = tx.size_bytes
            return int(v()) if callable(v) else int(v)
            
        return None


    def _chain_state_token_locked(self): 
        tip_hash = self.blockchain.chain[-1].hash() if self.blockchain.chain else None
        return (self.blockchain.height, tip_hash)


    def _validate_chain_context_locked(self, block: Block) -> bool: 
        expected_height = self.blockchain.height + 1 if self.blockchain.chain else 0
        if block.height != expected_height:
            self.blockchain._last_block_validation_error = "height_mismatch"
            return False
        if self.blockchain.chain and block.prev_block_hash != self.blockchain.chain[-1].hash():
            self.blockchain._last_block_validation_error = "prev_hash_mismatch"
            return False
        if not self.blockchain.chain and (block.height != 0 or block.prev_block_hash != CFG.ZERO_HASH):
            self.blockchain._last_block_validation_error = "bad_genesis_prevhash"
            return False
        if not self.blockchain.chain and block.height == 0 and GENESIS_HASH is not None:
            if block.hash() != GENESIS_HASH:
                self.blockchain._last_block_validation_error = "genesis_hash_mismatch"
                return False
        mtp = self.blockchain.median_time_past(CFG.MTP_WINDOWS)
        if block.timestamp < mtp:
            self.blockchain._last_block_validation_error = "timestamp_too_old"
            return False
        if block.timestamp > int(time.time()) + CFG.FUTURE_DRIFT:
            self.blockchain._last_block_validation_error = "timestamp_in_future"
            return False
        if self.blockchain.chain:
            parent_ts = int(getattr(self.blockchain.chain[-1], "timestamp", 0) or 0)
            if block.timestamp + int(CFG.TARGET_BLOCK_TIME) < parent_ts:
                self.blockchain._last_block_validation_error = "timestamp_backwards"
                return False
        if not self.blockchain._validate_difficulty(block):
            self.blockchain._last_block_validation_error = "difficulty_invalid"
            return False
        return True


    def _ensure_unique_txids(self, block: Block) -> bool: 
        seen_txids = set()
        for tx in block.transactions or []:
            if hasattr(tx, "compute_txid") and (getattr(tx, "txid", None) is None):
                tx.compute_txid()
            txid_b = getattr(tx, "txid", None)
            if not isinstance(txid_b, (bytes, bytearray)):
                txid_b = bytes.fromhex(txid_b) if isinstance(txid_b, str) else None
            if txid_b is None:
                self.blockchain._last_block_validation_error = "txid_missing"
                return False
            if txid_b in seen_txids:
                self.blockchain._last_block_validation_error = "txid_duplicate"
                return False
            seen_txids.add(txid_b)
        return True


    def _check_block_limits(self, block: Block) -> bool: 
        txs_ex_coinbase = max(0, (len(block.transactions) or 0) - 1)
        if txs_ex_coinbase > CFG.MAX_TXS_PER_BLOCK:
            self.blockchain._last_block_validation_error = "too_many_txs"
            return False
        est_size = self._estimate_block_size(block)
        if est_size is not None and est_size > CFG.MAX_BLOCK_BYTES:
            self.blockchain._last_block_validation_error = "block_size_exceeded"
            return False
        return True


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
            return spk.serialize()
        if isinstance(spk, (bytes, bytearray)):
            return bytes(spk)
        if isinstance(spk, str):
            return bytes.fromhex(spk)
        return None


    def _validate_graffiti_output(self, spk_obj) -> bool: 
        raw = self._extract_raw_spk(spk_obj)
        if not raw:
            return True
        data = H.last_pushdata(raw)
        if not data or not data.startswith(CFG.GRAFFITI_MAGIC):
            return True
        if len(data) > int(CFG.MAX_GRAFFITI_OPRET):
            self.blockchain._last_block_validation_error = "graffiti_opreturn_too_large"
            return False
        meta = GRAFFITI.parse_payload(data)
        if not meta:
            self.blockchain._last_block_validation_error = "graffiti_payload_invalid"
            return False
            
        event = str(meta.get("event", "")).upper()
        if event == "POST":
            return self._validate_graffiti_post_event(meta)
        elif event == "COMMENT":
            return self._validate_graffiti_comment_event(meta)
        return True


    def _extract_raw_spk(self, spk_obj) -> bytes | None: 
        if hasattr(spk_obj, "serialize"):
            return spk_obj.serialize()
        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)
        if isinstance(spk_obj, str):
            try:
                return bytes.fromhex(spk_obj)
            except ValueError:
                return None
        return None


    def _validate_graffiti_post_event(self, meta) -> bool: 
        size_val = int(meta.get("size", 0))
        if size_val <= 0:
            self.blockchain._last_block_validation_error = "graffiti_size_invalid"
            return False
        if size_val > int(CFG.GRAFFITI_MAX_SIZE_BYTES):
            self.blockchain._last_block_validation_error = "graffiti_size_exceeds_limit"
            return False
        return True


    def _validate_graffiti_comment_event(self, meta) -> bool: 
        comment_len = int(meta.get("comment_len", 0))
        if comment_len <= 0:
            self.blockchain._last_block_validation_error = "graffiti_comment_empty"
            return False
        if comment_len > int(CFG.GRAFFITI_COMMENT_MAX_BYTES):
            self.blockchain._last_block_validation_error = "graffiti_comment_too_large"
            return False
        amount = int(meta.get("amount", 0))
        if amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
            self.blockchain._last_block_validation_error = "graffiti_comment_fee_too_low"
            return False
        tip = int(meta.get("tip", 0))
        if tip < 0:
            self.blockchain._last_block_validation_error = "graffiti_comment_tip_negative"
            return False
        return True


    def _spk_to_address(self, spk_obj) -> str | None: 
        if hasattr(spk_obj, "serialize"):
            spk_bytes = spk_obj.serialize()
        elif isinstance(spk_obj, (bytes, bytearray)):
            spk_bytes = bytes(spk_obj)
        elif isinstance(spk_obj, str):
            try:
                spk_bytes = bytes.fromhex(spk_obj)
            except ValueError:
                return None
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
        return None


    def _script_to_bytes(self, spk_obj): 
        if spk_obj is None:
            return None
        if isinstance(spk_obj, dict):
            spk_obj = spk_obj.get("script_pubkey", spk_obj.get("script"))
        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)
        if isinstance(spk_obj, str):
            return bytes.fromhex(spk_obj)
        script_attr = getattr(spk_obj, "script_pubkey", None)
        if script_attr is not None:
            spk_obj = script_attr
        if hasattr(spk_obj, "serialize"):
            return spk_obj.serialize()
        if hasattr(spk_obj, "to_bytes"):
            return bytes(spk_obj.to_bytes())
        return None


    def _txid_hex(self, value): 
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            return value.hex()
        return str(value)


    def _legacy_lookup(self, snapshot_map, prev_txid_hex: str, prev_index: int): 
        if not isinstance(snapshot_map, dict):
            return None

        txid_lower = prev_txid_hex.lower()
        idx = int(prev_index)

        # Standard key "txid_hex:vout"
        key = f"{txid_lower}:{idx}"
        entry = snapshot_map.get(key) or snapshot_map.get(prev_txid_hex)
        if entry is not None:
            return entry

        # Bytes key b"txid_hex:vout"
        entry = snapshot_map.get(key.encode("utf-8"))
        if entry is not None:
            return entry

        # Bucket snapshot_map[txid_hex][vout]
        bucket = snapshot_map.get(txid_lower) or snapshot_map.get(prev_txid_hex)
        if isinstance(bucket, dict) and idx in bucket:
            return bucket[idx]

        # Tuple keys (txid_hex, vout) or (txid_bytes, vout)
        for tuple_key in ((txid_lower, idx), (prev_txid_hex, idx)):
            if tuple_key in snapshot_map:
                return snapshot_map[tuple_key]

        try:
            tuple_b = (bytes.fromhex(prev_txid_hex), idx)
            if tuple_b in snapshot_map:
                return snapshot_map[tuple_b]
        except Exception:
            pass

        return None


    def _resolve_prevout(self, store_lookup, utxo_view, prev_txid_hex: str, prev_index: int): 
        if callable(store_lookup):
            return store_lookup(prev_txid_hex, prev_index)
        return self._legacy_lookup(utxo_view, prev_txid_hex, prev_index)


    def _normalize_snapshot_entry(self, entry, key_desc: str): 
        candidate = entry
        if isinstance(candidate, dict):
            tx_out = candidate.get("tx_out") or candidate
        else:
            tx_out = getattr(candidate, "tx_out", None) or candidate
        script_bytes = self._script_to_bytes(tx_out)
        if script_bytes is None and isinstance(candidate, dict):
            script_bytes = self._script_to_bytes(candidate.get("script_pubkey"))
        if script_bytes is None:
            log.warning("[native_snapshot] entry %s missing script", key_desc)
            return None
        if isinstance(tx_out, dict):
            amount_val = tx_out.get("amount")
        elif hasattr(tx_out, "amount"):
            amount_val = getattr(tx_out, "amount", None)
        else:
            amount_val = getattr(candidate, "amount", None)
        amt = int(amount_val if amount_val is not None else 0)
        if isinstance(candidate, dict):
            is_cb = bool(candidate.get("is_coinbase", False))
            born = int(candidate.get("block_height", candidate.get("height", 0)))
        else:
            is_cb = bool(getattr(candidate, "is_coinbase", False))
            born = int(
                getattr(candidate, "block_height", getattr(candidate, "height", 0)) or 0
            )
        return {
            "amount": amt,
            "script_pubkey": script_bytes,
            "is_coinbase": is_cb,
            "block_height": born,
        }


    def _build_block_payload_compact(self, tx_list, snapshot_dict): 
        tx_payloads = []
        for tx in tx_list:
            compact = H.tx_to_compact_tuple(tx)
            tx_payloads.append(compact)

        utxo_items = []
        for key, entry in snapshot_dict.items():
            if isinstance(key, bytes):
                key = key.decode("utf-8")
            if ":" not in key:
                continue
            txid_hex, vout_str = key.split(":", 1)
            txid_b = bytes.fromhex(txid_hex)
            vout_i = int(vout_str)
            utxo_items.append(
                (
                    txid_b,
                    vout_i,
                    int(entry.get("amount", 0)),
                    bytes(entry.get("script_pubkey", b"")),
                    bool(entry.get("is_coinbase", False)),
                    int(entry.get("block_height", 0)),
                )
            )
        return tx_payloads, utxo_items


    def _utxo_lookup(self, lookup_fn, utxo_view, txid_b: bytes, vout_i: int): 
        entry = None
        if callable(lookup_fn):
            entry = lookup_fn(txid_b.hex(), int(vout_i))
        elif isinstance(utxo_view, dict):
            key = f"{txid_b.hex()}:{int(vout_i)}"
            entry = utxo_view.get(key) or utxo_view.get(key.lower())
        if entry is None:
            return None
        return self._entry_script_bytes(entry)


    def _check_sigops_budget(self, block: Block, store: UTXODB, utxo_view) -> bool: 
        lookup_fn = getattr(store, "lookup_entry", None)

        total_sigops = 0
        for tx in block.transactions or []:
            if getattr(tx, "is_coinbase", False):
                continue
            if hasattr(tx, "sigops_count"):
                so = int(
                    tx.sigops_count(
                        lambda txid, vout: self._utxo_lookup(
                            lookup_fn, utxo_view, txid, vout
                        )
                    )
                )
            else:
                so = len(getattr(tx, "inputs", []))
            if so > int(CFG.MAX_SIGOPS_PER_TX):
                self.blockchain._last_block_validation_error = "sigops_per_tx_exceeded"
                return False
            total_sigops += so
        if total_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
            self.blockchain._last_block_validation_error = "sigops_per_block_exceeded"
            return False
        return True
