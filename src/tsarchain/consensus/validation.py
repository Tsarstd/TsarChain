# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: Merkle

from __future__ import annotations

import time
from copy import deepcopy
from typing import Optional

# ---------------- Local Project ----------------
from ..core.block import Block
from ..storage.utxo import UTXODB
from ..utils import config as CFG
from ..utils.helpers import bits_to_target, merkle_root
from ..utils import helpers as H
from .genesis import GENESIS_HASH

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.validation')

class ValidationMixin:
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

    def _validate_transactions(self, block: Block) -> bool:
        store = self._ensure_utxodb() or UTXODB()
        try:
            utxos = getattr(store, "utxos", store.load_utxo_set())
        except Exception:
            try:
                utxos = store.load_utxo_set()
            except Exception:
                log.exception("[_validate_transactions] Cannot load UTXO set")
                return False

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

        total_fee = sum(int(getattr(t, "fee", 0)) for t in txs[1:])
        minted_before = self._cumulative_supply_until(block.height)
        base = self._scheduled_reward(block.height)
        reward = min(max(0, base), max(0, CFG.MAX_SUPPLY - minted_before))
        expected_cb = reward + total_fee

        actual_cb = sum(int(o.amount) for o in getattr(cb, "outputs", []))
        if actual_cb != expected_cb:
            self._last_block_validation_error = f"coinbase_amount_mismatch expected={expected_cb} actual={actual_cb}"
            return False
        # Clone UTXO view so we can mutate for intra-block spends without touching disk store
        if isinstance(utxos, dict):
            try:
                utxo_view = {k: deepcopy(v) for k, v in utxos.items()}
            except Exception:
                utxo_view = dict(utxos)
        else:
            utxo_view = {}

        spend_height = int(getattr(block, "height", 0))

        def _script_to_hex(spk_obj):
            if spk_obj is None:
                return None
            if isinstance(spk_obj, dict):
                spk_obj = spk_obj.get("script_pubkey")
            if isinstance(spk_obj, str):
                return spk_obj.lower()
            if isinstance(spk_obj, (bytes, bytearray)):
                return spk_obj.hex()
            script_attr = getattr(spk_obj, "script_pubkey", None)
            if script_attr is not None:
                spk_obj = script_attr
            if hasattr(spk_obj, "serialize"):
                try:
                    return spk_obj.serialize().hex()
                except Exception:
                    return None
            if hasattr(spk_obj, "to_hex"):
                try:
                    return spk_obj.to_hex().lower()
                except Exception:
                    return None
            return None

        snapshot = {}
        for key, entry in utxo_view.items():
            k = str(key).lower()
            if not isinstance(entry, dict):
                log.debug("[native_snapshot] drop entry %s: not dict (type=%s)", key, type(entry).__name__)
                self._last_block_validation_error = "native_snapshot_invalid_entry"
                return False
            
            candidate = entry
            tx_out = candidate.get("tx_out") or candidate
            script_hex = _script_to_hex(tx_out) or _script_to_hex(candidate.get("script_pubkey"))
            if script_hex is None:
                log.debug("[native_snapshot] entry %s missing script", k)
                self._last_block_validation_error = "native_snapshot_missing_script"
                return False
            
            if isinstance(tx_out, dict):
                amount_val = tx_out.get("amount")
            elif hasattr(tx_out, "amount"):
                amount_val = getattr(tx_out, "amount", None)
            else:
                amount_val = candidate.get("amount")
            try:
                amt = int(amount_val if amount_val is not None else 0)
            except Exception:
                log.debug("[native_snapshot] entry %s amount invalid (%s)", k, amount_val)
                self._last_block_validation_error = "native_snapshot_invalid_amount"
                return False
            
            snapshot[k] = {
                "amount": amt,
                "script_pubkey": script_hex,
                "is_coinbase": bool(candidate.get("is_coinbase", False)),
                "block_height": int(candidate.get("block_height", 0)),
            }

        opts = {
            "coinbase_maturity": int(CFG.COINBASE_MATURITY),
            "max_sigops_per_tx": int(CFG.MAX_SIGOPS_PER_TX),
            "max_sigops_per_block": int(CFG.MAX_SIGOPS_PER_BLOCK),
            "enforce_low_s": True,
        }
        try:
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

        if isinstance(fees, (list, tuple)):
            for tx_obj, fee_val in zip(txs[1:], fees):
                try:
                    tx_obj.fee = int(fee_val)
                except Exception:
                    setattr(tx_obj, "fee", int(fee_val))

        self._last_block_validation_error = None
        return True

    def _estimate_block_size(self, block: Block) -> Optional[int]:
        try:
            size = 80  # header
            for tx in block.transactions or []:
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

    def validate_block(self, block: Block) -> bool:
        try:
            with self.lock:
                if not all([block.height is not None, block.prev_block_hash, block.transactions]):
                    return False

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

                if not self._validate_pow(block):
                    return False

                if not self._validate_merkle(block):
                    return False

                # --- Hardening: duplicate txid check (always runs, not only when the merkle check fails) ---
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
                except Exception:
                    return False

                # --- Per-block transaction count & size limits ---
                try:
                    txs_ex_coinbase = max(0, (len(block.transactions) or 0) - 1)
                    if txs_ex_coinbase > CFG.MAX_TXS_PER_BLOCK:
                        return False

                    est_size = self._estimate_block_size(block)
                    if est_size is not None and est_size > CFG.MAX_BLOCK_BYTES:
                        return False

                except Exception:
                    return False

                # --- SIGOPS budget: per-tx & per-block ---
                try:
                    store = self._ensure_utxodb() or UTXODB()
                    try:
                        utxos = getattr(store, "utxos", store.load_utxo_set())
                    except Exception:
                        utxos = store.load_utxo_set()

                    def _utxo_lookup(txid_b: bytes, vout_i: int):
                        try:
                            k = f"{txid_b.hex()}:{int(vout_i)}"
                            entry = utxos.get(k) if isinstance(utxos, dict) else None
                            if entry is None:
                                return None

                            if isinstance(entry, dict):
                                spk_hex = ((entry.get("tx_out") or {}).get("script_pubkey")
                                        or entry.get("script_pubkey"))
                                if isinstance(spk_hex, str):
                                    return bytes.fromhex(spk_hex)

                                txo = entry.get("tx_out")
                                if hasattr(txo, "script_pubkey"):
                                    return txo.script_pubkey.serialize()

                            if hasattr(entry, "tx_out") and hasattr(entry.tx_out, "script_pubkey"):
                                return entry.tx_out.script_pubkey.serialize()

                            log.debug("[_utxo_lookup] UTXO lookup found no script_pubkey for %s", k)
                        except Exception:
                            return None

                        return None

                    total_sigops = 0
                    for tx in (block.transactions or []):
                        if getattr(tx, "is_coinbase", False):
                            continue

                        so = int(tx.sigops_count(_utxo_lookup)) if hasattr(tx, "sigops_count") else len(getattr(tx, "inputs", []))
                        if so > int(CFG.MAX_SIGOPS_PER_TX):
                            return False

                        total_sigops += so

                    if total_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
                        return False

                except Exception:
                    est_sigops = self._count_block_sigops(block)
                    if est_sigops is not None and est_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
                        return False

                if block.height > 0 and not self._validate_transactions(block):
                    return False

            return True

        except Exception:
            log.exception("[validate_block] Unexpected error during block validation")
            return False
