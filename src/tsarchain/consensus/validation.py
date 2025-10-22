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
from ..mempool.pool import TxPoolDB
from ..storage.utxo import UTXODB
from ..utils import config as CFG
from ..utils.helpers import bits_to_target, merkle_root
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

        base_utxos = getattr(store, "utxos", {}) if isinstance(getattr(store, "utxos", {}), dict) else {}
        nested_cache = None

        def _inject_prevout_from_store(missing_key: str) -> bool:
            nonlocal nested_cache
            mk = (missing_key or "").strip()
            if not mk:
                return False
            txid_part, _, idx_part = mk.partition(":")
            try:
                idx_int = int(idx_part)
            except Exception:
                idx_int = None

            candidates = {
                mk,
                mk.lower(),
                mk.upper(),
                f"{txid_part.lower()}:{idx_int}" if idx_int is not None else mk.lower(),
            }

            for key in list(candidates):
                entry = base_utxos.get(key)
                if entry is not None:
                    if idx_int is None:
                        try:
                            _, _, idx_str = key.partition(":")
                            idx_int_candidate = int(idx_str)
                        except Exception:
                            idx_int_candidate = None
                    else:
                        idx_int_candidate = idx_int
                    if idx_int_candidate is not None:
                        target_key = f"{txid_part.lower()}:{idx_int_candidate}"
                        utxo_view[target_key] = deepcopy(entry)
                        return True

            if nested_cache is None:
                try:
                    nested_cache = store.load_utxo_set()
                except Exception:
                    nested_cache = {}

            if isinstance(nested_cache, dict) and idx_int is not None:
                for cand_txid in {txid_part, txid_part.lower(), txid_part.upper()}:
                    bucket = nested_cache.get(cand_txid)
                    if isinstance(bucket, dict) and idx_int in bucket:
                        utxo_view[f"{cand_txid.lower()}:{idx_int}"] = deepcopy(bucket[idx_int])
                        return True
            return False

        pool = TxPoolDB(utxo_store=self._ensure_utxodb())
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

        def _remove_prevout(txid_hex: str, index: int):
            flat = f"{txid_hex}:{index}"
            utxo_view.pop(flat, None)
            utxo_view.pop(flat.lower(), None)
            utxo_view.pop(flat.upper(), None)
            utxo_view.pop((txid_hex, index), None)
            try:
                txid_bytes = bytes.fromhex(txid_hex)
                utxo_view.pop((txid_bytes, index), None)
            except Exception:
                pass

        def _add_output(txid_hex: str, index: int, tx_out) -> None:
            try:
                spk_bytes = tx_out.script_pubkey.serialize()
                spk_hex = spk_bytes.hex()
            except Exception:
                spk_hex = None
            entry = {
                "tx_out": {
                    "amount": int(getattr(tx_out, "amount", 0) or 0),
                    "script_pubkey": spk_hex,
                },
                "amount": int(getattr(tx_out, "amount", 0) or 0),
                "script_pubkey": spk_hex,
                "is_coinbase": False,
                "block_height": int(getattr(block, "height", 0)),
            }
            utxo_view[f"{txid_hex}:{index}"] = entry

        spend_height = int(getattr(block, "height", 0))
        for tx in txs[1:]:
            try:
                txid_hex = tx.txid.hex() if isinstance(tx.txid, (bytes, bytearray)) else str(tx.txid)
            except Exception:
                txid_hex = None

            if not pool.validate_transaction(tx, utxo_view, spend_at_height=spend_height):
                reason = pool.last_error_reason or "tx_validation_failed"
                injected = False
                if isinstance(reason, str) and reason.startswith("prevout_missing "):
                    missing_key = reason.split(" ", 1)[1].strip()
                    try:
                        txid_part, _, idx_part = missing_key.partition(":")
                        short_tx = txid_part[:8] + ".." + txid_part[-8:] if len(txid_part) > 16 else txid_part
                        log.warning(
                            "[_validate_transactions] Block %s missing prevout %s:%s (tx %s)",
                            getattr(block, "height", "?"),
                            short_tx,
                            idx_part or "?",
                            (txid_hex[:8] + ".." + txid_hex[-8:]) if txid_hex else "unknown",
                        )
                    except Exception:
                        pass
                    injected = _inject_prevout_from_store(missing_key)
                    if injected and pool.validate_transaction(tx, utxo_view, spend_at_height=spend_height):
                        reason = None

                if reason:
                    if txid_hex:
                        self._last_block_validation_error = f"{reason} tx={txid_hex}"
                    else:
                        self._last_block_validation_error = reason
                    try:
                        log.warning("[_validate_transactions] Reject tx in block %s injected=%s", self._last_block_validation_error, injected)
                    except Exception:
                        pass
                    return False

            if not txid_hex:
                self._last_block_validation_error = "tx_missing_txid"
                return False

            for txin in getattr(tx, "inputs", []):
                try:
                    prev_hex = txin.txid.hex() if isinstance(txin.txid, (bytes, bytearray)) else str(txin.txid)
                except Exception:
                    prev_hex = None
                if prev_hex is None:
                    self._last_block_validation_error = "tx_input_missing_txid"
                    return False
                _remove_prevout(prev_hex.lower(), int(getattr(txin, "vout", 0)))

            for idx, tx_out in enumerate(getattr(tx, "outputs", [])):
                _add_output(txid_hex.lower(), idx, tx_out)

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
