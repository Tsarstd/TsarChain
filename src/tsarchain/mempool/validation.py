# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141

from __future__ import annotations

import time
from typing import Any

from ..core.tx import Tx
from ..storage.utxo import UTXODB
from .scripts import get_utxo_script_bytes
from ..contracts import graffiti as GRAFFITI
from ..contracts.graffiti_registry import GraffitiRegistry
from ..utils.helpers import (
    is_p2wpkh,
    is_p2wsh,
    last_pushdata,
    tx_to_compact_tuple,
    native_validate_tx_p2wpkh_compact,
    compute_tx_weight_vsize,
)
from bech32 import bech32_encode, convertbits
from ..utils import config as CFG
from ..utils.benchmarks import benchmark


from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.validation")

__all__ = ["TxMempoolValidator"]


class TxMempoolValidator:
    utxo: UTXODB
    last_error_reason: str | None
    
    def script_to_address(self, script) -> str | None:
        """
        Convert P2WPKH/P2WSH scriptPubKey to bech32 address.
        """
        b = None
        if hasattr(script, "serialize"):
            b = script.serialize()
        elif isinstance(script, (bytes, bytearray)):
            b = bytes(script)
        elif isinstance(script, str):
            b = bytes.fromhex(script)
        if not b:
            return None
        if len(b) == 22 and b[0] == 0x00 and b[1] == 0x14:
            data = [0] + list(convertbits(b[2:], 8, 5, True))
            return bech32_encode(CFG.ADDRESS_PREFIX, data)
        
        if len(b) == 34 and b[0] == 0x00 and b[1] == 0x20:
            data = [0] + list(convertbits(b[2:], 8, 5, True))
            return bech32_encode(CFG.ADDRESS_PREFIX, data)
        
        return None

    def _get_utxo_amount(self, utxo_data):
        if isinstance(utxo_data, dict):
            if "tx_out" in utxo_data:
                txo = utxo_data["tx_out"]
                if hasattr(txo, "amount"):
                    return int(getattr(txo, "amount", 0))
                if isinstance(txo, dict) and "amount" in txo:
                    return int(txo.get("amount", 0))
            if "amount" in utxo_data:
                return int(utxo_data["amount"])
        elif hasattr(utxo_data, "amount"):
            return int(utxo_data.amount)
        raise ValueError(f"Unknown UTXO format: {utxo_data}")

    def _txin_prev_txid(self, tx_in) -> str | None:
        txid_val = getattr(tx_in, "txid", None) or getattr(tx_in, "prev_tx", None)
        if txid_val is None:
            return None
        if isinstance(txid_val, (bytes, bytearray)):
            return txid_val.hex().lower()
        return str(txid_val).lower()

    def _lookup_utxo_entry(self, snapshot, prev_txid_hex: str, prev_index: int):
        if prev_txid_hex is None:
            return None
        idx = int(prev_index)

        txid_raw = str(prev_txid_hex)
        txid = txid_raw.lower()
        key_lower = f"{txid}:{idx}"
        key_raw = f"{txid_raw}:{idx}"

        if isinstance(snapshot, dict):
            # Flat canonical key (used by both LMDB/JSON backend in memory)
            for k in (key_lower, key_raw):
                if k in snapshot:
                    return snapshot[k]
            kb = key_lower.encode("utf-8")
            if kb in snapshot:
                return snapshot[kb]

            # Tuple key variant
            for tk in ((txid, idx), (txid_raw, idx)):
                if tk in snapshot:
                    return snapshot[tk]

            # Nested bucket variant (from load_utxo_set)
            bucket = snapshot.get(txid) or snapshot.get(txid_raw)
            if isinstance(bucket, dict):
                if idx in bucket:
                    return bucket[idx]

            # Bytes txid tuple variant
            try:
                txid_bytes = bytes.fromhex(txid)
            except ValueError:
                txid_bytes = None
            if txid_bytes:
                tuple_b = (txid_bytes, idx)
                if tuple_b in snapshot:
                    return snapshot[tuple_b]

        lookup_method = getattr(self.utxo, "lookup_entry", None)
        if callable(lookup_method):
            return lookup_method(txid, idx)
        return None

    @staticmethod
    def _coinbase_confirmations(born_height: int, spend_height: int) -> int:
        return max(0, int(spend_height) - int(born_height))

    def _utxo_snapshot_to_items(self, snapshot) -> list[tuple]:
        items = []
        if not isinstance(snapshot, dict):
            return items
        for key, entry in snapshot.items():
            if isinstance(key, bytes):
                key_str = key.decode("utf-8")
            else:
                key_str = str(key)
            if ":" not in key_str:
                continue
            txid_hex, vout_str = key_str.split(":", 1)
            txid_b = bytes.fromhex(txid_hex)
            vout_i = int(vout_str)
            amt = self._get_utxo_amount(entry)
            spk_bytes = get_utxo_script_bytes(entry)
            is_cb, born = self.utxo._get_utxo_meta(entry)
            items.append((txid_b, vout_i, int(amt), spk_bytes, bool(is_cb), int(born)))
        return items
    
    # Graffiti OP_RETURN guard (size/comment/min fee)
    def _validate_graffiti_output(self, spk_obj) -> bool:
        raw = None
        if hasattr(spk_obj, "serialize"):
            raw = spk_obj.serialize()
        elif isinstance(spk_obj, (bytes, bytearray)):
            raw = bytes(spk_obj)
        elif isinstance(spk_obj, str):
            try:
                raw = bytes.fromhex(spk_obj)
            except ValueError:
                return True
        if not raw:
            return True
        data = last_pushdata(raw)
        if not data or not data.startswith(CFG.GRAFFITI_MAGIC):
            return True
        if len(data) > int(CFG.MAX_GRAFFITI_OPRET):
            self.last_error_reason = "graffiti_opreturn_too_large"
            return False
        meta = GRAFFITI.parse_payload(data)
        if not meta:
            self.last_error_reason = "graffiti_payload_invalid"
            return False
        event = str(meta.get("event", "")).upper()
        if event == "POST":
            size_val = int(meta.get("size", 0))
            if size_val <= 0:
                self.last_error_reason = "graffiti_size_invalid"
                return False
            if size_val > int(CFG.GRAFFITI_MAX_SIZE_BYTES):
                self.last_error_reason = "graffiti_size_exceeds_limit"
                return False
        elif event == "COMMENT":
            comment_len = int(meta.get("comment_len", 0))
            if comment_len <= 0:
                self.last_error_reason = "graffiti_comment_empty"
                return False
            if comment_len > int(CFG.GRAFFITI_COMMENT_MAX_BYTES):
                self.last_error_reason = "graffiti_comment_too_large"
                return False
            amount = int(meta.get("amount", 0))
            if amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
                self.last_error_reason = "graffiti_comment_fee_too_low"
                return False
            tip = int(meta.get("tip", 0))
            if tip < 0:
                self.last_error_reason = "graffiti_comment_tip_negative"
                return False
        return True

    @benchmark(label="validate_transaction", threshold_ms=15.0)
    def validate_transaction(self, tx: Tx, utxo_set: dict[str, Any], spend_at_height: int | None = None,) -> bool:
        if getattr(tx, "is_coinbase", False):
            return False

        # ---- TX size / io guard ----
        try:
            weight, vsize, _base_size, _total_size = compute_tx_weight_vsize(tx)
        except Exception:
            log.exception("[validate_transaction] weight_calc_failed txid=%s", getattr(tx, "txid", None))
            self.last_error_reason = "tx_weight_calc_failed"
            return False

        vin = len(getattr(tx, "inputs", []) or [])
        vout = len(getattr(tx, "outputs", []) or [])
        if vsize > int(CFG.MAX_TX_VSIZE):
            self.last_error_reason = "tx_vsize_exceeds_limit"
            return False
        if vsize < int(CFG.MIN_TX_VSIZE):
            self.last_error_reason = "tx_vsize_below_min"
            return False
        if weight > int(CFG.MAX_TX_WEIGHT):
            self.last_error_reason = "tx_weight_exceeds_limit"
            return False
        if weight < int(CFG.MIN_TX_WEIGHT):
            self.last_error_reason = "tx_weight_below_min"
            return False
        if vin > int(CFG.MAX_TX_INPUTS):
            self.last_error_reason = "tx_inputs_exceed_limit"
            return False
        if vout > int(CFG.MAX_TX_OUTPUTS):
            self.last_error_reason = "tx_outputs_exceed_limit"
            return False

        for tx_out in getattr(tx, "outputs", []) or []:
            if not self._validate_graffiti_output(getattr(tx_out, "script_pubkey", None)):
                return False

        current_height = (spend_at_height if spend_at_height is not None else self.utxo._get_tip_height_from_state())
        try:
            # ---- Special handling for Graffiti PAYOUT (P2WSH pool) ----
            payout_meta = None
            for tx_out in getattr(tx, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                meta = None
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if meta and str(meta.get("event", "")).upper() == "PAYOUT":
                    payout_meta = meta
                    break

            if payout_meta:
                reg = getattr(self.utxo, "_graffiti_registry", None) or GraffitiRegistry()
                art_id = str(payout_meta.get("art_id") or "").strip().lower()
                post = reg.get_post(art_id)
                if not post:
                    self.last_error_reason = "payout_unknown_art"
                    log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                    return False
                
                stats = post.get("stats") or {}
                pool_balance = int(stats.get("pool_balance", 0))
                last_epoch = int(stats.get("last_paid_epoch", -1))
                epoch = int(payout_meta.get("epoch", -1))
                if epoch >= 0 and epoch <= last_epoch:
                    self.last_error_reason = "payout_epoch_rewind"
                    log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                    return False
                
                if epoch >= 0:
                    latest_proof = reg.get_latest_proof_epoch(art_id)
                    if latest_proof < epoch:
                        proof_epoch = int(payout_meta.get("proof_epoch", -1))
                        
                        if proof_epoch is None or proof_epoch < 0:
                            proof_height = int(payout_meta.get("proof_height", payout_meta.get("height", -1)))
                            
                            if proof_height >= 0:
                                proof_epoch = GRAFFITI.compute_proof_epoch(proof_height)
                                
                        if proof_epoch is None or proof_epoch < epoch:
                            self.last_error_reason = "payout_missing_proof"
                            log.warning("[mempool] payout reject art=%s reason=%s last_proof=%s epoch=%s", art_id[:16], self.last_error_reason, latest_proof, epoch)
                            return False

                # Collect payout recipients
                recs = payout_meta.get("recipients") or []
                if not isinstance(recs, list) or not recs:
                    self.last_error_reason = "payout_no_recipients"
                    log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                    return False

                # Build paymap from outputs
                paymap: dict[str, int] = {}
                for out in getattr(tx, "outputs", []) or []:
                    amt = int(getattr(out, "amount", 0) or 0)
                    if amt <= 0:
                        continue
                    
                    spk_bytes = get_utxo_script_bytes({"tx_out": {"script_pubkey": getattr(out, "script_pubkey", None)}})
                    if is_p2wpkh(spk_bytes) or is_p2wsh(spk_bytes):
                        addr = self.script_to_address(getattr(out, "script_pubkey", None))
                        
                        if addr:
                            paymap[addr.strip().lower()] = paymap.get(addr.strip().lower(), 0) + amt
                    # ignore OP_RETURN

                # Sum required + shortfall check
                total_req = 0
                for rec in recs:
                    addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
                    amt_req = int(rec.get("amount", 0))
                    if not addr or amt_req <= 0:
                        self.last_error_reason = "payout_bad_recipient"
                        log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                        return False
                    
                    total_req += amt_req
                    if paymap.get(addr, 0) < amt_req:
                        self.last_error_reason = "payout_shortfall"
                        log.warning("[mempool] payout reject art=%s reason=%s paid=%s req=%s", art_id[:16], self.last_error_reason, paymap.get(addr, 0), amt_req)
                        return False
                    
                if total_req > pool_balance:
                    self.last_error_reason = "payout_exceeds_pool"
                    log.warning("[mempool] payout reject art=%s reason=%s total=%s pool=%s", art_id[:16], self.last_error_reason, total_req, pool_balance)
                    return False

                # Validate inputs: must spend pool P2WSH for this art_id
                total_in = 0
                pool_script_hash = GRAFFITI.hash_pool_redeem_script(art_id)
                for txin in getattr(tx, "inputs", []) or []:
                    prev_txid_hex = self._txin_prev_txid(txin)
                    vout = int(getattr(txin, "vout", getattr(txin, "prev_index", 0)))
                    utxo_entry = self._lookup_utxo_entry(utxo_set, prev_txid_hex, vout)
                    if not utxo_entry:
                        self.last_error_reason = "missing_prevout"
                        log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                        return False
                    
                    spk_bytes = get_utxo_script_bytes(utxo_entry)
                    amt_prev = self._get_utxo_amount(utxo_entry)
                    total_in += int(amt_prev)
                    if not (is_p2wsh(spk_bytes) and len(spk_bytes) == 34):
                        self.last_error_reason = "payout_prev_not_pool"
                        log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                        return False
                    
                    prog = spk_bytes[2:]
                    if prog.hex() != pool_script_hash:
                        self.last_error_reason = "payout_wrong_pool"
                        log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                        return False

                total_out = sum(int(getattr(o, "amount", 0) or 0) for o in getattr(tx, "outputs", []) or [])
                if total_out > total_in:
                    self.last_error_reason = "payout_fee_negative"
                    log.warning("[mempool] payout reject art=%s reason=%s", art_id[:16], self.last_error_reason)
                    return False
                
                tx.fee = int(total_in - total_out)
                return True

            compact_tx = tx_to_compact_tuple(tx)
            utxo_items = self._utxo_snapshot_to_items(utxo_set)
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
            ok, reason, fee = native_validate_tx_p2wpkh_compact(
                compact_tx,
                utxo_items,
                int(current_height if spend_at_height is None else spend_at_height),
                opts,
            )
            if ok:
                tx.fee = int(fee or 0)
                # Graffiti queue limit: only enforced when inserting into mempool (spend_at_height None).
                enforce_limit = spend_at_height is None
                if enforce_limit:
                    is_post = False
                    for tx_out in getattr(tx, "outputs", []) or []:
                        spk = getattr(tx_out, "script_pubkey", None)
                        meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                        if meta and str(meta.get("event", "")).upper() == "POST":
                            is_post = True
                            break
                        
                    if is_post and int(CFG.MAX_GRAFFITI_ON_MEMPOOL) > 0:
                        current_posts = 0
                        for existing in getattr(self, "_pool", {}).values():
                            for out in getattr(existing, "outputs", []) or []:
                                spk2 = getattr(out, "script_pubkey", None)
                                meta2 = GRAFFITI.parse_from_script(spk2) if spk2 is not None else None
                                if meta2 and str(meta2.get("event", "")).upper() == "POST":
                                    current_posts += 1
                                    if current_posts >= int(CFG.MAX_GRAFFITI_ON_MEMPOOL):
                                        self.last_error_reason = "mempool_graffiti_full"
                                        return False
                                    
                    # Payout sanity check (soft, mirrors consensus)
                    reg = getattr(self.utxo, "_graffiti_registry", None) or GraffitiRegistry()
                    paymap: dict[str, int] = {}
                    for out in getattr(tx, "outputs", []) or []:
                        addr = self.script_to_address(getattr(out, "script_pubkey", None))
                        if not addr:
                            continue
                        
                        amt = int(getattr(out, "amount", 0) or 0)
                        if amt <= 0:
                            continue
                        
                        paymap[addr.strip().lower()] = paymap.get(addr.strip().lower(), 0) + amt
                    for out in getattr(tx, "outputs", []) or []:
                        spk = getattr(out, "script_pubkey", None)
                        meta = None
                        meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                        if not meta or str(meta.get("event", "")).upper() != "PAYOUT":
                            continue
                        
                        art_id = str(meta.get("art_id") or "").strip().lower()
                        if not art_id:
                            self.last_error_reason = "payout_bad_art_id"
                            return False
                        
                        post = reg.get_post(art_id)
                        if not post:
                            self.last_error_reason = "payout_unknown_art"
                            return False
                        
                        stats = post.get("stats") or {}
                        pool_balance = int(stats.get("pool_balance", 0))
                        last_epoch = int(stats.get("last_paid_epoch", -1))
                        epoch = int(meta.get("epoch", -1))
                        if epoch >= 0 and epoch <= last_epoch:
                            self.last_error_reason = "payout_epoch_rewind"
                            return False
                        
                        if epoch >= 0:
                            latest_proof = reg.get_latest_proof_epoch(art_id)
                            if latest_proof < epoch:
                                self.last_error_reason = "payout_missing_proof"
                                return False
                            
                        recs = meta.get("recipients") or []
                        if not isinstance(recs, list) or not recs:
                            self.last_error_reason = "payout_no_recipients"
                            return False
                        
                        total_req = 0
                        for rec in recs:
                            addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
                            amt_req = int(rec.get("amount", 0))
                            if not addr or amt_req <= 0:
                                self.last_error_reason = "payout_bad_recipient"
                                return False
                            
                            total_req += amt_req
                            paid = paymap.get(addr, 0)
                            if paid < amt_req:
                                self.last_error_reason = "payout_shortfall"
                                return False
                            
                        if total_req > pool_balance:
                            self.last_error_reason = "payout_exceeds_pool"
                            return False
                        
                return True
            
            else:
                self.last_error_reason = reason or "native_mempool_reject"
                log.warning(
                    "[validate_transaction] Native reject txid=%s reason=%s",
                    getattr(tx, "txid", None),
                    self.last_error_reason,
                )
        except Exception:
            log.exception("[validate_transaction] Native validation error for tx %s", getattr(tx, "txid", None))
            self.last_error_reason = "native_mempool_failed"
            return False
