# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP143; BIP141

from __future__ import annotations

from typing import Any

from ..core.tx import Tx
from ..utils import config as CFG
from ..storage.utxo import UTXODB
from ..utils.benchmarks import benchmark
from .scripts import get_utxo_script_bytes, script_to_address
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

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.validation")

_PAYOUT_REJECT_MSG = "[mempool] payout reject art=%s reason=%s"

__all__ = ["TxMempoolValidator"]


class TxMempoolValidator:
    utxo: UTXODB
    last_error_reason: str | None


    @benchmark(label="validate_transaction_mempool", threshold_ms=15.0)
    def validate_transaction(self, tx: Tx, utxo_set: dict[str, Any], spend_at_height: int | None = None,) -> bool:
        if not self._validate_tx_basic_guards(tx):
            return False

        current_height = (spend_at_height if spend_at_height is not None else self.utxo._get_tip_height_from_state())
        try:
            # ---- Special handling for Graffiti PAYOUT (P2WSH pool) ----
            payout_meta = self._find_payout_meta(tx)
            if payout_meta:
                return self._validate_payout_tx(tx, payout_meta, utxo_set)

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
                    if not self._enforce_mempool_post_limit(tx):
                        return False
                                    
                    # Payout sanity check (soft, mirrors consensus)
                    if not self._check_mempool_payout_sanity(tx):
                        return False
                        
                return True
            
            else:
                self.last_error_reason = reason or "native_mempool_reject"
                try:
                    tx_txid = tx.txid
                except AttributeError:
                    tx_txid = None
                log.warning(
                    "[validate_transaction] Native reject txid=%s reason=%s",
                    tx_txid,
                    self.last_error_reason,
                )
        except Exception:
            try:
                tx_txid = tx.txid
            except AttributeError:
                tx_txid = None
            log.exception("[validate_transaction] Native validation error for tx %s", tx_txid)
            self.last_error_reason = "native_mempool_failed"
            return False


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _script_to_address(self, script) -> str | None:
        """
        Convert P2WPKH/P2WSH scriptPubKey to bech32 address.
        """
        return script_to_address(script)


    def _check_mempool_payout_sanity(self, tx: Tx) -> bool:
        try:
            reg = self.utxo._graffiti_registry
        except AttributeError:
            reg = None
        if reg is None:
            reg = GraffitiRegistry()
        paymap: dict[str, int] = {}
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        for out in outputs:
            try:
                spk = out.script_pubkey
            except AttributeError:
                spk = None
            addr = self._script_to_address(spk)
            if not addr:
                continue
            
            try:
                amt = int(out.amount or 0)
            except (AttributeError, TypeError):
                amt = 0
            if amt <= 0:
                continue
            
            paymap[addr.strip().lower()] = paymap.get(addr.strip().lower(), 0) + amt
        
        return self._validate_payout_sanity(tx, paymap, reg)


    def _validate_payout_art_and_epoch(self, payout_meta: dict[str, Any], reg: GraffitiRegistry) -> bool:
        art_id = str(payout_meta.get("art_id") or "").strip().lower()
        post = reg.get_post(art_id)
        if not post:
            self.last_error_reason = "payout_unknown_art"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False
        
        stats = post.get("stats") or {}
        last_epoch = int(stats.get("last_paid_epoch", -1))
        epoch = int(payout_meta.get("epoch", -1))
        if epoch >= 0 and epoch <= last_epoch:
            self.last_error_reason = "payout_epoch_rewind"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False
        
        if epoch >= 0:
            latest_proof = reg.get_latest_proof_epoch(art_id)
            if latest_proof < epoch:
                proof_epoch = int(payout_meta.get("proof_epoch", -1))
                if proof_epoch < 0:
                    proof_height = int(payout_meta.get("proof_height", payout_meta.get("height", -1)))
                    if proof_height >= 0:
                        proof_epoch = GRAFFITI.compute_proof_epoch(proof_height)
                        
                if proof_epoch < epoch:
                    self.last_error_reason = "payout_missing_proof"
                    log.warning("[mempool] payout reject art=%s reason=%s last_proof=%s epoch=%s", art_id[:16], self.last_error_reason, latest_proof, epoch)
                    return False
        return True


    def _validate_payout_recipients_and_balance(self, tx: Tx, payout_meta: dict[str, Any], post: dict[str, Any]) -> bool:
        art_id = str(payout_meta.get("art_id") or "").strip().lower()
        stats = post.get("stats") or {}
        pool_balance = int(stats.get("pool_balance", 0))

        recs = payout_meta.get("recipients") or []
        if type(recs) is not list or not recs:
            self.last_error_reason = "payout_no_recipients"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False

        paymap: dict[str, int] = {}
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        for out in outputs:
            try:
                amt = int(out.amount or 0)
            except (AttributeError, TypeError):
                amt = 0
            if amt <= 0:
                continue
            
            try:
                spk = out.script_pubkey
            except AttributeError:
                spk = None
            spk_bytes = get_utxo_script_bytes({"tx_out": {"script_pubkey": spk}})
            if is_p2wpkh(spk_bytes) or is_p2wsh(spk_bytes):
                addr = self._script_to_address(spk)
                if addr:
                    paymap[addr.strip().lower()] = paymap.get(addr.strip().lower(), 0) + amt

        total_req = 0
        for rec in recs:
            addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
            amt_req = int(rec.get("amount", 0))
            if not addr or amt_req <= 0:
                self.last_error_reason = "payout_bad_recipient"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False
            
            total_req += amt_req
            if paymap.get(addr, 0) < amt_req:
                self.last_error_reason = "payout_shortfall"
                log.warning("[mempool] payout reject art=%s reason=%s paid=%s req=%s", art_id[:16], self.last_error_reason, paymap.get(addr, 0), amt_req)
                return False
            
        if total_req > pool_balance:
            self.last_error_reason = "payout_exceeds_pool"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False
        return True


    def _validate_payout_inputs(self, tx: Tx, art_id: str, utxo_set: dict[str, Any]) -> bool:
        total_in = 0
        pool_script_hash = GRAFFITI.hash_pool_redeem_script(art_id)
        try:
            inputs = tx.inputs or []
        except AttributeError:
            inputs = []
        for txin in inputs:
            prev_txid_hex = self._txin_prev_txid(txin)
            try:
                v_val = txin.vout
            except AttributeError:
                try:
                    v_val = txin.prev_index
                except AttributeError:
                    v_val = 0
            vout = int(v_val if v_val is not None else 0)
            utxo_entry = self._lookup_utxo_entry(utxo_set, prev_txid_hex, vout)
            if not utxo_entry:
                self.last_error_reason = "missing_prevout"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False
            
            spk_bytes = get_utxo_script_bytes(utxo_entry)
            amt_prev = self._get_utxo_amount(utxo_entry)
            total_in += int(amt_prev)
            if not (is_p2wsh(spk_bytes) and len(spk_bytes) == 34):
                self.last_error_reason = "payout_prev_not_pool"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False
            
            prog = spk_bytes[2:]
            if prog.hex() != pool_script_hash:
                self.last_error_reason = "payout_wrong_pool"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False

        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        total_out = 0
        for o in outputs:
            try:
                total_out += int(o.amount or 0)
            except (AttributeError, TypeError):
                pass
        if total_out > total_in:
            self.last_error_reason = "payout_fee_negative"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False
        
        tx.fee = int(total_in - total_out)
        return True


    def _has_exceeded_mempool_post_limit(self, max_limit: int) -> bool:
        current_posts = 0
        try:
            pool_values = self._pool.values()
        except AttributeError:
            pool_values = []
        for existing in pool_values:
            try:
                outputs = existing.outputs or []
            except AttributeError:
                outputs = []
            for out in outputs:
                try:
                    spk2 = out.script_pubkey
                except AttributeError:
                    spk2 = None
                meta2 = GRAFFITI.parse_from_script(spk2) if spk2 is not None else None
                if meta2 and str(meta2.get("event", "")).upper() == "POST":
                    current_posts += 1
                    if current_posts >= max_limit:
                        return True
        return False


    def _validate_single_payout_sanity(self, meta: dict[str, Any], paymap: dict[str, int], reg: GraffitiRegistry) -> bool:
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
        if type(recs) is not list or not recs:
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


    def _validate_tx_basic_guards(self, tx: Tx) -> bool:
        try:
            if tx.is_coinbase:
                return False
        except AttributeError:
            pass

        try:
            tx_txid = tx.txid
        except AttributeError:
            tx_txid = None

        try:
            weight, vsize, _base_size, _total_size = compute_tx_weight_vsize(tx)
        except Exception:
            log.exception("[validate_transaction] weight_calc_failed txid=%s", tx_txid)
            self.last_error_reason = "tx_weight_calc_failed"
            return False

        try:
            inputs = tx.inputs or []
        except AttributeError:
            inputs = []
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        vin = len(inputs)
        vout = len(outputs)
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

        for tx_out in outputs:
            try:
                spk = tx_out.script_pubkey
            except AttributeError:
                spk = None
            if not self._validate_graffiti_output(spk):
                return False
        return True


    def _find_payout_meta(self, tx: Tx) -> dict[str, Any] | None:
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        for tx_out in outputs:
            try:
                spk = tx_out.script_pubkey
            except AttributeError:
                spk = None
            meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
            if meta and str(meta.get("event", "")).upper() == "PAYOUT":
                return meta
        return None


    def _validate_payout_tx(self, tx: Tx, payout_meta: dict[str, Any], utxo_set: dict[str, Any]) -> bool:
        try:
            reg = self.utxo._graffiti_registry
        except AttributeError:
            reg = None
        if reg is None:
            reg = GraffitiRegistry()
        if not self._validate_payout_art_and_epoch(payout_meta, reg):
            return False

        art_id = str(payout_meta.get("art_id") or "").strip().lower()
        post = reg.get_post(art_id)
        
        if not self._validate_payout_recipients_and_balance(tx, payout_meta, post):
            return False

        return self._validate_payout_inputs(tx, art_id, utxo_set)


    def _enforce_mempool_post_limit(self, tx: Tx) -> bool:
        is_post = False
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        for tx_out in outputs:
            try:
                spk = tx_out.script_pubkey
            except AttributeError:
                spk = None
            meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
            if meta and str(meta.get("event", "")).upper() == "POST":
                is_post = True
                art_id = str(meta.get("art_id") or "").strip().lower()
                if not art_id:
                    sha_hex = str(meta.get("sha256") or "").strip().lower()
                    creator = str(meta.get("creator") or "").strip().lower()
                    art_id = GRAFFITI.compute_art_id(sha_hex, creator) if sha_hex and creator else ""
                if art_id:
                    try:
                        pool_addr = GRAFFITI.derive_pool_address(art_id)
                        min_fee = int(GRAFFITI.calc_upload_fee_sats(int(meta.get("size") or 0)))
                        paid = 0
                        for out in outputs:
                            try:
                                out_spk = out.script_pubkey
                            except AttributeError:
                                out_spk = None
                            try:
                                out_addr = out.address
                            except AttributeError:
                                out_addr = None
                            addr_cand = script_to_address(out_spk) if out_spk is not None else out_addr
                            if addr_cand == pool_addr:
                                try:
                                    paid += int(out.amount or 0)
                                except (AttributeError, TypeError):
                                    pass
                        if paid < min_fee:
                            self.last_error_reason = "graffiti_post_fee_insufficient"
                            log.warning("[_enforce_mempool_post_limit] POST rejected due to insufficient pool fee: paid=%s required=%s art_id=%s", paid, min_fee, art_id[:16])
                            return False
                    except Exception:
                        pass
                break
            
        if is_post and int(CFG.MAX_GRAFFITI_ON_MEMPOOL) > 0:
            if self._has_exceeded_mempool_post_limit(int(CFG.MAX_GRAFFITI_ON_MEMPOOL)):
                self.last_error_reason = "mempool_graffiti_full"
                return False
        return True


    def _validate_payout_sanity(self, tx: Tx, paymap: dict[str, int], reg: GraffitiRegistry) -> bool:
        try:
            outputs = tx.outputs or []
        except AttributeError:
            outputs = []
        for out in outputs:
            try:
                spk = out.script_pubkey
            except AttributeError:
                spk = None
            meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
            if meta and str(meta.get("event", "")).upper() == "PAYOUT":
                if not self._validate_single_payout_sanity(meta, paymap, reg):
                    return False
        return True


    def _lookup_in_snapshot_dict(self, snapshot: dict, txid: str, txid_raw: str, idx: int):
        key_lower = f"{txid}:{idx}"
        key_raw = f"{txid_raw}:{idx}"
        for k in (key_lower, key_raw):
            if k in snapshot:
                return snapshot[k]
        kb = key_lower.encode("utf-8")
        if kb in snapshot:
            return snapshot[kb]

        for tk in ((txid, idx), (txid_raw, idx)):
            if tk in snapshot:
                return snapshot[tk]

        bucket = snapshot.get(txid) or snapshot.get(txid_raw)
        if type(bucket) is dict and idx in bucket:
            return bucket[idx]

        try:
            txid_bytes = bytes.fromhex(txid)
        except ValueError:
            txid_bytes = None
        if txid_bytes:
            tuple_b = (txid_bytes, idx)
            if tuple_b in snapshot:
                return snapshot[tuple_b]
        return None


    def _get_utxo_amount(self, utxo_data):
        if type(utxo_data) is dict:
            if "tx_out" in utxo_data:
                txo = utxo_data["tx_out"]
                if type(txo) is dict and "amount" in txo:
                    return int(txo.get("amount", 0))
                try:
                    amt = txo.amount
                    if amt is not None:
                        return int(amt)
                except AttributeError:
                    pass
            if "amount" in utxo_data:
                return int(utxo_data["amount"])
        else:
            try:
                amt = utxo_data.amount
                if amt is not None:
                    return int(amt)
            except AttributeError:
                pass
        raise ValueError(f"Unknown UTXO format: {utxo_data}")


    def _txin_prev_txid(self, tx_in) -> str | None:
        try:
            txid_val = tx_in.txid
        except AttributeError:
            try:
                txid_val = tx_in.prev_tx
            except AttributeError:
                txid_val = None
        if txid_val is None:
            try:
                txid_val = tx_in.prev_tx
            except AttributeError:
                txid_val = None
        if txid_val is None:
            return None
        if type(txid_val) in (bytes, bytearray):
            return txid_val.hex().lower()
        return str(txid_val).lower()


    def _lookup_utxo_entry(self, snapshot, prev_txid_hex: str, prev_index: int):
        if prev_txid_hex is None:
            return None
        idx = int(prev_index)

        txid_raw = str(prev_txid_hex)
        txid = txid_raw.lower()

        if type(snapshot) is dict:
            res = self._lookup_in_snapshot_dict(snapshot, txid, txid_raw, idx)
            if res is not None:
                return res

        try:
            lookup_method = self.utxo.lookup_entry
            if callable(lookup_method):
                return lookup_method(txid, idx)
        except AttributeError:
            pass
        return None


    def _utxo_snapshot_to_items(self, snapshot) -> list[tuple]:
        items = []
        if type(snapshot) is not dict:
            return items
        for key, entry in snapshot.items():
            if type(key) in (bytes, bytearray):
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
        try:
            raw = spk_obj.serialize()
        except (AttributeError, TypeError):
            if type(spk_obj) in (bytes, bytearray):
                raw = bytes(spk_obj)
            elif type(spk_obj) is str:
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