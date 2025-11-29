# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141

from __future__ import annotations

from typing import Any

from ..core.tx import Tx
from ..utils import helpers as H
from ..utils.helpers import hash160, is_p2wpkh_script, bip143_sig_hash
from ..utils.tsar_logging import get_ctx_logger
from ..utils import config as CFG
from ..storage.utxo import UTXODB
from .scripts import (
    extract_p2pkh_scriptsig,
    get_utxo_script_bytes,
    is_p2pkh_script,
    legacy_sighash,
    p2wpkh_script_code_from_spk,
    vk_from_pubkey_bytes,
)
from .types import PrevoutRef, PrevoutMeta

log = get_ctx_logger("tsarchain.mempool.validation")

__all__ = ["TxMempoolValidator"]


class TxMempoolValidator:
    utxo: UTXODB
    last_error_reason: str | None

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
        key_str = f"{prev_txid_hex}:{int(prev_index)}"
        if isinstance(snapshot, dict):
            entry = snapshot.get(key_str)
            if entry is not None:
                return entry
            entry = snapshot.get(key_str.lower())
            if entry is not None:
                return entry
            try:
                entry = snapshot.get(key_str.encode("utf-8"))
                if entry is not None:
                    return entry
            except Exception:
                pass

            bucket = snapshot.get(prev_txid_hex) or snapshot.get(prev_txid_hex.lower())
            if isinstance(bucket, dict) and int(prev_index) in bucket:
                return bucket[int(prev_index)]

            tuple_key = (prev_txid_hex, int(prev_index))
            if tuple_key in snapshot:
                return snapshot[tuple_key]

            try:
                tuple_b = (bytes.fromhex(prev_txid_hex), int(prev_index))
            except ValueError:
                tuple_b = None
            if tuple_b and tuple_b in snapshot:
                return snapshot[tuple_b]

            if len(snapshot) <= 2048:
                lookup_key_ci = key_str.lower()
                for key, value in snapshot.items():
                    try:
                        if isinstance(key, str) and key.lower() == lookup_key_ci:
                            return value
                        if isinstance(key, tuple) and len(key) == 2:
                            k_txid = key[0]
                            k_vout = int(key[1])
                            if k_vout != int(prev_index):
                                continue
                            if isinstance(k_txid, (bytes, bytearray)):
                                cmp = k_txid.hex().lower()
                            else:
                                cmp = str(k_txid).lower()
                            if cmp == prev_txid_hex.lower():
                                return value
                    except Exception:
                        continue

        lookup_method = getattr(self.utxo, "lookup_entry", None)
        if callable(lookup_method):
            return lookup_method(prev_txid_hex, int(prev_index))
        return None

    @staticmethod
    def _coinbase_confirmations(born_height: int, spend_height: int) -> int:
        try:
            return max(0, int(spend_height) - int(born_height))
        except Exception:
            return 0

    def validate_transaction(
        self,
        tx: Tx,
        utxo_set: dict[str, Any],
        spend_at_height: int | None = None,
    ) -> bool:
        
        if getattr(tx, "is_coinbase", False):
            return False

        input_sum = 0
        output_sum = 0
        current_height = (
            spend_at_height if spend_at_height is not None else self.utxo._get_tip_height_from_state()
        )
        prevouts: list[PrevoutMeta] = []
        seen_prevouts: set[PrevoutRef] = set()

        for tx_in in tx.inputs:
            prev_txid_hex = self._txin_prev_txid(tx_in)
            if prev_txid_hex is None:
                self.last_error_reason = "missing_prev_txid"
                return False
            prev_index_val = getattr(tx_in, "vout", getattr(tx_in, "prev_index", None))
            if prev_index_val is None:
                self.last_error_reason = "missing_prev_index"
                return False
            try:
                prev_index = int(prev_index_val)
            except Exception:
                self.last_error_reason = "invalid_prev_index"
                return False

            ref = PrevoutRef(prev_txid_hex, prev_index)
            if ref in seen_prevouts:
                self.last_error_reason = "duplicate_prevout_in_tx"
                return False
            seen_prevouts.add(ref)

            utxo_entry = self._lookup_utxo_entry(utxo_set, prev_txid_hex, prev_index)
            if utxo_entry is None:
                self.last_error_reason = f"prevout_missing {prev_txid_hex}:{prev_index}"
                return False

            try:
                amount = self._get_utxo_amount(utxo_entry)
            except ValueError:
                self.last_error_reason = "invalid_utxo_amount"
                return False

            is_cb, born_height = self.utxo._get_utxo_meta(utxo_entry)
            if is_cb:
                effective_height = (
                    int(spend_at_height) if spend_at_height is not None else int(current_height) + 1
                )
                confirmations = self._coinbase_confirmations(born_height, effective_height)
                if confirmations < int(CFG.COINBASE_MATURITY):
                    self.last_error_reason = (
                        f"coinbase_immature conf={confirmations} need>={CFG.COINBASE_MATURITY}"
                    )
                    return False

            input_sum += int(amount)
            try:
                tx_in.amount = int(amount)
            except Exception:
                pass

            try:
                spk_bytes = get_utxo_script_bytes(utxo_entry)
            except Exception:
                log.warning(
                    "[validate_transaction] Error extracting script_pubkey from UTXO %s:%d",
                    prev_txid_hex,
                    prev_index,
                )
                self.last_error_reason = "invalid_utxo_script"
                return False

            prevouts.append(
                PrevoutMeta(
                    amount=int(amount),
                    script_pubkey=spk_bytes,
                    is_coinbase=is_cb,
                    born_height=int(born_height),
                )
            )

        for tx_out in tx.outputs:
            amt = int(tx_out.amount)
            is_opret = False
            try:
                spk_bytes = tx_out.script_pubkey.serialize()
                is_opret = (
                    isinstance(tx_out.script_pubkey, H.Script)
                    and spk_bytes
                    and spk_bytes[0] == H.OP_RETURN
                )
            except Exception:
                is_opret = False

            if amt <= 0:
                if is_opret and amt == 0:
                    continue

                self.last_error_reason = "nonpositive_output_amount"
                return False

            output_sum += amt

        if input_sum < output_sum:
            log.warning(
                "[validate_transaction] inputs < outputs: in=%d out=%d",
                input_sum,
                output_sum,
            )
            self.last_error_reason = f"inputs_less_than_outputs in={input_sum} out={output_sum}"
            return False

        fee_value = int(input_sum - output_sum)
        try:
            tx.fee = fee_value
        except Exception:
            setattr(tx, "fee", fee_value)

        for i, tx_in in enumerate(tx.inputs):
            meta = prevouts[i]
            amount = meta.amount
            spk_bytes = meta.script_pubkey

            if is_p2wpkh_script(spk_bytes):
                wit = getattr(tx_in, "witness", None) or []
                if len(wit) < 2:
                    self.last_error_reason = "missing_witness"
                    return False
                sig = wit[0]
                pubkey = wit[1]
                if isinstance(sig, str):
                    sig = bytes.fromhex(sig)
                if isinstance(pubkey, str):
                    pubkey = bytes.fromhex(pubkey)
                if len(sig) < 2:
                    return False

                sighash_type = sig[-1]
                sig_der = sig[:-1]
                if sighash_type != H.SIGHASH_ALL:
                    self.last_error_reason = "unsupported_sighash"
                    return False

                pkhash = spk_bytes[2:22]
                if hash160(pubkey) != pkhash:
                    self.last_error_reason = "pubkey_hash_mismatch"
                    return False

                try:
                    script_code = p2wpkh_script_code_from_spk(spk_bytes)
                    digest32 = bip143_sig_hash(tx, i, script_code, int(amount), sighash_type)
                except Exception as e:
                    log.warning(
                        "[validate_transaction] Failed to compute BIP143 sighash in vin %d",
                        i,
                    )
                    self.last_error_reason = f"bip143_sighash_error:{e}"
                    return False

                vk = vk_from_pubkey_bytes(pubkey)
                if not H.is_signature_canonical_low_s(sig_der):
                    self.last_error_reason = "sighash_or_der_non_canonical"
                    return False

                if not H.verify_der_strict_low_s(vk, digest32, sig_der):
                    self.last_error_reason = "ecdsa_verify_failed"
                    return False

            else:
                log.warning(
                    "[validate_transaction] Unsupported scriptPubKey type in vin %d", i
                )
                self.last_error_reason = "unsupported_spk_type"
                return False

        return True
