# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141

from __future__ import annotations

from typing import Any

from ..core.tx import Tx
from ..utils.helpers import (tx_to_compact_tuple, native_validate_tx_p2wpkh_compact,)
from ..storage.utxo import UTXODB
from .scripts import get_utxo_script_bytes
from ..contracts import graffiti as GRAFFITI
from ..utils import config as CFG


from ..utils.tsar_logging import get_ctx_logger
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

    def _utxo_snapshot_to_items(self, snapshot) -> list[tuple]:
        items = []
        if not isinstance(snapshot, dict):
            return items
        for key, entry in snapshot.items():
            try:
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
            except Exception:
                continue
        return items

    def validate_transaction(self, tx: Tx, utxo_set: dict[str, Any], spend_at_height: int | None = None,) -> bool:
        if getattr(tx, "is_coinbase", False):
            return False

        current_height = (spend_at_height if spend_at_height is not None else self.utxo._get_tip_height_from_state())

        try:
            compact_tx = tx_to_compact_tuple(tx)
            utxo_items = self._utxo_snapshot_to_items(utxo_set)
            ok, reason, fee = native_validate_tx_p2wpkh_compact(
                compact_tx,
                utxo_items,
                int(current_height if spend_at_height is None else spend_at_height),
                int(CFG.COINBASE_MATURITY),
            )
            if ok:
                try:
                    tx.fee = int(fee or 0)
                except Exception:
                    setattr(tx, "fee", int(fee or 0))
                # Graffiti queue limit: only enforced when inserting into mempool (spend_at_height None).
                enforce_limit = spend_at_height is None
                if enforce_limit:
                    try:
                        is_post = False
                        for tx_out in getattr(tx, "outputs", []) or []:
                            spk = getattr(tx_out, "script_pubkey", None)
                            meta = None
                            try:
                                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                            except Exception:
                                meta = None
                            if meta and str(meta.get("event", "")).upper() == "POST":
                                is_post = True
                                break
                        if is_post and int(CFG.MAX_GRAFFITI_ON_MEMPOOL) > 0:
                            current_posts = 0
                            for existing in getattr(self, "_pool", {}).values():
                                for out in getattr(existing, "outputs", []) or []:
                                    spk2 = getattr(out, "script_pubkey", None)
                                    try:
                                        meta2 = GRAFFITI.parse_from_script(spk2) if spk2 is not None else None
                                    except Exception:
                                        meta2 = None
                                    if meta2 and str(meta2.get("event", "")).upper() == "POST":
                                        current_posts += 1
                                        if current_posts >= int(CFG.MAX_GRAFFITI_ON_MEMPOOL):
                                            self.last_error_reason = "mempool_graffiti_full"
                                            return False
                    except Exception:
                        pass
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
