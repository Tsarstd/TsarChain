# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

from collections import defaultdict
from bech32 import bech32_decode, convertbits

from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic(balances)")

class UTXOBalanceMixin:
    def _script_hex_from_tx_out(self, tx_out) -> str | None:
        if tx_out is None:
            return None
        spk = None
        if hasattr(tx_out, "script_pubkey"):
            spk = tx_out.script_pubkey
        elif isinstance(tx_out, dict):
            spk = tx_out.get("script_pubkey")
        elif hasattr(tx_out, "serialize"):
            return tx_out.serialize().hex().lower()
        if spk is None:
            return None
        if hasattr(spk, "serialize"):
            return spk.serialize().hex().lower()
        if isinstance(spk, (bytes, bytearray)):
            return bytes(spk).hex().lower()
        if isinstance(spk, str):
            return spk.lower()
        return None

    def _amount_from_tx_out(self, tx_out) -> int:
        if isinstance(tx_out, dict):
            return int(tx_out.get("amount", 0) or 0)
        return int(getattr(tx_out, "amount", 0) or 0)
    
    def _normalize_target_spk_hex(self, x: str) -> str:
        x = (x or "").strip().lower()
        if x.startswith("tsar1"):
            hrp, data = bech32_decode(x)
            if hrp != "tsar" or data is None:
                raise ValueError("invalid tsar bech32 address")
            prog = convertbits(data[1:], 5, 8, False)
            if prog is None or len(prog) not in (20, 32):
                raise ValueError("invalid witness program length")
            if len(prog) == 20:
                return "0014" + bytes(prog).hex()
            return "0020" + bytes(prog).hex()
        if x.startswith("00") and len(x) in (42, 66):
            return "00" + x[2:]
        if x.startswith("0014") and len(x) == 44:
            return x
        if x.startswith("0020") and len(x) == 68:
            return x
        return x

    def _ensure_index_locked(self):
        if self._address_index is not None:
            return
        
        self._address_index = defaultdict(set)
        self._key_to_spk.clear()
        for key, entry in self.utxos.items():
            tx_out = entry.get("tx_out")
            spk_hex = self._script_hex_from_tx_out(tx_out)
            if spk_hex:
                self._address_index[spk_hex].add(key)
                self._key_to_spk[key] = spk_hex

    def _get_index_bucket(self, script_hex: str) -> set[str]:
        script_hex = (script_hex or "").lower()
        self._ensure_index_locked()
        bucket = self._address_index.get(script_hex) if self._address_index else None
        return set(bucket) if bucket else set()

    def _index_entry(self, key: str, tx_out):
        if self._address_index is None:
            return
        
        spk_hex = self._script_hex_from_tx_out(tx_out)
        if spk_hex:
            self._address_index.setdefault(spk_hex, set()).add(key)
            self._key_to_spk[key] = spk_hex

    def _drop_index_entry(self, key: str):
        if self._address_index is None:
            return
        spk = self._key_to_spk.pop(key, None)
        if not spk:
            return
        bucket = self._address_index.get(spk)
        if bucket:
            bucket.discard(key)
            if not bucket:
                self._address_index.pop(spk, None)

    def get_balance(self, identifier: str, mode: str = "total",
                    current_height: int = None, maturity: int = CFG.COINBASE_MATURITY):

        if current_height is None:
            current_height = self._get_tip_height_from_state()

        target_spk_hex = self._normalize_target_spk_hex(identifier)

        total = mature = immature = 0
        with self._lock:
            keys = list(self._get_index_bucket(target_spk_hex))
            for key in keys:
                entry = self.utxos.get(key)
                if not entry:
                    continue
                tx_out = entry["tx_out"]
                amt = self._amount_from_tx_out(tx_out)
                is_cb = bool(entry.get("is_coinbase", False))
                born = int(entry.get("block_height", entry.get("height", 0)))

                if is_cb:
                    confirmations = max(0, (int(current_height) - born) + 1)
                    if confirmations >= int(maturity):
                        mature += amt
                    else:
                        immature += amt
                else:
                    mature += amt
                total += amt

        if mode == "total":
            return int(total)
        if mode == "spendable":
            return int(mature)
        return {"total": int(total), "mature": int(mature), "immature": int(immature)}
    
    def count_utxos(self, identifier: str) -> int:
        target_spk_hex = self._normalize_target_spk_hex(identifier)
        with self._lock:
            keys = list(self._get_index_bucket(target_spk_hex))
            valid_count = 0
            for key in keys:
                if key in self.utxos:
                    valid_count += 1
            
            return valid_count

    def get(self, identifier: str):
        target_spk_hex = self._normalize_target_spk_hex(identifier)
        result = {}
        with self._lock:
            keys = list(self._get_index_bucket(target_spk_hex))
            for key in keys:
                data = self.utxos.get(key)
                if not data:
                    continue
                result[key] = {
                    "amount": self._amount_from_tx_out(data["tx_out"]),
                    "script_pubkey": target_spk_hex,
                    "is_coinbase": bool(data.get("is_coinbase", False)),
                    "block_height": int(data.get("block_height", 0)),
                }
        return result

    def lookup_entry(self, txid_hex: str, index: int):
        if txid_hex is None:
            return None
        key = f"{str(txid_hex).lower()}:{int(index)}"
        with self._lock:
            return self.utxos.get(key)
