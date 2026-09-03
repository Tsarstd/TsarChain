# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: BIP141; BIP173

from collections import defaultdict
from bech32 import bech32_decode, convertbits

from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic(balances)")

class UTXOBalanceMixin:


    def get_balance(self, identifier: str, mode: str = "total",
                    current_height: int = None, maturity: int = CFG.COINBASE_MATURITY):

        if current_height is None:
            current_height = self._get_tip_height_from_state()

        target_spk_hex = self._normalize_target_spk_hex(identifier)

        with self._lock:
            self._ensure_index_locked()
            total = self._addr_total_balance.get(target_spk_hex, 0)
            if not total:
                if mode == "total":
                    return 0
                if mode == "spendable":
                    return 0
                return {"total": 0, "mature": 0, "immature": 0}

            immature = 0
            if self._coinbases_by_height:
                maturity_int = int(maturity)
                curr_h = int(current_height) if current_height is not None else 0
                # Immature coinbases satisfy: (curr_h - born + 1) < maturity_int <=> born >= curr_h + 2 - maturity_int
                min_immature_born = max(0, curr_h + 2 - maturity_int)
                for h in range(min_immature_born, curr_h + 1):
                    entries = self._coinbases_by_height.get(h)
                    if entries:
                        for spk, amt in entries.values():
                            if spk == target_spk_hex:
                                immature += amt

            mature = max(0, total - immature)

        if mode == "total":
            return int(total)
        if mode == "spendable":
            return int(mature)
        return {"total": int(total), "mature": int(mature), "immature": int(immature)}


    def count_utxos(self, identifier: str) -> int:
        target_spk_hex = self._normalize_target_spk_hex(identifier)
        with self._lock:
            self._ensure_index_locked()
            bucket = self._address_index.get(target_spk_hex) if self._address_index else None
            if not bucket:
                return 0
            return sum(1 for k in bucket if k in self.utxos)


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


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _script_hex_from_tx_out(self, tx_out) -> str | None:
        if tx_out is None:
            return None
        if type(tx_out) is dict:
            spk = tx_out.get("script_pubkey")
        else:
            try:
                spk = tx_out.script_pubkey
            except AttributeError:
                try:
                    return tx_out.serialize().hex().lower()
                except (AttributeError, TypeError):
                    spk = None
        if spk is None:
            return None
        try:
            return spk.serialize().hex().lower()
        except (AttributeError, TypeError):
            pass
        if type(spk) in (bytes, bytearray):
            return bytes(spk).hex().lower()
        if type(spk) is str:
            return spk.lower()
        return None


    def _amount_from_tx_out(self, tx_out) -> int:
        if type(tx_out) is dict:
            return int(tx_out.get("amount", 0) or 0)

        amt = tx_out.amount
        return int(amt or 0)


    def _normalize_target_spk_hex(self, x: str) -> str:
        x = (x or "").strip().lower()
        hrp, data = bech32_decode(x)
        if hrp is not None:
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
        self._key_to_amount = {}
        self._addr_total_balance = defaultdict(int)
        self._coinbases_by_height = defaultdict(dict)
        for key, entry in self.utxos.items():
            if entry is None:
                continue
            tx_out = entry.get("tx_out")
            spk_hex = self._script_hex_from_tx_out(tx_out)
            if spk_hex:
                amt = self._amount_from_tx_out(tx_out)
                self._address_index[spk_hex].add(key)
                self._key_to_spk[key] = spk_hex
                self._key_to_amount[key] = amt
                self._addr_total_balance[spk_hex] = self._addr_total_balance.get(spk_hex, 0) + amt
                is_cb = bool(entry.get("is_coinbase", False))
                if is_cb:
                    born = int(entry.get("block_height", entry.get("height", 0)))
                    self._coinbases_by_height[born][key] = (spk_hex, amt)


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
            amt = self._amount_from_tx_out(tx_out)
            self._address_index.setdefault(spk_hex, set()).add(key)
            self._key_to_spk[key] = spk_hex
            self._key_to_amount[key] = amt
            self._addr_total_balance[spk_hex] = self._addr_total_balance.get(spk_hex, 0) + amt
            entry = self.utxos.get(key)
            if entry and bool(entry.get("is_coinbase", False)):
                born = int(entry.get("block_height", entry.get("height", 0)))
                self._coinbases_by_height[born][key] = (spk_hex, amt)


    def _drop_index_entry(self, key: str):
        if self._address_index is None:
            return
        spk = self._key_to_spk.pop(key, None)
        if not spk:
            return
        amt = self._key_to_amount.pop(key, 0)
        bucket = self._address_index.get(spk)
        if bucket:
            bucket.discard(key)
            if not bucket:
                self._address_index.pop(spk, None)
        if spk in self._addr_total_balance:
            rem = self._addr_total_balance[spk] - amt
            if rem <= 0:
                self._addr_total_balance.pop(spk, None)
            else:
                self._addr_total_balance[spk] = rem
        for born, d in list(self._coinbases_by_height.items()):
            if key in d:
                d.pop(key, None)
                if not d:
                    self._coinbases_by_height.pop(born, None)
                break