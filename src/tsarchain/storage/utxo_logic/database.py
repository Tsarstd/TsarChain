# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

import json
import time

from ...core.tx import TxOut
from ...utils import config as CFG
from ..db import AtomicJSONFile
from ..kv import kv_enabled, iter_prefix, batch, clear_db

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic(database)")


class UTXODatabaseMixin:
    def _serialize_entry(self, entry):
        tx_out = entry.get("tx_out")
        if hasattr(tx_out, "to_dict"):
            try:
                tx_out_dict = tx_out.to_dict()
            except Exception:
                tx_out_dict = {}
        elif isinstance(tx_out, dict):
            tx_out_dict = dict(tx_out)
        else:
            amount = getattr(tx_out, "amount", 0) if tx_out is not None else 0
            spk = getattr(tx_out, "script_pubkey", None) if tx_out is not None else None
            spk_hex = None
            if spk is not None:
                if hasattr(spk, "serialize"):
                    try:
                        spk_hex = spk.serialize().hex()
                    except Exception:
                        spk_hex = None
                elif isinstance(spk, (bytes, bytearray)):
                    spk_hex = bytes(spk).hex()
                elif isinstance(spk, str):
                    spk_hex = spk
            tx_out_dict = {"amount": amount, "script_pubkey": spk_hex}
        return {
            "tx_out": tx_out_dict,
            "is_coinbase": bool(entry.get("is_coinbase", False)),
            "block_height": int(entry.get("block_height", 0)),
        }

    def to_dict(self):
        with self._lock:
            return {key: self._serialize_entry(value) for key, value in self.utxos.items()}

    def from_dict(cls, data: dict):
        utxo_db = cls()
        utxo_db.utxos.clear()
        for key, value in (data or {}).items():
            if not isinstance(value, dict):
                continue
            if "tx_out" in value:
                tx_out_data = value["tx_out"]
                if isinstance(tx_out_data, dict) and "amount" in tx_out_data and "script_pubkey" in tx_out_data:
                    tx_out_obj = TxOut.from_dict(tx_out_data)
                else:
                    continue
                utxo_db.utxos[key] = {
                    "tx_out": tx_out_obj,
                    "is_coinbase": bool(value.get("is_coinbase", False)),
                    "block_height": int(value.get("block_height", 0)),
                }
            elif "amount" in value and "script_pubkey" in value:
                tx_out_obj = TxOut.from_dict(value)
                utxo_db.utxos[key] = {
                    "tx_out": tx_out_obj,
                    "is_coinbase": False,
                    "block_height": 0,
                }
        utxo_db._dirty = True
        utxo_db._dirty_keys = set(utxo_db.utxos.keys())
        utxo_db._removed_keys.clear()
        utxo_db._rewrite_all = True
        utxo_db._address_index = None
        utxo_db._key_to_spk.clear()
        utxo_db._bump_version()
        return utxo_db

    def load_utxo_set(self):
        if kv_enabled():
            nested = {}
            try:
                for k, v in iter_prefix('utxo', b''):
                    try:
                        key = k.decode('utf-8')
                        txid, index = key.split(":"); index = int(index)
                        obj = json.loads(v.decode('utf-8'))
                        nested.setdefault(txid, {})[index] = obj
                    except Exception:
                        continue
                return nested
            except Exception as e:
                log.debug("[UTXODB] LMDB read error: %s", e)
                return {}
        else:
            try:
                data = self.load_json(self.filepath) or {}
                nested = {}
                for key, val in data.items():
                    try:
                        txid, index = key.split(":")
                        index = int(index)
                        nested.setdefault(txid, {})[index] = val
                    except ValueError:
                        log.debug("[UTXODB] Format key UTXO invalid: %s", key)
                return nested
            except Exception as e:
                log.warning("[UTXODB] Failed To Read %s: %s", self.filepath, e)
                return {}

    def _load(self, *, force: bool = False):
        if not self._persist_enabled:
            return
        with self._lock:
            if not force and getattr(self, "_dirty", False):
                return
            self.utxos.clear()
            self._address_index = None
            self._key_to_spk.clear()
            if kv_enabled():
                for k, v in iter_prefix('utxo', b''):
                    try:
                        key = k.decode('utf-8')
                        obj = json.loads(v.decode('utf-8'))
                        txo = obj.get('tx_out') or obj
                        if isinstance(txo, dict) and 'amount' in txo and 'script_pubkey' in txo:
                            tx_out = TxOut.from_dict(txo)
                            if self._is_unspendable_opreturn(tx_out):
                                continue
                            self.utxos[key] = {
                                'tx_out': tx_out,
                                'is_coinbase': bool(obj.get('is_coinbase', False)),
                                'block_height': int(obj.get('block_height', 0)),
                            }
                    except Exception:
                        continue
            else:
                data = self.load_json(self.filepath) or {}
                for key, value in data.items():
                    if not isinstance(value, dict):
                        continue
                    if "tx_out" in value:
                        txo = value["tx_out"]
                        if not (isinstance(txo, dict) and "amount" in txo and "script_pubkey" in txo):
                            continue
                        tx_out_obj = TxOut.from_dict(txo)

                        if self._is_unspendable_opreturn(tx_out_obj):
                            continue

                        self.utxos[key] = {
                            "tx_out": TxOut.from_dict(txo),
                            "is_coinbase": bool(value.get("is_coinbase", False)),
                            "block_height": int(value.get("block_height", 0)),
                        }
                    elif "amount" in value and "script_pubkey" in value:
                        self.utxos[key] = {
                            "tx_out": TxOut.from_dict(value),
                            "is_coinbase": False,
                            "block_height": 0,
                        }
                    else:
                        log.debug("[UTXODB] Skip UTXO invalid (less fields): %s", key)
            self._dirty = False
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = False
            self._bump_version()

    def _save(self, force: bool = False):
        if not self._persist_enabled:
            return
        if not force and not self._dirty:
            return
        with self._lock:
            if not force and not self._dirty:
                return
            rewrite = bool(force or self._rewrite_all)
            target_keys = self.utxos.keys() if rewrite else set(self._dirty_keys)
            if kv_enabled():
                try:
                    if rewrite:
                        clear_db('utxo')
                    with batch('utxo') as b:
                        for key in target_keys:
                            entry = self.utxos.get(key)
                            if entry is None:
                                continue
                            payload = self._serialize_entry(entry)
                            b.put(key.encode('utf-8'), json.dumps(payload, separators=(",", ":")).encode('utf-8'))
                        if not rewrite and self._removed_keys:
                            for key in self._removed_keys:
                                b.delete(key.encode('utf-8'))
                except Exception as e:
                    log.warning("[UTXODB] LMDB save failed: %s", e)
            else:
                payload = {k: self._serialize_entry(v) for k, v in self.utxos.items()}
                self.save_json(self.filepath, payload)
            self._dirty = False
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = False

    def flush(self, force: bool = False) -> bool:
        if not force and not self._dirty:
            return False
        self._save(force=force)
        return True

    def _get_tip_height_from_state(self, *, use_cache: bool = True) -> int:
        now = time.time()
        if use_cache and (now - self._tip_cache.get("ts", 0.0)) <= self._tip_cache_ttl:
            return int(self._tip_cache.get("height", 0))

        height = 0
        if kv_enabled():
            try:
                items = dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in iter_prefix('state', b'k:'))
                tb = int(items.get('k:total_blocks', '0'))
                height = max(0, tb - 1)
            except Exception:
                pass
            else:
                self._tip_cache.update(height=height, ts=now)
                return height
        try:
            data = AtomicJSONFile(CFG.STATE_FILE).load(default={})
            total_blocks = int(data.get("total_blocks", 0))
            height = max(0, total_blocks - 1)
        except Exception:
            height = 0
        self._tip_cache.update(height=height, ts=now)
        return height

    def _get_utxo_meta(self, utxo_data):
        if isinstance(utxo_data, dict):
            if "is_coinbase" in utxo_data or "block_height" in utxo_data:
                return bool(utxo_data.get("is_coinbase", False)), int(utxo_data.get("block_height", 0))
        return False, 0

    def _bump_version(self):
        self._version = (self._version + 1) % (1 << 63)
        self._tip_cache["ts"] = 0.0

    def version(self) -> int:
        return self._version
