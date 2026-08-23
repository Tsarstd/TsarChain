# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import time
import struct

from ...core.tx import TxOut
from ...utils import config as CFG
from ..kv import iter_prefix, batch, clear_db

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic.database")


class UTXODatabaseMixin:

    def load_utxo_set(self):
        return self._load_utxo_set_kv()


    def flush(self, force: bool = False) -> bool:
        if not force and not self._dirty:
            return False
        self._save(force=force)
        return True


    def to_dict(self):
        with self._lock:
            return {key: self._serialize_entry(value) for key, value in self.utxos.items()}


    @classmethod
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


    def _serialize_entry(self, entry):
        tx_out = entry.get("tx_out")
        to_dict = getattr(tx_out, "to_dict", None)
        if callable(to_dict):
            tx_out_dict = to_dict()
        else:
            tx_out_dict = dict(tx_out) if isinstance(tx_out, (dict, list, tuple)) else getattr(tx_out, "__dict__", {})

        address = None
        script_type = None
        spk_bytes = None
        spk = getattr(tx_out, "script_pubkey", None)
        if spk is not None:
            spk_ser = getattr(spk, "serialize", None)
            if callable(spk_ser):
                spk_bytes = spk_ser()
            elif isinstance(spk, (bytes, bytearray)):
                spk_bytes = bytes(spk)
            elif isinstance(spk, str):
                try:
                    spk_bytes = bytes.fromhex(spk)
                except ValueError:
                    pass
        if not spk_bytes and isinstance(tx_out_dict.get("script_pubkey"), str):
            try:
                spk_bytes = bytes.fromhex(tx_out_dict["script_pubkey"])
            except ValueError:
                pass
        if spk_bytes:
            if len(spk_bytes) == 22 and spk_bytes[0] == 0x00 and spk_bytes[1] == 0x14:
                script_type = "p2wpkh"
            elif len(spk_bytes) == 34 and spk_bytes[0] == 0x00 and spk_bytes[1] == 0x20:
                script_type = "p2wsh"
            script_to_addr = getattr(self, "script_to_address", None)
            if address is None and callable(script_to_addr):
                address = script_to_addr(spk_bytes)
        if address is None:
            script_to_addr = getattr(self, "script_to_address", None)
            if callable(script_to_addr):
                address = script_to_addr(getattr(tx_out, "script_pubkey", None))
        return {
            "tx_out": tx_out_dict,
            "is_coinbase": bool(entry.get("is_coinbase", False)),
            "block_height": int(entry.get("block_height", 0)),
            "address": address,
            "script_type": script_type,
        }


    def _load_utxo_set_kv(self) -> dict:
        nested = {}
        for k, v in iter_prefix('utxo', b''):
            key = k.decode('utf-8')
            if ":" not in key:
                continue
            parts = key.split(":")
            if len(parts) != 2:
                continue
            txid, index = parts[0], int(parts[1])
            if len(v) < 19:
                continue
            amount, is_cb, block_height, spk_len = struct.unpack_from("<Q?qH", v, 0)
            spk_hex = v[19:19 + spk_len].hex()
            entry = {
                "tx_out": {"amount": amount, "script_pubkey": spk_hex},
                "is_coinbase": is_cb,
                "block_height": block_height,
            }
            nested.setdefault(txid, {})[index] = entry
        return nested


    def _load_kv(self) -> None:
        for k, v in iter_prefix('utxo', b''):
            if k == b'__meta__':
                self._meta = json.loads(v.decode('utf-8')) or {}
                continue
            key = k.decode('utf-8')
            if len(v) < 19:
                continue
            amount, is_cb, block_height, spk_len = struct.unpack_from("<Q?qH", v, 0)
            spk_hex = v[19:19 + spk_len].hex()
            tx_out = TxOut.from_dict({"amount": amount, "script_pubkey": spk_hex})
            if self._is_unspendable_opreturn(tx_out):
                continue
            self.utxos[key] = {
                'tx_out': tx_out,
                'is_coinbase': bool(is_cb),
                'block_height': int(block_height),
            }


    def _load(self, *, force: bool = False):
        with self._lock:
            if not force and getattr(self, "_dirty", False):
                return
            self.utxos.clear()
            self._address_index = None
            self._key_to_spk.clear()
            self._meta = {}
            self._load_kv()
            self._dirty = False
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = False
            self._bump_version()


    def _save_kv(self, rewrite: bool, target_keys, meta: dict) -> None:
        if rewrite:
            clear_db('utxo')
        with batch('utxo') as b:
            b.put(b'__meta__', json.dumps(meta, separators=CFG.CANONICAL_SEP).encode('utf-8'))
            for key in target_keys:
                entry = self.utxos.get(key)
                if entry is None:
                    continue
                tx_out = entry.get("tx_out")
                amt = int(getattr(tx_out, "amount", 0))
                spk = getattr(tx_out, "script_pubkey", b"")
                spk_ser = getattr(spk, "serialize", None)
                if callable(spk_ser):
                    spk_bytes = spk_ser()
                elif isinstance(spk, (bytes, bytearray)):
                    spk_bytes = bytes(spk)
                elif isinstance(spk, str):
                    spk_bytes = bytes.fromhex(spk)
                else:
                    spk_bytes = b""
                is_cb = bool(entry.get("is_coinbase", False))
                h = int(entry.get("block_height", 0))
                payload = struct.pack("<Q?qH", amt, is_cb, h, len(spk_bytes)) + spk_bytes
                b.put(key.encode('utf-8'), payload)
            if not rewrite and self._removed_keys:
                for key in self._removed_keys:
                    b.delete(key.encode('utf-8'))


    def _save(self, force: bool = False):
        if not force and not self._dirty:
            return
        with self._lock:
            if not force and not self._dirty:
                return
            rewrite = bool(force or self._rewrite_all)
            target_keys = self.utxos.keys() if rewrite else set(self._dirty_keys)
            meta = self._build_meta()
            self._save_kv(rewrite, target_keys, meta)
            self._dirty = False
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = False


    def _get_tip_height_from_state(self, *, use_cache: bool = True) -> int:
        now = time.time()
        if use_cache and (now - self._tip_cache.get("ts", 0.0)) <= self._tip_cache_ttl:
            return int(self._tip_cache.get("height", 0))

        items = {k.decode('utf-8'): v.decode('utf-8') for k, v in iter_prefix('state', b'k:')}
        tb = int(items.get('k:total_blocks', '0'))
        height = max(0, tb - 1)
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


    def _build_meta(self) -> dict:
        height_hint = self._get_tip_height_from_state(use_cache=False)
        return {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "generated_at": int(time.time()),
            "backend": "lmdb",
            "utxo_set_size": len(self.utxos),
            "tip_height_hint": int(height_hint),
        }
