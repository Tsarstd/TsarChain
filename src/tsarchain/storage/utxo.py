# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; Signal-X3DH

import json
import threading
import time
from bech32 import bech32_decode, convertbits

# ---------------- Local Project ----------------
from ..core.tx import TxOut
from .db import BaseDatabase
from .db import AtomicJSONFile
from ..utils import config as CFG
from .kv import kv_enabled, iter_prefix, batch, clear_db

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage(utxo)")


class UTXODB(BaseDatabase):
    def __init__(self):
        self.filepath = CFG.UTXOS_FILE
        self.utxos = {}
        self._lock = threading.RLock()
        self._dirty = False
        self._dirty_keys = set()
        self._removed_keys = set()
        self._rewrite_all = False
        self._load()

    # ===================== SERIALIZE =====================
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
                # old format → convert
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

    # ===================== FILE I/O =====================
    def _load(self, *, force: bool = False):
        with self._lock:
            if not force and getattr(self, "_dirty", False):
                # Keep in-memory state (contains latest unsaved blocks/txs)
                return
            self.utxos.clear()
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

    def _save(self, force: bool = False):
        if not force and not self._dirty:
            return
        with self._lock:
            if not force and not self._dirty:
                return
            started = time.time()
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
            removed = len(self._removed_keys)
            self._dirty = False
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = False
            duration = time.time() - started
            backend = "lmdb" if kv_enabled() else "json"
            written = len(self.utxos) if rewrite else len(target_keys)

    # ===================== MODIFIKASI DATA =====================
    def _txid_hex(self, x):
        if x is None:
            return None
        if isinstance(x, (bytes, bytearray)):
            return x.hex()
        return str(x)

    def _prevout_from_txin(self, tx_input):
        prev_txid = getattr(tx_input, "txid", None)
        if prev_txid is None:
            prev_txid = getattr(tx_input, "prev_tx", None)
        prev_txid_hex = self._txid_hex(prev_txid)

        vout = getattr(tx_input, "vout", None)
        if vout is None:
            vout = getattr(tx_input, "prev_index", None)
        try:
            vout = int(vout)
        except Exception:
            vout = None

        return prev_txid_hex, vout
    
    def _is_unspendable_opreturn(self, tx_out) -> bool:
        try:
            spk = getattr(tx_out, "script_pubkey", None)
            if spk is None:
                return False
            if hasattr(spk, "serialize"):
                b = spk.serialize()
            elif isinstance(spk, (bytes, bytearray)):
                b = bytes(spk)
            elif isinstance(spk, str):
                b = bytes.fromhex(spk)
            else:
                return False
            return len(b) >= 1 and b[0] == 0x6A  # OP_RETURN
        except Exception:
            log.exception("[_is_unspendable_opreturn] Error checking OP_RETURN in scriptPubKey")
            return False

    def update(self, transactions, block_height: int, *, autosave: bool = True):
        if not transactions:
            return
        with self._lock:
            for tx in transactions:
                txid_hex = self._txid_hex(getattr(tx, "txid", None))
                is_coinbase = bool(getattr(tx, "is_coinbase", False))

                if not is_coinbase:
                    for tx_input in getattr(tx, "inputs", []):
                        prev_txid_hex, vout = self._prevout_from_txin(tx_input)
                        if prev_txid_hex is None or vout is None:
                            continue
                        spent_key = f"{prev_txid_hex}:{int(vout)}"
                        if self.utxos.pop(spent_key, None) is not None:
                            self._removed_keys.add(spent_key)
                            self._dirty_keys.discard(spent_key)

                for index, tx_out in enumerate(getattr(tx, "outputs", [])):
                    self.add(txid_hex, index, tx_out,
                             is_coinbase=is_coinbase,
                             block_height=block_height,
                             autosave=False)
            self._dirty = True
            if autosave:
                self._save()


    def rebuild_from_chain(self, blocks) -> None:
        started = time.time()
        block_count = len(blocks or [])
        with self._lock:
            self.utxos.clear()
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = True
            for block in blocks or []:
                txs = getattr(block, "transactions", []) or []
                height = int(getattr(block, "height", 0))
                for tx in txs:
                    txid_hex = self._txid_hex(getattr(tx, "txid", None))
                    is_coinbase = bool(getattr(tx, "is_coinbase", False))
                    if not is_coinbase:
                        for tx_input in getattr(tx, "inputs", []) or []:
                            prev_txid_hex, vout = self._prevout_from_txin(tx_input)
                            if prev_txid_hex is None or vout is None:
                                continue
                            spent_key = f"{prev_txid_hex}:{int(vout)}"
                            self.utxos.pop(spent_key, None)
                    for index, tx_out in enumerate(getattr(tx, "outputs", []) or []):
                        self.add(txid_hex, index, tx_out, is_coinbase=is_coinbase, block_height=height, autosave=False)
            self._dirty = True
            self._save(force=True)
        duration = time.time() - started

    def flush(self, force: bool = False) -> bool:
        if not force and not self._dirty:
            return False
        self._save(force=force)
        return True

    def add(self, txid: str, index: int, tx_out: TxOut, is_coinbase: bool = False, block_height: int = 0, autosave: bool = True):
        if self._is_unspendable_opreturn(tx_out):
            return
        
        key = f"{self._txid_hex(txid)}:{int(index)}"
        with self._lock:
            self.utxos[key] = {
                "tx_out": tx_out,
                "is_coinbase": bool(is_coinbase),
                "block_height": int(block_height),
            }
            self._dirty = True
            self._dirty_keys.add(key)
            self._removed_keys.discard(key)
            if autosave:
                self._save()

    def remove(self, txid, index: int, autosave: bool = True):
        key = f"{self._txid_hex(txid)}:{int(index)}"
        with self._lock:
            if self.utxos.pop(key, None) is not None:
                self._dirty = True
                self._dirty_keys.discard(key)
                self._removed_keys.add(key)
                if autosave:
                    self._save()

    def spend_input(self, tx_input):
        prev_txid_hex, vout = self._prevout_from_txin(tx_input)
        if prev_txid_hex is None or vout is None:
            raise AttributeError("TxIn missing prevout (txid/vout)")
        self.remove(prev_txid_hex, int(vout))


    # ===================== QUERY / BALANCE =====================
    def _get_tip_height_from_state(self) -> int:
        # Prefer KV state when enabled
        if kv_enabled():
            try:
                items = dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in iter_prefix('state', b'k:'))
                tb = int(items.get('k:total_blocks', '0'))
                return max(0, tb - 1)
            except Exception:
                pass
        try:
            data = AtomicJSONFile(CFG.STATE_FILE).load(default={})
            total_blocks = int(data.get("total_blocks", 0))
            return max(0, total_blocks - 1)
        except Exception:
            return 0

    def _get_utxo_meta(self, utxo_data):
        if isinstance(utxo_data, dict):
            if "is_coinbase" in utxo_data or "block_height" in utxo_data:
                return bool(utxo_data.get("is_coinbase", False)), int(utxo_data.get("block_height", 0))
        return False, 0

    def get_balance(self, identifier: str, mode: str = "total",
                    current_height: int = None, maturity: int = CFG.COINBASE_MATURITY):
        def _normalize_target_spk_hex(x: str) -> str:
            x = (x or "").strip().lower()
            if x.startswith("tsar1"):
                hrp, data = bech32_decode(x)
                if hrp != "tsar" or data is None:
                    raise ValueError("invalid tsar bech32 address")
                prog = convertbits(data[1:], 5, 8, False)
                if prog is None or len(prog) != 20:
                    raise ValueError("invalid witness program length for P2WPKH")
                return "0014" + bytes(prog).hex()
            if x.startswith("00") and len(x) == 42:
                return "0014" + x[2:]
            if x.startswith("0014") and len(x) == 44:
                return x
            return x

        if current_height is None:
            current_height = self._get_tip_height_from_state()

        target_spk_hex = _normalize_target_spk_hex(identifier)

        total = mature = immature = 0
        with self._lock:
            for _, entry in self.utxos.items():
                try:
                    tx_out = entry["tx_out"]
                    spk_hex = tx_out.script_pubkey.serialize().hex().lower()
                except Exception:
                    continue
                if spk_hex != target_spk_hex:
                    continue

                amt = int(getattr(tx_out, "amount", 0))
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

    def apply_tx_to_utxoset(self, tx, utxos: dict, block_height: int | None = None) -> dict:
        if utxos is None:
            return utxos

        def _txid_hex(x):
            if x is None:
                return None
            if isinstance(x, (bytes, bytearray)):
                return x.hex()
            return str(x)

        def _remove_prevout(snapshot: dict, prev_txid_hex: str, vout: int):
            key_int = int(vout)

            # Flat-string layout: "txid:vout"
            key_str = f"{prev_txid_hex}:{key_int}"
            if key_str in snapshot:
                snapshot.pop(key_str, None)
                return True

            # Flat-tuple layout: (txid, vout)
            key_tuple = (prev_txid_hex, key_int)
            if key_tuple in snapshot:
                snapshot.pop(key_tuple, None)
                return True

            m = snapshot.get(prev_txid_hex)
            if isinstance(m, dict) and int(vout) in m:
                try:
                    del m[int(vout)]
                    if not m:
                        snapshot.pop(prev_txid_hex, None)
                except Exception:
                    log.exception("[apply_tx_to_utxoset] Error removing prevout from dict")
                    pass
                return True
            removed = False
            for addr, lst in list(snapshot.items()):
                if isinstance(lst, list):
                    for i in range(len(lst) - 1, -1, -1):
                        ent = lst[i]
                        tid = ent.get("txid") or ent.get("txid_hex") or ent.get("prev_txid")
                        vv = ent.get("vout") if "vout" in ent else ent.get("index")
                        if _txid_hex(tid) == prev_txid_hex and int(vv) == int(vout):
                            lst.pop(i)
                            removed = True
                    if not lst:
                        try:
                            snapshot.pop(addr, None)
                        except Exception:
                            log.exception("[apply_tx_to_utxoset] Error removing empty address bucket")
                            pass
            return removed
        
        for n, txout in enumerate(getattr(tx, "outputs", [])):
            try:
                spk = getattr(txout, "script_pubkey", None)
                b = spk.serialize() if hasattr(spk, "serialize") else (spk if isinstance(spk,(bytes,bytearray)) else (bytes.fromhex(spk) if isinstance(spk,str) else b""))
                if len(b) >= 1 and b[0] == 0x6A:
                    continue
            except Exception:
                log.exception("[apply_tx_to_utxoset] Error checking OP_RETURN in scriptPubKey")
                pass

        def _insert_output(snapshot: dict, txid_hex: str, n: int, entry: dict, address: str | None):
            layout = None
            for k, v in snapshot.items():
                if isinstance(k, str) and ":" in k:
                    layout = "flat_string"
                    break
                if isinstance(k, tuple) and len(k) == 2:
                    layout = "flat_tuple"
                    break
                if isinstance(v, dict) and all(isinstance(_, int) for _ in v.keys()):
                    layout = "per_txid_dict"
                    break
                if isinstance(v, list):
                    layout = "per_address_list"
                    break

            if layout == "flat_string":
                snapshot[f"{txid_hex}:{int(n)}"] = entry
                return

            if layout == "flat_tuple":
                snapshot[(txid_hex, int(n))] = entry
                return

            if layout == "per_txid_dict":
                bucket = snapshot.setdefault(txid_hex, {})
                if isinstance(bucket, dict):
                    bucket[int(n)] = entry
                    return

            if layout == "per_address_list" and address:
                bucket = snapshot.setdefault(address, [])
                if isinstance(bucket, list):
                    bucket.append(entry)
                    return

            # Default fallback: maintain flat-string layout
            snapshot[f"{txid_hex}:{int(n)}"] = entry

        is_coinbase = bool(getattr(tx, "is_coinbase", False))
        txid_hex = _txid_hex(getattr(tx, "txid", None)) or getattr(tx, "txid_hex", lambda: None)()

        if not is_coinbase:
            for txin in getattr(tx, "inputs", []):
                prev_txid_hex = _txid_hex(getattr(txin, "txid", None) or getattr(txin, "prev_tx", None))
                vout = int(getattr(txin, "vout", getattr(txin, "prev_index", 0)))
                if prev_txid_hex is not None:
                    _remove_prevout(utxos, prev_txid_hex, vout)

        for n, txout in enumerate(getattr(tx, "outputs", [])):
            try:
                spk = getattr(txout, "script_pubkey", None)
                b = spk.serialize() if hasattr(spk, "serialize") else (
                    spk if isinstance(spk, (bytes, bytearray)) else
                    (bytes.fromhex(spk) if isinstance(spk, str) else b"")
                )
                if len(b) >= 1 and b[0] == 0x6A:
                    continue
            except Exception:
                log.exception("[apply_tx_to_utxoset] Error checking OP_RETURN in scriptPubKey")
                pass

            amount = int(getattr(txout, "amount", 0))
            spk = getattr(txout, "script_pubkey", None)
            try:
                if hasattr(spk, "serialize"):
                    spk_hex = spk.serialize().hex()
                elif isinstance(spk, (bytes, bytearray)):
                    spk_hex = spk.hex()
                else:
                    spk_hex = str(spk) if spk is not None else None
            except Exception:
                spk_hex = None

            address = None
            try:
                if hasattr(self, "script_to_address"):
                    address = self.script_to_address(spk)
                elif hasattr(txout, "address"):
                    address = getattr(txout, "address")
            except Exception:
                address = None

            entry = {
                "txid": txid_hex,
                "vout": int(n),
                "amount": amount,
                "script_pubkey": spk_hex,
                "is_coinbase": is_coinbase,
                "height": None if block_height is None else int(block_height),
                "address": address,
            }
            _insert_output(utxos, txid_hex, n, entry, address)
        return utxos

    def get(self, identifier: str):
        def _normalize_target_spk_hex(x: str) -> str:
            x = (x or "").strip().lower()
            if x.startswith("tsar1"):
                hrp, data = bech32_decode(x)
                if hrp != "tsar" or data is None:
                    raise ValueError("invalid tsar bech32 address")
                prog = convertbits(data[1:], 5, 8, False)
                if prog is None or len(prog) != 20:
                    raise ValueError("invalid witness program length for P2WPKH")
                return "0014" + bytes(prog).hex()
            if x.startswith("00") and len(x) == 42:
                return "0014" + x[2:]
            if x.startswith("0014") and len(x) == 44:
                return x
            return x

        target_spk_hex = _normalize_target_spk_hex(identifier)
        result = {}
        with self._lock:
            for key, data in self.utxos.items():
                try:
                    spk_hex = data["tx_out"].script_pubkey.serialize().hex().lower()
                except Exception:
                    continue
                if spk_hex == target_spk_hex:
                    result[key] = {
                        "amount": int(data["tx_out"].amount),
                        "script_pubkey": spk_hex,
                        "is_coinbase": bool(data.get("is_coinbase", False)),
                        "block_height": int(data.get("block_height", 0)),
                    }
        return result

