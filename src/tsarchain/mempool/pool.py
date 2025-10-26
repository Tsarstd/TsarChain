# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141; libsecp256k1; Signal-X3DH

import json
import threading
import time
from collections import OrderedDict
from typing import Optional, Dict
from ecdsa import VerifyingKey, SECP256k1

# ---------------- Local Project ----------------
from ..storage.kv import kv_enabled, iter_prefix, batch, clear_db
from ..storage.db import BaseDatabase
from ..core.tx import Tx
from ..storage.utxo import UTXODB
from ..contracts.storage_nodes import StorageNodeRegistry
from ..utils.helpers import is_p2wpkh_script, bip143_sig_hash, hash160, hash256, serialize_tx_for_txid
from ..utils import helpers as H
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool(pool)")


def _is_p2pkh_script(spk: bytes) -> bool:
    return (
        isinstance(spk, (bytes, bytearray)) and len(spk) == 25 and
        spk[0] == 0x76 and spk[1] == 0xA9 and spk[2] == 0x14 and
        spk[23] == 0x88 and spk[24] == 0xAC)

def _decompress_pubkey33(pub33: bytes) -> bytes:
    if not (len(pub33) == 33 and pub33[0] in (2, 3)):
        raise ValueError("Invalid compressed pubkey")
    
    x = int.from_bytes(pub33[1:], "big")
    y_sq = (pow(x, 3, H.SECP256K1_P) + 7) % H.SECP256K1_P
    y = pow(y_sq, (H.SECP256K1_P + 1) // 4, H.SECP256K1_P)
    
    if (y & 1) != (pub33[0] & 1):
        y = H.SECP256K1_P - y
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")

def _vk_from_pubkey_bytes(pubkey: bytes) -> VerifyingKey:
    if len(pubkey) == 33 and pubkey[0] in (2, 3):
        raw = _decompress_pubkey33(pubkey)
        return VerifyingKey.from_string(raw, curve=SECP256k1)
    
    if len(pubkey) == 65 and pubkey[0] == 4:
        return VerifyingKey.from_string(pubkey[1:], curve=SECP256k1)
    
    if len(pubkey) == 64:
        return VerifyingKey.from_string(pubkey, curve=SECP256k1)
    
    raise ValueError("Unsupported pubkey format")

def _extract_p2pkh_scriptsig(script_sig_bytes: bytes):
    if not script_sig_bytes or len(script_sig_bytes) < 2:
        raise ValueError("scriptSig too short")
    
    i = 0
    L1 = script_sig_bytes[i]; i += 1
    if i + L1 > len(script_sig_bytes):
        raise ValueError("Bad sig length in scriptSig")
    
    sig_all = script_sig_bytes[i:i+L1]; i += L1
    if len(sig_all) < 2:
        raise ValueError("Bad DER+hashtype")
    
    sighash_type = sig_all[-1]
    sig_der = sig_all[:-1]

    if i >= len(script_sig_bytes):
        raise ValueError("Missing pubkey push")
    
    L2 = script_sig_bytes[i]; i += 1
    if i + L2 > len(script_sig_bytes):
        raise ValueError("Bad pubkey length in scriptSig")
    
    pubkey = script_sig_bytes[i:i+L2]
    return sig_der, sighash_type, pubkey

def _get_utxo_script_bytes(utxo_entry) -> bytes:
    # dict with tx_out object
    if isinstance(utxo_entry, dict):
        tx_out = utxo_entry.get("tx_out")
        if tx_out is not None:
            if hasattr(tx_out, "script_pubkey") and hasattr(tx_out.script_pubkey, "serialize"):
                try:
                    return tx_out.script_pubkey.serialize()
                except Exception:
                    pass
                
            # tx_out dict
            if isinstance(tx_out, dict) and "script_pubkey" in tx_out:
                spk = tx_out["script_pubkey"]
                if isinstance(spk, (bytes, bytearray)):
                    return bytes(spk)
                if isinstance(spk, str):
                    try:
                        return bytes.fromhex(spk)
                    except Exception:
                        pass

        # flat dict
        if "script_pubkey" in utxo_entry:
            spk = utxo_entry["script_pubkey"]
            if isinstance(spk, (bytes, bytearray)):
                return bytes(spk)
            if isinstance(spk, str):
                try:
                    return bytes.fromhex(spk)
                except Exception:
                    pass

    # object level (namedtuple/dataclass)
    if hasattr(utxo_entry, "tx_out") and hasattr(utxo_entry.tx_out, "script_pubkey"):
        spk_obj = utxo_entry.tx_out.script_pubkey
        if hasattr(spk_obj, "serialize"):
            try:
                return spk_obj.serialize()
            except Exception:
                pass
            
        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)

    if hasattr(utxo_entry, "script_pubkey"):
        spk_obj = utxo_entry.script_pubkey
        if hasattr(spk_obj, "serialize"):
            try:
                return spk_obj.serialize()
            except Exception:
                pass
            
        if isinstance(spk_obj, (bytes, bytearray)):
            return bytes(spk_obj)

    raise ValueError("script_pubkey not found in UTXO entry")

def _p2wpkh_script_code_from_spk(spk_bytes: bytes) -> bytes:
    if not is_p2wpkh_script(spk_bytes):
        raise ValueError("Not a P2WPKH script")
    
    pkhash = spk_bytes[2:22]
    return b"\x19\x76\xa9\x14" + pkhash + b"\x88\xac"

def _legacy_sighash(tx: "Tx", vin_index: int, script_code: bytes, sighash_type: int) -> bytes:
    orig_scripts = [tin.script_sig for tin in tx.inputs]
    try:
        for tin in tx.inputs:
            tin.script_sig = H.Script([])
        tx.inputs[vin_index].script_sig = H.Script.deserialize(script_code)
        preimage = serialize_tx_for_txid(tx) + int(sighash_type).to_bytes(4, "little")
        return hash256(preimage)
    
    finally:
        for tin, orig in zip(tx.inputs, orig_scripts):
            tin.script_sig = orig


class TxPoolDB(BaseDatabase):
    def __init__(
        self,
        filepath: str = CFG.MEMPOOL_FILE,
        max_size_mb: int = CFG.MEMPOOL_MAX_SIZE,
        utxo_store: Optional[UTXODB] = None,
        inherit_state: bool = False,
    ):
        self.filepath = filepath
        self.max_size_mb = max_size_mb
        self._lock = threading.RLock()
        self._auto_flush_interval = max(1.0, float(CFG.MEMPOOL_FLUSH_INTERVAL))
        self._pool: "OrderedDict[str, Tx]" = OrderedDict()
        self._size_map: Dict[str, int] = {}
        self._dirty = False
        self._change_seq = 0
        self._last_flush = time.time()

        storage_items = self._load_storage_pool()
        self._hydrate_pool(storage_items)
        self.current_size = sum(self._size_map.values())

        utxo_store = utxo_store or UTXODB()
        self.utxo = utxo_store
        if inherit_state:
            try:
                self.utxo._load()
            except Exception:
                pass

        # Last error/context for receive_tx to report back to clients
        self.last_error_reason: str | None = None
        # Orphan transactions awaiting missing prevouts (txid -> tx_dict)
        self._orphan_pool: Dict[str, dict] = {}
        self._orphan_missing: Dict[str, str] = {}

    # ------------- Storage helpers -------------
    def _load_storage_pool(self) -> list:
        if kv_enabled():
            out = []
            try:
                for _k, v in iter_prefix('mempool', b''):
                    try:
                        out.append(json.loads(v.decode('utf-8')))
                    except Exception:
                        continue
            except Exception:
                log.error("[load_pool] LMDB read failed, falling back to file storage")
                return []
            return out
        return self.load_json(self.filepath) or []

    def _hydrate_pool(self, entries: list) -> None:
        for entry in entries:
            try:
                tx_obj = self._tx_from_any(entry)
            except Exception:
                log.warning("[mempool] Failed to hydrate entry, skipping")
                continue
            txid = self._normalize_txid(tx_obj.txid)
            self._pool[txid] = tx_obj
            self._size_map[txid] = self._estimate_tx_size(tx_obj)

    def _normalize_txid(self, txid) -> str:
        if txid is None:
            raise ValueError("Transaction missing txid")
        if isinstance(txid, (bytes, bytearray)):
            return txid.hex().lower()
        return str(txid).lower()

    def _tx_from_any(self, item) -> Tx:
        if isinstance(item, Tx):
            tx_obj = item
        elif isinstance(item, dict):
            tx_obj = Tx.from_dict(item)
        else:
            raise TypeError(f"Unsupported mempool entry type: {type(item)}")
        if not getattr(tx_obj, "txid", None):
            tx_obj.compute_txid()
        return tx_obj

    def _serialize_tx(self, tx_obj: Tx) -> dict:
        tx_dict = tx_obj.to_dict(include_txid=True)
        if not tx_dict.get("txid") and getattr(tx_obj, "txid", None):
            tx_dict["txid"] = tx_obj.txid.hex()
        return tx_dict

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._change_seq += 1

    # ------------- Public API -------------
    @property
    def change_seq(self) -> int:
        return self._change_seq

    def flush(self, force: bool = False) -> bool:
        with self._lock:
            if not self._dirty and not force:
                return False
            now = time.time()
            if not force and (now - self._last_flush) < self._auto_flush_interval:
                return False

            snapshot = [self._serialize_tx(tx) for tx in self._pool.values()]
            self._dirty = False
            self._last_flush = now

        try:
            if kv_enabled():
                try:
                    clear_db('mempool')
                except Exception:
                    pass
                try:
                    with batch('mempool') as b:
                        for entry in snapshot:
                            txid = entry.get('txid')
                            if not txid:
                                continue
                            b.put(txid.encode('utf-8'), json.dumps(entry, separators=(",", ":")).encode('utf-8'))
                except Exception:
                    log.error("[flush] LMDB write failed, falling back to file storage")
                    self.save_json(self.filepath, snapshot)
            else:
                self.save_json(self.filepath, snapshot)
        except Exception:
            log.exception("[flush] Failed to persist mempool")
            with self._lock:
                self._dirty = True  # ensure retry on next flush
            return False
        return True

    def load_pool(self) -> list:
        with self._lock:
            return [self._serialize_tx(tx) for tx in self._pool.values()]

    def save_pool(self, pool: list) -> None:
        tx_objects = []
        for item in pool:
            try:
                tx_objects.append(self._tx_from_any(item))
            except Exception:
                log.warning("[save_pool] Skipping invalid entry during replace")
        with self._lock:
            self._pool = OrderedDict()
            self._size_map = {}
            for tx in tx_objects:
                txid = self._normalize_txid(tx.txid)
                self._pool[txid] = tx
                self._size_map[txid] = self._estimate_tx_size(tx)
            self.current_size = sum(self._size_map.values())
            self._mark_dirty()
        self.flush(force=True)

    def get_all_txs(self) -> list:
        with self._lock:
            return list(self._pool.values())

    def has_tx(self, txid_hex: str) -> bool:
        norm = self._normalize_txid(txid_hex)
        with self._lock:
            return norm in self._pool

    def _estimate_tx_size(self, tx: Tx) -> int:
        size = 0
        for txin in getattr(tx, "inputs", []) or []:
            size += 40
            if getattr(txin, "script_sig", None):
                try:
                    size += len(txin.script_sig.serialize())
                except Exception:
                    size += len(getattr(txin.script_sig, "asm", "") or "")
            if getattr(txin, "witness", None):
                try:
                    size += sum(len(w) for w in txin.witness)
                except Exception:
                    pass
        for txout in getattr(tx, "outputs", []) or []:
            size += 8
            if getattr(txout, "script_pubkey", None):
                try:
                    size += len(txout.script_pubkey.serialize())
                except Exception:
                    pass
        return max(size, len(tx.to_dict(include_txid=True)))

    def _ensure_space(self, needed_space: int) -> None:
        if needed_space <= 0:
            return
        with self._lock:
            if self.current_size + needed_space <= CFG.MEMPOOL_MAX_SIZE:
                return
            target = (self.current_size + needed_space) - CFG.MEMPOOL_MAX_SIZE
            ordered = sorted(
                self._pool.items(),
                key=lambda item: int(getattr(item[1], "fee", 0)) / max(1, self._size_map.get(item[0], 1))
            )
            freed = 0
            removal: list[str] = []
            for txid, tx in ordered:
                removal.append(txid)
                freed += self._size_map.get(txid, self._estimate_tx_size(tx))
                if freed >= target:
                    break
            if not removal:
                return
            for txid in removal:
                self._pool.pop(txid, None)
                size = self._size_map.pop(txid, 0)
                self.current_size -= size
            if freed:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()

    def add_tx(self, tx: "Tx") -> None:
        tx_obj = self._tx_from_any(tx)
        txid = self._normalize_txid(tx_obj.txid)
        tx_size = self._estimate_tx_size(tx_obj)
        self._ensure_space(tx_size)
        with self._lock:
            prev_size = 0
            if txid in self._pool:
                prev_size = self._size_map.get(txid, 0)
            self._pool[txid] = tx_obj
            self._size_map[txid] = tx_size
            self.current_size += tx_size - prev_size
            self._mark_dirty()

    def remove_tx(self, txid_hex: str) -> bool:
        norm = self._normalize_txid(txid_hex)
        with self._lock:
            tx = self._pool.pop(norm, None)
            if not tx:
                return False
            size = self._size_map.pop(norm, 0)
            self.current_size -= size
            if self.current_size < 0:
                self.current_size = 0
            self._mark_dirty()
            return True

    def remove_many(self, txids) -> int:
        removed = 0
        with self._lock:
            for txid in txids or []:
                norm = self._normalize_txid(txid)
                if norm in self._pool:
                    self.current_size -= self._size_map.pop(norm, 0)
                    self._pool.pop(norm, None)
                    removed += 1
            if removed:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()
        return removed

    def clear(self) -> None:
        with self._lock:
            if not self._pool:
                return
            self._pool.clear()
            self._size_map.clear()
            self.current_size = 0
            self._mark_dirty()
        self.flush(force=True)

    def drop_conflicts(self, spent_prevouts: set[tuple[str, int]]) -> int:
        if not spent_prevouts:
            return 0
        normalized_spent = {(str(txid).lower(), int(vout)) for txid, vout in spent_prevouts}
        removed = 0
        with self._lock:
            to_remove = []
            for txid, tx in self._pool.items():
                conflict = False
                for txin in getattr(tx, "inputs", []) or []:
                    prev_txid_hex = txin.txid.hex() if isinstance(txin.txid, (bytes, bytearray)) else str(txin.txid)
                    if (prev_txid_hex.lower(), int(getattr(txin, "vout", 0))) in normalized_spent:
                        conflict = True
                        break
                if conflict:
                    to_remove.append(txid)
            for txid in to_remove:
                self.current_size -= self._size_map.pop(txid, 0)
                self._pool.pop(txid, None)
                removed += 1
            if removed:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()
        return removed

    def prune_stale_entries(self) -> int:
        try:
            self.utxo._load()
        except Exception:
            log.debug("[prune_stale_entries] Failed to reload UTXO snapshot", exc_info=True)
        utxo_set = getattr(self.utxo, "utxos", {})
        tip = self.utxo._get_tip_height_from_state()
        removed = 0
        with self._lock:
            to_remove = []
            for txid, tx in self._pool.items():
                if not self.validate_transaction(tx, utxo_set, spend_at_height=tip + 1):
                    to_remove.append(txid)
            for txid in to_remove:
                self.current_size -= self._size_map.pop(txid, 0)
                self._pool.pop(txid, None)
                removed += 1
            if removed:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()
        return removed


    def _get_utxo_amount(self, utxo_data):
        if isinstance(utxo_data, dict):
            if "tx_out" in utxo_data:
                txo = utxo_data["tx_out"]
                if hasattr(txo, 'amount'):
                    return int(getattr(txo, 'amount', 0))
                if isinstance(txo, dict) and "amount" in txo:
                    return int(txo.get("amount", 0))
            if "amount" in utxo_data:
                return int(utxo_data["amount"])
        elif hasattr(utxo_data, 'amount'):
            return int(utxo_data.amount)
        raise ValueError(f"Unknown UTXO format: {utxo_data}")

    @staticmethod
    def _coinbase_confirmations(born_height: int, spend_height: int) -> int:
        try:
            return max(0, int(spend_height) - int(born_height))
        except Exception:
            return 0

    # ======== VALIDATE TRANSACTION ON MEMPOOL ========
    
    def validate_transaction(self, tx: "Tx", utxo_set: dict, spend_at_height: int | None = None) -> bool:
        if getattr(tx, "is_coinbase", False):
            return False

        input_sum = 0
        output_sum = 0
        current_height = spend_at_height if spend_at_height is not None else self.utxo._get_tip_height_from_state()
        prevouts: list[tuple[int, bytes, bool, int]] = []
        seen_prevouts: set[tuple[str, int]] = set()

        for tx_in in tx.inputs:
            prev_txid_hex = tx_in.txid.hex()
            prev_index = int(tx_in.vout)

            key_dup = (prev_txid_hex, prev_index)
            if key_dup in seen_prevouts:
                self.last_error_reason = "duplicate_prevout_in_tx"
                return False
            
            seen_prevouts.add(key_dup)
            found = False
            amount = 0
            utxo_entry = None

            def _extract_amount(entry, key_desc: str) -> int:
                try:
                    return self._get_utxo_amount(entry)
                except ValueError:
                    log.warning("[validate_transaction] Error extracting amount from UTXO %s", key_desc)
                    raise

            # Format FLAT: "txid:index"
            flat_key = f"{prev_txid_hex}:{prev_index}"
            if flat_key in utxo_set:
                found = True
                utxo_entry = utxo_set[flat_key]
                try:
                    amount = _extract_amount(utxo_entry, flat_key)
                except ValueError:
                    return False

            # Direct bytes key
            if not found:
                flat_key_b = flat_key.encode("utf-8")
                if flat_key_b in utxo_set:
                    found = True
                    utxo_entry = utxo_set[flat_key_b]
                    try:
                        amount = _extract_amount(utxo_entry, f"{flat_key} (bytes)")
                    except ValueError:
                        return False

            # Format NESTED: {txid: {index: data}}
            if not found and prev_txid_hex in utxo_set and isinstance(utxo_set[prev_txid_hex], dict):
                if prev_index in utxo_set[prev_txid_hex]:
                    found = True
                    utxo_entry = utxo_set[prev_txid_hex][prev_index]
                    try:
                        amount = _extract_amount(utxo_entry, f"{prev_txid_hex}:{prev_index}")
                    except ValueError:
                        return False
                    
            if not found:
                key_ci = prev_txid_hex.lower()
                for key, bucket in utxo_set.items():
                    if not isinstance(bucket, dict):
                        continue
                    if isinstance(key, str) and key.lower() == key_ci:
                        if prev_index in bucket:
                            found = True
                            utxo_entry = bucket[prev_index]
                            try:
                                amount = _extract_amount(utxo_entry, f"{key}:{prev_index} (nested-ci)")
                            except ValueError:
                                return False
                        break
                    
                    if isinstance(key, (bytes, bytearray)) and key.hex().lower() == key_ci:
                        if prev_index in bucket:
                            found = True
                            utxo_entry = bucket[prev_index]
                            try:
                                amount = _extract_amount(utxo_entry, f"{key.hex()}:{prev_index} (nested-bytes)")
                            except ValueError:
                                return False
                        break

            # Format TUPLE: {(txid, index): data}
            if not found:
                tuple_key = (prev_txid_hex, prev_index)
                if tuple_key in utxo_set:
                    found = True
                    utxo_entry = utxo_set[tuple_key]
                    try:
                        amount = _extract_amount(utxo_entry, f"{prev_txid_hex}:{prev_index} (tuple)")
                    except ValueError:
                        return False

            # Tuple with bytes txid
            if not found:
                try:
                    tuple_key_b = (bytes.fromhex(prev_txid_hex), prev_index)
                except ValueError:
                    tuple_key_b = None
                if tuple_key_b and tuple_key_b in utxo_set:
                    found = True
                    utxo_entry = utxo_set[tuple_key_b]
                    try:
                        amount = _extract_amount(utxo_entry, f"{prev_txid_hex}:{prev_index} (tuple-bytes)")
                    except ValueError:
                        return False

            # Fallback: case-insensitive scan for string keys
            if not found:
                lookup_key_ci = flat_key.lower()
                for key in utxo_set.keys():
                    try:
                        if isinstance(key, str) and key.lower() == lookup_key_ci:
                            utxo_entry = utxo_set[key]
                            amount = _extract_amount(utxo_entry, f"{key} (ci)")
                            found = True
                            break
                        
                        if isinstance(key, tuple) and len(key) == 2:
                            txid_part = key[0]
                            vout_part = int(key[1])
                            if vout_part != prev_index:
                                continue
                            
                            if isinstance(txid_part, (bytes, bytearray)):
                                key_hex = txid_part.hex()
                            else:
                                key_hex = str(txid_part)
                            if key_hex.lower() == prev_txid_hex.lower():
                                utxo_entry = utxo_set[key]
                                amount = _extract_amount(utxo_entry, f"{key} (tuple-ci)")
                                found = True
                                break
                            
                    except Exception:
                        continue

            if not found or utxo_entry is None:
                self.last_error_reason = f"prevout_missing {prev_txid_hex}:{prev_index}"
                short_prev = (
                    prev_txid_hex[:8] + ".." + prev_txid_hex[-8:]
                    if isinstance(prev_txid_hex, str) and len(prev_txid_hex) > 16
                    else prev_txid_hex
                )
                log.warning("[validate_transaction] Missing prevout %s:%d", short_prev, prev_index)
                return False

            # Coinbase maturity
            is_cb, born_height = self.utxo._get_utxo_meta(utxo_entry)
            if is_cb:
                effective_height = int(spend_at_height) if spend_at_height is not None else int(current_height) + 1
                confirmations = self._coinbase_confirmations(born_height, effective_height)
                if confirmations < int(CFG.COINBASE_MATURITY):
                    self.last_error_reason = f"coinbase_immature conf={confirmations} need>={CFG.COINBASE_MATURITY}"
                    return False

            input_sum += int(amount)
            try:
                tx_in.amount = int(amount)
            except Exception:
                pass
            
            try:
                spk_bytes = _get_utxo_script_bytes(utxo_entry)
            except Exception:
                log.warning("[validate_transaction] Error extracting script_pubkey from UTXO %s:%d", prev_txid_hex, prev_index)
                
                self.last_error_reason = "invalid_utxo_script"
                return False
            
            prevouts.append((int(amount), spk_bytes, is_cb, int(born_height)))

        # --- NEW: fobiden output 0/negativ + acumulation output_sum ---
        for tx_out in tx.outputs:
            amt = int(tx_out.amount)
            is_opret = False
            try:
                spk_bytes = tx_out.script_pubkey.serialize()
                is_opret = (isinstance(tx_out.script_pubkey, H.Script) and spk_bytes and spk_bytes[0] == H.OP_RETURN)
            except Exception:
                is_opret = False
                
            if amt <= 0:
                # Allow zero-amount OP_RETURN outputs
                if is_opret and amt == 0:
                    continue
                
                self.last_error_reason = "nonpositive_output_amount"
                return False
            
            output_sum += amt

        if input_sum < output_sum:
            log.warning("[validate_transaction] inputs < outputs: in=%d out=%d", input_sum, output_sum)
            self.last_error_reason = f"inputs_less_than_outputs in={input_sum} out={output_sum}"
            return False
        
        fee_value = int(input_sum - output_sum)
        try:
            tx.fee = fee_value
        except Exception:
            setattr(tx, "fee", fee_value)

        # ---------- VERIFICATION SIGNATURE ----------
        for i, tx_in in enumerate(tx.inputs):
            amount, spk_bytes, _, _ = prevouts[i]

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
                    script_code = _p2wpkh_script_code_from_spk(spk_bytes)
                    digest32 = bip143_sig_hash(tx, i, script_code, int(amount), sighash_type)
                except Exception as e:
                    log.warning("[validate_transaction] Failed to compute BIP143 sighash in vin %d", i)
                    self.last_error_reason = f"bip143_sighash_error:{e}"
                    return False
                
                vk = _vk_from_pubkey_bytes(pubkey)
                if not H.is_signature_canonical_low_s(sig_der):
                    self.last_error_reason = "sighash_or_der_non_canonical"
                    return False
                
                if not H.verify_der_strict_low_s(vk, digest32, sig_der):
                    self.last_error_reason = "ecdsa_verify_failed"
                    return False

            elif _is_p2pkh_script(spk_bytes):
                ss_bytes = getattr(tx_in, "script_sig", None)
                if ss_bytes is None:
                    self.last_error_reason = "missing_scriptsig"
                    return False
                
                if hasattr(ss_bytes, "serialize"):
                    ss_bytes = ss_bytes.serialize()
                if isinstance(ss_bytes, str):
                    ss_bytes = bytes.fromhex(ss_bytes)
                try:
                    sig_der, sighash_type, pubkey = _extract_p2pkh_scriptsig(ss_bytes)
                except Exception:
                    log.warning("[validate_transaction] Failed to parse scriptSig in vin %d", i)
                    self.last_error_reason = f"scriptsig_parse_error:{e}"
                    return False

                if sighash_type != H.SIGHASH_ALL:
                    self.last_error_reason = "unsupported_sighash"
                    return False

                pkhash = spk_bytes[3:23]
                if hash160(pubkey) != pkhash:
                    self.last_error_reason = "pubkey_hash_mismatch"
                    return False

                try:
                    digest32 = _legacy_sighash(tx, i, spk_bytes, sighash_type)
                except Exception:
                    log.warning("[validate_transaction] Failed to compute legacy sighash in vin %d", i)
                    self.last_error_reason = f"legacy_sighash_error:{e}"
                    return False

                vk = _vk_from_pubkey_bytes(pubkey)
                if not H.is_signature_canonical_low_s(sig_der):
                    self.last_error_reason = "sighash_or_der_non_canonical"
                    return False
                
                if not H.verify_der_strict_low_s(vk, digest32, sig_der):
                    self.last_error_reason = "ecdsa_verify_failed"
                    return False
            else:
                log.warning("[validate_transaction] Unsupported scriptPubKey type in vin %d", i)
                self.last_error_reason = "unsupported_spk_type"
                return False
        try:
            reg = StorageNodeRegistry()
            if not reg.validate_tx(tx):
                self.last_error_reason = "storage_reg_invalid"
                return False
            
        except Exception:
            log.warning("[validate_transaction] Storage REG check exception")
            self.last_error_reason = "storage_reg_error"
            return False

        return True


    def add_valid_tx(self, tx_data) -> bool:
        # Reset last error
        self.last_error_reason = None
        try:
            transaction_obj = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
        except Exception as e:
            log.warning("[add_valid_tx] Failed to parse transaction: %s", e)
            self.last_error_reason = f"parse_error:{e}"
            return False

        txid_hex = transaction_obj.txid.hex() if transaction_obj.txid else None
        if txid_hex and self.has_tx(txid_hex):
            self.last_error_reason = "tx_already_in_pool"
            return False

        utxo_set = self.utxo.utxos
        tip = self.utxo._get_tip_height_from_state()
        if not self.validate_transaction(transaction_obj, utxo_set, spend_at_height=tip + 1):
            if not self.last_error_reason:
                self.last_error_reason = "tx_validation_failed"
            else:
                reason = str(self.last_error_reason)
                if reason.startswith("prevout_missing "):
                    missing = reason.split(" ", 1)[1].strip()
                    self._queue_orphan(transaction_obj, missing)
                    self.last_error_reason = f"orphan_waiting {missing}"
            return False

        # Double-spend check & basic RBF (replace-by-fee) for conflicting prevouts
        existing_txs = self.get_all_txs()
        new_prevouts = {(txin.txid, txin.vout) for txin in transaction_obj.inputs}

        conflicts: list[Tx] = []
        for old in existing_txs:
            old_prevouts = {(tin.txid, tin.vout) for tin in old.inputs}
            if new_prevouts & old_prevouts:
                conflicts.append(old)

        if conflicts:
            # Calculate simple fee rates (fee / size) to decide replacement
            try:
                new_fee = int(getattr(transaction_obj, "fee", 0))
                new_size = max(1, self._estimate_tx_size(transaction_obj))
                new_rate = new_fee / new_size
            except Exception:
                new_fee = int(getattr(transaction_obj, "fee", 0))
                new_rate = new_fee / max(1, len(json.dumps(transaction_obj.to_dict())))

            worst_old_rate = 0.0
            worst_old_fee = 0
            conflict_txids: list[str] = []
            for old in conflicts:
                try:
                    old_fee = int(getattr(old, "fee", 0))
                    old_rate = old_fee / max(1, self._estimate_tx_size(old))
                except Exception:
                    old_fee = int(getattr(old, "fee", 0))
                    old_rate = old_fee / max(1, len(json.dumps(old.to_dict())))
                worst_old_rate = max(worst_old_rate, old_rate)
                worst_old_fee = max(worst_old_fee, old_fee)
                conflict_txids.append(old.txid.hex() if getattr(old, "txid", None) else "")

            if (new_rate > worst_old_rate) or (new_fee > worst_old_fee):
                for ctid in conflict_txids:
                    try:
                        if ctid:
                            self.remove_tx(ctid)
                    except Exception:
                        log.exception("[add_valid_tx] Failed to remove conflicting tx %s", ctid)
                        pass
            else:
                try:
                    any_prev = next(iter(new_prevouts))
                    prev_str = f"{any_prev[0].hex()}:{any_prev[1]}" if any_prev and hasattr(any_prev[0], 'hex') else str(any_prev)
                except Exception:
                    prev_str = "unknown"
                self.last_error_reason = f"double_spend_conflict prev={prev_str} with={','.join(conflict_txids)}"
                log.warning("[add_valid_tx] Rejecting tx due to double-spend conflict: %s", self.last_error_reason)
                return False

        self.add_tx(transaction_obj)
        return True

    def _queue_orphan(self, tx_obj: Tx, missing_key: str) -> None:
        try:
            tx_dict = tx_obj.to_dict(include_txid=True)
        except Exception:
            if isinstance(tx_obj, dict):
                tx_dict = dict(tx_obj)
            else:
                return
        txid_hex = tx_dict.get("txid")
        if not txid_hex:
            try:
                if getattr(tx_obj, "txid", None):
                    txid_hex = tx_obj.txid.hex()
                    tx_dict["txid"] = txid_hex
            except Exception:
                return
        if not txid_hex:
            return
        key = txid_hex.lower()
        self._orphan_pool[key] = tx_dict
        self._orphan_missing[key] = missing_key.lower()

    def recheck_orphans(self) -> int:
        if not self._orphan_pool:
            return 0
        retry_items = list(self._orphan_pool.items())
        # Clear before retry to avoid infinite loops; will be repopulated if still missing
        self._orphan_pool = {}
        self._orphan_missing = {}
        added = 0
        for key, tx_dict in retry_items:
            try:
                tx_obj = Tx.from_dict(tx_dict)
            except Exception:
                continue
            if self.add_valid_tx(tx_obj):
                added += 1
            else:
                reason = self.last_error_reason or ""
                if reason.startswith("prevout_missing "):
                    missing = reason.split(" ", 1)[1].strip()
                    self._queue_orphan(tx_obj, missing)
                elif reason.startswith("orphan_waiting "):
                    missing = reason.split(" ", 1)[1].strip()
                    self._queue_orphan(tx_obj, missing)
        return added

    def __del__(self):
        try:
            self.flush(force=False)
        except Exception:
            pass
