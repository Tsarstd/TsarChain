# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141; libsecp256k1; Signal-X3DH

import json
from ecdsa import VerifyingKey, SECP256k1

# ---------------- Local Project ----------------
from ..storage.kv import kv_enabled, iter_prefix, batch, clear_db
from ..storage.db import BaseDatabase
from ..core.tx import Tx
from ..storage.utxo import UTXODB
from ..contracts.storage_nodes import StorageNodeRegistry
from ..utils.helpers import is_p2wpkh_script, bip143_sig_hash, hash160, hash256, serialize_tx_for_txid
from ..utils.helpers import Script, OP_RETURN, SECP256K1_P, SIGHASH_ALL
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
    y_sq = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if (y & 1) != (pub33[0] & 1):
        y = SECP256K1_P - y
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
    if isinstance(utxo_entry, dict):
        if "tx_out" in utxo_entry and hasattr(utxo_entry["tx_out"], "script_pubkey"):
            return utxo_entry["tx_out"].script_pubkey.serialize()
        
        if "tx_out" in utxo_entry and isinstance(utxo_entry["tx_out"], dict) and "script_pubkey" in utxo_entry["tx_out"]:
            spk = utxo_entry["tx_out"]["script_pubkey"]
            return bytes.fromhex(spk) if isinstance(spk, str) else (spk or b"")
        
        if "script_pubkey" in utxo_entry:
            spk = utxo_entry["script_pubkey"]
            return bytes.fromhex(spk) if isinstance(spk, str) else (spk or b"")
        
    if hasattr(utxo_entry, "script_pubkey"):
        return utxo_entry.script_pubkey.serialize()
    raise ValueError("Cannot extract script_pubkey bytes from UTXO entry")

def _p2wpkh_script_code_from_spk(spk_bytes: bytes) -> bytes:
    if not is_p2wpkh_script(spk_bytes):
        raise ValueError("Not a P2WPKH script")
    pkhash = spk_bytes[2:22]
    return b"\x19\x76\xa9\x14" + pkhash + b"\x88\xac"

def _legacy_sighash(tx: "Tx", vin_index: int, script_code: bytes, sighash_type: int) -> bytes:
    orig_scripts = [tin.script_sig for tin in tx.inputs]
    try:
        for tin in tx.inputs:
            tin.script_sig = Script([])
        tx.inputs[vin_index].script_sig = Script.deserialize(script_code)
        preimage = serialize_tx_for_txid(tx) + int(sighash_type).to_bytes(4, "little")
        return hash256(preimage)
    finally:
        for tin, orig in zip(tx.inputs, orig_scripts):
            tin.script_sig = orig


class TxPoolDB(BaseDatabase):
    def __init__(self, filepath: str = CFG.MEMPOOL_FILE, max_size_mb: int = 50):
        self.filepath = filepath
        self.max_size_mb = max_size_mb
        pool = self.load_pool()
        try:
            self.current_size = sum(self._estimate_tx_size_any(Tx.from_dict(x) if isinstance(x, dict) else x) for x in pool)
        except Exception:
            self.current_size = 0
        self.utxo = UTXODB()
        # Last error/context for receive_tx to report back to clients
        self.last_error_reason: str | None = None

    def save_pool(self, pool: list) -> None:
        if kv_enabled():
            try:
                clear_db('mempool')
            except Exception:
                pass
            try:
                with batch('mempool') as b:
                    for item in pool:
                        try:
                            d = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, 'to_dict') else item)
                            txid = d.get('txid')
                            if not txid:
                                continue
                            b.put(txid.encode('utf-8'), json.dumps(d, separators=(",", ":")).encode('utf-8'))
                        except Exception:
                            continue
            except Exception:
                log.error("[save_pool] LMDB write failed, falling back to file storage")
        else:
            self.save_json(self.filepath, pool)

    def load_pool(self) -> list:
        if kv_enabled():
            out = []
            try:
                for k, v in iter_prefix('mempool', b''):
                    try:
                        out.append(json.loads(v.decode('utf-8')))
                    except Exception:
                        continue
                return out
            except Exception:
                log.error("[load_pool] LMDB read failed, falling back to file storage")
                return []
        return self.load_json(self.filepath) or []
    
    def get_all_txs(self) -> list:
        tx_dicts = self.load_pool()
        tx_list = []
        for tx_data in tx_dicts:
            try:
                if isinstance(tx_data, bytes):
                    tx_data = tx_data.decode('utf-8')
                if isinstance(tx_data, str):
                    tx_data = json.loads(tx_data)
                tx_obj = Tx.from_dict(tx_data)
                tx_list.append(tx_obj)
            except Exception:
                log.warning("[get_all_txs] Failed to parse transaction in pool, skipping")
                continue
        return tx_list

    def has_tx(self, txid_hex: str) -> bool:
        pool = self.load_pool()
        for item in pool:
            if isinstance(item, dict):
                if item.get("txid") == txid_hex:
                    return True
            elif isinstance(item, Tx):
                if item.txid and item.txid.hex() == txid_hex:
                    return True
        return False

    def add_tx(self, tx: "Tx") -> None:
        tx_size = self._estimate_tx_size(tx)
        if self.current_size + tx_size > self.max_size_mb * 1024 * 1024:
            self._evict_low_fee_txs(tx_size)
        
        pool = self.load_pool()
        if isinstance(tx, Tx):
            pool.append(tx.to_dict())
        elif isinstance(tx, dict):
            pool.append(tx)
        else:
            raise TypeError("add_tx only accepts Tx objects or dicts")
        
        self.save_pool(pool)
        self.current_size += tx_size
        
    def _estimate_tx_size(self, tx) -> int:
        size = 0
        for txin in tx.inputs:
            size += 40  # txid + vout
            size += len(txin.script_sig.serialize()) if txin.script_sig else 0
            size += sum(len(w) for w in txin.witness) if txin.witness else 0

        for txout in tx.outputs:
            size += 8  # amount
            size += len(txout.script_pubkey.serialize()) if txout.script_pubkey else 0
        
        return size
    
    def _estimate_tx_size_any(self, tx_like) -> int:
        if isinstance(tx_like, dict):
            try:
                return self._estimate_tx_size(Tx.from_dict(tx_like))
            except Exception:
                return len(json.dumps(tx_like))
        return self._estimate_tx_size(tx_like)

    def _evict_low_fee_txs(self, needed_space: int):
        pool = self.load_pool()
        if not pool:
            return
        
        sorted_txs = sorted(pool, key=lambda x: x.get('fee', 0) / max(1, self._estimate_tx_size_any(x)))
        
        freed_space = 0
        while sorted_txs and freed_space < needed_space:
            tx = sorted_txs.pop(0)
            tx_size = self._estimate_tx_size_any(tx)
            pool.remove(tx)
            freed_space += tx_size
            self.current_size -= tx_size
        
        self.save_pool(pool)

    def remove_tx(self, txid_hex: str) -> None:
        pool = self.load_pool()
        new_pool = []
        for item in pool:
            if isinstance(item, dict):
                if item.get("txid") != txid_hex:
                    new_pool.append(item)
            elif isinstance(item, Tx):
                if not (item.txid and item.txid.hex() == txid_hex):
                    new_pool.append(item)
        self.save_pool(new_pool)

    def clear(self) -> None:
        self.save_pool([])

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

            # Format FLAT: "txid:index"
            flat_key = f"{prev_txid_hex}:{prev_index}"
            if flat_key in utxo_set:
                found = True
                utxo_entry = utxo_set[flat_key]
                try:
                    amount = self._get_utxo_amount(utxo_entry)
                except ValueError:
                    log.warning("[validate_transaction] Error extracting amount from UTXO %s", flat_key)
                    return False

            # Format NESTED: {txid: {index: data}}
            if not found and prev_txid_hex in utxo_set and isinstance(utxo_set[prev_txid_hex], dict):
                if prev_index in utxo_set[prev_txid_hex]:
                    found = True
                    utxo_entry = utxo_set[prev_txid_hex][prev_index]
                    try:
                        amount = self._get_utxo_amount(utxo_entry)
                    except ValueError:
                        log.warning("[validate_transaction] Error extracting amount from UTXO %s:%d", prev_txid_hex, prev_index)
                        return False

            # Coinbase maturity
            is_cb, born_height = self.utxo._get_utxo_meta(utxo_entry)
            if is_cb:
                effective_height = int(spend_at_height) if spend_at_height is not None else int(current_height) + 1
                confirmations = max(0, (effective_height - int(born_height)) + 1)
                if confirmations < int(CFG.COINBASE_MATURITY):
                    self.last_error_reason = f"coinbase_immature conf={confirmations} need>={CFG.COINBASE_MATURITY}"
                    return False

            input_sum += int(amount)
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
                is_opret = (isinstance(tx_out.script_pubkey, Script) and spk_bytes and spk_bytes[0] == OP_RETURN)
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
                if sighash_type != SIGHASH_ALL:
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

                if sighash_type != SIGHASH_ALL:
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
                
                # --- [NEW] Storage Registry ---
                try:
                    reg = StorageNodeRegistry()
                    if not reg.validate_tx(tx):
                        log.warning("[validate_transaction] Storage REG check failed in vin %d", i)
                        self.last_error_reason = "storage_reg_invalid"
                        return False
                except Exception:
                    log.warning("[validate_transaction] Storage REG check exception in vin %d", i)
                    self.last_error_reason = "storage_reg_error"
                    return False

            else:
                log.warning("[validate_transaction] Unsupported scriptPubKey type in vin %d", i)
                self.last_error_reason = "unsupported_spk_type"
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

        utxo_db = UTXODB()
        utxo_set = utxo_db.utxos
        tip = self.utxo._get_tip_height_from_state()
        if not self.validate_transaction(transaction_obj, utxo_set, spend_at_height=tip + 1):
            if not self.last_error_reason:
                self.last_error_reason = "tx_validation_failed"
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
