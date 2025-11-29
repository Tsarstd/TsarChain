# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

from typing import Any

from ...core.tx import TxOut
from ...utils import helpers as H
from ..kv import kv_enabled, _ensure_env
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic(validate)")


class UTXOValidationMixin:
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
            
            return len(b) >= 1 and b[0] == 0x6A
        except Exception:
            log.exception("[_is_unspendable_opreturn] Error checking OP_RETURN in scriptPubKey")
            return False

    # ---------------------------
    # Native UTXO delta apply
    # ---------------------------
    def _apply_native_ops_for_txs(self, txs, block_height: int, block_hash: str | None = None, *, autosave: bool = True) -> bool:
        try:
            block_txs = []
            for tx in txs or []:
                txid_raw = getattr(tx, "txid", None)
                if isinstance(txid_raw, str):
                    txid_raw = bytes.fromhex(txid_raw)
                if not isinstance(txid_raw, (bytes, bytearray)) or len(txid_raw) != 32:
                    return False

                inputs_compact = []
                for txin in getattr(tx, "inputs", []) or []:
                    prev = getattr(txin, "txid", None) or getattr(txin, "prev_tx", None)
                    if isinstance(prev, str):
                        prev = bytes.fromhex(prev)
                    if not isinstance(prev, (bytes, bytearray)) or len(prev) != 32:
                        return False
                    try:
                        vout = int(getattr(txin, "vout", getattr(txin, "prev_index", 0)))
                    except Exception:
                        return False
                    seq = getattr(txin, "sequence", 0xffffffff)
                    wit_vec = []
                    for w in getattr(txin, "witness", None) or []:
                        if isinstance(w, str):
                            try:
                                wit_vec.append(bytes.fromhex(w))
                                continue
                            except Exception:
                                return False
                        if isinstance(w, (bytes, bytearray)):
                            wit_vec.append(bytes(w))
                        else:
                            return False
                    inputs_compact.append((bytes(prev), int(vout), int(seq), wit_vec))

                outputs_compact = []
                for txout in getattr(tx, "outputs", []) or []:
                    try:
                        amt = int(getattr(txout, "amount", 0))
                    except Exception:
                        return False
                    spk_obj = getattr(txout, "script_pubkey", None)
                    if hasattr(spk_obj, "serialize"):
                        try:
                            spk_bytes = spk_obj.serialize()
                        except Exception:
                            spk_bytes = b""
                    elif isinstance(spk_obj, (bytes, bytearray)):
                        spk_bytes = bytes(spk_obj)
                    elif isinstance(spk_obj, str):
                        try:
                            spk_bytes = bytes.fromhex(spk_obj)
                        except Exception:
                            spk_bytes = b""
                    else:
                        spk_bytes = b""
                    outputs_compact.append((amt, spk_bytes))

                block_txs.append(
                    (
                        int(getattr(tx, "version", 1)),
                        int(getattr(tx, "locktime", 0)),
                        inputs_compact,
                        outputs_compact,
                        bytes(txid_raw),
                        bool(getattr(tx, "is_coinbase", False)),
                    )
                )

            ops = H.native_utxo_build_ops_compact(block_txs, int(block_height))
        except Exception:
            return False

        with self._lock:
            for op in ops or []:
                if not isinstance(op, (tuple, list)) or len(op) < 5:
                    continue
                key = op[0]
                amount = op[1]
                spk_bytes = op[2]
                is_coinbase = op[3]
                born_height = op[4]

                if not isinstance(key, str):
                    continue

                if amount is None:
                    if self.utxos.pop(key, None) is not None:
                        self._removed_keys.add(key)
                        self._dirty_keys.discard(key)
                        self._drop_index_entry(key)
                        self._dirty = True
                    continue

                try:
                    amt_int = int(amount)
                except Exception:
                    continue
                spk_hex = None
                if isinstance(spk_bytes, (bytes, bytearray)):
                    spk_hex = bytes(spk_bytes).hex()
                entry = {
                    "tx_out": {"amount": amt_int, "script_pubkey": spk_hex},
                    "is_coinbase": bool(is_coinbase),
                    "block_height": int(born_height),
                }
                self.utxos[key] = entry
                self._dirty = True
                self._dirty_keys.add(key)
                self._removed_keys.discard(key)
                self._index_entry(key, entry.get("tx_out"))

            if kv_enabled():
                store = _ensure_env()
                store.apply_utxo_ops(ops)  # type: ignore[attr-defined]
                self._dirty = False
                self._dirty_keys.clear()
                self._removed_keys.clear()
                self._rewrite_all = False
            elif autosave:
                try:
                    self._save()
                except Exception:
                    log.debug("[_apply_native_ops_for_txs] _save failed", exc_info=True)
            self._bump_version()

        try:
            for tx in txs or []:
                outputs_info = []
                for tx_out in getattr(tx, "outputs", []) or []:
                    script_bytes = getattr(tx_out, "script_pubkey", None)
                    if hasattr(script_bytes, "serialize"):
                        try:
                            script_bytes = script_bytes.serialize()
                        except Exception:
                            script_bytes = None
                    elif isinstance(script_bytes, str):
                        try:
                            script_bytes = bytes.fromhex(script_bytes)
                        except Exception:
                            script_bytes = None
                    amount = int(getattr(tx_out, "amount", 0))
                    address = None
                    try:
                        if hasattr(self, "script_to_address"):
                            address = self.script_to_address(getattr(tx_out, "script_pubkey", None))
                    except Exception:
                        address = None
                    outputs_info.append({"script_bytes": script_bytes, "amount": amount, "address": address})
                try:
                    blk_hash = block_hash
                    self._record_graffiti_event(tx, outputs_info, block_height, blk_hash)
                except Exception:
                    pass
                
        except Exception:
            pass
        return True


    def update(self, transactions, block_height: int, *, block_hash: str | None = None, autosave: bool = True):
        if not transactions:
            return
        ok = self._apply_native_ops_for_txs(transactions, block_height, block_hash, autosave=autosave)
        if not ok:
            raise RuntimeError("native UTXO apply failed")

    def rebuild_from_chain(self, blocks) -> None:
        with self._lock:
            self.utxos.clear()
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = True
            for block in blocks or []:
                txs = getattr(block, "transactions", []) or []
                height = int(getattr(block, "height", 0))
                try:
                    blk_hash = block.hash().hex()
                except Exception:
                    blk_hash = None
                for tx in txs:
                    txid_hex = self._txid_hex(getattr(tx, "txid", None))
                    is_coinbase = bool(getattr(tx, "is_coinbase", False))
                    if not is_coinbase:
                        for tx_input in getattr(tx, "inputs", []) or []:
                            prev_txid_hex, vout = self._prevout_from_txin(tx_input)
                            if prev_txid_hex is None or vout is None:
                                continue
                            
                            spent_key = f"{prev_txid_hex}:{int(vout)}"
                            if self.utxos.pop(spent_key, None) is not None:
                                self._drop_index_entry(spent_key)
                                
                    outputs_info = []
                    for index, tx_out in enumerate(getattr(tx, "outputs", []) or []):
                        self.add(txid_hex, index, tx_out, is_coinbase=is_coinbase, block_height=height, autosave=False)
                        amount = int(getattr(tx_out, "amount", 0))
                        script_bytes = self._script_bytes(getattr(tx_out, "script_pubkey", None))
                        address = None
                        try:
                            if hasattr(self, "script_to_address"):
                                address = self.script_to_address(getattr(tx_out, "script_pubkey", None))
                            elif hasattr(tx_out, "address"):
                                address = getattr(tx_out, "address")
                        except Exception:
                            address = None
                        outputs_info.append({"script_bytes": script_bytes, "amount": amount, "address": address})
                    self._record_graffiti_event(tx, outputs_info, height, blk_hash)
            self._dirty = True
            if self._persist_enabled:
                self._save(force=True)
            self._bump_version()

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
            self._index_entry(key, tx_out)
            self._bump_version()

    def remove(self, txid, index: int, autosave: bool = True):
        key = f"{self._txid_hex(txid)}:{int(index)}"
        with self._lock:
            if self.utxos.pop(key, None) is not None:
                self._dirty = True
                self._dirty_keys.discard(key)
                self._removed_keys.add(key)
                if autosave:
                    self._save()
                    
                self._drop_index_entry(key)
                self._bump_version()

    def spend_input(self, tx_input):
        prev_txid_hex, vout = self._prevout_from_txin(tx_input)
        if prev_txid_hex is None or vout is None:
            raise AttributeError("TxIn missing prevout (txid/vout)")
        self.remove(prev_txid_hex, int(vout))

    def apply_tx_to_utxoset(self, tx, utxos: dict, block_height: int | None = None, block_hash: str | None = None) -> dict:
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
            key_str = f"{prev_txid_hex}:{key_int}"
            if key_str in snapshot:
                snapshot.pop(key_str, None)
                return True

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

        outputs_info: list[dict[str, Any]] = []
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

            outputs_info.append({"script_bytes": b, "address": address, "amount": amount})
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

        if block_height is not None:
            self._record_graffiti_event(tx, outputs_info, block_height, block_hash)

        return utxos
