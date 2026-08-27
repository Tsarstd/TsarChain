# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

from typing import Any

from ...core.tx import TxOut
from ...utils import helpers as H
from ..kv import _ensure_env

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic.validate")


class UTXOValidationMixin:


    def _txid_hex(self, x):
        if x is None:
            return None
        if type(x) in (bytes, bytearray):
            return x.hex()
        return str(x)


    def _prevout_from_txin(self, tx_input):
        try:
            prev_txid = tx_input.txid
        except AttributeError:
            try:
                prev_txid = tx_input.prev_tx
            except AttributeError:
                prev_txid = None
        if prev_txid is None:
            try:
                prev_txid = tx_input.prev_tx
            except AttributeError:
                pass
            
        prev_txid_hex = self._txid_hex(prev_txid)
        try:
            vout = tx_input.vout
        except AttributeError:
            try:
                vout = tx_input.prev_index
            except AttributeError:
                vout = None
        if vout is None:
            try:
                vout = tx_input.prev_index
            except AttributeError:
                pass
        if vout is not None:
            vout = int(vout)
        return prev_txid_hex, vout


    def _is_unspendable_opreturn(self, tx_out) -> bool:
        try:
            spk = tx_out.script_pubkey
        except AttributeError:
            spk = tx_out
        if spk is None:
            return False
    
        b = self._parse_script_bytes(spk)
        return len(b) >= 1 and b[0] == 0x6A


    # ---------------------------
    # Native UTXO delta apply
    # ---------------------------
    def _apply_native_ops_for_txs(self, txs, block_height: int, block_hash: str | None = None) -> bool:
        block_txs = self._build_compact_block_txs(txs)
        if block_txs is None:
            return False

        ops = H.native_utxo_build_ops_compact(block_txs, int(block_height))
        self._apply_native_ops_to_state(ops)
        self._process_graffiti_for_txs(txs, block_height, block_hash)
        
        return True


    def _build_compact_block_txs(self, txs) -> list | None:
        block_txs = []
        for tx in txs or []:
            txid_raw = tx.txid
            if type(txid_raw) is str:
                txid_raw = bytes.fromhex(txid_raw)
            if type(txid_raw) not in (bytes, bytearray) or len(txid_raw) != 32:
                return None

            inputs_compact = self._build_compact_inputs(tx)
            if inputs_compact is None:
                return None
                
            outputs_compact = self._build_compact_outputs(tx)

            ver = int(tx.version)
            lock = int(tx.locktime)
            is_cb = bool(tx.is_coinbase)
            block_txs.append(
                (
                    ver,
                    lock,
                    inputs_compact,
                    outputs_compact,
                    bytes(txid_raw),
                    is_cb,
                )
            )
        return block_txs


    def _build_compact_inputs(self, tx) -> list | None:
        inputs_compact = []
        inputs = tx.inputs or []
        for txin in inputs:
            prev = txin.txid
            if prev is None:
                prev = txin.prev_tx
            if type(prev) is str:
                prev = bytes.fromhex(prev)
            if type(prev) not in (bytes, bytearray) or len(prev) != 32:
                return None

            vout_val = txin.vout
            vout = int(vout_val if vout_val is not None else 0)
            try:
                seq = int(txin.sequence)
            except (AttributeError, TypeError, ValueError):
                seq = 0xFFFFFFFF
            wit_vec = []
            witness = txin.witness or []
            for w in witness:
                if type(w) is str:
                    try:
                        wit_vec.append(bytes.fromhex(w))
                        continue
                    except Exception:
                        log.exception("[_apply_native_ops_for_txs] unexpected error")
                        return None
                if type(w) in (bytes, bytearray):
                    wit_vec.append(bytes(w))
                else:
                    return None
            inputs_compact.append((bytes(prev), int(vout), int(seq), wit_vec))
        return inputs_compact


    def _build_compact_outputs(self, tx) -> list:
        outputs_compact = []
        outputs = tx.outputs or []
        for txout in outputs:
            amt = int(txout.amount or 0)
            try:
                spk_obj = txout.script_pubkey
            except AttributeError:
                spk_obj = txout
            spk_bytes = self._parse_script_bytes(spk_obj)
            outputs_compact.append((amt, spk_bytes))
        return outputs_compact


    def _apply_native_ops_to_state(self, ops) -> None:
        with self._lock:
            for op in ops or []:
                if type(op) not in (tuple, list) or len(op) < 5:
                    continue
                key = op[0]
                amount = op[1]
                spk_bytes = op[2]
                is_coinbase = op[3]
                born_height = op[4]

                if type(key) is not str:
                    continue

                if amount is None:
                    if self.utxos.pop(key, None) is not None:
                        self._removed_keys.add(key)
                        self._dirty_keys.discard(key)
                        self._drop_index_entry(key)
                        self._dirty = True
                    continue

                amt_int = int(amount)
                spk_hex = None
                if type(spk_bytes) in (bytes, bytearray):
                    spk_hex = bytes(spk_bytes).hex()
                tx_out_obj = TxOut.from_dict({"amount": amt_int, "script_pubkey": spk_hex or ""})
                entry = {
                    "tx_out": tx_out_obj,
                    "is_coinbase": bool(is_coinbase),
                    "block_height": int(born_height),
                }
                self.utxos[key] = entry
                self._dirty = True
                self._dirty_keys.add(key)
                self._removed_keys.discard(key)
                self._index_entry(key, tx_out_obj)

            store = _ensure_env("utxo")
            store.apply_utxo_ops(ops)  # type: ignore[attr-defined]
            self._dirty = False
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = False
            self._bump_version()


    def _process_graffiti_for_txs(self, txs, block_height: int, block_hash: str | None) -> None:
        try:
            script_to_addr = self.script_to_address
        except AttributeError:
            script_to_addr = None
        for tx in txs or []:
            outputs_info = []
            outputs = tx.outputs or []
            for tx_out in outputs:
                try:
                    raw_spk = tx_out.script_pubkey
                except AttributeError:
                    raw_spk = tx_out
                script_bytes = self._parse_script_bytes(raw_spk)
                amount = int(tx_out.amount or 0)
                if callable(script_to_addr):
                    address = script_to_addr(raw_spk)
                else:
                    try:
                        address = tx_out.address
                    except AttributeError:
                        address = None
                outputs_info.append({"script_bytes": script_bytes, "amount": amount, "address": address})
            self._record_graffiti_event(tx, outputs_info, block_height, block_hash)


    def update(self, transactions, block_height: int, *, block_hash: str | None = None):
        if not transactions:
            return
        ok = self._apply_native_ops_for_txs(transactions, block_height, block_hash)
        if not ok:
            raise RuntimeError("native UTXO apply failed")


    def rebuild_from_chain(self, blocks) -> None:
        log.warning("[rebuild_from_chain] Rebuilding entire UTXO state from %d block(s)...", len(blocks) if blocks else 0)
        with self._lock:
            self.utxos.clear()
            self._dirty_keys.clear()
            self._removed_keys.clear()
            self._rewrite_all = True
            for block in blocks or []:
                self._rebuild_block(block)
            self._dirty = True
            self._save(force=True)
            self._bump_version()


    def _rebuild_block(self, block) -> None:
        txs = block.transactions or []
        height = int(block.height or 0)
        blk_hash = block.hash().hex()
        for tx in txs:
            self._rebuild_tx(tx, height, blk_hash)


    def _rebuild_tx(self, tx, height: int, blk_hash: str) -> None:
        tx_txid = tx.txid
        txid_hex = self._txid_hex(tx_txid)
        is_coinbase = bool(tx.is_coinbase)
        if not is_coinbase:
            self._rebuild_spend_inputs(tx)
        
        outputs_info = []
        outputs = tx.outputs or []
        for index, tx_out in enumerate(outputs):
            self.add(txid_hex, index, tx_out, is_coinbase=is_coinbase, block_height=height)
            outputs_info.append(self._build_output_info(tx_out))
            
        self._record_graffiti_event(tx, outputs_info, height, blk_hash)


    def _rebuild_spend_inputs(self, tx) -> None:
        inputs = tx.inputs or []
        for tx_input in inputs:
            prev_txid_hex, vout = self._prevout_from_txin(tx_input)
            if prev_txid_hex is None or vout is None:
                continue
            spent_key = f"{prev_txid_hex}:{int(vout)}"
            if self.utxos.pop(spent_key, None) is not None:
                self._drop_index_entry(spent_key)


    def _build_output_info(self, tx_out) -> dict:
        amount = int(tx_out.amount or 0)
        try:
            raw_spk = tx_out.script_pubkey
        except AttributeError:
            raw_spk = tx_out
        script_bytes = self._parse_script_bytes(raw_spk)
        try:
            script_to_addr = self.script_to_address
        except AttributeError:
            script_to_addr = None
        if callable(script_to_addr):
            address = script_to_addr(raw_spk)
        else:
            try:
                address = tx_out.address
            except AttributeError:
                address = None
        return {"script_bytes": script_bytes, "amount": amount, "address": address}


    def add(self, txid: str, index: int, tx_out: TxOut, is_coinbase: bool = False, block_height: int = 0):
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
            self._index_entry(key, tx_out)
            self._bump_version()


    def remove(self, txid, index: int):
        key = f"{self._txid_hex(txid)}:{int(index)}"
        with self._lock:
            if self.utxos.pop(key, None) is not None:
                self._dirty = True
                self._dirty_keys.discard(key)
                self._removed_keys.add(key)
                self._drop_index_entry(key)
                self._bump_version()


    def spend_input(self, tx_input):
        prev_txid_hex, vout = self._prevout_from_txin(tx_input)
        if prev_txid_hex is None or vout is None:
            raise AttributeError("TxIn missing prevout (txid/vout)")
        self.remove(prev_txid_hex, int(vout))


    def _parse_script_bytes(self, spk) -> bytes:
        try:
            return spk.serialize()
        except (AttributeError, TypeError):
            pass
        if type(spk) in (bytes, bytearray):
            return bytes(spk)
        if type(spk) is str:
            try:
                return bytes.fromhex(spk)
            except ValueError:
                return b""
        return b""


    def _apply_tx_remove_prevout(self, snapshot: dict, prev_txid_hex: str, vout: int) -> bool:
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
        if type(m) is dict and int(vout) in m:
            del m[int(vout)]
            if not m:
                snapshot.pop(prev_txid_hex, None)
            return True
        
        removed = False
        for addr, lst in list(snapshot.items()):
            if type(lst) is list:
                for i in range(len(lst) - 1, -1, -1):
                    ent = lst[i]
                    tid = ent.get("txid") or ent.get("txid_hex") or ent.get("prev_txid")
                    vv = ent.get("vout") if "vout" in ent else ent.get("index")
                    if self._txid_hex(tid) == prev_txid_hex and int(vv) == int(vout):
                        lst.pop(i)
                        removed = True
                if not lst:
                    snapshot.pop(addr, None)
        return removed


    def _detect_snapshot_layout(self, snapshot: dict) -> str | None:
        for k, v in snapshot.items():
            if type(k) is str and ":" in k:
                return "flat_string"
            if type(k) is tuple and len(k) == 2:
                return "flat_tuple"
            if type(v) is dict and all(type(_) is int for _ in v.keys()):
                return "per_txid_dict"
            if type(v) is list:
                return "per_address_list"
        return None


    def _apply_tx_insert_output(self, snapshot: dict, layout: str | None, txid_hex: str, n: int, entry: dict, address: str | None):
        if layout is None:
            layout = self._detect_snapshot_layout(snapshot)

        if layout == "flat_string":
            snapshot[f"{txid_hex}:{int(n)}"] = entry
            return
        if layout == "flat_tuple":
            snapshot[(txid_hex, int(n))] = entry
            return
        if layout == "per_txid_dict":
            bucket = snapshot.setdefault(txid_hex, {})
            if type(bucket) is dict:
                bucket[int(n)] = entry
                return
        if layout == "per_address_list" and address:
            bucket = snapshot.setdefault(address, [])
            if type(bucket) is list:
                bucket.append(entry)
                return

        snapshot[f"{txid_hex}:{int(n)}"] = entry


    def apply_tx_to_utxoset(self, tx, utxos: dict, block_height: int | None = None, block_hash: str | None = None) -> dict:
        if utxos is None:
            return utxos

        is_coinbase = bool(tx.is_coinbase)
        tx_txid = tx.txid
        txid_hex = self._txid_hex(tx_txid)
        if not txid_hex:
            txid_hex_fn = tx.txid_hex
            txid_hex = txid_hex_fn() if callable(txid_hex_fn) else str(txid_hex_fn or "")
        detected_layout = self._detect_snapshot_layout(utxos)

        if not is_coinbase:
            inputs = tx.inputs or []
            for txin in inputs:
                prev_id = txin.txid
                if prev_id is None:
                    prev_id = txin.prev_tx

                prev_txid_hex = self._txid_hex(prev_id)
                v_val = txin.vout
                vout = int(v_val if v_val is not None else 0)
                if prev_txid_hex is not None:
                    self._apply_tx_remove_prevout(utxos, prev_txid_hex, vout)

        outputs_info: list[dict[str, Any]] = []
        outputs = tx.outputs or []
        for n, txout in enumerate(outputs):
            try:
                spk = txout.script_pubkey
            except AttributeError:
                spk = txout
            b = self._parse_script_bytes(spk)
            if len(b) >= 1 and b[0] == 0x6A:
                continue

            amount = int(txout.amount or 0)
            try:
                spk_hex = spk.serialize().hex()
            except (AttributeError, TypeError):
                if type(spk) in (bytes, bytearray):
                    spk_hex = bytes(spk).hex()
                elif type(spk) is str:
                    spk_hex = spk
                else:
                    spk_hex = ""

            try:
                script_to_addr = self.script_to_address
            except AttributeError:
                script_to_addr = None
            if callable(script_to_addr):
                address = script_to_addr(spk)
            else:
                try:
                    address = txout.address
                except AttributeError:
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
            self._apply_tx_insert_output(utxos, detected_layout, txid_hex, n, entry, address)

        if block_height is not None:
            self._record_graffiti_event(tx, outputs_info, block_height, block_hash)

        return utxos