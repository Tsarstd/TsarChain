# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md.

from __future__ import annotations

import json
import time
import heapq
from collections import OrderedDict

from ..core.tx import Tx
from ..storage.kv import kv_enabled, iter_prefix, batch, clear_db
from ..utils import config as CFG

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.storage")

__all__ = ["MempoolStorageMixin"]


class MempoolStorageMixin:
    def _load_storage_pool(self) -> tuple[list, dict]:
        meta = {}
        if kv_enabled():
            out = []
            for k, v in iter_prefix("mempool", b""):
                key = k.decode("utf-8")
                if key == "__meta__":
                    meta = json.loads(v.decode("utf-8")) or {}
                    continue
                out.append(json.loads(v.decode("utf-8")))
            return out, meta
        raw = self.load_json(self.filepath) or []
        if isinstance(raw, dict):
            meta = raw.get("meta") or {}
            if "schema_version" in raw and "schema_version" not in meta:
                meta["schema_version"] = raw.get("schema_version")
            entries = raw.get("txs") or []
        else:
            entries = raw
        return entries, meta

    def _hydrate_pool(self, entries: list) -> None:
        for entry in entries:
            meta = {}
            if isinstance(entry, dict):
                meta = entry.get("_meta") or {}
            tx_obj = self._tx_from_any(entry)
            txid = self._normalize_txid(tx_obj.txid)
            recv_at = meta.get("received_at") if isinstance(meta, dict) else None
            if recv_at:
                setattr(tx_obj, "_received_at", float(recv_at))

            hinted_size = None
            if isinstance(meta, dict):
                hinted_size = meta.get("vbytes") or meta.get("virtual_size")
                
            size = int(hinted_size) if hinted_size is not None else None
            if size is None:
                size = self._estimate_tx_size(tx_obj)

            self._pool[txid] = tx_obj
            self._size_map[txid] = size
            self._record_fee_rate(txid, tx_obj, size)
            self._index_tx_prevouts(tx_obj)

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
        tx_size = self._estimate_tx_size(tx_obj)
        meta = {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "received_at": getattr(tx_obj, "_received_at", None),
            "vbytes": int(tx_size),
            "weight": int(tx_size * 4),
            "fee_rate": self._compute_fee_rate(tx_obj, tx_size),
        }
        tx_dict["_meta"] = meta
        return tx_dict

    def _build_meta_snapshot(self) -> dict:
        return {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "generated_at": int(time.time()),
            "count": len(self._pool),
            "virtual_size": int(self.current_size),
            "max_size_bytes": int(self.max_size_mb),
        }

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._change_seq += 1

    def _maybe_flush_after_mutation(self) -> None:
        if not self._dirty:
            return
        now = time.time()
        if (now - self._last_flush) < self._auto_flush_interval:
            return
        self.flush(force=False)

    def _compute_fee_rate(self, tx_obj: Tx, tx_size: int | None = None) -> float:
        fee = float(getattr(tx_obj, "fee", 0) or 0)
        if tx_size is None:
            tx_size = self._estimate_tx_size(tx_obj)
        return fee / max(1, int(tx_size))

    def _record_fee_rate(self, txid: str, tx_obj: Tx, tx_size: int | None = None) -> None:
        rate = self._compute_fee_rate(tx_obj, tx_size)
        self._heap_entries[txid] = rate
        heapq.heappush(self._fee_heap, (rate, txid))

    def _remove_fee_record(self, txid: str) -> None:
        self._heap_entries.pop(txid, None)

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
            meta = self._build_meta_snapshot()
            self._dirty = False
            self._last_flush = now

        if kv_enabled():
            clear_db("mempool")
            with batch("mempool") as b:
                b.put(b"__meta__", json.dumps(meta, separators=CFG.CANONICAL_SEP).encode("utf-8"),)
                for entry in snapshot:
                    txid = entry.get("txid")
                    if not txid:
                        continue
                    b.put(txid.encode("utf-8"), json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8"),)
        else:
            payload = {
                "schema_version": meta.get("schema_version"),
                "meta": meta,
                "txs": snapshot,
            }
            self.save_json(self.filepath, payload)
        return True

    def load_pool(self) -> list:
        with self._lock:
            return [self._serialize_tx(tx) for tx in self._pool.values()]

    def save_pool(self, pool: list) -> None:
        tx_objects = []
        for item in pool:
            tx_objects.append(self._tx_from_any(item))
        with self._lock:
            self._pool = OrderedDict()
            self._size_map = {}
            self._prevout_index = {}
            self._fee_heap = []
            self._heap_entries = {}
            for tx in tx_objects:
                txid = self._normalize_txid(tx.txid)
                self._pool[txid] = tx
                self._size_map[txid] = self._estimate_tx_size(tx)
                self._index_tx_prevouts(tx)
                self._record_fee_rate(txid, tx, self._size_map[txid])
            self.current_size = sum(self._size_map.values())
            self._mark_dirty()
        self.flush(force=True)

    def get_all_txs(self) -> list:
        with self._lock:
            return list(self._pool.values())

    def stats(self) -> dict:
        with self._lock:
            return {
                "count": len(self._pool),
                "virtual_size": int(self.current_size),
            }

    def has_tx(self, txid_hex: str) -> bool:
        norm = self._normalize_txid(txid_hex)
        with self._lock:
            return norm in self._pool

    def _estimate_tx_size(self, tx: Tx) -> int:
        size = 0
        for txin in getattr(tx, "inputs", []) or []:
            size += 40
            if getattr(txin, "script_sig", None):
                size += len(txin.script_sig.serialize())
            if getattr(txin, "witness", None):
                size += sum(len(w) for w in txin.witness)
        for txout in getattr(tx, "outputs", []) or []:
            size += 8
            if getattr(txout, "script_pubkey", None):
                size += len(txout.script_pubkey.serialize())
        return max(size, len(tx.to_dict(include_txid=True)))

    def add_tx(self, tx: Tx) -> None:
        tx_obj = self._tx_from_any(tx)
        if not hasattr(tx_obj, "_received_at"):
            setattr(tx_obj, "_received_at", time.time())
        txid = self._normalize_txid(tx_obj.txid)
        tx_size = self._estimate_tx_size(tx_obj)
        self._ensure_space(tx_size)

        with self._lock:
            prev_size = 0
            old_tx = self._pool.get(txid)
            if old_tx:
                prev_size = self._size_map.get(txid, 0)
                self._drop_tx_prevouts(old_tx)
                self._remove_fee_record(txid)
            self._pool[txid] = tx_obj
            self._size_map[txid] = tx_size
            self.current_size += tx_size - prev_size
            self._index_tx_prevouts(tx_obj)
            self._record_fee_rate(txid, tx_obj, tx_size)
            self._mark_dirty()
        self._maybe_flush_after_mutation()

    def remove_tx(self, txid_hex: str) -> bool:
        norm = self._normalize_txid(txid_hex)
        with self._lock:
            tx = self._pool.pop(norm, None)
            if not tx:
                return False
            self._drop_tx_prevouts(tx)
            self._remove_fee_record(norm)
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
                    tx_obj = self._pool.pop(norm, None)
                    if tx_obj:
                        self._drop_tx_prevouts(tx_obj)
                    self._remove_fee_record(norm)
                    self.current_size -= self._size_map.pop(norm, 0)
                    removed += 1
            if removed:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()
        if removed:
            self._maybe_flush_after_mutation()
        return removed

    def clear(self) -> None:
        with self._lock:
            if not self._pool:
                return
            self._pool.clear()
            self._size_map.clear()
            self.current_size = 0
            self._prevout_index.clear()
            self._fee_heap.clear()
            self._heap_entries.clear()
        self._mark_dirty()
        self.flush(force=True)
