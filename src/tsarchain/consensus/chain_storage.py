# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import datetime as dt
import json
import os
from collections import Counter
from typing import Optional
import shutil
import time
import hashlib

from ..core.block import Block
from ..mempool.pool import TxPoolDB
from ..storage.utxo import UTXODB
from ..storage.kv import kv_enabled, batch, iter_prefix, clear_db, delete, _ensure_env
from ..utils import config as CFG
from ..utils.bootstrap import annotate_local_snapshot_meta
from ..utils.helpers import bits_to_target, target_to_difficulty
from ..utils.tsar_logging import get_ctx_logger
from .genesis import GENESIS_HASH

log = get_ctx_logger('tsarchain.consensus.chain_storage')

class StorageMixin:
    def _mark_chain_dirty(self, height: int = 0) -> None:
        if height < 0:
            height = 0
        if self._chain_dirty_from is None:
            self._chain_dirty_from = height
        else:
            self._chain_dirty_from = min(self._chain_dirty_from, height)

    def _prune_chain_store(self, start_height: int) -> None:
        if self.in_memory or not kv_enabled():
            return
        if start_height < 0:
            start_height = 0
        try:
            keys_to_remove: list[bytes] = []
            for key, _ in iter_prefix('chain', b'h:'):
                try:
                    h = int(key[2:].decode('utf-8'))
                except Exception:
                    continue
                if h >= start_height:
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                try:
                    delete('chain', key)
                except Exception:
                    pass
        except Exception:
            log.exception("[_prune_chain_store] Failed pruning chain entries from height %s", start_height)

    def _reset_chain_store(self) -> None:
        if self.in_memory:
            return
        if kv_enabled():
            try:
                clear_db('chain')
            except Exception:
                log.exception("[_reset_chain_store] Failed clearing LMDB chain data")
        try:
            self._chain_store.save([])
        except Exception:
            log.exception("[_reset_chain_store] Failed clearing JSON chain data")
        meta_path = CFG.SNAPSHOT_META_PATH
        if meta_path and os.path.exists(meta_path):
            try:
                os.remove(meta_path)
            except Exception:
                log.warning("[_reset_chain_store] Failed removing snapshot meta file at %s", meta_path)
        self._persisted_height = -1
        self._chain_dirty_from = None
        try:
            self._snapshot_last_backup_height = -1
        except Exception:
            pass

    def _backup_snapshot_enabled(self) -> bool:
        if self.in_memory:
            return False
        return bool(CFG.BACKUP_SNAPSHOT)

    def _maybe_backup_snapshot(self, tip_height: int) -> None:
        if tip_height < 0 or not kv_enabled():
            return
        if not self._backup_snapshot_enabled():
            return
        interval = int(CFG.BLOCK_BACKUP_SNAPSHOT or 0)
        if interval <= 0:
            return
        last = getattr(self, "_snapshot_last_backup_height", -1)
        if last >= 0 and (tip_height - last) < interval:
            return
        target_dir = CFG.SNAPSHOT_BACKUP_DIR
        if not target_dir:
            return
        try:
            self._copy_snapshot_env(target_dir)
            tip_ts = None
            try:
                if self.chain:
                    tip_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)
            except Exception:
                tip_ts = None
            meta = None
            try:
                meta = annotate_local_snapshot_meta(height=tip_height, tip_timestamp=tip_ts)
            except Exception:
                log.debug("[backup_snapshot] annotate meta failed", exc_info=True)
            backup_dir = os.path.abspath(target_dir)
            if meta:
                meta_name = os.path.basename(CFG.SNAPSHOT_META_PATH or "snapshot.meta.json")
                backup_meta_path = os.path.join(backup_dir, meta_name)
                try:
                    with open(backup_meta_path, "w", encoding="utf-8") as fh:
                        json.dump(meta, fh, indent=2, sort_keys=True)
                except Exception:
                    log.warning("[backup_snapshot] Failed to write snapshot meta copy at %s", backup_meta_path)
                try:
                    self._write_snapshot_manifest(backup_dir, meta, tip_height)
                except Exception:
                    log.warning("[backup_snapshot] Failed to write snapshot manifest copy", exc_info=True)
            self._snapshot_last_backup_height = tip_height
            log.info("[backup_snapshot] Snapshot updated at height %s to %s", tip_height, target_dir)
        except Exception:
            log.exception("[backup_snapshot] Failed to update snapshot backup")

    def _copy_snapshot_env(self, target_dir: str) -> None:
        target_dir = os.path.abspath(target_dir)
        parent = os.path.dirname(target_dir)
        if parent:
            os.makedirs(parent, exist_ok=True)
            
        tmp_dir = f"{target_dir}.tmp"
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
            
        env = _ensure_env() if kv_enabled() else None
        if env is not None:
            os.makedirs(tmp_dir, exist_ok=True)
            env.copy(tmp_dir, compact=True)
        else:
            os.makedirs(tmp_dir, exist_ok=True)
            data_file = CFG.LMDB_DATA_FILE
            if data_file and os.path.exists(data_file):
                shutil.copy2(data_file, os.path.join(tmp_dir, os.path.basename(data_file)))
            lock_file = CFG.LMDB_LOCK_FILE
            if lock_file and os.path.exists(lock_file):
                shutil.copy2(lock_file, os.path.join(tmp_dir, os.path.basename(lock_file)))
                
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        os.replace(tmp_dir, target_dir)

    @staticmethod
    def _hash_file(path: str) -> Optional[str]:
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest()
        except Exception:
            return None

    def _write_snapshot_manifest(self, target_dir: str, meta: dict, height: int) -> None:
        data_basename = os.path.basename(CFG.LMDB_DATA_FILE)
        data_path = os.path.join(target_dir, data_basename)
        sha = meta.get("sha256")
        size = meta.get("size")
        if (not sha or not size) and os.path.exists(data_path):
            size = size or os.path.getsize(data_path)
            sha = sha or self._hash_file(data_path)
        manifest = {
            "version": 1,
            "snapshot_url": meta.get("source") or CFG.SNAPSHOT_FILE_URL,
            "size": int(size or 0),
            "sha256": sha or "",
            "height": int(meta.get("height", height)),
            "generated_at": int(meta.get("generated_at") or int(time.time())),
        }
        manifest_path = os.path.join(target_dir, "snapshot.manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)

    def save_chain(self, *, force_full: bool = False):
        if CFG.CHAIN_FORCE_FULL_FLUSH:
            force_full = True
        if self.in_memory:
            return
        with self.lock:
            tip_height = len(self.chain) - 1
            full_flush = force_full or self._persisted_height < 0
            if force_full:
                self._chain_dirty_from = 0
                self._persisted_height = -1

            if tip_height < 0:
                if force_full:
                    if kv_enabled():
                        try:
                            clear_db('chain')
                        except Exception:
                            pass
                    else:
                        self._chain_store.save([])
                self._chain_dirty_from = None
                self._persisted_height = -1
                return

            start_height: Optional[int] = None
            if self._chain_dirty_from is not None:
                start_height = max(0, self._chain_dirty_from)
            elif tip_height > self._persisted_height:
                start_height = self._persisted_height + 1
            elif force_full or self._persisted_height < 0:
                start_height = 0
            if full_flush:
                start_height = 0

            flush_interval = max(1, int(CFG.CHAIN_FLUSH_INTERVAL))
            should_flush = (
                full_flush
                or tip_height < self._persisted_height
                or flush_interval <= 1
            )

            if not should_flush and start_height is not None:
                pending = tip_height - self._persisted_height if self._persisted_height >= 0 else tip_height + 1
                if pending < flush_interval:
                    if self._chain_dirty_from is None:
                        self._chain_dirty_from = start_height
                    else:
                        self._chain_dirty_from = min(self._chain_dirty_from, start_height)
                    return

            if kv_enabled():
                try:
                    if full_flush:
                        clear_db('chain')
                        self._persisted_height = -1
                    if tip_height < self._persisted_height:
                        self._prune_chain_store(tip_height + 1)
                        self._persisted_height = tip_height
                    if start_height is not None and start_height <= tip_height:
                        with batch('chain') as b:
                            for height in range(start_height, tip_height + 1):
                                key = f"h:{height:012d}".encode('utf-8')
                                payload = json.dumps(self.chain[height].to_dict(), separators=(",", ":")).encode('utf-8')
                                b.put(key, payload)
                        self._persisted_height = tip_height
                except Exception:
                    log.exception("[save_chain] LMDB save_chain failed")
            else:
                if full_flush or start_height is not None or tip_height != self._persisted_height:
                    self._chain_store.save([block.to_dict() for block in self.chain])
                    self._persisted_height = tip_height

            self._chain_dirty_from = None
            if tip_height >= 0:
                self._maybe_backup_snapshot(tip_height)

    def load_chain(self):
        if self.in_memory:
            return
        data_list = []
        if kv_enabled():
            try:
                # Collect and sort by height key
                items = list(iter_prefix('chain', b'h:'))
                items.sort(key=lambda kv: kv[0])
                data_list = [json.loads(v.decode('utf-8')) for _, v in items]
            except Exception:
                log.exception("[load_chain] LMDB load_chain failed")
                data_list = []
        if not data_list:
            data_list = self._chain_store.load(default=[])
        if not data_list:
            return
        chain = [Block.from_dict(d) for d in data_list]
        if not chain:
            return
        if chain[0].height != 0 or chain[0].prev_block_hash != CFG.ZERO_HASH:
            prev_hex = None
            try:
                prev_hex = chain[0].prev_block_hash.hex()  # type: ignore[attr-defined]
            except Exception:
                prev_hex = str(chain[0].prev_block_hash)
            log.error(
                "[load_chain] Invalid on-disk genesis header fields (height=%s prev=%s); resetting chain store",
                chain[0].height,
                prev_hex,
            )
            self._reset_chain_store()
            return
        if GENESIS_HASH is not None and chain[0].hash() != GENESIS_HASH:
            log.error(
                "[load_chain] Invalid genesis for this network. Expected %s, got %s; resetting chain store",
                GENESIS_HASH.hex(),
                chain[0].hash().hex(),
            )
            self._reset_chain_store()
            return

        self.chain = chain
        self.total_blocks = len(self.chain)
        self.total_supply = self.calculate_total_supply()
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0
        self._persisted_height = len(self.chain) - 1
        self._chain_dirty_from = None
        try:
            self._snapshot_last_backup_height = self._persisted_height
        except Exception:
            pass
        if not self.in_memory:
            self._ensure_utxodb()
            self._utxo_last_flush_height = self.height
            self._utxo_dirty = False
            try:
                tip_ts = None
                if self.chain:
                    tip_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)
            except Exception:
                tip_ts = None
            try:
                annotate_local_snapshot_meta(height=self.height, tip_timestamp=tip_ts)
            except Exception:
                log.debug("[load_chain] snapshot meta annotate failed", exc_info=True)

    def load_state(self):
        if self.in_memory:
            return
        data = {}
        if kv_enabled():
            try:
                # State stored as individual keys
                items = dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in iter_prefix('state', b'k:'))
                if items:
                    data["total_supply"] = int(items.get('k:total_supply', '0'))
                    data["total_blocks"] = int(items.get('k:total_blocks', '0'))
            except Exception:
                log.exception("[load_state] LMDB load_state failed")
        if not data:
            data = self._state_store.load(default={})
        self.total_supply = int(data.get("total_supply", 0) or 0)
        self.total_blocks = int(data.get("total_blocks", 0) or 0)
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0

    def save_state(self):
        if self.in_memory:
            return
        # Compute based on in-memory chain; avoid JSON IO when KV enabled
        blocks_count = len(self.chain)
        self.total_blocks = blocks_count
        self.total_supply = self.calculate_total_supply()
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0
        data = self._compute_state_snapshot()
        try:
            data["total_supply"] = int(self.total_supply)
            data["total_blocks"] = int(self.total_blocks)
        except Exception:
            pass
        # Save to LMDB
        if kv_enabled():
            try:
                with batch('state') as b:
                    b.put(b'k:total_supply', str(int(self.total_supply)).encode('utf-8'))
                    b.put(b'k:total_blocks', str(int(self.total_blocks)).encode('utf-8'))
            except Exception:
                log.exception("[save_state] LMDB save_state failed")
        else:
            self._state_store.save(data)

    def _compute_state_snapshot(self) -> dict:
        chain = [b.to_dict() for b in (self.chain or [])]

        total_blocks = len(chain)
        tip_height   = max(-1, total_blocks - 1)

        # ---- Detail tip/genesis ----
        tip = chain[-1] if total_blocks > 0 else None
        g   = chain[0]  if total_blocks > 0 else None

        tip_bits      = int(tip["bits"]) if tip else None
        tip_target    = None
        tip_difficulty = None
        try:
            if tip_bits is not None:
                tgt = bits_to_target(tip_bits)
                tip_target = int(tgt)
                tip_difficulty = int(target_to_difficulty(tgt))
        except Exception:
            pass

        AVG_WINDOW = 20
        avg_block_time_sec = None
        est_hashrate_hps   = None
        try:
            if total_blocks >= 2:
                ts = [b.get("timestamp", 0) for b in chain]
                w  = min(AVG_WINDOW, total_blocks - 1)
                intervals = [ts[i] - ts[i-1] for i in range(total_blocks - w, total_blocks)]
                intervals = [x for x in intervals if isinstance(x, (int, float)) and x > 0]
                if intervals:
                    avg_block_time_sec = sum(intervals) / len(intervals)
                    if tip_difficulty:
                        # work per block approximated as difficulty / avg_block_time -> hash rate
                        est_hashrate_hps = int(tip_difficulty / max(1, avg_block_time_sec))
        except Exception:
            pass

        # ---- Hitung transaksi ----
        total_txs              = sum(len(b.get("transactions", [])) for b in chain)
        total_non_coinbase_txs = sum(max(0, len(b.get("transactions", [])) - 1) for b in chain)

        # ---- Hitung fee kumulatif (fee = coinbase_amount - subsidy_teoritis) ----
        total_fees_paid = 0
        try:
            for b in chain:
                h  = int(b.get("height", 0))
                txs = b.get("transactions") or []
                if not txs:
                    continue
                cb = txs[0]  # coinbase
                cb_amt = int((cb.get("outputs") or [{}])[0].get("amount", 0))
                # subsidy teoritis:
                base = self._scheduled_reward(h)
                fee  = max(0, cb_amt - base)
                total_fees_paid += fee
        except Exception:
            pass

        # ---- Mempool ----
        mempool_count = 0
        mempool_vbytes_est = None
        try:
            pool = TxPoolDB(utxo_store=self._ensure_utxodb())
            mempool_count = len(pool.get_all_txs())
            mempool_vbytes_est = int(getattr(pool, "current_size", 0))
        except Exception:
            pass

        # ---- UTXO & sirkulasi (mature vs immature) ----
        utxo_set_size        = 0
        circulating_estimate = 0
        immature_coinbase    = 0
        errors               = 0
        try:
            utxo = self._ensure_utxodb() or UTXODB()
            try:
                data_map = utxo.to_dict()
            except Exception:
                data_map = utxo.load_json(utxo.filepath) or {}

            utxo_set_size = len(data_map)
            maturity = int(CFG.COINBASE_MATURITY)

            for _, entry in data_map.items():
                try:
                    tx_out = entry.get("tx_out", {}) or {}
                    amt    = int(tx_out.get("amount", 0) or 0)
                    if amt <= 0:
                        continue

                    is_cb  = bool(entry.get("is_coinbase", False))
                    born   = int(entry.get("block_height", entry.get("height", 0)) or 0)

                except Exception:
                    errors += 1
                    continue

                if is_cb:
                    conf = max(0, (tip_height - born) + 1)
                    if conf >= maturity:
                        circulating_estimate += amt
                    else:
                        immature_coinbase += amt
                else:
                    circulating_estimate += amt

            if errors:
                log.warning("[_compute_state_snapshot] %d UTXO entries failed to parse (suppressed)", errors)

        except Exception:
            log.exception("[_compute_state_snapshot] UTXODB load error")

        # ---- Supply emisi (subsidy) sampai tip ----
        try:
            emitted_subsidy = self.calculate_total_supply()
        except Exception:
            log.exception("[_compute_state_snapshot] calculate_total_supply failed")
            emitted_subsidy = self.total_supply or 0

        # ---- Identitas & file checksum ----
        chain_sha256 = None
        try:
            if hasattr(self._chain_store, "sha_path") and os.path.exists(self._chain_store.sha_path):
                with open(self._chain_store.sha_path, "r", encoding="utf-8") as fh:
                    chain_sha256 = fh.read().strip() or None
        except Exception:
            log.exception("[_compute_state_snapshot] cannot read chain SHA256")

        # Info halving/epoch
        cur_epoch = 0 if tip_height < 0 else int(tip_height // int(CFG.BLOCKS_PER_HALVING))
        next_halving_height = int((cur_epoch + 1) * int(CFG.BLOCKS_PER_HALVING))
        blocks_to_halving   = None if tip_height < 0 else max(0, next_halving_height - (tip_height + 1))
        current_block_subsidy = self._scheduled_reward(max(0, tip_height))

        # ---- Susun snapshot ----
        snapshot = {
            "schema_version": 1,
            "last_updated": dt.datetime.now().astimezone().isoformat(),
            "identity": {
                "network_id": CFG.DEFAULT_NET_ID,
                "address_prefix": CFG.ADDRESS_PREFIX,
                "network_magic_hex": CFG.NETWORK_MAGIC.hex(),
            },
            "chain": {
                "total_blocks": total_blocks,
                "tip_height": tip_height,
                "genesis_hash": (g or {}).get("hash"),
                "genesis_message": (((g or {}).get("transactions") or [{}])[0] or {}).get("block_id"),
                "tip_hash": (tip or {}).get("hash"),
                "tip_timestamp": (tip or {}).get("timestamp"),
                "tip_bits": tip_bits,
                "tip_target_hex": (None if tip_target is None else hex(tip_target)),
                "tip_difficulty": tip_difficulty,
                "avg_block_time_sec_window": None if avg_block_time_sec is None else round(float(avg_block_time_sec), 3),
                "est_network_hashrate_hps_window": est_hashrate_hps,
            },
            "supply": {
                "max_supply": int(CFG.MAX_SUPPLY),
                "emitted_subsidy": int(emitted_subsidy),
                "circulating_estimate": int(circulating_estimate),
                "immature_coinbase": int(immature_coinbase),
                "coinbase_maturity": int(CFG.COINBASE_MATURITY),
                "current_block_subsidy": int(current_block_subsidy),
                "current_epoch": int(cur_epoch),
                "next_halving_height": int(next_halving_height),
                "blocks_to_halving": None if blocks_to_halving is None else int(blocks_to_halving),
            },
            "transactions": {
                "total_txs": int(total_txs),
                "total_non_coinbase_txs": int(total_non_coinbase_txs),
                "total_fees_paid": int(total_fees_paid),
                "mempool_txs": int(mempool_count),
                "mempool_vbytes_estimate": mempool_vbytes_est,
            },
            "utxo": {
                "utxo_set_size": int(utxo_set_size),
            },
            "miners_snapshot": {
                "top_miners": [
                    (miner, count)
                    for miner, count in Counter(
                        (
                            ((b.get("transactions") or [{}])[0] or {}).get("to_address")
                            for b in chain
                            if (b.get("transactions") or [{}])[0]
                        )
                    ).most_common()
                    if miner
                ]
            },
            "files": {
                "blockchain_json_sha256": chain_sha256
            }
        }

        return snapshot
