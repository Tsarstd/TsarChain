# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import time
import json
import shutil
import hashlib
import threading
import datetime as dt

from typing import Optional
from collections import Counter

from ..core.block import Block
from ..core.tx import Tx
from ..storage.utxo import UTXODB
from ..storage.kv import kv_enabled, batch, iter_prefix, clear_db, delete, _ensure_env
from ..storage.db import AtomicJSONFile
from ..utils import config as CFG
from ..utils.bootstrap import annotate_local_snapshot_meta
from ..utils.helpers import bits_to_target, target_to_difficulty, estimate_block_size_bytes
from ..contracts import graffiti as GRAFFITI
from ..contracts.graffiti_registry import GraffitiRegistry
from .genesis import GENESIS_HASH

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.chain_storage')

class StorageMixin:
# =============================================================================
# 1. HELPER
# =============================================================================
    def _build_block_meta(self, block: Block, chainwork_so_far: int = 0) -> dict:
        txs = getattr(block, "transactions", []) or []
        tx_count = len(txs)
        size_b = estimate_block_size_bytes(block)
        cw = int(chainwork_so_far) + int(self._work_from_bits(getattr(block, "bits", CFG.MAX_BITS)))
        target_val = None
        difficulty_val = None
        tgt = bits_to_target(int(getattr(block, "bits", CFG.MAX_BITS)))
        target_val = int(tgt)
        difficulty_val = int(target_to_difficulty(tgt))
        meta = {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "tx_count": tx_count,
            "size_bytes": int(size_b),
            "chainwork": int(cw),
            "target": target_val,
            "difficulty": difficulty_val,
        }
        return meta

    def _build_chain_meta(self, tip_height: int, tip_hash: str | None = None) -> dict:
        return {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "generated_at": int(time.time()),
            "tip_height": int(tip_height),
            "tip_hash": tip_hash,
            "network_id": CFG.DEFAULT_NET_ID,
            "pow_algo": CFG.POW_ALGO,
            "max_bits": int(CFG.MAX_BITS),
            "target_block_time_sec": int(CFG.TARGET_BLOCK_TIME),
            "blocks": int(tip_height + 1 if tip_height >= 0 else 0),
        }

    def _extract_graffiti_events(self, block: Block) -> tuple[list[dict], list[dict], list[dict]]:
        posts: list[dict] = []
        comments: list[dict] = []
        payouts: list[dict] = []

        def _txid_hex(tx_obj):
            txid = getattr(tx_obj, "txid", None)
            if isinstance(txid, (bytes, bytearray)):
                return txid.hex()
            return str(txid) if txid is not None else None

        for tx in getattr(block, "transactions", []) or []:
            txid_hex = _txid_hex(tx)
            for tx_out in getattr(tx, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if not meta:
                    continue
                event = str(meta.get("event", "")).upper()
                if event == "POST":
                    posts.append({
                        "txid": txid_hex,
                        "sha256": meta.get("sha256"),
                        "size": meta.get("size"),
                        "mime": meta.get("mime"),
                        "creator": meta.get("creator"),
                    })
                elif event == "COMMENT":
                    comments.append({
                        "txid": txid_hex,
                        "art_id": meta.get("art_id"),
                        "comment_len": meta.get("comment_len"),
                        "commenter": meta.get("commenter"),
                    })
                elif event == "PAYOUT":
                    payouts.append({
                        "txid": txid_hex,
                        "art_id": meta.get("art_id"),
                        "epoch": meta.get("epoch"),
                        "recipients": meta.get("recipients"),
                    })
        return posts, comments, payouts

    def _serialize_block_for_store(self, block: Block, prev_chainwork: int = 0) -> tuple[dict, int]:
        blk_dict = block.to_dict()
        meta = self._build_block_meta(block, chainwork_so_far=prev_chainwork)
        graff_posts, graff_comments, graff_payouts = self._extract_graffiti_events(block)
        meta["graffiti_post_count"] = len(graff_posts)
        meta["comment_count"] = len(graff_comments)
        meta["payout_count"] = len(graff_payouts)
        blk_dict["_meta"] = meta
        cw = meta.get("chainwork", prev_chainwork)
        cw_int = int(cw) if cw is not None else int(prev_chainwork)
        return blk_dict, cw_int

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
            
        keys_to_remove: list[bytes] = []
        for key, _ in iter_prefix('chain', b'h:'):
            h = int(key[2:].decode('utf-8'))
            if h >= start_height:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            delete('chain', key)

    def _reset_chain_store(self) -> None:
        if self.in_memory:
            return
        if kv_enabled():
            clear_db('chain')
        else:
            AtomicJSONFile(CFG.BLOCK_FILE).save({})
        meta_path = CFG.SNAPSHOT_META_PATH
        if meta_path and os.path.exists(meta_path):
            os.remove(meta_path)
        journal_path = CFG.CHAIN_JOURNAL_FILE
        if journal_path and os.path.exists(journal_path):
            os.remove(journal_path)
        self._persisted_height = -1
        self._chain_dirty_from = None
        self._snapshot_last_backup_height = -1


# =============================================================================
# 2. SNAPSHOTS BACKUP (FOR FAST SYNC)
# =============================================================================
    def _backup_snapshot_enabled(self) -> bool:
        if self.in_memory:
            return False
        return bool(CFG.BACKUP_SNAPSHOT)

    def _write_snapshot_manifest(self, target_dir: str, meta: dict, height: int) -> None:
        data_path = os.path.join(target_dir)
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


    def _maybe_backup_snapshot(self, tip_height: int, *, tip_timestamp: int | None = None) -> None:
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

        lock = getattr(self, "_snapshot_backup_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._snapshot_backup_lock = lock

        with lock:
            if getattr(self, "_snapshot_backup_active", False):
                return
            self._snapshot_backup_active = True

        threading.Thread(
            target=self._run_backup,
            args=(target_dir, tip_height, tip_timestamp),
            name="tsarchain.snapshot_backup",
            daemon=True,
        ).start()
        
    def _run_backup(self, target_dir: str, height: int, ts_hint: int | None):
        try:
            # 1) copy LMDB env -> data/snapshot/
            self._copy_snapshot_env(target_dir)

            backup_dir = os.path.abspath(target_dir)
            snapshot_data_path = os.path.join(backup_dir, "data.mdb")

            # 2) tip timestamp
            tip_ts = ts_hint
            if tip_ts is None and self.chain:
                tip_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)

            # 3) meta baseline from DB live
            meta = annotate_local_snapshot_meta(height=height, tip_timestamp=tip_ts)

            # 3b) override size & sha256 with snapshot file
            if meta and os.path.exists(snapshot_data_path):
                try:
                    stat = os.stat(snapshot_data_path)
                    meta["size"] = int(stat.st_size)
                    snap_sha = self._hash_file(snapshot_data_path)
                    if snap_sha:
                        meta["sha256"] = snap_sha
                except Exception:
                    log.exception("[backup_snapshot] Failed to recompute hash/size for snapshot env")

            if meta:
                # 4) write snapshot.meta.json to snapshot folder
                meta_name = os.path.basename(CFG.SNAPSHOT_META_PATH or "snapshot.meta.json")
                backup_meta_path = os.path.join(backup_dir, meta_name)
                with open(backup_meta_path, "w", encoding="utf-8") as fh:
                    json.dump(meta, fh, indent=2, sort_keys=True)

                # 5) generate snapshot.manifest.json from overridden meta
                self._write_snapshot_manifest(backup_dir, meta, height)

            self._snapshot_last_backup_height = height
            log.info("[backup_snapshot] Snapshot updated at height %s to %s", height, target_dir)
        except Exception:
            log.exception("[backup_snapshot] Unexpected error during snapshot backup:")
        finally:
            with self._snapshot_backup_lock:
                self._snapshot_backup_active = False


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
                shutil.copy2(
                    data_file,
                    os.path.join(tmp_dir, os.path.basename(data_file)),
                )

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
            log.exception("err_hash_file")
            return None


# =============================================================================
# 3. JOURNAL (.json)        NOTE: journal is Python-only fallback for non-LMDB mode; not performance-critical, no plan to port to Rust for now.
# =============================================================================
    def _chain_journal_enabled(self) -> bool:
        return (not self.in_memory) and (not kv_enabled())

    def _chain_journal_size(self) -> int:
        path = CFG.CHAIN_JOURNAL_FILE
        if path and os.path.exists(path):
            try:
                return os.path.getsize(path)
            except Exception:
                log.exception("[_chain_journal_size] Failed getting size for %s", path)
                return 0
        return 0

    def _clear_chain_journal(self) -> None:
        path = CFG.CHAIN_JOURNAL_FILE
        if not path or not os.path.exists(path):
            return
        os.remove(path)

    def _append_chain_journal(self, start_height: int, blocks: list[Block]) -> None:
        if not self._chain_journal_enabled() or not blocks:
            return
        path = CFG.CHAIN_JOURNAL_FILE
        if not path:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            for offset, block in enumerate(blocks):
                entry = {
                    "height": int(start_height + offset),
                    "block": block.to_dict(),
                }
                fh.write(json.dumps(entry, separators=CFG.CANONICAL_SEP) + "\n")

    def _apply_chain_journal(self, chain_data: list[dict]) -> list[dict]:
        path = CFG.CHAIN_JOURNAL_FILE
        if not path or not os.path.exists(path):
            return chain_data or []
        result = list(chain_data or [])
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    log.exception("[_apply_chain_journal] Failed parsing journal line")
                    continue
                height = rec.get("height")
                block_dict = rec.get("block")
                if block_dict is None:
                    continue
                try:
                    height = int(height)
                except Exception:
                    log.exception("[_apply_chain_journal] Failed parsing journal height")
                    continue
                if height < 0:
                    continue
                if height < len(result):
                    result[height] = block_dict
                elif height == len(result):
                    result.append(block_dict)
                else:
                    # journal gap; skip to avoid corrupting chain
                    continue
        return result


# =============================================================================
# 4. SAVE & LOAD CHAIN
# =============================================================================
    def save_chain(self, *, force_full: bool = False):
        if CFG.CHAIN_FORCE_FULL_FLUSH:
            force_full = True
        if self.in_memory:
            return
        backup_tip = None
        backup_ts = None
        with self.lock:
            tip_height = len(self.chain) - 1
            if tip_height < 0:
                self._chain_dirty_from = None
                self._persisted_height = -1
                return

            tip_hash = self.chain[-1].hash().hex()
            chain_meta = self._build_chain_meta(tip_height, tip_hash)
            full_flush = force_full or self._persisted_height < 0
            if force_full:
                self._chain_dirty_from = 0
                self._persisted_height = -1

            start_height = self._determine_save_start_height(tip_height, force_full, full_flush)
            if not self._should_flush_chain(tip_height, start_height, full_flush):
                return

            if kv_enabled():
                self._save_chain_kv(tip_height, start_height, full_flush, chain_meta)
            else:
                self._save_chain_json(tip_height, start_height, full_flush, chain_meta)

            self._chain_dirty_from = None
            backup_tip = tip_height
            backup_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)

        if backup_tip is not None:
            self._maybe_backup_snapshot(backup_tip, tip_timestamp=backup_ts)

    def _determine_save_start_height(self, tip_height: int, force_full: bool, full_flush: bool) -> Optional[int]:
        if full_flush:
            return 0
        if self._chain_dirty_from is not None:
            return max(0, self._chain_dirty_from)
        if tip_height > self._persisted_height:
            return self._persisted_height + 1
        if force_full or self._persisted_height < 0:
            return 0
        return None

    def _should_flush_chain(self, tip_height: int, start_height: Optional[int], full_flush: bool) -> bool:
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
                return False
        return True

    def _save_chain_kv(self, tip_height: int, start_height: Optional[int], full_flush: bool, chain_meta: dict):
        if full_flush:
            clear_db('chain')
            self._persisted_height = -1
            
        cw_prev = 0
        if start_height and start_height > 0:
            prev_blk = self.chain[start_height - 1]
            cw_prev = int(getattr(prev_blk, "chainwork", 0) or 0)
            if cw_prev == 0:
                cw_prev = int(self._compute_chainwork_for_chain(self.chain[:start_height]))
                
        if tip_height < self._persisted_height:
            self._prune_chain_store(tip_height + 1)
            self._persisted_height = tip_height
            
        if start_height is not None and start_height <= tip_height:
            with batch('chain') as b:
                b.put(b'__meta__', json.dumps(chain_meta, separators=CFG.CANONICAL_SEP).encode('utf-8'))
                for height in range(start_height, tip_height + 1):
                    key = f"h:{height:012d}".encode('utf-8')
                    blk_dict, cw_prev = self._serialize_block_for_store(self.chain[height], cw_prev)
                    payload = json.dumps(blk_dict, separators=CFG.CANONICAL_SEP).encode('utf-8')
                    b.put(key, payload)
            self._persisted_height = tip_height

    def _save_chain_json(self, tip_height: int, start_height: Optional[int], full_flush: bool, chain_meta: dict):
        if not self._chain_journal_enabled() or full_flush or start_height in (None, 0):
            if full_flush or start_height is not None or tip_height != self._persisted_height:
                self._save_chain_json_full(tip_height, chain_meta)
        else:
            if start_height is not None and start_height <= tip_height:
                new_blocks = [self.chain[h] for h in range(start_height, tip_height + 1)]
                self._append_chain_journal(start_height, new_blocks)
                self._persisted_height = tip_height
                if self._chain_journal_size() > int(CFG.CHAIN_JOURNAL_MAX_BYTES):
                    self._save_chain_json_full(tip_height, chain_meta)

    def _save_chain_json_full(self, tip_height: int, chain_meta: dict):
        ordered_blocks = []
        cw_prev = 0
        for blk in sorted(self.chain, key=lambda b: getattr(b, "height", 0)):
            blk_dict, cw_prev = self._serialize_block_for_store(blk, cw_prev)
            ordered_blocks.append(blk_dict)
        payload = {
            "schema_version": int(chain_meta.get("schema_version", 1)),
            "meta": chain_meta,
            "blocks": ordered_blocks,
        }
        AtomicJSONFile(CFG.BLOCK_FILE).save(payload)
        self._persisted_height = tip_height
        self._clear_chain_journal()

    def load_chain(self):
        if self.in_memory:
            return
        meta = {}
        data_list = []
        if kv_enabled():
            meta, data_list = self._fetch_kv_chain_data()
            
        if not isinstance(data_list, list):
            data_list = []
        data_list = self._apply_chain_journal(data_list)
        if not data_list:
            return
        chain = [Block.from_dict(d) for d in data_list]
        if not chain or not self._validate_loaded_chain(chain):
            return

        self.chain = chain
        self._chain_meta = meta or {}
        self.total_blocks = len(self.chain)
        self.total_supply = self.calculate_total_supply()
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0
        self._persisted_height = len(self.chain) - 1
        self._chain_dirty_from = None
        
        interval = int(CFG.BLOCK_BACKUP_SNAPSHOT)
        if interval > 0 and self._persisted_height >= 0:
            self._snapshot_last_backup_height = (self._persisted_height // interval) * interval
        else:
            self._snapshot_last_backup_height = self._persisted_height
            
        if not self.in_memory:
            self._ensure_utxodb()
            self._utxo_last_flush_height = getattr(self, "height", len(self.chain) - 1)
            self._utxo_dirty = False
            tip_ts = None
            if self.chain:
                tip_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)
            annotate_local_snapshot_meta(height=getattr(self, "height", len(self.chain) - 1), tip_timestamp=tip_ts)

    def _fetch_kv_chain_data(self) -> tuple[dict, list]:
        meta = {}
        items = list(iter_prefix('chain', b''))
        blocks: list[tuple[bytes, bytes]] = []
        for k, v in items:
            if k == b'__meta__':
                meta = json.loads(v.decode('utf-8')) or {}
            elif k.startswith(b'h:'):
                blocks.append((k, v))
        blocks.sort(key=lambda kv: kv[0])
        data_list = [json.loads(v.decode('utf-8')) for _, v in blocks]
        return meta, data_list

    def _validate_loaded_chain(self, chain: list) -> bool:
        if chain[0].height != 0 or chain[0].prev_block_hash != CFG.ZERO_HASH:
            prev_hex = chain[0].prev_block_hash.hex()
            log.error(
                "[load_chain] Invalid on-disk genesis header fields (height=%s prev=%s); resetting chain store",
                chain[0].height,
                prev_hex,
            )
            self._reset_chain_store()
            return False
            
        if GENESIS_HASH is not None and chain[0].hash() != GENESIS_HASH:
            log.error(
                "[load_chain] Invalid genesis for this network. Expected %s, got %s; resetting chain store",
                GENESIS_HASH.hex(),
                chain[0].hash().hex(),
            )
            self._reset_chain_store()
            return False
            
        return True


# =============================================================================
# 5. STATE I/O & COMPUTE
# =============================================================================
    def _read_snapshot_state(self) -> dict:
        if self.in_memory:
            return {}
        data: dict = {}
        if kv_enabled():
            items = {
                k.decode("utf-8"): v.decode("utf-8")
                for k, v in iter_prefix("state", b"k:")
            }

            snap_raw = items.get("k:snapshot")
            if snap_raw:
                data = json.loads(snap_raw)

            if (not data) and items:
                data["total_supply"] = int(items.get("k:total_supply", "0"))
                data["total_blocks"] = int(items.get("k:total_blocks", "0"))
        else:
            data = AtomicJSONFile(CFG.STATE_FILE, keep_backups=3).load()
            
        if not isinstance(data, dict):
            data = {}
        return data

    def load_state(self):
        if self.in_memory:
            return
        data = self._read_snapshot_state()
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
        data["total_supply"] = int(self.total_supply)
        data["total_blocks"] = int(self.total_blocks)

        # Normalize schema version from config
        data["schema_version"] = int(CFG.DATA_SCHEMA_VERSION)

        ordered = {
            "schema_version": data.get("schema_version"),
            "last_updated": data.get("last_updated"),
            "total_blocks": data.get("total_blocks", self.total_blocks),
            "total_supply": data.get("total_supply", self.total_supply),
            "identity": data.get("identity", {}),
            "chain": data.get("chain", {}),
            "supply": data.get("supply", {}),
            "transactions": data.get("transactions", {}),
            "utxo": data.get("utxo", {}),
            "graffiti": data.get("graffiti", {}),
            "miners_snapshot": data.get("miners_snapshot", {}),
        }

        # Save to LMDB
        if kv_enabled():
            with batch('state') as b:
                b.put(b'k:total_supply', str(int(self.total_supply)).encode('utf-8'))
                b.put(b'k:total_blocks', str(int(self.total_blocks)).encode('utf-8'))
                b.put(b'k:snapshot', json.dumps(ordered, separators=CFG.CANONICAL_SEP).encode('utf-8'))
        else:
            AtomicJSONFile(CFG.STATE_FILE, keep_backups=3).save(ordered)

    def _compute_state_snapshot(self) -> dict:
        tip_height = self.height
        utxo = self._ensure_utxodb() or UTXODB()
        utxo_version = getattr(utxo, "version", 0)
        cache = getattr(self, "_state_snapshot_cache", None)
        token = (tip_height, utxo_version)
        if cache and cache.get("token") == token and cache.get("data"):
            return dict(cache["data"])

        chain = self.chain or []
        chain_stats = self._compute_chain_stats(chain)
        tx_stats = self._compute_transaction_and_miner_stats(chain)
        mempool_stats = self._compute_mempool_stats()
        supply_stats = self._compute_utxo_supply_stats(utxo, tip_height)
        graffiti_stats = self._compute_graffiti_stats(utxo)

        emitted_subsidy = self.calculate_total_supply()
        cur_epoch = 0 if tip_height < 0 else int(tip_height // int(CFG.BLOCKS_PER_HALVING))
        next_halving_height = int((cur_epoch + 1) * int(CFG.BLOCKS_PER_HALVING))
        blocks_to_halving = None if tip_height < 0 else max(0, next_halving_height - (tip_height + 1))
        current_block_subsidy = self._scheduled_reward(max(0, tip_height))

        genesis_block = chain[0] if chain else None
        tip_block = chain[-1] if chain else None
        tip_hash = tip_block.hash().hex() if tip_block else None
        tip_timestamp = int(getattr(tip_block, "timestamp", 0) or 0) if tip_block else None
        genesis_dict = genesis_block.to_dict() if genesis_block else {}
        tip_dict = tip_block.to_dict() if tip_block else {}

        snapshot = {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "last_updated": dt.datetime.now().astimezone().isoformat(),
            "identity": {
                "network_id": CFG.DEFAULT_NET_ID,
                "address_prefix": CFG.ADDRESS_PREFIX,
                "network_magic_hex": CFG.NETWORK_MAGIC.hex(),
                "pow_algo": CFG.POW_ALGO,
            },
            "chain": {
                "total_blocks": chain_stats["total_blocks"],
                "tip_height": tip_height,
                "genesis_hash": genesis_dict.get("hash"),
                "genesis_message": (((genesis_dict.get("transactions") or [{}])[0]) or {}).get("block_id"),
                "tip_hash": tip_hash or tip_dict.get("hash"),
                "tip_timestamp": tip_timestamp or tip_dict.get("timestamp"),
                "tip_bits": chain_stats["tip_bits"],
                "tip_target_hex": (None if chain_stats["tip_target"] is None else hex(chain_stats["tip_target"])),
                "tip_difficulty": chain_stats["tip_difficulty"],
                "tip_chainwork": chain_stats["tip_chainwork"],
                "median_time_past": chain_stats["median_time_past_val"],
                "max_bits": int(CFG.MAX_BITS),
                "target_block_time_sec": int(CFG.TARGET_BLOCK_TIME),
                "total_block_size_bytes": int(chain_stats["total_block_size_bytes"]),
                "avg_block_time_sec_window": None if chain_stats["avg_block_time_sec"] is None else round(float(chain_stats["avg_block_time_sec"]), 3),
                "est_network_hashrate_hps_window": chain_stats["est_hashrate_hps"],
            },
            "supply": {
                "max_supply": int(CFG.MAX_SUPPLY),
                "emitted_subsidy": int(emitted_subsidy),
                "circulating_estimate": int(supply_stats["circulating_estimate"]),
                "immature_coinbase": int(supply_stats["immature_coinbase"]),
                "utxo_total_value": int(supply_stats["utxo_total_value"]),
                "coinbase_maturity": int(CFG.COINBASE_MATURITY),
                "current_block_subsidy": int(current_block_subsidy),
                "current_epoch": int(cur_epoch),
                "next_halving_height": int(next_halving_height),
                "blocks_to_halving": None if blocks_to_halving is None else int(blocks_to_halving),
            },
            "transactions": {
                "total_txs": int(tx_stats["total_txs"]),
                "total_non_coinbase_txs": int(tx_stats["total_non_coinbase_txs"]),
                "total_fees_paid": int(tx_stats["total_fees_paid"]),
                "mempool_txs": int(mempool_stats["mempool_count"]),
                "mempool_vbytes_estimate": mempool_stats["mempool_vbytes_est"],
                "mempool_bytes_estimate": mempool_stats["mempool_bytes_est"],
                "mempool_max_bytes": int(CFG.MEMPOOL_MAX_SIZE),
            },
            "utxo": {
                "utxo_set_size": int(supply_stats["utxo_set_size"]),
            },
            "graffiti": graffiti_stats,
            "miners_snapshot": {
                "top_miners": [(miner, count) for miner, count in tx_stats["miner_counter"].most_common() if miner]
            },
        }

        self._state_snapshot_cache = {"token": token, "data": dict(snapshot)}
        return snapshot

    def _compute_chain_stats(self, chain: list) -> dict:
        total_blocks = len(chain)
        tip_block = chain[-1] if chain else None
        total_block_size_bytes = sum(estimate_block_size_bytes(b) for b in chain)

        cw = getattr(tip_block, "chainwork", None)
        if cw is None:
            cw = self._compute_chainwork_for_chain(chain)
        tip_chainwork = int(cw)
        median_time_past_val = int(self.median_time_past())

        tip_bits = int(getattr(tip_block, "bits", 0)) if tip_block else None
        tip_target = None
        tip_difficulty = None
        if tip_bits is not None:
            tgt = bits_to_target(tip_bits)
            tip_target = int(tgt)
            tip_difficulty = int(target_to_difficulty(tgt))

        AVG_WINDOW = 20
        avg_block_time_sec = None
        est_hashrate_hps = None
        if total_blocks >= 2:
            window = min(AVG_WINDOW, total_blocks - 1)
            timestamps = [int(getattr(chain[i], "timestamp", 0) or 0) for i in range(total_blocks - window - 1, total_blocks)]
            intervals = []
            for i in range(1, len(timestamps)):
                delta = timestamps[i] - timestamps[i - 1]
                if isinstance(delta, (int, float)) and delta > 0:
                    intervals.append(delta)
            if intervals:
                avg_block_time_sec = sum(intervals) / len(intervals)
                if tip_difficulty:
                    est_hashrate_hps = int(tip_difficulty / max(1, avg_block_time_sec))

        return {
            "total_blocks": total_blocks,
            "total_block_size_bytes": total_block_size_bytes,
            "tip_chainwork": tip_chainwork,
            "median_time_past_val": median_time_past_val,
            "tip_bits": tip_bits,
            "tip_target": tip_target,
            "tip_difficulty": tip_difficulty,
            "avg_block_time_sec": avg_block_time_sec,
            "est_hashrate_hps": est_hashrate_hps,
        }

    def _compute_transaction_and_miner_stats(self, chain: list) -> dict:
        total_txs = 0
        total_non_coinbase_txs = 0
        total_fees_paid = 0
        miner_counter: Counter[str] = Counter()
        for blk in chain:
            txs = getattr(blk, "transactions", []) or []
            total_txs += len(txs)
            total_non_coinbase_txs += max(0, len(txs) - 1)
            if not txs:
                continue
            coinbase = txs[0]
            outputs = getattr(coinbase, "outputs", []) or []
            cb_amt = 0
            if outputs:
                cb_amt = int(getattr(outputs[0], "amount", 0) or 0)
            base = self._scheduled_reward(int(getattr(blk, "height", 0) or 0))
            fee = max(0, cb_amt - base)
            total_fees_paid += fee
            miner_addr = getattr(coinbase, "to_address", None)
            if not miner_addr and outputs:
                miner_addr = getattr(outputs[0], "address", None)
            if miner_addr:
                miner_counter[str(miner_addr)] += 1
        return {
            "total_txs": total_txs,
            "total_non_coinbase_txs": total_non_coinbase_txs,
            "total_fees_paid": total_fees_paid,
            "miner_counter": miner_counter,
        }

    def _compute_mempool_stats(self) -> dict:
        mempool_count = 0
        mempool_vbytes_est = None
        mempool_bytes_est = None
        pool = getattr(self, "get_mempool", lambda: None)()
        if pool:
            stats = pool.stats()
            mempool_count = int(stats.get("count", 0))
            mempool_vbytes_est = int(stats.get("virtual_size", 0))
            mempool_bytes_est = int(stats.get("virtual_size", 0))
        return {
            "mempool_count": mempool_count,
            "mempool_vbytes_est": mempool_vbytes_est,
            "mempool_bytes_est": mempool_bytes_est,
        }

    def _compute_utxo_supply_stats(self, utxo, tip_height: int) -> dict:
        utxo_set_size = 0
        circulating_estimate = 0
        immature_coinbase = 0
        utxo_total_value = 0
        maturity = int(CFG.COINBASE_MATURITY)
        
        with utxo._lock:  # type: ignore[attr-defined]
            utxo_items = list(utxo.utxos.values())
        utxo_set_size = len(utxo_items)
        for entry in utxo_items:
            tx_out = entry.get("tx_out") if isinstance(entry, dict) else getattr(entry, "tx_out", None)
            amount_val = None
            if isinstance(tx_out, dict):
                amount_val = tx_out.get("amount")
            elif hasattr(tx_out, "amount"):
                amount_val = getattr(tx_out, "amount", None)
            elif isinstance(entry, dict):
                amount_val = entry.get("amount")
            amount = int(amount_val if amount_val is not None else 0)
            if amount <= 0:
                continue
            utxo_total_value += amount
            is_cb = bool(entry.get("is_coinbase", False)) if isinstance(entry, dict) else bool(getattr(entry, "is_coinbase", False))
            born = int(entry.get("block_height", entry.get("height", 0)) if isinstance(entry, dict) else getattr(entry, "block_height", getattr(entry, "height", 0)) or 0)
            if is_cb:
                conf = max(0, (tip_height - born) + 1)
                if conf > maturity:
                    circulating_estimate += amount
                else:
                    immature_coinbase += amount
            else:
                circulating_estimate += amount
        return {
            "utxo_set_size": utxo_set_size,
            "circulating_estimate": circulating_estimate,
            "immature_coinbase": immature_coinbase,
            "utxo_total_value": utxo_total_value,
        }

    def _compute_graffiti_stats(self, utxo) -> dict:
        graffiti_posts = 0
        total_comments = 0
        total_graffiti_storage = 0
        graffiti_on_mempool = 0
        reg = getattr(utxo, "_graffiti_registry", None)
        if reg is None:
            reg = GraffitiRegistry()
        data_g = getattr(reg, "data", {}) or {}
        posts_data = data_g.get("posts") or {}
        graffiti_posts = len(posts_data)
        
        total_pool_balances = 0
        for post in posts_data.values():
            if not isinstance(post, dict):
                continue
            size_val = post.get("size")
            if size_val is None:
                stats = post.get("stats") or {}
                size_val = stats.get("size") or {}
            total_graffiti_storage += int(size_val or 0)
            stats = post.get("stats") or {}
            total_pool_balances += int(stats.get("pool_balance", 0) or 0)
            
        total_comments = sum(len(v or []) for v in (data_g.get("comments") or {}).values())
        
        mem = getattr(self, "mempool", None)
        if mem:
            for tx in mem.get_all_txs():
                for tx_out in getattr(tx, "outputs", []) or []:
                    spk = getattr(tx_out, "script_pubkey", None)
                    meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                    if meta and str(meta.get("event", "")).upper() == "POST":
                        graffiti_on_mempool += 1
                        
        total_payouts = sum(len(v or []) for v in (data_g.get("payouts") or {}).values())

        return {
            "posts": int(graffiti_posts),
            "comments": int(total_comments),
            "graffiti_on_mempool": int(graffiti_on_mempool),
            "payouts": int(total_payouts),
            "pool_balances": int(total_pool_balances),
            "total_graffiti_storage": int(total_graffiti_storage),
        }
