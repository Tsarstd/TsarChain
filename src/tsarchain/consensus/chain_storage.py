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
import threading

from ..core.block import Block
from ..core.tx import Tx
from ..storage.utxo import UTXODB
from ..storage.kv import kv_enabled, batch, iter_prefix, clear_db, delete, _ensure_env
from ..utils import config as CFG
from ..utils.bootstrap import annotate_local_snapshot_meta
from ..utils.helpers import bits_to_target, target_to_difficulty
from ..contracts import graffiti as GRAFFITI
from ..contracts.graffiti_registry import GraffitiRegistry
from .genesis import GENESIS_HASH

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.chain_storage')

class StorageMixin:

# =============================================================================
# 1. HELPER
# =============================================================================
    def _estimate_tx_size_bytes(self, tx: Tx) -> int:
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
        try:
            size = max(size, len(tx.to_dict(include_txid=True)))
        except Exception:
            pass
        return int(size)

    def _estimate_block_size_bytes(self, block: Block) -> int:
        txs = getattr(block, "transactions", []) or []
        total = 80  # header bytes
        for tx in txs:
            if isinstance(tx, Tx):
                total += self._estimate_tx_size_bytes(tx)
            else:
                try:
                    total += len(json.dumps(tx))
                except Exception:
                    total += 0
        try:
            total = max(total, len(json.dumps(block.to_dict())))
        except Exception:
            pass
        return int(total)

    def _build_block_meta(self, block: Block, chainwork_so_far: int = 0) -> dict:
        txs = getattr(block, "transactions", []) or []
        tx_count = len(txs)
        size_b = self._estimate_block_size_bytes(block)
        cw = getattr(block, "chainwork", None)
        if cw is None:
            try:
                cw = int(chainwork_so_far) + int(self._work_from_bits(getattr(block, "bits", CFG.MAX_BITS)))
            except Exception:
                cw = None
        target_val = None
        difficulty_val = None
        try:
            tgt = bits_to_target(int(getattr(block, "bits", CFG.MAX_BITS)))
            target_val = int(tgt)
            difficulty_val = int(target_to_difficulty(tgt))
        except Exception:
            pass
        meta = {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "tx_count": tx_count,
            "size_bytes": int(size_b),
            "vbytes": int(size_b),
            "weight": int(size_b * 4),
            "chainwork": None if cw is None else int(cw),
            "target": target_val,
            "difficulty": difficulty_val,
        }
        try:
            meta["hash"] = block.hash().hex()
        except Exception:
            pass
        try:
            if isinstance(block.prev_block_hash, (bytes, bytearray)):
                meta["prev_block_hash"] = block.prev_block_hash.hex()
            else:
                meta["prev_block_hash"] = str(block.prev_block_hash)
        except Exception:
            pass
        try:
            meta["merkle_root"] = block.merkle_root.hex() if isinstance(block.merkle_root, (bytes, bytearray)) else str(block.merkle_root)
        except Exception:
            pass
        meta["height"] = int(getattr(block, "height", 0) or 0)
        meta["timestamp"] = int(getattr(block, "timestamp", 0) or 0)
        meta["bits"] = int(getattr(block, "bits", CFG.MAX_BITS))
        meta["nonce"] = int(getattr(block, "nonce", 0) or 0)
        meta["version"] = int(getattr(block, "version", 1) or 1)
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

        try:
            blk_hash = block.hash().hex()
        except Exception:
            blk_hash = None

        def _txid_hex(tx_obj):
            txid = getattr(tx_obj, "txid", None)
            if isinstance(txid, (bytes, bytearray)):
                return txid.hex()
            return str(txid) if txid is not None else None

        for tx in getattr(block, "transactions", []) or []:
            txid_hex = _txid_hex(tx)
            for tx_out in getattr(tx, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                try:
                    meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                except Exception:
                    meta = None
                if not meta:
                    continue
                event = str(meta.get("event", "")).upper()
                if event == "POST":
                    sha_hex = meta.get("sha256")
                    creator = meta.get("creator")
                    art_id = meta.get("art_id")
                    if not art_id and sha_hex and creator:
                        try:
                            art_id = GRAFFITI.compute_art_id(sha_hex, creator)
                        except Exception:
                            art_id = None
                    posts.append({
                        "txid": txid_hex,
                        "art_id": art_id,
                        "sha256": meta.get("sha256"),
                        "size": meta.get("size"),
                        "mime": meta.get("mime"),
                        "storer": meta.get("storer"),
                        "receipt": meta.get("receipt"),
                        "creator": creator,
                        "block_hash": blk_hash,
                    })
                elif event == "COMMENT":
                    comments.append({
                        "txid": txid_hex,
                        "art_id": meta.get("art_id"),
                        "comment_len": meta.get("comment_len"),
                        "amount": meta.get("amount"),
                        "tip": meta.get("tip"),
                        "creator": meta.get("creator"),
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
        meta["graffiti"] = graff_posts
        meta["comments"] = graff_comments
        meta["payouts"] = graff_payouts
        meta["graffiti_post_count"] = len(graff_posts)
        meta["comment_count"] = len(graff_comments)
        meta["payout_count"] = len(graff_payouts)
        blk_dict["_meta"] = meta
        cw = meta.get("chainwork", prev_chainwork)
        try:
            cw_int = int(cw) if cw is not None else int(prev_chainwork)
        except Exception:
            cw_int = int(prev_chainwork)
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
        journal_path = getattr(self, "_chain_journal_path", None)
        if journal_path and os.path.exists(journal_path):
            try:
                os.remove(journal_path)
            except Exception:
                log.warning("[_reset_chain_store] Failed removing chain journal at %s", journal_path)
        self._persisted_height = -1
        self._chain_dirty_from = None
        try:
            self._snapshot_last_backup_height = -1
        except Exception:
            pass


# =============================================================================
# 2. SNAPSHOTS BACKUP (FOR FAST SYNC)
# =============================================================================
    def _backup_snapshot_enabled(self) -> bool:
        if self.in_memory:
            return False
        return bool(CFG.BACKUP_SNAPSHOT)

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

        def _run_backup(height: int, ts_hint: int | None):
            try:
                self._copy_snapshot_env(target_dir)
                tip_ts = ts_hint
                if tip_ts is None:
                    try:
                        if self.chain:
                            tip_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)
                    except Exception:
                        tip_ts = None
                meta = None
                try:
                    meta = annotate_local_snapshot_meta(height=height, tip_timestamp=tip_ts)
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
                        self._write_snapshot_manifest(backup_dir, meta, height)
                    except Exception:
                        log.warning("[backup_snapshot] Failed to write snapshot manifest copy", exc_info=True)
                self._snapshot_last_backup_height = height
                log.info("[backup_snapshot] Snapshot updated at height %s to %s", height, target_dir)
            except Exception:
                log.exception("[backup_snapshot] Failed to update snapshot backup")
            finally:
                with self._snapshot_backup_lock:
                    self._snapshot_backup_active = False

        threading.Thread(
            target=_run_backup,
            args=(tip_height, tip_timestamp),
            name="tsarchain.snapshot_backup",
            daemon=True,
        ).start()

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


# =============================================================================
# 3. JOURNAL (.json)        NOTE: journal is Python-only fallback for non-LMDB mode; not performance-critical, no plan to port to Rust for now.
# =============================================================================
    def _chain_journal_enabled(self) -> bool:
        return (not self.in_memory) and (not kv_enabled()) and bool(getattr(self, "_chain_journal_path", None))

    def _chain_journal_size(self) -> int:
        path = getattr(self, "_chain_journal_path", None)
        if path and os.path.exists(path):
            try:
                return os.path.getsize(path)
            except Exception:
                return 0
        return 0

    def _clear_chain_journal(self) -> None:
        path = getattr(self, "_chain_journal_path", None)
        if not path or not os.path.exists(path):
            return
        try:
            os.remove(path)
        except Exception:
            log.warning("[_clear_chain_journal] Failed removing %s", path)

    def _append_chain_journal(self, start_height: int, blocks: list[Block]) -> None:
        if not self._chain_journal_enabled() or not blocks:
            return
        path = getattr(self, "_chain_journal_path", None)
        if not path:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, "a", encoding="utf-8") as fh:
                for offset, block in enumerate(blocks):
                    entry = {
                        "height": int(start_height + offset),
                        "block": block.to_dict(),
                    }
                    fh.write(json.dumps(entry, separators=CFG.CANONICAL_SEP) + "\n")
        except Exception:
            log.exception("[_append_chain_journal] Failed to write journal entries")

    def _apply_chain_journal(self, chain_data: list[dict]) -> list[dict]:
        path = getattr(self, "_chain_journal_path", None)
        if not path or not os.path.exists(path):
            return chain_data or []
        result = list(chain_data or [])
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    height = rec.get("height")
                    block_dict = rec.get("block")
                    if block_dict is None:
                        continue
                    try:
                        height = int(height)
                    except Exception:
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
        except Exception:
            log.exception("[_apply_chain_journal] Failed to replay journal")
            return chain_data or []
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
            tip_hash = None
            try:
                tip_hash = self.chain[-1].hash().hex() if tip_height >= 0 else None
            except Exception:
                tip_hash = None
            chain_meta = self._build_chain_meta(tip_height, tip_hash)
            full_flush = force_full or self._persisted_height < 0
            if force_full:
                self._chain_dirty_from = 0
                self._persisted_height = -1

            if tip_height < 0:
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
                    cw_prev = 0
                    if start_height and start_height > 0:
                        try:
                            prev_blk = self.chain[start_height - 1]
                            cw_prev = int(getattr(prev_blk, "chainwork", 0) or 0)
                            if cw_prev == 0:
                                cw_prev = int(self._compute_chainwork_for_chain(self.chain[:start_height]))
                        except Exception:
                            cw_prev = 0
                    if tip_height < self._persisted_height:
                        self._prune_chain_store(tip_height + 1)
                        self._persisted_height = tip_height
                    if start_height is not None and start_height <= tip_height:
                        with batch('chain') as b:
                            try:
                                b.put(b'__meta__', json.dumps(chain_meta, separators=CFG.CANONICAL_SEP).encode('utf-8'))
                            except Exception:
                                log.debug("[save_chain] failed writing chain meta")
                            for height in range(start_height, tip_height + 1):
                                key = f"h:{height:012d}".encode('utf-8')
                                blk_dict, cw_prev = self._serialize_block_for_store(self.chain[height], cw_prev)
                                payload = json.dumps(blk_dict, separators=CFG.CANONICAL_SEP).encode('utf-8')
                                b.put(key, payload)
                        self._persisted_height = tip_height
                except Exception:
                    log.exception("[save_chain] LMDB save_chain failed")
            else:
                if not self._chain_journal_enabled() or full_flush or start_height in (None, 0):
                    if full_flush or start_height is not None or tip_height != self._persisted_height:
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
                        self._chain_store.save(payload)
                        self._persisted_height = tip_height
                        self._clear_chain_journal()
                else:
                    if start_height is not None and start_height <= tip_height:
                        new_blocks = [self.chain[h] for h in range(start_height, tip_height + 1)]
                        self._append_chain_journal(start_height, new_blocks)
                        self._persisted_height = tip_height
                        if self._chain_journal_size() > int(CFG.CHAIN_JOURNAL_MAX_BYTES):
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
                            self._chain_store.save(payload)
                            self._persisted_height = tip_height
                            self._clear_chain_journal()

            self._chain_dirty_from = None
            if tip_height >= 0:
                backup_tip = tip_height
                try:
                    backup_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)
                except Exception:
                    backup_ts = None

        if backup_tip is not None:
            self._maybe_backup_snapshot(backup_tip, tip_timestamp=backup_ts)

    def load_chain(self):
        if self.in_memory:
            return
        meta = {}
        data_list = []
        if kv_enabled():
            try:
                # Collect and sort by height key, plus optional meta
                items = list(iter_prefix('chain', b''))
                blocks: list[tuple[bytes, bytes]] = []
                for k, v in items:
                    if k == b'__meta__':
                        try:
                            meta = json.loads(v.decode('utf-8')) or {}
                        except Exception:
                            log.debug("[load_chain] failed to parse chain meta from LMDB")
                        continue
                    if k.startswith(b'h:'):
                        blocks.append((k, v))
                blocks.sort(key=lambda kv: kv[0])
                data_list = [json.loads(v.decode('utf-8')) for _, v in blocks]
            except Exception:
                log.exception("[load_chain] LMDB load_chain failed")
                data_list = []
        if not data_list:
            raw = self._chain_store.load(default=[])
            if isinstance(raw, dict):
                meta = raw.get("meta") or {}
                blk_list = raw.get("blocks")
                if isinstance(blk_list, list):
                    data_list = blk_list
                elif isinstance(raw.get("chain"), list):
                    data_list = raw.get("chain")  # legacy name safeguard
            else:
                data_list = raw
        if not isinstance(data_list, list):
            data_list = []
        data_list = self._apply_chain_journal(data_list)
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
        try:
            self._chain_meta = meta or {}
        except Exception:
            self._chain_meta = {}
        self.total_blocks = len(self.chain)
        self.total_supply = self.calculate_total_supply()
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0
        self._persisted_height = len(self.chain) - 1
        self._chain_dirty_from = None
        try:
            # Align last backup marker to nearest interval to avoid drift across restarts
            interval = int(CFG.BLOCK_BACKUP_SNAPSHOT)
            if interval > 0 and self._persisted_height >= 0:
                self._snapshot_last_backup_height = (self._persisted_height // interval) * interval
            else:
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


# =============================================================================
# 5. STATE I/O & COMPUTE
# =============================================================================
    def load_state(self):
        if self.in_memory:
            return
        data = {}
        if kv_enabled():
            try:
                # State stored as individual keys
                items = dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in iter_prefix('state', b'k:'))
                snap_raw = items.get('k:snapshot')
                if snap_raw:
                    try:
                        data = json.loads(snap_raw)
                    except Exception:
                        log.exception("[load_state] Failed to parse snapshot JSON from LMDB")
                if not data and items:
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

        # Normalize schema version from config
        try:
            data["schema_version"] = int(CFG.DATA_SCHEMA_VERSION)
        except Exception:
            data["schema_version"] = data.get("schema_version", 1)

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
            "files": data.get("files", {}),
            "graffiti": data.get("graffiti", {}),
            "miners_snapshot": data.get("miners_snapshot", {}),
        }

        # Save to LMDB
        if kv_enabled():
            try:
                with batch('state') as b:
                    b.put(b'k:total_supply', str(int(self.total_supply)).encode('utf-8'))
                    b.put(b'k:total_blocks', str(int(self.total_blocks)).encode('utf-8'))
                    b.put(b'k:snapshot', json.dumps(ordered, separators=CFG.CANONICAL_SEP).encode('utf-8'))
            except Exception:
                log.exception("[save_state] LMDB save_state failed")
        else:
            self._state_store.save(ordered)

    def _compute_state_snapshot(self) -> dict:
        tip_height = self.height
        utxo = self._ensure_utxodb() or UTXODB()
        utxo_version = getattr(utxo, "version", 0)
        cache = getattr(self, "_state_snapshot_cache", None)
        token = (tip_height, utxo_version)
        if cache and cache.get("token") == token and cache.get("data"):
            return dict(cache["data"])

        chain = self.chain or []
        total_blocks = len(chain)
        tip_block = chain[-1] if chain else None
        genesis_block = chain[0] if chain else None

        total_block_size_bytes = 0
        try:
            total_block_size_bytes = sum(self._estimate_block_size_bytes(b) for b in chain)
        except Exception:
            total_block_size_bytes = 0

        tip_chainwork = None
        try:
            cw = getattr(tip_block, "chainwork", None)
            if cw is None:
                cw = self._compute_chainwork_for_chain(chain)
            tip_chainwork = int(cw)
        except Exception:
            pass

        median_time_past_val = None
        try:
            median_time_past_val = int(self.median_time_past())
        except Exception:
            pass

        tip_bits = int(getattr(tip_block, "bits", 0)) if tip_block else None
        tip_target = None
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
        est_hashrate_hps = None
        try:
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
        except Exception:
            pass

        total_txs = 0
        total_non_coinbase_txs = 0
        total_fees_paid = 0
        miner_counter: Counter[str] = Counter()
        try:
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
                    try:
                        cb_amt = int(getattr(outputs[0], "amount", 0) or 0)
                    except Exception:
                        cb_amt = 0
                base = self._scheduled_reward(int(getattr(blk, "height", 0) or 0))
                fee = max(0, cb_amt - base)
                total_fees_paid += fee
                miner_addr = getattr(coinbase, "to_address", None)
                if not miner_addr and outputs:
                    miner_addr = getattr(outputs[0], "address", None)
                if miner_addr:
                    miner_counter[str(miner_addr)] += 1
        except Exception:
            pass

        mempool_count = 0
        mempool_vbytes_est = None
        mempool_bytes_est = None
        pool = getattr(self, "get_mempool", lambda: None)()
        if pool:
            try:
                stats = pool.stats()
                mempool_count = int(stats.get("count", 0))
                mempool_vbytes_est = int(stats.get("virtual_size", 0))
                mempool_bytes_est = int(stats.get("virtual_size", 0))
            except Exception:
                pass

        utxo_set_size = 0
        circulating_estimate = 0
        immature_coinbase = 0
        utxo_total_value = 0
        maturity = int(CFG.COINBASE_MATURITY)
        try:
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
                try:
                    amount = int(amount_val if amount_val is not None else 0)
                except Exception:
                    continue
                if amount <= 0:
                    continue
                utxo_total_value += amount
                is_cb = bool(entry.get("is_coinbase", False)) if isinstance(entry, dict) else bool(getattr(entry, "is_coinbase", False))
                born = int(entry.get("block_height", entry.get("height", 0)) if isinstance(entry, dict) else getattr(entry, "block_height", getattr(entry, "height", 0)) or 0)
                if is_cb:
                    conf = max(0, (tip_height - born) + 1)
                    # Coinbase boleh dianggap beredar hanya setelah melewati jumlah blok maturity penuh
                    if conf > maturity:
                        circulating_estimate += amount
                    else:
                        immature_coinbase += amount
                else:
                    circulating_estimate += amount
        except Exception:
            log.exception("[_compute_state_snapshot] UTXO stats failed")

        graffiti_posts = 0
        total_comments = 0
        graffiti_on_mempool = 0
        try:
            reg = getattr(utxo, "_graffiti_registry", None)
            if reg is None:
                reg = GraffitiRegistry()
            data_g = getattr(reg, "data", {}) or {}
            graffiti_posts = len(data_g.get("posts") or {})
            total_comments = sum(len(v or []) for v in (data_g.get("comments") or {}).values())
        except Exception:
            log.exception("[_compute_state_snapshot] graffiti aggregation failed")
        try:
            mem = getattr(self, "mempool", None)
            if mem:
                for tx in mem.get_all_txs():
                    for tx_out in getattr(tx, "outputs", []) or []:
                        spk = getattr(tx_out, "script_pubkey", None)
                        meta = None
                        try:
                            meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                        except Exception:
                            meta = None
                        if meta and str(meta.get("event", "")).upper() == "POST":
                            graffiti_on_mempool += 1
        except Exception:
            log.exception("[_compute_state_snapshot] graffiti mempool count failed")

        try:
            emitted_subsidy = self.calculate_total_supply()
        except Exception:
            log.exception("[_compute_state_snapshot] calculate_total_supply failed")
            emitted_subsidy = self.total_supply or 0

        chain_sha256 = None
        try:
            if hasattr(self._chain_store, "sha_path") and os.path.exists(self._chain_store.sha_path):
                with open(self._chain_store.sha_path, "r", encoding="utf-8") as fh:
                    chain_sha256 = fh.read().strip() or None
        except Exception:
            log.exception("[_compute_state_snapshot] cannot read chain SHA256")

        cur_epoch = 0 if tip_height < 0 else int(tip_height // int(CFG.BLOCKS_PER_HALVING))
        next_halving_height = int((cur_epoch + 1) * int(CFG.BLOCKS_PER_HALVING))
        blocks_to_halving = None if tip_height < 0 else max(0, next_halving_height - (tip_height + 1))
        current_block_subsidy = self._scheduled_reward(max(0, tip_height))

        tip_hash = tip_block.hash().hex() if tip_block else None
        tip_timestamp = int(getattr(tip_block, "timestamp", 0) or 0) if tip_block else None
        genesis_dict = genesis_block.to_dict() if genesis_block else {}
        tip_dict = tip_block.to_dict() if tip_block else {}

        total_payouts = 0
        try:
            total_payouts = sum(len(v or []) for v in (data_g.get("payouts") or {}).values())
        except Exception:
            total_payouts = 0
        total_pool_balances = 0
        try:
            for post in (data_g.get("posts") or {}).values():
                if not isinstance(post, dict):
                    continue
                stats = post.get("stats") or {}
                total_pool_balances += int(stats.get("pool_balance", 0) or 0)
        except Exception:
            total_pool_balances = 0

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
                "total_blocks": total_blocks,
                "tip_height": tip_height,
                "genesis_hash": genesis_dict.get("hash"),
                "genesis_message": (((genesis_dict.get("transactions") or [{}])[0]) or {}).get("block_id"),
                "tip_hash": tip_hash or tip_dict.get("hash"),
                "tip_timestamp": tip_timestamp or tip_dict.get("timestamp"),
                "tip_bits": tip_bits,
                "tip_target_hex": (None if tip_target is None else hex(tip_target)),
                "tip_difficulty": tip_difficulty,
                "tip_chainwork": tip_chainwork,
                "median_time_past": median_time_past_val,
                "max_bits": int(CFG.MAX_BITS),
                "target_block_time_sec": int(CFG.TARGET_BLOCK_TIME),
                "total_block_size_bytes": int(total_block_size_bytes),
                "avg_block_time_sec_window": None if avg_block_time_sec is None else round(float(avg_block_time_sec), 3),
                "est_network_hashrate_hps_window": est_hashrate_hps,
            },
            "supply": {
                "max_supply": int(CFG.MAX_SUPPLY),
                "emitted_subsidy": int(emitted_subsidy),
                "circulating_estimate": int(circulating_estimate),
                "immature_coinbase": int(immature_coinbase),
                "utxo_total_value": int(utxo_total_value),
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
                "mempool_bytes_estimate": mempool_bytes_est,
                "mempool_max_bytes": int(CFG.MEMPOOL_MAX_SIZE),
            },
            "utxo": {
                "utxo_set_size": int(utxo_set_size),
            },
            "graffiti": {
                "posts": int(graffiti_posts),
                "comments": int(total_comments),
                "graffiti_on_mempool": int(graffiti_on_mempool),
                "payouts": int(total_payouts),
                "pool_balances": int(total_pool_balances),
            },
            "miners_snapshot": {
                "top_miners": [(miner, count) for miner, count in miner_counter.most_common() if miner]
            },
            "files": {
                "blockchain_json_sha256": chain_sha256
            }
        }

        self._state_snapshot_cache = {"token": token, "data": dict(snapshot)}
        return snapshot
