# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import json
import threading
import queue
from typing import List, Optional
from collections import OrderedDict

# ---------------- Local Project ----------------
from ..core.block import Block
from ..storage.utxo import UTXODB
from ..mempool.pool import TxPoolDB
from ..storage.kv import kv_enabled, iter_prefix
from ..utils import config as CFG
from .chain_ops import ChainOpsMixin
from .difficulty import DifficultyMixin
from .genesis import GENESIS_HASH, GenesisMixin
from .mining import MiningMixin
from .rewards import RewardMixin
from .chain_storage import StorageMixin
from .utxo_validate import UTXOMixin
from .validation import ValidationMixin

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.consensus.blockchain")

__all__ = ["Blockchain"]


class Blockchain(GenesisMixin, RewardMixin, DifficultyMixin, UTXOMixin, StorageMixin, ValidationMixin, ChainOpsMixin, MiningMixin,):
    
    def __init__(self, miner_address: str | None = None, in_memory: bool = False, use_cores: int | None = None,):
        self.in_memory = in_memory
        self.chain: List[Block] = []
        self.total_supply = 0
        self.total_blocks = 0
        self._hash_cache: OrderedDict[int, str] = OrderedDict()
        self.supply_in_tsar = 0
        self._chain_meta: dict | None = None
        
        self.miner_address = miner_address
        self.use_cores = use_cores
        self.lock = threading.RLock()
        
        self.pending_blocks: List[Block] = []
            
        self._persisted_height: int = -1
        self._chain_dirty_from: Optional[int] = None
        self._utxodb: Optional[UTXODB] = None
        self._utxo_dirty: bool = False
        self._utxo_last_flush_height: int = -1
        self._utxo_flush_interval: int = max(1, int(CFG.UTXO_FLUSH_INTERVAL))
        self._utxo_synced: bool = False
        
        self._snapshot_last_backup_height: int = -1
        self._state_snapshot_cache: dict | None = None
        self._last_block_validation_error: str | None = None
        self._mempool: TxPoolDB | None = None
        self._mining_cooloff_until: float = 0.0
        
        self._persist_queue: queue.Queue[bool | None] | None = None
        self._persist_thread: threading.Thread | None = None
        self._persist_stop = threading.Event()
        self._persist_opts_lock = threading.Lock()
        self._persist_opts = {
            "force_full": False,
            "flush_force": False,
            "save_state": True,
        }
        self._persist_pending = False
        self._cold_reload_attempted: bool = False
        

        if not self.in_memory:
            self._start_persist_worker()
            self.load_chain()
            self.load_state()
            if not self.chain:
                self._cold_reload_attempted = True
                self._reload_chain_from_kv()
            if self.chain:
                self._enforce_genesis_lock()
                self._rebuild_hash_cache()
                return
            if GENESIS_HASH is not None and not CFG.ALLOW_AUTO_GENESIS:
                log.info("[__init__] Genesis lock set; auto-genesis disabled. Waiting for peer sync.")
                return
            if CFG.ALLOW_AUTO_GENESIS:
                log.info("[__init__] Auto-genesis enabled (use_cores=%s)", self.use_cores)
                self._create_genesis_with_lock(self.miner_address or "", self.use_cores)
            else:
                log.info("[__init__] Auto-genesis disabled; node will wait for peers to sync")
                self.chain = []
                self.total_blocks = 0
                self.total_supply = 0
                self._persist_empty_state_if_needed()
        else:
            self.chain = []
            self.total_blocks = 0
            self.total_supply = 0
            self._rebuild_hash_cache()
            
        if kv_enabled:
            return
        else:
            os.makedirs(os.path.dirname(CFG.CHAIN_JOURNAL_FILE), exist_ok=True)
            

    def _rebuild_hash_cache(self):
        try:
            cache: OrderedDict[int, str] = OrderedDict()
            for b in self.chain:
                h = None
                try:
                    h = b.hash()
                except Exception:
                    h = getattr(b, "hash", None)
                    h = h() if callable(h) else h
                if isinstance(h, (bytes, bytearray)):
                    h = h.hex()
                elif not isinstance(h, str):
                    h = None
                if h:
                    cache[int(getattr(b, "height", 0) or 0)] = h
            # trim to config bound
            max_entries = max(1, int(CFG.HASH_CACHE_MAX))
            while len(cache) > max_entries:
                cache.popitem(last=False)
            self._hash_cache = cache
        except Exception:
            log.debug("[_rebuild_hash_cache] failed", exc_info=True)

    def get_block_hash(self, height: int):
        if height < 0:
            return None

        if height in self._hash_cache:
            h = self._hash_cache.pop(height)
            self._hash_cache[height] = h  # move to end (MRU)
            return h
        
        with self.lock:
            if height < 0 or height >= len(self.chain):
                return None
            
            h = self.chain[height].hash()
            h_hex = h.hex() if isinstance(h, (bytes, bytearray)) else str(h)
            max_entries = max(1, int(CFG.HASH_CACHE_MAX))
            try:
                # ensure LRU order and bound
                if height in self._hash_cache:
                    self._hash_cache.pop(height, None)
                self._hash_cache[height] = h_hex
                while len(self._hash_cache) > max_entries:
                    self._hash_cache.popitem(last=False)
            except Exception:
                log.exception("get_block_hash.self.lock")
                pass
            return h_hex

    def _start_persist_worker(self) -> None:
        if self.in_memory or self._persist_thread is not None:
            return
        self._persist_queue = queue.Queue()
        self._persist_stop.clear()
        with self._persist_opts_lock:
            self._persist_opts = {
                "force_full": False,
                "flush_force": False,
                "save_state": True,
            }
            self._persist_pending = False
        self._persist_thread = threading.Thread(
            target=self._persist_loop,
            name="tsarchain.persist",
            daemon=True,
        )
        self._persist_thread.start()

    def _reload_chain_from_kv(self) -> bool:
        if self.in_memory or not kv_enabled():
            return False
        try:
            items = list(iter_prefix('chain', b''))
            if not items:
                return False
            blocks = []
            meta = {}
            for k, v in items:
                if k == b'__meta__':
                    try:
                        meta = json.loads(v.decode('utf-8')) or {}
                    except Exception:
                        log.debug("[reload_chain] failed to parse chain meta", exc_info=True)
                    continue
                if k.startswith(b'h:'):
                    blocks.append((k, v))
            blocks.sort(key=lambda kv: kv[0])
            data_list = [json.loads(v.decode('utf-8')) for _, v in blocks]
            if not data_list:
                return False
            chain = [Block.from_dict(d) for d in data_list]
            if not chain:
                return False
            self.chain = chain
            try:
                self._chain_meta = meta
            except Exception:
                self._chain_meta = {}
            self.total_blocks = len(self.chain)
            try:
                self.total_supply = self.calculate_total_supply()
            except Exception:
                self.total_supply = 0
            self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0
            self._persisted_height = len(self.chain) - 1
            self._chain_dirty_from = None
            # UTXO akan disinkronkan ulang saat _ensure_utxodb dipanggil
            self._utxo_last_flush_height = self.height
            self._utxo_dirty = False
            self._utxo_synced = False
            log.info("[reload_chain] Loaded %s blocks from LMDB fallback", len(self.chain))
            return True
        except Exception:
            log.exception("[reload_chain] Failed to reload chain from LMDB")
            return False

    def _persist_loop(self) -> None:
        assert self._persist_queue is not None
        while not self._persist_stop.is_set():
            try:
                task = self._persist_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if task is None:
                self._persist_queue.task_done()
                break
            with self._persist_opts_lock:
                opts = self._persist_opts.copy()
                self._persist_opts = {
                    "force_full": False,
                    "flush_force": False,
                    "save_state": True,
                }
                self._persist_pending = False
            try:
                self.save_chain(force_full=opts["force_full"])
                self._maybe_flush_utxo(force=opts["flush_force"])
                if opts["save_state"]:
                    self.save_state()
            except Exception:
                log.exception("[persist_worker] Failed persisting chain/utxo snapshot")
            finally:
                self._persist_queue.task_done()
        log.info("[persist_worker] stopped")

    def _schedule_persist(self, *, force_full: bool = False, flush_force: bool = False, save_state: bool = True, wait: bool = False) -> None:
        if self.in_memory:
            return
        if wait or self._persist_queue is None:
            self.save_chain(force_full=force_full)
            self._maybe_flush_utxo(force=flush_force)
            if save_state:
                self.save_state()
            return
        with self._persist_opts_lock:
            self._persist_opts["force_full"] = self._persist_opts["force_full"] or force_full
            self._persist_opts["flush_force"] = self._persist_opts["flush_force"] or flush_force
            self._persist_opts["save_state"] = self._persist_opts["save_state"] or save_state
            if not self._persist_pending:
                self._persist_pending = True
                self._persist_queue.put(True)

    def _stop_persist_worker(self) -> None:
        if self.in_memory or self._persist_thread is None or self._persist_queue is None:
            return
        self._persist_stop.set()
        worker = self._persist_thread
        try:
            self._persist_queue.put(None, timeout=1.0)
        except Exception:
            pass
        if worker is not None:
            worker.join(timeout=5.0)
            still_alive = worker.is_alive()
        else:
            still_alive = False
        if still_alive:
            log.warning("[persist_worker] did not stop gracefully within timeout")
        self._persist_thread = None
        self._persist_queue = None
        if (not self.chain) and GENESIS_HASH is not None and not CFG.ALLOW_AUTO_GENESIS:
            log.debug("[_stop_persist_worker] Skip final persistence (genesis locked & chain empty)")
            return
        # Final synchronous persistence to ensure no data loss
        self.save_chain(force_full=True)
        self._maybe_flush_utxo(force=True)
        self.save_state()

    def attach_mempool(self, pool: TxPoolDB) -> None:
        self._mempool = pool

    def get_mempool(self) -> TxPoolDB | None:
        return self._mempool

    @property
    def height(self) -> int:
        return len(self.chain) - 1

    def get_last_block(self) -> Optional[Block]:
        return self.chain[-1] if self.chain else None

    def to_dict(self) -> List[dict]:
        return [block.to_dict() for block in self.chain]

    @classmethod
    def from_dict(cls, data_list: List[dict]):
        bc = cls(in_memory=True)
        bc.chain = [Block.from_dict(b) for b in data_list]
        bc.total_blocks = len(bc.chain)
        bc.total_supply = 0
        bc.supply_in_tsar = 0
        return bc

    def shutdown(self) -> None:
        self._stop_persist_worker()
