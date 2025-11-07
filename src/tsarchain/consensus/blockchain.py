# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import threading
import queue
from typing import List, Optional

# ---------------- Local Project ----------------
from ..core.block import Block
from ..storage.db import AtomicJSONFile
from ..storage.utxo import UTXODB
from ..mempool.pool import TxPoolDB
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
    
    def __init__(self, db_path: str = CFG.BLOCK_FILE, miner_address: str | None = None, in_memory: bool = False, use_cores: int | None = None,):
        self.in_memory = in_memory
        self.db_path = db_path
        self.chain: List[Block] = []
        self.total_supply = 0
        self.total_blocks = 0
        self.use_cores = use_cores
        self.supply_in_tsar = 0
        self.miner_address = miner_address
        self.lock = threading.RLock()
        self.pending_blocks: List[Block] = []
        self._chain_store = AtomicJSONFile(CFG.BLOCK_FILE, keep_backups=3)
        self._state_store = AtomicJSONFile(CFG.STATE_FILE, keep_backups=3)
        self._persisted_height: int = -1
        self._chain_dirty_from: Optional[int] = None
        self._utxodb: Optional[UTXODB] = None
        self._utxo_dirty: bool = False
        self._utxo_last_flush_height: int = -1
        self._utxo_flush_interval: int = max(1, int(CFG.UTXO_FLUSH_INTERVAL))
        self._utxo_synced: bool = False
        self._last_block_validation_error: str | None = None
        self._mempool: TxPoolDB | None = None
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

        if not self.in_memory:
            if self.db_path:
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            os.makedirs(os.path.dirname(CFG.STATE_FILE), exist_ok=True)
            self._start_persist_worker()
            self.load_chain()
            self.load_state()
            if self.chain:
                self._enforce_genesis_lock()
                return
            if GENESIS_HASH is not None and not CFG.ALLOW_AUTO_GENESIS:
                log.info("[__init__] Genesis lock set; auto-genesis disabled. Waiting for peer sync.")
                self.chain = []
                self.total_blocks = 0
                self.total_supply = 0
                self._persist_empty_state_if_needed()
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
            try:
                self.save_chain(force_full=force_full)
                self._maybe_flush_utxo(force=flush_force)
                if save_state:
                    self.save_state()
            except Exception:
                log.exception("[_schedule_persist] synchronous persistence failed")
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
        # Final synchronous persistence to ensure no data loss
        try:
            self.save_chain(force_full=True)
            self._maybe_flush_utxo(force=True)
            self.save_state()
        except Exception:
            log.exception("[_stop_persist_worker] final persistence failed")

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
