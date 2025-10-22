# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import threading
from typing import List, Optional

# ---------------- Local Project ----------------
from ..core.block import Block
from ..storage.db import AtomicJSONFile
from ..storage.utxo import UTXODB
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

        if not self.in_memory:
            if self.db_path:
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            os.makedirs(os.path.dirname(CFG.STATE_FILE), exist_ok=True)
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
