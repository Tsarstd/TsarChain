# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import time
import threading
from collections import OrderedDict
from typing import Dict, Optional

from ..core.tx import Tx
from ..utils import config as CFG
from ..storage.utxo import UTXODB

from .types import PrevoutRef
from .orphan import OrphanPoolMixin
from .policy import MempoolPolicyMixin
from .storage import MempoolStorageMixin
from .validation import TxMempoolValidator

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.pool")


class TxPool(
    MempoolStorageMixin,
    MempoolPolicyMixin,
    TxMempoolValidator,
    OrphanPoolMixin,
):

    def __init__(
        self,
        filepath: Optional[str] = None,
        max_size_mb: int = CFG.MEMPOOL_MAX_SIZE,
        utxo_store: Optional[UTXODB] = None,
        inherit_state: bool = False,
    ):
        super().__init__()
        self.filepath = filepath or CFG.LMDB_MEMPOOL_DIR
        self.max_size_mb = max_size_mb
        self._lock = threading.RLock()
        self._pool: "OrderedDict[str, Tx]" = OrderedDict()
        self._size_map: Dict[str, int] = {}
        self._dirty = False
        self._change_seq = 0
        self._last_flush = time.time()
        self._fee_heap: list[tuple[float, str]] = []
        self._heap_entries: Dict[str, float] = {}
        self.current_size = 0

        self._prevout_index: dict[PrevoutRef, str] = {}
        self._last_prune_version: int | None = None
        self._last_prune_reload_ts = 0.0

        self._meta: dict = {}
        storage_items, storage_meta = self._load_storage_pool()
        self._meta = storage_meta or {}
        self._hydrate_pool(storage_items)
        self.current_size = sum(self._size_map.values())

        utxo_store = utxo_store or UTXODB()
        self.utxo = utxo_store
        if inherit_state:
            self.utxo._load()

        self.last_error_reason: str | None = None
        self._orphan_pool: Dict[str, dict] = {}
        self._orphan_missing: Dict[str, str] = {}

    def __del__(self):
        self.flush(force=False)