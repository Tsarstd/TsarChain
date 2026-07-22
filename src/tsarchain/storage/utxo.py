# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md

import threading

from .db import BaseDatabase
from ..utils import config as CFG
from ..contracts.graffiti_registry import GraffitiRegistry

from .utxo_logic.balances import UTXOBalanceMixin
from .utxo_logic.database import UTXODatabaseMixin
from .utxo_logic.graff_utxo import UTXOGraffitiMixin
from .utxo_logic.validate import UTXOValidationMixin


class UTXODB(
    UTXOGraffitiMixin,
    UTXOBalanceMixin,
    UTXOValidationMixin,
    UTXODatabaseMixin,
    BaseDatabase,
):
    def __init__(self):
        self.filepath = CFG.UTXOS_FILE
        self.utxos = {}
        self._lock = threading.RLock()
        self._dirty = False
        self._dirty_keys = set()
        self._removed_keys = set()
        self._rewrite_all = False
        self._version = 0
        self._meta: dict = {}
        self._address_index: dict[str, set[str]] | None = None
        self._key_to_spk: dict[str, str] = {}
        self._tip_cache = {"height": 0, "ts": 0.0}
        self._tip_cache_ttl = float(CFG.STATE_HEIGHT_CACHE_TTL)
        self._load()
        self._graffiti_registry = GraffitiRegistry()


__all__ = ["UTXODB"]
