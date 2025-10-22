# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations
import re

# ---------------- Local Project ----------------
from ..core.block import Block
from ..core.coinbase import CoinbaseTx
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.genesis')

def _resolve_genesis_hash():
    cfg_hex = CFG.GENESIS_HASH_HEX
    if cfg_hex.startswith("0x"):
        cfg_hex = cfg_hex[2:]
    if cfg_hex:
        if not re.fullmatch(r"[0-9a-f]{64}", cfg_hex):
            raise ValueError("Invalid Genesis Hash!!")
        return bytes.fromhex(cfg_hex)

    return None

GENESIS_HASH = _resolve_genesis_hash()

class GenesisMixin:
    def has_genesis(self) -> bool:
        return bool(self.chain)

    def _persist_empty_state_if_needed(self):
        try:
            self.save_state()
        except Exception:
            log.exception("[_persist_empty_state_if_needed] failed to save empty state snapshot")

    def _enforce_genesis_lock(self):
        if GENESIS_HASH is None or not self.chain:
            return
        g = self.chain[0]
        if getattr(g, "height", None) != 0:
            raise ValueError("[Blockchain] Genesis must have height=0")
        if getattr(g, "prev_block_hash", None) != CFG.ZERO_HASH:
            raise ValueError("[Blockchain] Genesis prev_block_hash must be ZERO_HASH")
        try:
            g_hash = g.hash() if hasattr(g, "hash") else bytes.fromhex(g.get("hash"))
        except Exception as e:
            raise ValueError(f"[Blockchain] Cannot read genesis hash from chain: {e}")
        if g_hash != GENESIS_HASH:
            raise ValueError("[Blockchain] Genesis mismatch vs TSAR_GENESIS_HASH. "
                             "Wipe local data or unset the lock to continue.")

    def _create_genesis_with_lock(self, miner_address: str, use_cores: int | None):
        self.create_genesis_block(miner_address, use_cores=use_cores)
        if GENESIS_HASH is not None:
            g_hash = self.chain[0].hash()
            if g_hash != GENESIS_HASH:
                raise ValueError("[Blockchain] Created genesis does not match TSAR_GENESIS_HASH; aborting")
        if not self.in_memory:
            self.save_chain()
            self.save_state()

    def ensure_genesis(self, miner_address: str, use_cores: int | None = None) -> bool:
        if self.chain:
            return False
        if not CFG.ALLOW_AUTO_GENESIS:
            log.info("[ensure_genesis] Auto-genesis disabled; waiting for peer sync")
            return False
        self._create_genesis_with_lock(miner_address, use_cores)
        return True

    def create_genesis_block(self, miner_address, use_cores: int | None = None):
        height = 0
        reward = self.get_block_reward(height)
        block_id = CFG.GENESIS_BLOCK_ID_DEFAULT
        coinbase = CoinbaseTx(to_address=miner_address, reward=reward, block_id=block_id, height=height,)
        try:
            coinbase.compute_txid()
        except Exception:
            pass
        genesis = Block(height=0, prev_block_hash=CFG.ZERO_HASH, transactions=[coinbase])
        try:
            genesis.bits = CFG.INITIAL_BITS
        except Exception:
            pass
        genesis.mine(use_cores=use_cores)
        if not self.validate_block(genesis):
            raise ValueError("[Blockchain] Genesis block validation failed")

        self.chain.append(genesis)
        if GENESIS_HASH is not None and genesis.hash() != GENESIS_HASH:
            raise ValueError("[Genesis] Newly created genesis does not match TSAR_GENESIS_HASH")
        if not self.in_memory:
            self._mark_chain_dirty(genesis.height)
            self.save_chain(force_full=True)
            store = self._ensure_utxodb()
            if store is not None:
                store.update(genesis.transactions, block_height=0, autosave=False)
                self._mark_utxo_dirty()
                self._maybe_flush_utxo(force=True)
            self.save_state()

        else:
            try:
                self.total_supply = self.calculate_total_supply()
            except Exception:
                pass
        return genesis
