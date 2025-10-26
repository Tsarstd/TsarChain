# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: LWMA-Zawy

from __future__ import annotations

import multiprocessing as mp
from multiprocessing.synchronize import Event as MpEvent

# ---------------- Local Project ----------------
from ..core.block import Block
from ..core.coinbase import CoinbaseTx
from ..mempool.pool import TxPoolDB
from ..storage.utxo import UTXODB
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.mining')

class MiningMixin:
    def mine_block(self, miner_address, use_cores: int | None = None, cancel_event: MpEvent | None = None, pow_backend: str = "auto", progress_queue: mp.Queue | None = None,):
        if not self.chain and not CFG.ALLOW_AUTO_GENESIS:
            log.warning("[mine_block] refusing to mine genesis; sync from peers first.")
            return None

        if self._has_pending_blocks():
            log.warning("[mine_block] pending blocks detected; skipping mining")
            return None

        if not self._is_chain_consistent():
            log.warning("[mine_block] chain inconsistency detected; syncing first")
            return None

        last_block = self.chain[-1] if self.chain else None
        height     = len(self.chain)
        reward = self.get_block_reward(height)
        if self.total_supply + reward > CFG.MAX_SUPPLY:
            reward = max(0, CFG.MAX_SUPPLY - self.total_supply)
        pool = None
        if hasattr(self, "get_mempool"):
            try:
                pool = self.get_mempool()
            except Exception:
                pool = None
                
        if pool is None:
            pool = TxPoolDB(utxo_store=self._ensure_utxodb())
            if hasattr(self, "attach_mempool"):
                try:
                    self.attach_mempool(pool)  # type: ignore[arg-type]
                except Exception:
                    pass
                
        txs_from_mempool = pool.get_all_txs()
        store = self._ensure_utxodb() or UTXODB()
        try:
            current_utxos = getattr(store, "utxos", store.load_utxo_set())
        except Exception:
            current_utxos = store.load_utxo_set()

        temp_utxos = current_utxos.copy() if isinstance(current_utxos, dict) else dict(current_utxos)

        # --- double-spend guard ---
        valid_txs, invalid_txids, used_utxos_in_block = [], [], set()
        for tx in txs_from_mempool:
            # prevent double-spend within the same candidate block
            ds_in_block = any((txin.txid, txin.vout) in used_utxos_in_block for txin in tx.inputs)
            if ds_in_block:
                invalid_txids.append(tx.txid.hex())
                continue

            if not pool.validate_transaction(tx, temp_utxos, spend_at_height=height):
                invalid_txids.append(tx.txid.hex())
                continue

            # Passed all checks - include and update temp UTXO snapshot
            for txin in tx.inputs:
                used_utxos_in_block.add((txin.txid, txin.vout))
            valid_txs.append(tx)
            try:
                self._utxodb.apply_tx_to_utxoset(tx, temp_utxos)
            except Exception:
                pass

        total_fee      = sum(int(getattr(tx, "fee", 0)) for tx in valid_txs)
        coinbase_value = int(reward + total_fee)

        coinbase = CoinbaseTx(to_address=miner_address, reward=coinbase_value, height=height)
        coinbase.compute_txid()

        block_txs = [coinbase] + valid_txs
        prev_hash = last_block.hash() if last_block else CFG.ZERO_HASH
        new_block = Block(height, prev_hash, block_txs)

        # --- Target/bits (LWMA) ---
        if height > 0:
            expected_bits = self.calculate_expected_bits(height)
            new_block.bits = expected_bits
            log.debug("[mine_block] Using bits (LWMA): %s", hex(expected_bits))

        # --- PoW ---
        found = new_block.mine(use_cores=use_cores, stop_event=cancel_event, pow_backend=pow_backend, progress_queue=progress_queue,)
        if not found:
            return None
        if not self.validate_block(new_block):
            return None
        ok = self.add_block(new_block)
        if not ok:
            return None

        log.info("[mine_block] Block mined: height=%d reward=%d fee=%d", new_block.height, reward, total_fee)
        return new_block
