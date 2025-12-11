# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: LWMA-Zawy

from __future__ import annotations

import multiprocessing as mp
import time
from multiprocessing.synchronize import Event as MpEvent

# ---------------- Local Project ----------------
from ..core.block import Block
from ..core.coinbase import CoinbaseTx
from ..mempool.pool import TxPoolDB
from ..storage.utxo import UTXODB
from ..utils import config as CFG
from ..contracts import graffiti as GRAFFITI

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.mining')

class MiningMixin:
    def _select_graffiti_art_id(self, txs) -> str | None:
        """
        Inspect candidate transactions for a Graffiti POST event and return its art_id.
        Only the first valid POST per block is used to anchor the block_id.
        """
        for tx in txs or []:
            outputs = getattr(tx, "outputs", []) or []
            for txout in outputs:
                script = getattr(txout, "script_pubkey", None)
                if script is None:
                    continue
                meta = GRAFFITI.parse_from_script(script)
                if not meta:
                    continue
                event = str(meta.get("event", "POST")).strip().upper()
                if event != "POST":
                    continue
                art_id = str(meta.get("art_id") or "").strip().lower()
                if not art_id:
                    sha_hex = str(meta.get("sha256") or "").strip().lower()
                    creator = str(meta.get("creator") or "").strip().lower()
                    art_id = GRAFFITI.compute_art_id(sha_hex, creator) if sha_hex and creator else ""
                if art_id:
                    txid = getattr(tx, "txid", None)
                    if isinstance(txid, (bytes, bytearray)):
                        txid_hex = txid.hex()
                    else:
                        txid_hex = str(txid)
                    log.debug("[mine_block] Graffiti POST found tx=%s art_id=%s", (txid_hex or "")[:12], art_id[:24])
                    return art_id
        return None

    def mine_block(self, miner_address, use_cores: int | None = None, cancel_event: MpEvent | None = None, pow_backend: str = "auto", progress_queue: mp.Queue | None = None,):
        if not self.chain:
            reloaded = getattr(self, "_reload_chain_from_kv", lambda: False)()
            if reloaded:
                log.debug("[mine_block] chain reloaded from LMDB; continuing mining")
                
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
            pool = self.get_mempool()
                
        if pool is None:
            pool = TxPoolDB(utxo_store=self._ensure_utxodb())
            if hasattr(self, "attach_mempool"):
                self.attach_mempool(pool)  # type: ignore[arg-type]
                
        txs_raw = pool.get_all_txs()

        def _is_graffiti_post(tx_obj) -> bool:
            for tx_out in getattr(tx_obj, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if meta and str(meta.get("event", "")).upper() == "POST":
                    return True
            return False

        def _received_at(tx_obj) -> float:
            return float(getattr(tx_obj, "_received_at", 0) or 0)

        def _fee(tx_obj) -> int:
            return int(getattr(tx_obj, "fee", 0) or 0)

        graff_posts = [tx for tx in txs_raw if _is_graffiti_post(tx)]
        other_txs   = [tx for tx in txs_raw if tx not in graff_posts]

        graff_posts.sort(key=_received_at)  # earliest first
        other_txs.sort(key=lambda t: (-_fee(t), _received_at(t)))  # fee desc, then arrival

        # Include all POST's (sorted); 1-GRAFFITI-per-block guard applies during validation.
        txs_from_mempool = graff_posts + other_txs
        store = self._ensure_utxodb() or UTXODB()
        current_utxos = getattr(store, "utxos", store.load_utxo_set())
        temp_utxos = current_utxos.copy() if isinstance(current_utxos, dict) else dict(current_utxos)

        # --- double-spend guard ---
        valid_txs, invalid_txids, used_utxos_in_block = [], [], set()
        graffiti_post_seen = False
        for tx in txs_from_mempool:
            # prevent double-spend within the same candidate block
            ds_in_block = any((txin.txid, txin.vout) in used_utxos_in_block for txin in tx.inputs)
            if ds_in_block:
                invalid_txids.append(tx.txid.hex())
                continue

            if not pool.validate_transaction(tx, temp_utxos, spend_at_height=height):
                invalid_txids.append(tx.txid.hex())
                reason = getattr(pool, "last_error_reason", None)
                if reason:
                    log.warning("[mine_block] tx %s rejected: %s", tx.txid.hex()[:12], reason)
                continue

            # Allow a maximum of one Graffiti POST per block: skip other Graffiti POST's to queue them in the next block.
            is_graff_post = False
            for tx_out in getattr(tx, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if meta and str(meta.get("event", "")).upper() == "POST":
                    is_graff_post = True
                    break
            if is_graff_post and graffiti_post_seen:
                log.info("[mine_block] skip extra Graffiti POST tx=%s (quota per block = 1)", tx.txid.hex()[:12])
                continue

            # Passed all checks - include and update temp UTXO snapshot
            for txin in tx.inputs:
                used_utxos_in_block.add((txin.txid, txin.vout))
            valid_txs.append(tx)
            if is_graff_post:
                graffiti_post_seen = True
            self._utxodb.apply_tx_to_utxoset(tx, temp_utxos)

        total_fee      = sum(int(getattr(tx, "fee", 0)) for tx in valid_txs)
        coinbase_value = int(reward + total_fee)

        graffiti_art_id = self._select_graffiti_art_id(valid_txs)
        coinbase_kwargs = dict(to_address=miner_address, reward=coinbase_value, height=height)
        if graffiti_art_id:
            coinbase_kwargs["block_id"] = graffiti_art_id
            log.info("[mine_block] Anchoring block_id to graffiti art_id %s", graffiti_art_id[:32])

        coinbase = CoinbaseTx(**coinbase_kwargs)
        coinbase.compute_txid()

        block_txs = [coinbase] + valid_txs
        prev_hash = last_block.hash() if last_block else CFG.ZERO_HASH
        new_block = Block(height, prev_hash, block_txs)

        # --- Target/bits (LWMA) ---
        if height > 0:
            expected_bits = self.calculate_expected_bits(height)
            new_block.bits = expected_bits

        # --- PoW ---
        found = new_block.mine(use_cores=use_cores, stop_event=cancel_event, pow_backend=pow_backend, progress_queue=progress_queue,)
        if not found:
            return None
        # Re-check tip to avoid stale submissions (chain may have advanced during mining)
        try:
            latest = self.get_last_block()
            if latest is not None and (latest.hash() != getattr(new_block, "prev_block_hash", None) or getattr(new_block, "height", 0) != getattr(latest, "height", -1) + 1):
                log.info(
                    "[mine_block] discard stale candidate height=%s prev=%s latest=%s",
                    getattr(new_block, "height", None),
                    getattr(new_block, "prev_block_hash", None).hex() if hasattr(getattr(new_block, "prev_block_hash", None), "hex") else getattr(new_block, "prev_block_hash", None),
                    latest.hash().hex() if latest and hasattr(latest.hash(), "hex") else (latest.hash() if latest else None),
                )
                return None
        except Exception:
            log.debug("[mine_block] stale-check failed", exc_info=True)
            
        # Cool-off after we know we're mining on the latest tip as of now
        cooloff = float(CFG.MINING_COOLDOWN_AFTER_BLOCK)
        if cooloff > 0:
            remain = float(getattr(self, "_mining_cooloff_until", 0.0)) - time.time()
            if remain > 0:
                time.sleep(min(remain, cooloff))
        if not self.validate_block(new_block):
            reason = getattr(self, "_last_block_validation_error", None) or "unknown"
            blk_hex = new_block.hash().hex()
            prev_hex = getattr(new_block, "prev_block_hash", None)
            if hasattr(prev_hex, "hex"):
                prev_hex = prev_hex.hex()
            log.warning(
                "[block_reject] stage=validate source=local_miner height=%s hash=%s prev=%s reason=%s",
                height,
                blk_hex[:16],
                prev_hex,
                reason,
            )
            return None
        ok = self.add_block(new_block)
        if not ok:
            reason = getattr(self, "_last_block_validation_error", None) or "unknown"
            blk_hex = new_block.hash().hex()
            log.warning(
                "[block_reject] stage=add_block source=local_miner height=%s hash=%s reason=%s",
                height,
                blk_hex[:16],
                reason,
            )
            return None
        log.info("[mine_block] Block mined: height=%d reward=%d fee=%d", new_block.height, reward, total_fee)
        return new_block
