# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import time
from typing import List, TYPE_CHECKING

# ---------------- Local Project ----------------
from ..core.block import Block
from ..mempool.pool import TxPool
from ..utils import config as CFG
from .genesis import GENESIS_HASH
from ..utils.helpers import bits_to_target, merkle_root

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.chain_ops')


if TYPE_CHECKING:
    from .blockchain import Blockchain
    
    
class ChainOperations:
    def __init__(self, blockchain: "Blockchain"):
        self.blockchain = blockchain


    def add_block(self, block: Block):
        if not self.blockchain.chain:
            self._add_genesis_block(block)
        else:
            self._add_subsequent_block(block)
        return True


    def replace_with(self, other_chain: "Blockchain"):
        with self.blockchain.lock:
            self._validate_replacement_chain(other_chain)
            old_chain = list(self.blockchain.chain)
            self._commit_chain_replacement(other_chain)
            self._reinject_mempool_from_reorg(old_chain, other_chain.chain)
            if self.blockchain.chain:
                last_b = self.blockchain.chain[-1]
                self._notify_tip(last_b.height, last_b.hash().hex())


    def swap_tip_if_better(self, block: Block):
        with self.blockchain.lock:
            if not self._is_valid_tip_candidate(block):
                return None
            old_tip = self._commit_tip_swap(block)
            self._notify_tip(block.height, block.hash().hex())
            return old_tip


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _notify_tip(self, height: int, blk_hash: str):
        fn = getattr(self.blockchain, "notify_tip_changed", None)
        if callable(fn):
            try:
                fn(height, blk_hash)
            except Exception:
                log.exception("[_notify_tip] callback error")


    def _add_genesis_block(self, block: Block):
        if getattr(block, "height", 0) != 0:
            raise ValueError("[Blockchain] First block must be the genesis block (height=0)")
        if GENESIS_HASH is not None and block.hash() != GENESIS_HASH:
            raise ValueError("[Blockchain] Incoming genesis does not match TSAR_GENESIS_HASH")

        self.blockchain.chain.append(block)
        self.blockchain.total_blocks = len(self.blockchain.chain)
        setattr(block, "chainwork", self.blockchain._work_from_bits(block.bits))
        block.difficulty = self.blockchain._work_from_bits(block.bits)
        try:
            hash_cache = getattr(self.blockchain, "_hash_cache", None)
            if isinstance(hash_cache, dict):
                hash_cache[int(block.height)] = block.hash().hex()
        except Exception:
            log.exception("[add_block] cache genesis hash failed")

        store = self.blockchain.ensure_utxodb()
        if store is not None:
            blk_hash = block.hash().hex()
            store.update(block.transactions, block_height=0, block_hash=blk_hash)
            self.blockchain.mark_utxo_dirty()
            self.blockchain._utxo_synced = True
            self.blockchain._schedule_persist(force_full=True, flush_force=True, save_state=True)

        self._prune_mempool_confirmed(block)
        self.blockchain._mark_chain_dirty(block.height)
        self._notify_tip(int(block.height), block.hash().hex())


    def _add_subsequent_block(self, block: Block):
        last_block = self.blockchain.get_last_block()
        if block.height != last_block.height + 1:
            raise ValueError(f"[Blockchain] Height mismatch: {block.height} bukan {last_block.height + 1}")
        if block.prev_block_hash != last_block.hash():
            raise ValueError("[Blockchain] prev_block_hash does not match the last block")

        self.blockchain.chain.append(block)
        self.blockchain.total_blocks = len(self.blockchain.chain)

        prev_cw = getattr(last_block, "chainwork", None)
        if prev_cw is None:
            prev_cw = self.blockchain._compute_chainwork_for_chain(self.blockchain.chain[:-1])
        self.blockchain.chain[-1].chainwork = int(prev_cw) + self.blockchain._work_from_bits(block.bits)
        block.difficulty = self.blockchain._work_from_bits(block.bits)
        self.blockchain._mark_chain_dirty(block.height)
        try:
            hash_cache = getattr(self.blockchain, "_hash_cache", None)
            if isinstance(hash_cache, dict):
                hash_cache[int(block.height)] = block.hash().hex()
        except Exception:
            log.exception("[add_block] cache tip hash failed")

        store = self.blockchain.ensure_utxodb()
        if store is not None:
            blk_hash = block.hash().hex()
            store.update(block.transactions, block_height=block.height, block_hash=blk_hash)
            self.blockchain.mark_utxo_dirty()

        self._prune_mempool_confirmed(block)
        self.blockchain._schedule_persist()
        self._notify_tip(int(block.height), block.hash().hex())


    def _validate_replacement_chain(self, other_chain: "Blockchain"):
        if not self._validate_complete_chain(other_chain.chain):
            raise ValueError("Cannot replace with invalid chain")

        their_cw = self.blockchain._compute_chainwork_for_chain(other_chain.chain)
        our_cw   = self.blockchain._compute_chainwork_for_chain(self.blockchain.chain)
        if their_cw < our_cw:
            raise ValueError("Reject: candidate chainwork < local")
        if their_cw == our_cw:
            their_h = len(other_chain.chain) - 1
            our_h = len(self.blockchain.chain) - 1
            if their_h < our_h:
                raise ValueError("Reject: candidate height < local at equal work")
            if their_h == our_h:
                try:
                    their_hash = other_chain.chain[-1].hash()
                    our_hash = self.blockchain.chain[-1].hash()
                    if their_hash >= our_hash:
                        raise ValueError("Reject: candidate tie-break loses (hash)")
                except Exception:
                    raise ValueError("Reject: candidate chainwork tie without deterministic tie-break")

        if CFG.ENABLE_REORG_LIMIT and self.blockchain.chain and other_chain.chain:
            fork_h = self.blockchain._common_ancestor_height(other_chain.chain)
            if fork_h >= 0:
                local_reorg_depth = (len(self.blockchain.chain) - 1) - fork_h
                if local_reorg_depth > CFG.REORG_LIMIT:
                    raise ValueError(f"Reject deep reorg: {local_reorg_depth} > {CFG.REORG_LIMIT}")


    # ---------------------------
    # Reorg & Tip Swapping
    # ---------------------------
    def _commit_chain_replacement(self, other_chain: "Blockchain"):
        self.blockchain.chain = list(other_chain.chain)
        self.blockchain.total_supply = other_chain.total_supply
        self.blockchain.total_blocks = len(self.blockchain.chain)
        try:
            rebuild_fn = getattr(self.blockchain, "_rebuild_hash_cache", None)
            if callable(rebuild_fn):
                rebuild_fn()
        except Exception:
            log.exception("[replace_with] hash cache rebuild failed")

        self.blockchain._mark_chain_dirty(0)
        self.blockchain.save_chain(force_full=True)
        store = self.blockchain.ensure_utxodb()
        if store is not None:
            store.rebuild_from_chain(self.blockchain.chain)
            self.blockchain._utxo_dirty = False
            self.blockchain._utxo_last_flush_height = self.blockchain.height
            self.blockchain._utxo_synced = True
        self.blockchain.save_state()


    def _reinject_mempool_from_reorg(self, old_chain: List[Block], new_chain: List[Block]):
        mempool = getattr(self.blockchain, "get_mempool", lambda: None)()
        if not mempool:
            return
        new_txids = set()
        for b in new_chain:
            for tx in (getattr(b, "transactions", []) or []):
                txid = getattr(tx, "txid", None)
                if txid:
                    txid_hex = txid.hex() if isinstance(txid, (bytes, bytearray)) else str(txid)
                    new_txids.add(txid_hex.lower())

        common_h = self.blockchain._common_ancestor_height(new_chain)
        start_h = max(0, common_h + 1) if common_h >= 0 else 0
        for b in old_chain[start_h:]:
            for tx in (getattr(b, "transactions", []) or [])[1:]:
                txid = getattr(tx, "txid", None)
                if not txid:
                    continue
                txid_hex = (txid.hex() if isinstance(txid, (bytes, bytearray)) else str(txid)).lower()
                if txid_hex not in new_txids:
                    try:
                        mempool.add_valid_tx(tx)
                    except Exception:
                        pass
        try:
            recheck_fn = getattr(mempool, "recheck_orphans", None)
            if callable(recheck_fn):
                recheck_fn()
            mempool.flush()
        except Exception:
            pass


    def _is_valid_tip_candidate(self, block: Block) -> bool:
        if len(self.blockchain.chain) < 2:
            return False

        current_tip = self.blockchain.chain[-1]
        parent = self.blockchain.chain[-2]

        try:
            parent_hash = parent.hash()
        except Exception:
            log.exception("parent_hash_err")
            parent_hash = getattr(parent, "hash", lambda: None)()

        if not parent_hash or block.prev_block_hash != parent_hash:
            return False

        expected_height = getattr(parent, "height", 0) + 1
        if getattr(block, "height", expected_height) != expected_height:
            return False

        candidate_chain = list(self.blockchain.chain[:-1]) + [block]
        if not self._validate_complete_chain(candidate_chain):
            return False

        current_cw = self.blockchain._compute_chainwork_for_chain(self.blockchain.chain)
        candidate_cw = self.blockchain._compute_chainwork_for_chain(candidate_chain)
        if candidate_cw < current_cw:
            return False
        if candidate_cw == current_cw and block.hash() >= current_tip.hash():
            return False

        return True


    def _commit_tip_swap(self, block: Block) -> Block:
        old_tip = self.blockchain.chain[-1]
        parent = self.blockchain.chain[-2]
        self.blockchain.chain[-1] = block
        block.difficulty = self.blockchain._work_from_bits(block.bits)
        prev_cw = getattr(parent, "chainwork", None)
        if prev_cw is None:
            prev_cw = self.blockchain._compute_chainwork_for_chain(self.blockchain.chain[:-1])
        self.blockchain.chain[-1].chainwork = int(prev_cw) + self.blockchain._work_from_bits(block.bits)

        self.blockchain.total_blocks = len(self.blockchain.chain)
        try:
            hash_cache = getattr(self.blockchain, "_hash_cache", None)
            if isinstance(hash_cache, dict):
                hash_cache[int(block.height)] = block.hash().hex()
        except Exception:
            log.exception("[swap_tip_if_better] cache hash failed")

        self.blockchain._mark_chain_dirty(block.height)
        self.blockchain.save_chain()
        store = self.blockchain.ensure_utxodb()
        if store is not None:
            store.rebuild_from_chain(self.blockchain.chain)
            self.blockchain._utxo_dirty = False
            self.blockchain._utxo_last_flush_height = self.blockchain.height
        self.blockchain.save_state()

        self._prune_mempool_confirmed(block)
        return old_tip


    def _prune_mempool_confirmed(self, block: Block) -> None:
        txs = getattr(block, "transactions", []) or []
        if len(txs) <= 1:
            return

        spent_prevouts, txids = self._extract_spent_prevouts_and_txids(txs)
        if not txids:
            return

        get_mp = getattr(self.blockchain, "get_mempool", None)
        pool = get_mp() if callable(get_mp) else None
        if pool is None:
            return

        seen: set[str] = set()
        rem_many = getattr(pool, "remove_many", None)
        if callable(rem_many):
            rem_many(txids)
        else:
            for txid in txids:
                if txid in seen:
                    continue
                seen.add(txid)
                pool.remove_tx(txid)

        conflicts = pool.drop_conflicts(spent_prevouts)
        stale_removed = pool.prune_stale_entries()

        if conflicts or stale_removed:
            log.warning("[_prune_mempool_confirmed] pruned conflicts=%d stale=%d", conflicts, stale_removed)
            
        pool.flush()


    def _extract_spent_prevouts_and_txids(self, txs: list) -> tuple[set, list]:
        spent_prevouts: set[tuple[str, int]] = set()
        for tx in txs[1:]:
            if getattr(tx, "is_coinbase", False):
                continue
            for txin in getattr(tx, "inputs", []) or []:
                prev_txid = getattr(txin, "txid", None)
                if isinstance(prev_txid, (bytes, bytearray)):
                    prev_hex = prev_txid.hex()
                elif isinstance(prev_txid, str):
                    prev_hex = prev_txid
                else:
                    continue
                vout_index = int(getattr(txin, "vout", 0))
                spent_prevouts.add((prev_hex.lower(), vout_index))

        txids: list[str] = []
        for tx in txs[1:]:
            txid_hex: str | None = None
            candidate = getattr(tx, "txid", None)
            if isinstance(candidate, (bytes, bytearray)):
                txid_hex = candidate.hex()
            elif isinstance(candidate, str) and len(candidate) == 64:
                txid_hex = candidate.lower()
            else:
                txid_hex = getattr(tx, "txid_hex", lambda: None)()

            to_dict = getattr(tx, "to_dict", None)
            if not txid_hex and callable(to_dict):
                d = to_dict(include_txid=True)
                txid_hex = d.get("txid")

            if txid_hex:
                txids.append(txid_hex)
                lower = txid_hex.lower()
                if lower != txid_hex:
                    txids.append(lower)

        return spent_prevouts, txids


    def _has_pending_blocks(self) -> bool:
        with self.blockchain.lock:
            return bool(self.blockchain.pending_blocks)


    def _is_chain_consistent(self) -> bool:
        with self.blockchain.lock:
            if not self.blockchain.chain:
                return True
            consistency_checks = {
                'heights_sequential': True,
                'hash_linkages_valid': True,
                'block_hashes_valid': True,
                'genesis_valid': True,
                }

            genesis = self.blockchain.chain[0]
            if genesis.height != 0:
                consistency_checks['genesis_valid'] = False
            if genesis.prev_block_hash != CFG.ZERO_HASH:
                consistency_checks['genesis_valid'] = False

            for i in range(1, len(self.blockchain.chain)):
                prev = self.blockchain.chain[i - 1]
                cur = self.blockchain.chain[i]
                if cur.height != prev.height + 1:
                    consistency_checks['heights_sequential'] = False
                if cur.prev_block_hash != prev.hash():
                    consistency_checks['hash_linkages_valid'] = False

            ok = all(consistency_checks.values())
            return ok


    def _validate_complete_chain(self, chain: List[Block]) -> bool:
        if not isinstance(chain, list) or not chain:
            return False

        g = chain[0]
        ok_genesis, cumulative_supply = self._validate_genesis_block(g)
        if not ok_genesis:
            return False

        return self._validate_subsequent_blocks(chain, cumulative_supply)


    def _pow_ok(self, b: Block) -> bool:
        header_hash = b.hash()
        tgt = bits_to_target(int(getattr(b, "bits")))
        return int.from_bytes(header_hash, "big") <= int(tgt)


    def _merkle_ok(self, b: Block) -> bool:
        comp = merkle_root(getattr(b, "transactions", []) or [])
        mr = getattr(b, "merkle_root", None)
        if isinstance(mr, str):
            mr = bytes.fromhex(mr)
        return comp == mr


    def _validate_genesis_block(self, g: Block) -> tuple[bool, int]:
        cumulative_supply = 0
        if getattr(g, "height", None) != 0 or getattr(g, "prev_block_hash", None) != CFG.ZERO_HASH:
            return False, 0
        if GENESIS_HASH is not None and g.hash() != GENESIS_HASH:
            return False, 0
        if not self._pow_ok(g):
            return False, 0
        compute_txids = getattr(self.blockchain, "compute_txids_for_block", None)
        if callable(compute_txids):
            try:
                if not compute_txids(g):
                    return False, 0
            except Exception:
                log.exception("[_validate_complete_chain] Error computing txids for genesis")
                return False, 0
        if not self._merkle_ok(g):
            return False, 0

        base_reward = self.blockchain.scheduled_reward(0)
        reward = min(base_reward, max(0, CFG.MAX_SUPPLY - cumulative_supply))
        fees = 0
        cb = getattr(g, "transactions", [None])[0]
        if cb is None or not getattr(cb, "is_coinbase", False):
            return False, 0
        actual_cb = sum(int(o.amount) for o in getattr(cb, "outputs", []) or [])
        if actual_cb != reward + fees:
            return False, 0
        
        cumulative_supply += reward
        return True, cumulative_supply


    def _validate_block_timestamp(self, chain_prefix: List[Block], cur: Block) -> bool:
        now_ts = int(time.time())
        cur_ts = int(getattr(cur, "timestamp", 0) or 0)
        if cur_ts > now_ts + CFG.FUTURE_DRIFT:
            return False
        k = CFG.MTP_WINDOWS
        if chain_prefix:
            window = chain_prefix[-k:] if len(chain_prefix) >= k else chain_prefix
            times = sorted(int(getattr(b, "timestamp", 0) or 0) for b in window)
            mtp = times[len(times)//2] if times else 0
            if cur_ts < int(mtp):
                return False
        return True


    def _validate_subsequent_blocks(self, chain: List[Block], cumulative_supply: int) -> bool:
        # Ephemeral UTXO state to track inputs/spends throughout candidate chain
        temp_utxos: dict = {}
        g_txs = getattr(chain[0], "transactions", []) or []
        if g_txs:
            g_txid = getattr(g_txs[0], "txid", None)
            g_txid_hex = g_txid.hex() if isinstance(g_txid, (bytes, bytearray)) else str(g_txid or "")
            for idx, out in enumerate(getattr(g_txs[0], "outputs", []) or []):
                spk = getattr(out, "script_pubkey", None)
                temp_utxos[f"{g_txid_hex}:{idx}"] = {
                    "amount": int(getattr(out, "amount", 0)),
                    "script_pubkey": spk,
                    "height": 0,
                    "is_coinbase": True,
                }

        for i in range(1, len(chain)):
            prev = chain[i - 1]
            cur  = chain[i]

            if getattr(cur, "height", None) != getattr(prev, "height", -1) + 1:
                return False
            if getattr(cur, "prev_block_hash", None) != prev.hash():
                return False

            if not self._validate_block_timestamp(chain[:i], cur):
                return False

            expected_bits = self.blockchain._expected_bits_on_prefix(chain[:i], int(getattr(cur, "height", i)))
            got_bits = int(getattr(cur, "bits"))
            if int(expected_bits) != int(got_bits):
                return False

            if not self._pow_ok(cur):
                return False
            compute_txids = getattr(self.blockchain, "compute_txids_for_block", None)
            if callable(compute_txids):
                if not compute_txids(cur):
                    return False
            if not self._merkle_ok(cur):
                return False

            txs = getattr(cur, "transactions", []) or []
            if not txs or not getattr(txs[0], "is_coinbase", False) or any(getattr(t, "is_coinbase", False) for t in txs[1:]):
                return False

            cur_height = int(getattr(cur, "height", i))
            spent_in_block = set()
            for tx in txs[1:]:
                tx_in_sum = 0
                for txin in getattr(tx, "inputs", []):
                    prev_txid = getattr(txin, "txid", None) or getattr(txin, "prev_tx", None)
                    prev_txid_hex = prev_txid.hex() if isinstance(prev_txid, (bytes, bytearray)) else str(prev_txid or "")
                    vout = int(getattr(txin, "vout", getattr(txin, "prev_index", 0)))
                    outpoint = f"{prev_txid_hex}:{vout}"
                    if outpoint in spent_in_block or outpoint not in temp_utxos:
                        log.warning("[_validate_complete_chain] Invalid input %s at block %d", outpoint, cur_height)
                        return False
                    spent_in_block.add(outpoint)
                    entry = temp_utxos[outpoint]
                    if entry.get("is_coinbase") and (cur_height - entry.get("height", 0)) < CFG.COINBASE_MATURITY:
                        log.warning("[_validate_complete_chain] Immature coinbase spend at block %d", cur_height)
                        return False
                    tx_in_sum += int(entry.get("amount", 0))

                tx_out_sum = sum(int(getattr(o, "amount", 0)) for o in getattr(tx, "outputs", []))
                if tx_out_sum > tx_in_sum:
                    log.warning("[_validate_complete_chain] Negative fee at block %d", cur_height)
                    return False
                tx.fee = tx_in_sum - tx_out_sum

            fees = sum(int(getattr(t, "fee", 0)) for t in txs[1:])
            base_reward = self.blockchain.scheduled_reward(cur_height)
            reward = min(base_reward, max(0, CFG.MAX_SUPPLY - cumulative_supply))
            actual_cb = sum(int(o.amount) for o in getattr(txs[0], "outputs", []) or [])
            expected_cb = reward + fees
            if actual_cb != expected_cb:
                log.warning(
                    "[_validate_complete_chain] bad coinbase at height=%s expected=%s got=%s fees=%s",
                    getattr(cur, "height", None), expected_cb, actual_cb, fees,
                )
                return False

            for outpoint in spent_in_block:
                temp_utxos.pop(outpoint, None)

            for tx in txs:
                txid = getattr(tx, "txid", None)
                txid_hex = txid.hex() if isinstance(txid, (bytes, bytearray)) else str(txid or "")
                is_cb = bool(getattr(tx, "is_coinbase", False))
                for idx, out in enumerate(getattr(tx, "outputs", []) or []):
                    spk = getattr(out, "script_pubkey", None)
                    if spk is not None:
                        ser = getattr(spk, "serialize", None)
                        b = ser() if callable(ser) else (bytes(spk) if isinstance(spk, (bytes, bytearray)) else b"")
                        if len(b) >= 1 and b[0] == 0x6A:
                            continue

                    temp_utxos[f"{txid_hex}:{idx}"] = {
                        "amount": int(getattr(out, "amount", 0)),
                        "script_pubkey": spk,
                        "height": cur_height,
                        "is_coinbase": is_cb,
                    }

            cumulative_supply += reward

        return True