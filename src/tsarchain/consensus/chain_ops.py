# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import datetime as dt
import time
from copy import deepcopy
from typing import List, TYPE_CHECKING

# ---------------- Local Project ----------------
from ..core.block import Block
from ..mempool.pool import TxPoolDB
from ..utils import config as CFG
from ..utils.helpers import bits_to_target, merkle_root
from .genesis import GENESIS_HASH

if TYPE_CHECKING:
    from .blockchain import Blockchain

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.chain_ops')

class ChainOpsMixin:
    def replace_with(self, other_chain: "Blockchain"):
        with self.lock:
            # 1) pastikan kandidat valid full
            if not self._validate_complete_chain(other_chain.chain):
                raise ValueError("Cannot replace with invalid chain")

            # 2) compare chainwork (total work) - must be superior
            if CFG.ENABLE_CHAINWORK_RULE:
                their_cw = self._compute_chainwork_for_chain(other_chain.chain)
                our_cw   = self._compute_chainwork_for_chain(self.chain)
                if their_cw <= our_cw:
                    raise ValueError("Reject: candidate chainwork <= local")

            # 3) limit reorg depth (anti long-range)
            if CFG.ENABLE_REORG_LIMIT and self.chain and other_chain.chain:
                fork_h = self._common_ancestor_height(other_chain.chain)
                if fork_h >= 0:
                    local_reorg_depth = (len(self.chain) - 1) - fork_h
                    if local_reorg_depth > CFG.REORG_LIMIT:
                        raise ValueError(f"Reject deep reorg: {local_reorg_depth} > {CFG.REORG_LIMIT}")

            # 4) commit: ganti chain & rebuild state/utxo (persis alur lama)
            self.chain = deepcopy(other_chain.chain)
            self.total_supply = other_chain.total_supply
            self.total_blocks = len(self.chain)

            if not self.in_memory:
                self._mark_chain_dirty(0)
                self.save_chain(force_full=True)
                store = self._ensure_utxodb()
                if store is not None:
                    store.rebuild_from_chain(self.chain)
                    self._utxo_dirty = False
                    self._utxo_last_flush_height = self.height
                    self._utxo_synced = True
                self.save_state()
            else:
                try:
                    self.total_supply = self.calculate_total_supply()
                except Exception as e:
                    log.debug("[replace_with] calculate_total_supply skipped: %s", e)

    def add_block(self, block: Block):
        if not self.chain:
            if getattr(block, "height", 0) != 0:
                raise ValueError("[Blockchain] First block must be the genesis block (height=0)")
            if GENESIS_HASH is not None and block.hash() != GENESIS_HASH:
                raise ValueError("[Blockchain] Incoming genesis does not match TSAR_GENESIS_HASH")

            self.chain.append(block)
            try: setattr(block, 'chainwork', self._work_from_bits(block.bits))
            except Exception:
                log.exception("[add_block] Post-add hooks failed")

            try:
                if not self.in_memory:
                    store = self._ensure_utxodb()
                    if store is not None:
                        store.update(block.transactions, block_height=0, autosave=False)
                        self._mark_utxo_dirty()
                        self._utxo_synced = True
                        self._maybe_flush_utxo(force=True)
                try:
                    self._prune_mempool_confirmed(block)
                except Exception:
                    log.exception("[add_block] Failed to prune mempool after genesis")
                if not self.in_memory:
                    self._mark_chain_dirty(block.height)
                    self.save_chain(force_full=True)
                    self.save_state()
                else:
                    self.total_supply = self.calculate_total_supply()
            except Exception:
                log.exception("[add_block] failed to calculate")
            return True

        last_block = self.get_last_block()
        if block.height != last_block.height + 1:
            raise ValueError(f"[Blockchain] Height mismatch: {block.height} bukan {last_block.height + 1}")
        if block.prev_block_hash != last_block.hash():
            raise ValueError("[Blockchain] prev_block_hash does not match the last block")

        self.chain.append(block)
        # annotate cumulative chainwork for tip
        try:
            prev_cw = getattr(self.chain[-2], 'chainwork', None)
            if prev_cw is None:
                prev_cw = self._compute_chainwork_for_chain(self.chain[:-1])
            self.chain[-1].chainwork = int(prev_cw) + self._work_from_bits(block.bits)
        except Exception:
            log.exception("[add_block] failed to compute chainworks")
            pass

        self._mark_chain_dirty(block.height)

        try:
            # UTXO
            if not self.in_memory:
                try:
                    store = self._ensure_utxodb()
                    if store is not None:
                        store.update(block.transactions, block_height=block.height, autosave=False)
                        self._mark_utxo_dirty()
                except Exception:
                    pass
            try:
                self._prune_mempool_confirmed(block)
            except Exception:
                log.exception("[add_block] Failed to prune mempool")

            if not self.in_memory:
                self.save_chain()
                self._maybe_flush_utxo()
                self.save_state()
            else:
                self.total_supply = self.calculate_total_supply()
        except Exception:
            log.exception("[add_block] Failed to add block")

        return True

    def swap_tip_if_better(self, block: Block):
        with self.lock:
            if len(self.chain) < 2:
                return None

            current_tip = self.chain[-1]
            parent = self.chain[-2]

            try:
                parent_hash = parent.hash()
            except Exception:
                parent_hash = getattr(parent, "hash", lambda: None)()

            if not parent_hash or block.prev_block_hash != parent_hash:
                return None

            expected_height = getattr(parent, "height", 0) + 1
            if getattr(block, "height", expected_height) != expected_height:
                return None

            candidate_chain = list(self.chain[:-1]) + [block]
            if not self._validate_complete_chain(candidate_chain):
                return None

            if CFG.ENABLE_CHAINWORK_RULE:
                current_cw = self._compute_chainwork_for_chain(self.chain)
                candidate_cw = self._compute_chainwork_for_chain(candidate_chain)
                if candidate_cw < current_cw:
                    return None
                if candidate_cw == current_cw:
                    try:
                        if block.hash() >= current_tip.hash():
                            return None
                    except Exception:
                        return None

            old_tip = self.chain[-1]
            self.chain[-1] = block

            try:
                prev_cw = getattr(parent, "chainwork", None)
                if prev_cw is None:
                    prev_cw = self._compute_chainwork_for_chain(self.chain[:-1])
                self.chain[-1].chainwork = int(prev_cw) + self._work_from_bits(block.bits)
            except Exception:
                pass

            self.total_blocks = len(self.chain)

            if not self.in_memory:
                self._mark_chain_dirty(block.height)
                self.save_chain()
                store = self._ensure_utxodb()
                if store is not None:
                    store.rebuild_from_chain(self.chain)
                    self._utxo_dirty = False
                    self._utxo_last_flush_height = self.height
                self.save_state()
            else:
                try:
                    self.total_supply = self.calculate_total_supply()
                except Exception:
                    pass

            try:
                self._prune_mempool_confirmed(block)
            except Exception:
                log.exception("[swap_tip_if_better] Failed to prune mempool")

            return old_tip

    def _prune_mempool_confirmed(self, block: Block) -> None:
        txs = getattr(block, "transactions", []) or []
        if len(txs) <= 1:
            return

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

                try:
                    vout_index = int(getattr(txin, "vout", 0))
                except Exception:
                    vout_index = 0
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
                try:
                    txid_hex = getattr(tx, "txid_hex", lambda: None)()
                except Exception:
                    txid_hex = None

            if not txid_hex and hasattr(tx, "to_dict"):
                try:
                    d = tx.to_dict(include_txid=True)
                    txid_hex = d.get("txid")
                except Exception:
                    txid_hex = None

            if txid_hex:
                txids.append(txid_hex)
                lower = txid_hex.lower()
                if lower != txid_hex:
                    txids.append(lower)

        if not txids:
            return

        pool = TxPoolDB(utxo_store=self._ensure_utxodb())
        pruned = 0
        seen: set[str] = set()
        for txid in txids:
            if txid in seen:
                continue
            seen.add(txid)
            try:
                pool.remove_tx(txid)
                pruned += 1
            except Exception:
                log.debug("[_prune_mempool_confirmed] Failed to remove tx %s", txid)

        if pruned:
            log.debug("[_prune_mempool_confirmed] Removed %d confirmed txs from mempool", pruned)

        try:
            conflicts = pool.drop_conflicts(spent_prevouts)
        except Exception:
            log.exception("[_prune_mempool_confirmed] Failed to drop conflicting mempool entries")
            conflicts = 0

        stale_removed = 0
        try:
            stale_removed = pool.prune_stale_entries()
        except Exception:
            log.exception("[_prune_mempool_confirmed] Failed to prune stale mempool entries")

        if conflicts or stale_removed:
            log.debug("[_prune_mempool_confirmed] pruned conflicts=%d stale=%d", conflicts, stale_removed)

    def _has_pending_blocks(self) -> bool:
        try:
            with self.lock:
                return bool(self.pending_blocks)
        except Exception:
            return False

    def _is_chain_consistent(self) -> bool:
        try:
            with self.lock:
                if not self.chain:
                    return True
                consistency_checks = {
                    'heights_sequential': True,
                    'hash_linkages_valid': True,
                    'block_hashes_valid': True,
                    'genesis_valid': True,}

                genesis = self.chain[0]
                if genesis.height != 0:
                    consistency_checks['genesis_valid'] = False
                if genesis.prev_block_hash != CFG.ZERO_HASH:
                    consistency_checks['genesis_valid'] = False

                for i in range(1, len(self.chain)):
                    prev = self.chain[i - 1]
                    cur = self.chain[i]
                    if cur.height != prev.height + 1:
                        consistency_checks['heights_sequential'] = False
                    if cur.prev_block_hash != prev.hash():
                        consistency_checks['hash_linkages_valid'] = False

                ok = all(consistency_checks.values())
                if ok:
                    log.info("[_is_chain_consistent] Chain consistent: %d blocks", len(self.chain))
                else:
                    log.warning("[_is_chain_consistent] Chain inconsistent: %s", consistency_checks)
                return ok
        except Exception:
            log.exception("[_is_chain_consistent] Error")
            return False

    def _validate_complete_chain(self, chain: List[Block]) -> bool:
        try:
            if not isinstance(chain, list) or not chain:
                return False

            def _pow_ok(b: Block) -> bool:
                try:
                    header_hash = b.hash()
                    tgt = bits_to_target(int(getattr(b, "bits")))
                    return int.from_bytes(header_hash, "big") <= int(tgt)
                except Exception:
                    return False

            def _merkle_ok(b: Block) -> bool:
                try:
                    comp = merkle_root(getattr(b, "transactions", []) or [])
                    mr = getattr(b, "merkle_root", None)
                    if isinstance(mr, str):
                        mr = bytes.fromhex(mr)
                    return comp == mr
                except Exception:
                    return False

            cumulative_supply = 0
            g = chain[0]
            if getattr(g, "height", None) != 0 or getattr(g, "prev_block_hash", None) != CFG.ZERO_HASH:
                return False
            if GENESIS_HASH is not None and g.hash() != GENESIS_HASH:
                return False
            if not _pow_ok(g):
                return False
            if not _merkle_ok(g):
                return False

            base_reward = self._scheduled_reward(0)
            reward = min(base_reward, max(0, CFG.MAX_SUPPLY - cumulative_supply))
            fees = 0
            cb = getattr(g, "transactions", [None])[0]
            if cb is None or not getattr(cb, "is_coinbase", False):
                return False
            actual_cb = sum(int(o.amount) for o in getattr(cb, "outputs", []) or [])
            if actual_cb != reward + fees:
                return False
            cumulative_supply += reward

            for i in range(1, len(chain)):
                prev = chain[i - 1]
                cur  = chain[i]

                if getattr(cur, "height", None) != getattr(prev, "height", -1) + 1:
                    return False

                if getattr(cur, "prev_block_hash", None) != prev.hash():
                    return False

                # --- Timestamp checks (consistency with validate_block) ---
                try:
                    now_ts = int(time.time())
                    cur_ts = int(getattr(cur, "timestamp", 0) or 0)
                    if cur_ts > now_ts + CFG.FUTURE_DRIFT:
                        return False
                    k = CFG.MTP_WINDOWS
                    prefix = chain[:i]
                    if prefix:
                        window = prefix[-k:] if len(prefix) >= k else prefix
                        times = sorted(int(getattr(b, "timestamp", 0) or 0) for b in window)
                        mtp = times[len(times)//2] if times else 0
                        if cur_ts < int(mtp):
                            return False
                except Exception:
                    return False

                try:
                    expected_bits = self._expected_bits_on_prefix(chain[:i], int(getattr(cur, "height", i)))
                    got_bits = int(getattr(cur, "bits"))
                    if int(expected_bits) != int(got_bits):
                        return False
                except Exception:
                    log.exception("[_validate_complete_chain] Error computing expected bits at %d", i)
                    return False

                if not _pow_ok(cur):
                    return False
                if not _merkle_ok(cur):
                    return False

                txs = getattr(cur, "transactions", []) or []
                if not txs or not getattr(txs[0], "is_coinbase", False) or any(getattr(t, "is_coinbase", False) for t in txs[1:]):
                    return False

                fees = sum(int(getattr(t, "fee", 0)) for t in txs[1:])
                base_reward = self._scheduled_reward(int(getattr(cur, "height", 0)))
                reward = min(base_reward, max(0, CFG.MAX_SUPPLY - cumulative_supply))
                actual_cb = sum(int(o.amount) for o in getattr(txs[0], "outputs", []) or [])
                expected_cb = reward + fees
                if actual_cb != expected_cb:
                    return False
                cumulative_supply += reward

            return True
        except Exception:
            log.exception("[_validate_complete_chain] Error validating complete chain")
            return False

    def print_chain(
        self,
        max_blocks: int | None = None,
        columns: tuple[str, ...] = ("height", "time", "txs", "block_id", "hash", "prev"),
        widths: dict[str, int] | None = None,
        hash_len: int = 12,) -> str:

        allowed = {"height", "time", "txs", "block_id", "hash", "prev"}
        cols = [c for c in columns if c in allowed]
        if not cols:
            cols = ["height", "time", "txs", "block_id", "hash", "prev"]
        w = {
            "height": 6,
            "time":   8,
            "txs":    3,
            "block_id": 50,
            "hash":   hash_len,
            "prev":   hash_len, }

        if widths:
            w.update({k: int(v) for k, v in widths.items() if k in w and isinstance(v, (int,)) and v > 0})

        def _short(h: str | bytes | None, n: int) -> str:
            if h is None:
                return "-"
            if isinstance(h, bytes):
                h = h.hex()
            s = str(h)
            return s[:n] if len(s) > n else s

        def _fmt_time(ts) -> str:
            if ts is None:
                return "--:--:--"
            if isinstance(ts, (int, float)):
                try:
                    return dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                except Exception:
                    return "--:--:--"
            if isinstance(ts, str):
                try:
                    t = ts.replace("Z", "+00:00")
                    return dt.datetime.fromisoformat(t).strftime("%H:%M:%S")
                except Exception:
                    for sep in ("T", " "):
                        if sep in ts:
                            part = ts.split(sep)[-1]
                            if len(part) >= 8 and part[2] == ":" and part[5] == ":":
                                return part[:8]
                    return "--:--:--"
            return "--:--:--"

        def _get_hash(b) -> str:
            try:
                return b.hash().hex()
            except Exception:
                return getattr(b, "hash_hex", None) or getattr(b, "block_hash", None) or "-"

        def _get_prev(b) -> str:
            prev = getattr(b, "prev_block_hash", None) or getattr(b, "prev_hash", None)
            if isinstance(prev, bytes):
                return prev.hex()
            return prev.hex() if hasattr(prev, "hex") else (prev or "-")

        def _get_block_id(b, h_hex: str) -> str:
            bid = getattr(b, "block_id", None)
            if bid:
                return str(bid)
            tx_list = getattr(b, "transactions", []) or []
            if tx_list:
                cb = tx_list[0]
                try:
                    if getattr(cb, "is_coinbase", False):
                        bid = getattr(cb, "block_id", None)
                        if bid:
                            return str(bid)
                except Exception:
                    pass
                if isinstance(cb, dict) and cb.get("is_coinbase"):
                    bid = cb.get("block_id")
                    if bid:
                        return str(bid)
            if isinstance(h_hex, str) and h_hex != "-":
                return h_hex[:max(8, min(16, hash_len))]
            return "-"

        header = " | ".join({
            "height":  f"{'height':<{w['height']}}",
            "time":    f"{'time':<{w['time']}}",
            "txs":     f"{'txs':<{w['txs']}}",
            "block_id":f"{'block_id':<{w['block_id']}}",
            "hash":    f"{'hash':<{w['hash']}}",
            "prev":    f"{'prev':<{w['prev']}}",
        }[c] for c in cols)

        lines = [header]
        chain_iter = self.chain if not max_blocks else self.chain[-max_blocks:]

        for b in chain_iter:
            h_hex = _get_hash(b)
            row = []
            for c in cols:
                if c == "height":
                    val = getattr(b, "height", "?")
                    try:
                        sval = f"{int(val):>{w['height']}}"
                    except Exception:
                        sval = f"{str(val):>{w['height']}}"
                    row.append(sval)
                elif c == "time":
                    tstr = _fmt_time(getattr(b, "timestamp", None))
                    row.append(f"{tstr:<{w['time']}}")
                elif c == "txs":
                    txc = len(getattr(b, "transactions", []) or [])
                    row.append(f"{txc:>{w['txs']}}")
                elif c == "block_id":
                    bid = _get_block_id(b, h_hex)
                    row.append(f"{_short(bid, w['block_id']):<{w['block_id']}}")
                elif c == "hash":
                    row.append(f"{_short(h_hex, w['hash']):<{w['hash']}}")
                elif c == "prev":
                    prev = _get_prev(b)
                    row.append(f"{_short(prev, w['prev']):<{w['prev']}}")
            lines.append(" | ".join(row))

        return "\n".join(lines)
