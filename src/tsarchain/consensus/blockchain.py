# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: LWMA-Zawy; Merkle
from __future__ import annotations
import os, threading, time, re, json
import datetime as _dt
from copy import deepcopy
from typing import List, Optional
from multiprocessing.synchronize import Event as MpEvent
import multiprocessing as mp

# ---------------- Local Project ----------------
from ..core.block import Block
from ..core.coinbase import CoinbaseTx
from ..storage.utxo import UTXODB
from ..mempool.pool import TxPoolDB
from ..storage.db import AtomicJSONFile
from ..storage.kv import kv_enabled, batch, iter_prefix, clear_db
from ..utils.helpers import bits_to_target, target_to_bits, target_to_difficulty, difficulty_to_target, merkle_root
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger


GENESIS_HASH_HEX = os.getenv("TSAR_GENESIS_HASH", "").strip().lower()
if GENESIS_HASH_HEX.startswith("0x"):
    GENESIS_HASH_HEX = GENESIS_HASH_HEX[2:]

if GENESIS_HASH_HEX:
    if not re.fullmatch(r"[0-9a-f]{64}", GENESIS_HASH_HEX):
        raise ValueError("Invalid TSAR_GENESIS_HASH: must be 64 hex chars (32 bytes)")
    GENESIS_HASH = bytes.fromhex(GENESIS_HASH_HEX)
else:
    GENESIS_HASH = None

ALLOW_AUTO_GENESIS = False


class Blockchain:
    def __init__(self, db_path: str = CFG.BLOCK_FILE, miner_address: str | None = None, in_memory: bool = False, use_cores: int | None = None, *, auto_create_genesis: bool | None = None,):
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

        self._auto_create_genesis_flag = (ALLOW_AUTO_GENESIS if auto_create_genesis is None else bool(auto_create_genesis))
        self.log = get_ctx_logger("tsarchain.blockchain")

        if not self.in_memory:
            if self.db_path:
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            os.makedirs(os.path.dirname(CFG.STATE_FILE), exist_ok=True)
            self.load_chain()
            self.load_state()
            if self.chain:
                self._enforce_genesis_lock()
                return
            if GENESIS_HASH is not None and not ALLOW_AUTO_GENESIS:
                raise RuntimeError(
                    "Genesis missing while TSAR_GENESIS_HASH is set and TSAR_ALLOW_AUTO_GENESIS=0. "
                    "Sync from peers or provide the prebuilt genesis.")
            if self._auto_create_genesis_flag:
                self.log.info(f"[__init__] Auto-genesis enabled (use_cores={self.use_cores})")
                self._create_genesis_with_lock(self.miner_address or "", self.use_cores)
            else:
                self.log.info("[__init__] Auto-genesis disabled; node will wait for peers to sync")
                self.chain = []
                self.total_blocks = 0
                self.total_supply = 0
                self._persist_empty_state_if_needed()
        else:
            self.chain = []
            self.total_blocks = 0
            self.total_supply = 0

    # ------------------------ Helpers ------------------------

    def has_genesis(self) -> bool:
        return bool(self.chain)

    def _persist_empty_state_if_needed(self):
        try:
            self.save_state()
        except Exception:
            self.log.warning("[_persist_empty_state_if_needed]:", exc_info=True)

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
        self._create_genesis_with_lock(miner_address, use_cores)
        return True

    # ----------------- Utilities -----------------
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

    # ----------------- I/O Chain -----------------
    def save_chain(self):
        if self.in_memory:
            return
        with self.lock:
            chain_data = [block.to_dict() for block in self.chain]
            if kv_enabled():
                try:
                    clear_db('chain')
                    with batch('chain') as b:
                        for bidx, bd in enumerate(chain_data):
                            key = f"h:{bidx:012d}".encode('utf-8')
                            b.put(key, (json.dumps(bd, separators=(",", ":")).encode('utf-8')))
                except Exception as e:
                    self.log.exception("[save_chain] LMDB save_chain failed: %s", e)
            else:
                self._chain_store.save(chain_data)
            
    def load_chain(self):
        if self.in_memory:
            return
        data_list = []
        if kv_enabled():
            try:
                # Collect and sort by height key
                items = list(iter_prefix('chain', b'h:'))
                items.sort(key=lambda kv: kv[0])
                data_list = [json.loads(v.decode('utf-8')) for _, v in items]
            except Exception as e:
                self.log.exception("[load_chain] LMDB load_chain failed: %s", e)
                data_list = []
        if not data_list:
            data_list = self._chain_store.load(default=[])
        if not data_list:
            return
        chain = [Block.from_dict(d) for d in data_list]
        if not chain:
            return
        if chain[0].height != 0 or chain[0].prev_block_hash != CFG.ZERO_HASH:
            raise ValueError("[Blockchain] Invalid on-disk genesis header fields")
        if GENESIS_HASH is not None and chain[0].hash() != GENESIS_HASH:
            raise ValueError(f"[Blockchain] Invalid genesis for this network. Expected {GENESIS_HASH.hex()}, got {chain[0].hash().hex()}")
        
        self.chain = chain
        self.total_blocks = len(self.chain)
        self.total_supply = self.calculate_total_supply()
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0

    # ----------------- I/O State -----------------
    def load_state(self):
        if self.in_memory:
            return
        data = {}
        if kv_enabled():
            try:
                # State stored as individual keys
                items = dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in iter_prefix('state', b'k:'))
                if items:
                    data["total_supply"] = int(items.get('k:total_supply', '0'))
                    data["total_blocks"] = int(items.get('k:total_blocks', '0'))
            except Exception as e:
                self.log.exception("[load_state] LMDB load_state failed: %s", e)
        if not data:
            data = self._state_store.load(default={})
        self.total_supply = int(data.get("total_supply", 0) or 0)
        self.total_blocks = int(data.get("total_blocks", 0) or 0)
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0

    def save_state(self):
        if self.in_memory:
            return
        # Compute based on in-memory chain; avoid JSON IO when KV enabled
        blocks_count = len(self.chain)
        self.total_blocks = blocks_count
        self.total_supply = self.calculate_total_supply()
        self.supply_in_tsar = self.total_supply / CFG.TSAR if self.total_supply else 0
        data = self._compute_state_snapshot()
        try:
            data["total_supply"] = int(self.total_supply)
            data["total_blocks"] = int(self.total_blocks)
        except Exception:
            pass
        # Save to LMDB
        if kv_enabled():
            try:
                with batch('state') as b:
                    b.put(b'k:total_supply', str(int(self.total_supply)).encode('utf-8'))
                    b.put(b'k:total_blocks', str(int(self.total_blocks)).encode('utf-8'))
            except Exception as e:
                self.log.exception("[save_state] LMDB save_state failed: %s", e)
        else:
            self._state_store.save(data)

    def calculate_total_supply(self) -> int:
        tip_height = len(self.chain)
        return self._cumulative_supply_until(tip_height)
    
    def _compute_state_snapshot(self) -> dict:
        chain = [b.to_dict() for b in (self.chain or [])]

        total_blocks = len(chain)
        tip_height   = max(-1, total_blocks - 1)

        # ---- Detail tip/genesis ----
        tip = chain[-1] if total_blocks > 0 else None
        g   = chain[0]  if total_blocks > 0 else None

        tip_bits      = int(tip["bits"]) if tip else None
        tip_target    = None
        tip_difficulty = None
        try:
            if tip_bits is not None:
                tgt = bits_to_target(tip_bits)
                tip_target = int(tgt)
                tip_difficulty = int(target_to_difficulty(tgt))
        except Exception:
            pass

        AVG_WINDOW = 20
        avg_block_time_sec = None
        est_hashrate_hps   = None
        try:
            if total_blocks >= 2:
                ts = [b.get("timestamp", 0) for b in chain]
                w  = min(AVG_WINDOW, total_blocks - 1)
                intervals = [ts[i] - ts[i-1] for i in range(total_blocks - w, total_blocks)]
                intervals = [x for x in intervals if isinstance(x, (int, float)) and x > 0]
                if intervals:
                    avg_block_time_sec = sum(intervals) / len(intervals)
                    if tip_difficulty:
                        # work/block ÷ detik/blok ≈ H/s
                        est_hashrate_hps = int(tip_difficulty / max(1, avg_block_time_sec))
        except Exception:
            pass

        # ---- Hitung transaksi ----
        total_txs              = sum(len(b.get("transactions", [])) for b in chain)
        total_non_coinbase_txs = sum(max(0, len(b.get("transactions", [])) - 1) for b in chain)

        # ---- Hitung fee kumulatif (fee = coinbase_amount - subsidy_teoritis) ----
        total_fees_paid = 0
        try:
            for b in chain:
                h  = int(b.get("height", 0))
                txs = b.get("transactions") or []
                if not txs:
                    continue
                cb = txs[0]  # coinbase
                cb_amt = int((cb.get("outputs") or [{}])[0].get("amount", 0))
                # subsidy teoritis:
                base = int(CFG.INITIAL_REWARD) // (2 ** (h // int(CFG.BLOCKS_PER_HALVING)))
                fee  = max(0, cb_amt - base)
                total_fees_paid += fee
        except Exception:
            pass

        # ---- Mempool ----
        mempool_count = 0
        mempool_vbytes_est = None
        try:
            pool = TxPoolDB()
            mempool_count = len(pool.get_all_txs())
            mempool_vbytes_est = int(getattr(pool, "current_size", 0))
        except Exception:
            pass

        # ---- UTXO & sirkulasi (mature vs immature) ----
        utxo_set_size = 0
        circulating_estimate = 0
        immature_coinbase    = 0
        try:
            utxo = UTXODB()
            # Prefer in-memory map loaded from KV; fallback to JSON
            try:
                data_map = utxo.to_dict()
            except Exception:
                data_map = utxo.load_json(utxo.filepath) or {}
            utxo_set_size = len(data_map)
            maturity = int(CFG.COINBASE_MATURITY)
            for _, entry in data_map.items():
                try:
                    tx_out = entry.get("tx_out", {})
                    amt    = int(tx_out.get("amount", 0))
                    is_cb  = bool(entry.get("is_coinbase", False))
                    born   = int(entry.get("block_height", entry.get("height", 0)) or 0)
                    if is_cb:
                        conf = max(0, (tip_height - born) + 1)
                        if conf >= maturity:
                            circulating_estimate += amt
                        else:
                            immature_coinbase += amt
                    else:
                        circulating_estimate += amt
                except Exception:
                    self.log.exception("[_compute_state_snapshot] UTXO entry parse error")
        except Exception:
            self.log.exception("[_compute_state_snapshot] UTXODB load error")

        # ---- Supply emisi (subsidy) sampai tip ----
        try:
            emitted_subsidy = self.calculate_total_supply()
        except Exception:
            emitted_subsidy = self.total_supply or 0

        # ---- Identitas & file checksum ----
        chain_sha256 = None
        try:
            if hasattr(self._chain_store, "sha_path") and os.path.exists(self._chain_store.sha_path):
                with open(self._chain_store.sha_path, "r", encoding="utf-8") as fh:
                    chain_sha256 = fh.read().strip() or None
        except Exception:
            pass

        # Info halving/epoch
        cur_epoch = 0 if tip_height < 0 else int(tip_height // int(CFG.BLOCKS_PER_HALVING))
        next_halving_height = int((cur_epoch + 1) * int(CFG.BLOCKS_PER_HALVING))
        blocks_to_halving   = None if tip_height < 0 else max(0, next_halving_height - (tip_height + 1))
        current_block_subsidy = int(CFG.INITIAL_REWARD) // (2 ** cur_epoch)

        # ---- Susun snapshot ----
        snapshot = {
            "schema_version": 1,
            "last_updated": _dt.datetime.now().astimezone().isoformat(),
            "identity": {
                "network_id": CFG.DEFAULT_NET_ID,
                "address_prefix": CFG.ADDRESS_PREFIX,
                "network_magic_hex": CFG.NETWORK_MAGIC.hex(),
            },
            "chain": {
                "total_blocks": total_blocks,
                "tip_height": tip_height,
                "genesis_hash": (g or {}).get("hash"),
                "genesis_message": (((g or {}).get("transactions") or [{}])[0] or {}).get("block_id"),
                "tip_hash": (tip or {}).get("hash"),
                "tip_timestamp": (tip or {}).get("timestamp"),
                "tip_bits": tip_bits,
                "tip_target_hex": (None if tip_target is None else hex(tip_target)),
                "tip_difficulty": tip_difficulty,
                "avg_block_time_sec_window": None if avg_block_time_sec is None else round(float(avg_block_time_sec), 3),
                "est_network_hashrate_hps_window": est_hashrate_hps,
            },
            "supply": {
                "max_supply": int(CFG.MAX_SUPPLY),
                "emitted_subsidy": int(emitted_subsidy),
                "circulating_estimate": int(circulating_estimate),
                "immature_coinbase": int(immature_coinbase),
                "coinbase_maturity": int(CFG.COINBASE_MATURITY),
                "current_block_subsidy": int(current_block_subsidy),
                "current_epoch": int(cur_epoch),
                "next_halving_height": int(next_halving_height),
                "blocks_to_halving": None if blocks_to_halving is None else int(blocks_to_halving),
            },
            "transactions": {
                "total_txs": int(total_txs),
                "total_non_coinbase_txs": int(total_non_coinbase_txs),
                "total_fees_paid": int(total_fees_paid),
                "mempool_txs": int(mempool_count),
                "mempool_vbytes_estimate": mempool_vbytes_est,
            },
            "utxo": {
                "utxo_set_size": int(utxo_set_size),
            },
            "miners_snapshot": {
                "top_miners": (lambda _c: sorted(_c.items(), key=lambda x: x[1], reverse=True))(
                    (lambda cs: {a: cs.count(a) for a in cs})(
                        [((b.get("transactions") or [{}])[0] or {}).get("to_address") for b in chain if (b.get("transactions") or [{}])[0]]
                    )
                )
            },
            "files": {
                "blockchain_json_sha256": chain_sha256
            }
        }
        
        return snapshot

    # ----------------- Chain mutation -----------------
    def replace_with(self, other_chain: "Blockchain"):
        with self.lock:
            # 1) pastikan kandidat valid full
            if not self._validate_complete_chain(other_chain.chain):
                raise ValueError("Cannot replace with invalid chain")

            # 2) compare chainwork (total work) – must be superior
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
                self.save_chain()
                utxodb = UTXODB()
                utxodb.utxos.clear()
                for b in self.chain:
                    try:
                        utxodb.update(b.transactions, block_height=b.height)
                    except Exception:
                        pass
                try: utxodb._save()
                except Exception:
                    pass
                self.save_state()
            else:
                try:
                    self.total_supply = self.calculate_total_supply()
                except Exception:
                    pass



    def add_block(self, block: Block):
        if not self.chain:
            if getattr(block, "height", 0) != 0:
                raise ValueError("[Blockchain] First block must be the genesis block (height=0)")
            if GENESIS_HASH is not None and block.hash() != GENESIS_HASH:
                raise ValueError("[Blockchain] Incoming genesis does not match TSAR_GENESIS_HASH")

            self.chain.append(block)
            try: setattr(block, 'chainwork', self._work_from_bits(block.bits))
            except Exception as e:
                self.log.exception("[add_block] Post-add hooks failed: %s", e)

            try:
                if not self.in_memory:
                    utxodb = UTXODB()
                    utxodb.update(block.transactions, block_height=0)
                    try: utxodb._save()
                    except Exception:
                        pass
                    self.save_chain()
                    self.save_state()
                else:
                    self.total_supply = self.calculate_total_supply()
            except Exception as e:
                self.log.exception("[add_block] failed to calculate: %s", e)
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
        except Exception as e:
            self.log.exception("[add_block] failed to compute chainwork: %s", e)
            pass

        try:
            # UTXO
            if not self.in_memory:
                try:
                    utxodb = UTXODB()
                    utxodb.update(block.transactions, block_height=block.height)
                    try: utxodb._save()
                    except Exception: pass
                except Exception:
                    pass
                
            if not self.in_memory:
                self.save_chain()
                self.save_state()
            else:
                self.total_supply = self.calculate_total_supply()
        except Exception as e:
            self.log.exception("[add_block] Failed to add block: %s", e)

        return True



    # ----------------- Consistency helpers -----------------
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
                    self.log.info("[_is_chain_consistent] ✅ Chain consistent: %d blocks", len(self.chain))
                else:
                    self.log.warning("[_is_chain_consistent] ❌ Chain inconsistent: %s", consistency_checks)
                return ok
        except Exception:
            self.log.exception("[_is_chain_consistent] Error")
            return False

    # ----------------- Monetary policy -----------------
    
    def _cumulative_supply_until(self, height: int) -> int:
        total = 0
        if height <= 0:
            return 0
        for h in range(height):
            base = CFG.INITIAL_REWARD // (2 ** (h // CFG.BLOCKS_PER_HALVING))
            if base <= 0:
                break
            if total + base > CFG.MAX_SUPPLY:
                base = CFG.MAX_SUPPLY - total
            total += base
            if total >= CFG.MAX_SUPPLY:
                return CFG.MAX_SUPPLY
        return total
    
    def get_block_reward(self, height: int) -> int:
        base = CFG.INITIAL_REWARD // (2 ** (height // CFG.BLOCKS_PER_HALVING))
        if base <= 0:
            return 0
        minted_before = self._cumulative_supply_until(height)
        remaining = max(0, CFG.MAX_SUPPLY - minted_before)
        return min(base, remaining)

    # ----------------- Genesis -----------------
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
            self.save_chain()
            utxodb = UTXODB()
            utxodb.update(genesis.transactions, block_height=0)
            try:
                utxodb._save()
            except Exception:
                pass
            self.save_state()
            
        else:
            try:
                self.total_supply = self.calculate_total_supply()
            except Exception:
                pass
        return genesis

    # ----------------- Mining -----------------
    def mine_block(self, miner_address, use_cores: int | None = None, cancel_event: MpEvent | None = None, pow_backend: str = "auto", progress_queue: mp.Queue | None = None,):
        if self._has_pending_blocks():
            self.log.warning("[mine_block] ⚠️ Pending blocks detected, skipping mining")
            return None
        if not self._is_chain_consistent():
            self.log.warning("[mine_block] ⚠️ Chain inconsistency detected, syncing first")
            return None

        last_block = self.chain[-1] if self.chain else None
        height     = len(self.chain)
        reward = self.get_block_reward(height)
        if self.total_supply + reward > CFG.MAX_SUPPLY:
            reward = max(0, CFG.MAX_SUPPLY - self.total_supply)
        pool = TxPoolDB()
        txs_from_mempool = pool.get_all_txs()
        utxodb = UTXODB()
        try:
            utxodb._load()
            current_utxos = getattr(utxodb, "utxos", utxodb.load_utxo_set())
        except Exception:
            current_utxos = utxodb.load_utxo_set()

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

            # Passed all checks → include and update temp utxo snapshot
            for txin in tx.inputs:
                used_utxos_in_block.add((txin.txid, txin.vout))
            valid_txs.append(tx)
            try:
                utxodb.apply_tx_to_utxoset(tx, temp_utxos)
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
            self.log.debug("[mine_block] Using bits (LWMA): %s", hex(expected_bits))

        # --- PoW ---
        found = new_block.mine(use_cores=use_cores, stop_event=cancel_event, pow_backend=pow_backend, progress_queue=progress_queue,)
        if not found:
            return None
        if not self.validate_block(new_block):
            return None
        ok = self.add_block(new_block)
        if not ok:
            return None

        self.log.info("[mine_block] Block mined: height=%d reward=%d fee=%d", new_block.height, reward, total_fee)
        return new_block

    # ----------------- Difficulty (LWMA) -----------------

    def _expected_bits_on_prefix(self, prefix: "List[Block]", next_height: int) -> int:
        T = int(CFG.TARGET_BLOCK_TIME)
        if next_height <= 0 or not prefix:
            return int(CFG.MAX_BITS)
        if len(prefix) < 2:
            return int(getattr(prefix[-1], "bits", CFG.MAX_BITS))

        N = min(int(CFG.LWMA_WINDOW), len(prefix))
        window = prefix[-N:]
        k = (N * (N - 1)) // 2
        sum_wst = 0
        sum_diff = 0

        def _ts(b) -> int:
            t = getattr(b, "timestamp", 0)
            return int(t) if isinstance(t, (int, float)) else 0

        prev_ts = _ts(window[0])
        for i in range(1, N):
            b = window[i]
            st = _ts(b) - prev_ts
            if st < -6 * T: st = -6 * T
            if st >  6 * T: st =  6 * T
            if st < 1:      st = 1
            sum_wst += i * st

            bits_val = int(getattr(b, "bits", CFG.MAX_BITS))
            tgt  = bits_to_target(bits_val)
            diff = max(1, int(target_to_difficulty(tgt)))
            sum_diff += diff

            prev_ts = _ts(b)

        avg_diff = max(1, sum_diff // (N - 1))
        lwma_st  = max(1, sum_wst // k)
        next_diff = max(1, (avg_diff * T) // lwma_st)

        next_target = difficulty_to_target(next_diff)
        max_target  = bits_to_target(int(CFG.MAX_BITS))
        if next_target > max_target:
            next_target = max_target
            
            try:
                if CFG.ENABLE_DIFF_CLAMP:
                    prev_bits   = int(getattr(prefix[-1], "bits", CFG.MAX_BITS))
                    prev_target = bits_to_target(prev_bits)
                    factor = float(next_target) / float(prev_target or 1)
                    if factor > float(CFG.DIFF_CLAMP_MAX_UP):
                        next_target = int(prev_target * float(CFG.DIFF_CLAMP_MAX_UP))
                    elif factor < float(CFG.DIFF_CLAMP_MAX_DOWN):
                        next_target = int(prev_target * float(CFG.DIFF_CLAMP_MAX_DOWN))
                    if next_target > max_target:
                        next_target = max_target
            except Exception:
                pass

            try:
                if CFG.ENABLE_EDA:
                    T = int(CFG.TARGET_BLOCK_TIME)
                    M = min(int(CFG.EDA_WINDOW), len(prefix))
                    if M >= 2:
                        def _ts(b) -> int:
                            t = getattr(b, "timestamp", 0)
                            return int(t) if isinstance(t, (int, float)) else 0
                        times = [_ts(b) for b in prefix[-M:]]
                        intervals = []
                        for i in range(1, len(times)):
                            dt = times[i] - times[i-1]
                            if dt < 1: dt = 1
                            intervals.append(dt)
                        if intervals:
                            avg_dt = sum(intervals) / len(intervals)
                            if avg_dt > float(CFG.EDA_TRIGGER_RATIO) * T:
                                eased = int(bits_to_target(int(getattr(prefix[-1], "bits", CFG.MAX_BITS))) * float(CFG.EDA_EASE_MULTIPLIER))
                                next_target = min(int(eased), int(max_target))
            except Exception:
                pass

        return int(target_to_bits(next_target))

    def calculate_expected_bits(self, next_height: int) -> int:
        if next_height <= 0:
            return int(CFG.MAX_BITS)
        prefix = self.chain[:next_height]
        return self._expected_bits_on_prefix(prefix, next_height)

    def _validate_difficulty(self, block: Block) -> bool:
        if block.height == 0:
            return True
        try:
            expected_bits = self.calculate_expected_bits(block.height)
            if int(block.bits) != int(expected_bits):
                return False
            return True
        except Exception as e:
            self.log.exception("[_validate_difficulty] Error calculating expected bits : %s", e)
            return False

    # ----------------- Full chain validation (for replace_with) -----------------
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

            base_reward = CFG.INITIAL_REWARD // (2 ** (0 // CFG.BLOCKS_PER_HALVING))
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
                try:
                    expected_bits = self._expected_bits_on_prefix(chain[:i], int(getattr(cur, "height", i)))
                    got_bits = int(getattr(cur, "bits"))
                    if int(expected_bits) != int(got_bits):
                        return False
                except Exception:
                    self.log.exception("[_validate_complete_chain] Error computing expected bits at %d", i)
                    return False

                if not _pow_ok(cur):
                    return False
                if not _merkle_ok(cur):
                    return False

                txs = getattr(cur, "transactions", []) or []
                if not txs or not getattr(txs[0], "is_coinbase", False) or any(getattr(t, "is_coinbase", False) for t in txs[1:]):
                    return False
                
                fees = sum(int(getattr(t, "fee", 0)) for t in txs[1:])
                base_reward = CFG.INITIAL_REWARD // (2 ** (getattr(cur, "height", 0) // CFG.BLOCKS_PER_HALVING))
                reward = min(base_reward, max(0, CFG.MAX_SUPPLY - cumulative_supply))
                actual_cb = sum(int(o.amount) for o in getattr(txs[0], "outputs", []) or [])
                expected_cb = reward + fees
                if actual_cb != expected_cb:
                    return False
                cumulative_supply += reward

            return True
        except Exception as e:
            self.log.exception("[_validate_complete_chain] Error validating complete chain: %s", e)
            return False

    # ----------------- Timestamp helpers -----------------
    def median_time_past(self, k: int = 11) -> int:
        if not self.chain:
            return 0

        def _to_int_ts(v):
            if isinstance(v, (int, float)):
                return int(v)
            return 0

        window = self.chain[-k:] if len(self.chain) >= k else self.chain
        times = sorted(_to_int_ts(getattr(b, "timestamp", 0)) for b in window)
        return times[len(times) // 2]

    # ----------------- Block lookups -----------------
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
                    return _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                except Exception:
                    return "--:--:--"
            if isinstance(ts, str):
                try:
                    t = ts.replace("Z", "+00:00")
                    return _dt.datetime.fromisoformat(t).strftime("%H:%M:%S")
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

    # ----------------- Validation primitives -----------------
    def _validate_pow(self, block: Block) -> bool:
        try:
            header_hash = block.hash()
            target = bits_to_target(block.bits)
            return int.from_bytes(header_hash, "big") <= int(target)
        except Exception:
            return False

    def _validate_merkle(self, block: Block) -> bool:
        try:
            computed = merkle_root(block.transactions)
            header_mr = getattr(block, "merkle_root", None)
            if isinstance(header_mr, str):
                header_mr = bytes.fromhex(header_mr)
            return computed == header_mr
        except Exception:
            return False

    def _validate_transactions(self, block: Block) -> bool:
        try:
            utxodb = UTXODB()
            try:
                utxodb._load()
                utxos = getattr(utxodb, "utxos", utxodb.load_utxo_set())
            except Exception:
                utxos = utxodb.load_utxo_set()
        except Exception:
            return False

        pool = TxPoolDB()
        txs = getattr(block, "transactions", [])
        if not txs:
            return False

        cb = txs[0]
        if not getattr(cb, "is_coinbase", False):
            return False
        if any(getattr(t, "is_coinbase", False) for t in txs[1:]):
            return False

        total_fee = sum(int(getattr(t, "fee", 0)) for t in txs[1:])
        minted_before = self._cumulative_supply_until(block.height)
        base = CFG.INITIAL_REWARD // (2 ** (block.height // CFG.BLOCKS_PER_HALVING))
        reward = min(max(0, base), max(0, CFG.MAX_SUPPLY - minted_before))
        expected_cb = reward + total_fee

        actual_cb = sum(int(o.amount) for o in getattr(cb, "outputs", []))
        if actual_cb != expected_cb:
            return False
        for tx in txs[1:]:
            if not pool.validate_transaction(tx, utxos):
                return False
        
        return True

    # ----------------- Security/consensus helpers -----------------
    
    def _work_from_bits(self, bits: int) -> int:
        try:
            target = int(bits_to_target(bits))
            if target <= 0:
                return 0
            return (1 << 256) // (target + 1)
        except Exception:
            return 0

    def _estimate_block_size(self, block: Block) -> Optional[int]:
        try:
            size = 80  # header
            for tx in block.transactions or []:
                if hasattr(tx, 'serialize') and callable(getattr(tx, 'serialize', None)):
                    try:
                        raw = tx.serialize()
                        size += len(raw if isinstance(raw, (bytes, bytearray)) else bytes.fromhex(raw))
                        continue
                    except Exception:
                        pass
                if hasattr(tx, 'raw') and isinstance(getattr(tx, 'raw'), (bytes, bytearray)):
                    size += len(tx.raw); continue
                if hasattr(tx, 'size_bytes'):
                    v = tx.size_bytes
                    if callable(v): size += int(v()); 
                    else: size += int(v); continue
                return None
            return int(size)
        except Exception:
            return None

    def _count_block_sigops(self, block: Block) -> Optional[int]:
        total = 0
        try:
            for tx in block.transactions or []:
                if hasattr(tx, 'sigops_count') and callable(getattr(tx, 'sigops_count', None)):
                    total += int(tx.sigops_count()); continue
                if hasattr(tx, 'count_sigops') and callable(getattr(tx, 'count_sigops', None)):
                    total += int(tx.count_sigops()); continue
                return None
            return total
        except Exception:
            return None

    def _compute_chainwork_for_chain(self, chain: List[Block]) -> int:
        cw = 0
        for b in chain:
            w = self._work_from_bits(b.bits)
            cw += w
            try:
                setattr(b, 'chainwork', cw)
            except Exception:
                pass
        return cw

    def _common_ancestor_height(self, other_chain_blocks: List[Block]) -> int:
        if not self.chain or not other_chain_blocks:
            return -1
        index = { self.chain[i].hash(): i for i in range(len(self.chain)) }
        for j in range(len(other_chain_blocks)-1, -1, -1):
            h = other_chain_blocks[j].hash()
            if h in index:
                return index[h]
        return -1
    
    # ----------------- Full block validation -----------------

    def validate_block(self, block: Block) -> bool:
        try:
            with self.lock:
                if not all([block.height is not None, block.prev_block_hash, block.transactions]):
                    return False
                expected_height = self.height + 1 if self.chain else 0
                if block.height != expected_height:
                    return False
                if self.chain and block.prev_block_hash != self.chain[-1].hash():
                    return False
                if not self.chain and (block.height != 0 or block.prev_block_hash != CFG.ZERO_HASH):
                    return False
                if not self.chain and block.height == 0 and GENESIS_HASH is not None:
                    if block.hash() != GENESIS_HASH:
                        return False
                mtp = self.median_time_past(11)
                if block.timestamp < mtp:
                    return False
                if block.timestamp > int(time.time()) + CFG.FUTURE_DRIFT:
                    return False
                if self.chain:
                    parent_ts = int(getattr(self.chain[-1], "timestamp", 0) or 0)
                    if block.timestamp + int(CFG.TARGET_BLOCK_TIME) < parent_ts:
                        return False
                if not self._validate_difficulty(block):
                    return False
                if not self._validate_pow(block):
                    return False
                if not self._validate_merkle(block):
                    return False
                # --- Hardening: duplicate txid check (always runs, not only when the merkle check fails) ---
                try:
                    seen_txids = set()
                    for tx in (block.transactions or []):
                        if hasattr(tx, 'compute_txid') and (getattr(tx, 'txid', None) is None):
                            try:
                                tx.compute_txid()
                            except Exception:
                                return False
                        txid_b = getattr(tx, 'txid', None)
                        if not isinstance(txid_b, (bytes, bytearray)):
                            try:
                                txid_b = bytes.fromhex(txid_b) if isinstance(txid_b, str) else None
                            except Exception:
                                txid_b = None
                        if txid_b is None:
                            return False
                        if txid_b in seen_txids:
                            return False
                        seen_txids.add(txid_b)
                except Exception:
                    return False

                # --- Per-block transaction count & size limits ---
                try:
                    txs_ex_coinbase = max(0, (len(block.transactions) or 0) - 1)
                    if txs_ex_coinbase > CFG.MAX_TXS_PER_BLOCK:
                        return False
                    est_size = self._estimate_block_size(block)
                    if est_size is not None and est_size > CFG.MAX_BLOCK_BYTES:
                        return False
                except Exception:
                    return False

                # --- SIGOPS budget: per-tx & per-block ---
                try:
                    utxodb = UTXODB()
                    try:
                        utxodb._load()
                        utxos = getattr(utxodb, "utxos", utxodb.load_utxo_set())
                    except Exception:
                        utxos = utxodb.load_utxo_set()

                    def _utxo_lookup(txid_b: bytes, vout_i: int):
                        try:
                            k = f"{txid_b.hex()}:{int(vout_i)}"
                            entry = utxos.get(k) if isinstance(utxos, dict) else None
                            if entry is None:
                                return None
                            if isinstance(entry, dict):
                                spk_hex = ((entry.get("tx_out") or {}).get("script_pubkey")
                                        or entry.get("script_pubkey"))
                                if isinstance(spk_hex, str):
                                    return bytes.fromhex(spk_hex)
                                txo = entry.get("tx_out")
                                if hasattr(txo, "script_pubkey"):
                                    return txo.script_pubkey.serialize()
                            if hasattr(entry, "tx_out") and hasattr(entry.tx_out, "script_pubkey"):
                                return entry.tx_out.script_pubkey.serialize()
                        except Exception:
                            return None
                        return None

                    total_sigops = 0
                    for tx in (block.transactions or []):
                        if getattr(tx, "is_coinbase", False):
                            continue
                        so = int(tx.sigops_count(_utxo_lookup)) if hasattr(tx, "sigops_count") else len(getattr(tx, "inputs", []))
                        if so > int(CFG.MAX_SIGOPS_PER_TX):
                            return False
                        total_sigops += so

                    if total_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
                        return False
                except Exception:
                    est_sigops = self._count_block_sigops(block)
                    if est_sigops is not None and est_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
                        return False
                    
                if block.height > 0 and not self._validate_transactions(block):
                    return False

            return True
        except Exception as e:
            self.log.exception("[validate_block] Unexpected error during block validation: %s", e)
            return False