# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import multiprocessing as mp
import time
from typing import List, Optional
from multiprocessing.synchronize import Event as MpEvent


# ---------------- Local Project ----------------
from ..utils.helpers import int_to_little_endian, merkle_root, pow_hash_verify_light, bits_to_target, pow_key_for_height, native_randomx_mine
from ..core.coinbase import CoinbaseTx
from ..core.tx import Tx
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.core.block")

class BlockHeader:
    def __init__(self, version: int, prev_block_hash: bytes, merkle_root: bytes, timestamp: int, bits: int, nonce: int):
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def serialize_block(self) -> bytes:
        return (
            int_to_little_endian(self.version, 4) +
            (self.prev_block_hash if isinstance(self.prev_block_hash, (bytes, bytearray))
             else bytes.fromhex(self.prev_block_hash)) +
            (self.merkle_root if isinstance(self.merkle_root, (bytes, bytearray))
             else bytes.fromhex(self.merkle_root)) +
            int_to_little_endian(self.timestamp, 4) +
            int_to_little_endian(self.bits, 4) +
            int_to_little_endian(self.nonce, 4))


class Block:
    def __init__(self, height: int, prev_block_hash: bytes, transactions: List[Tx], version: int = 1, bits: int = CFG.INITIAL_BITS, timestamp: Optional[int] = None, nonce: int = 0, merkle_root_precomputed: bytes | None = None):
        self.height = height
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.transactions = transactions
        if merkle_root_precomputed is not None:
            self.merkle_root = bytes(merkle_root_precomputed)
        else:
            self.merkle_root = merkle_root(transactions)
        
        self.timestamp = int(time.time()) if timestamp is None else timestamp
        self.bits = bits
        self.nonce = nonce
        # Cache hash to avoid repeated RandomX verification during validation
        self._cached_hash = None
        self._cached_hash_nonce = None
        self._cached_hash_bits = None
        self._cached_hash_mr = None
        self._cached_hash_prev = None
        

    def to_dict(self):
        return {
            "height": self.height,
            "version": self.version,
            "prev_block_hash": self.prev_block_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "timestamp": self.timestamp,
            "bits": int(self.bits),
            "nonce": self.nonce,
            "hash": self.hash().hex(),
            "transactions": [tx.to_dict() for tx in self.transactions],}
        
    @staticmethod
    def _parse_bits(v):
        if v is None:
            return int(CFG.INITIAL_BITS) & 0xFFFFFFFF
        if isinstance(v, bool):
            return int(CFG.INITIAL_BITS) & 0xFFFFFFFF
        if isinstance(v, int):
            return v & 0xFFFFFFFF
        if isinstance(v, float):
            if v.is_integer():
                return int(v) & 0xFFFFFFFF
            raise TypeError(f"bits float non-integer: {v}")
        if isinstance(v, str):
            s = v.strip().lower()
            return int(s, 16) if s.startswith("0x") else int(s)
        raise TypeError(f"bits must be int/hexstr, got {type(v)}")

    @classmethod
    def from_dict(cls, data):
        tx_list = []
        for tx_data in data["transactions"]:
            tx_type = tx_data.get("type")
            if tx_type == "Coinbase" or tx_data.get("is_coinbase"):
                try:
                    tx_obj = CoinbaseTx.from_dict(tx_data)
                except Exception:
                    tx_obj = Tx.from_dict(tx_data)
                    log.exception("[Block.from_dict] Failed to parse CoinbaseTx, fallback to Tx")
            else:
                tx_obj = Tx.from_dict(tx_data)
            tx_list.append(tx_obj)
        prev_hash_bytes = (
            bytes.fromhex(data["prev_block_hash"])
            if not isinstance(data["prev_block_hash"], bytes)
            else data["prev_block_hash"])
        mr_bytes = data.get("merkle_root")
        if isinstance(mr_bytes, str):
            mr_bytes = bytes.fromhex(mr_bytes)
        
        obj = cls(
            height=data["height"],
            prev_block_hash=prev_hash_bytes,
            transactions=tx_list,
            timestamp=data.get("timestamp"),
            nonce=data.get("nonce"),
            bits=cls._parse_bits(data.get("bits")),
            version=data.get("version", 1),
            merkle_root_precomputed=mr_bytes,)
        
        # cache hash if provided to avoid double PoW verify; validation will still verify
        try:
            h_str = data.get("hash")
            if isinstance(h_str, str) and len(h_str) >= 64:
                h_b = bytes.fromhex(h_str)
                obj._cached_hash = h_b
                obj._cached_hash_nonce = obj.nonce
                obj._cached_hash_bits = obj.bits
                obj._cached_hash_mr = obj.merkle_root
                obj._cached_hash_prev = obj.prev_block_hash
        except Exception:
            log.exception("cache_hash_skiped")
            pass

        meta = data.get("_meta")
        if isinstance(meta, dict):
            try:
                obj._meta = dict(meta)
                if getattr(obj, "chainwork", None) is None and "chainwork" in meta:
                    obj.chainwork = meta.get("chainwork")
                if getattr(obj, "difficulty", None) is None and "difficulty" in meta:
                    obj.difficulty = meta.get("difficulty")
                if getattr(obj, "size_bytes", None) is None and "size_bytes" in meta:
                    obj.size_bytes = meta.get("size_bytes")
                if getattr(obj, "vbytes", None) is None and "vbytes" in meta:
                    obj.vbytes = meta.get("vbytes")
                if getattr(obj, "weight", None) is None and "weight" in meta:
                    obj.weight = meta.get("weight")
            except Exception:
                log.exception("cache_meta_skipped")
        return obj

    def header(self) -> bytes:
        h = BlockHeader(self.version, self.prev_block_hash, self.merkle_root, self.timestamp, self.bits, self.nonce)
        return h.serialize_block()

    @classmethod
    def deserialize_block(cls, data: dict):
        return cls.from_dict(data)

    # -----------------------------
    # MINING
    # -----------------------------

    def hash(self) -> bytes:
        # Recompute only if inputs changed (nonce/bits/merkle_root/prev_hash)
        if (
            isinstance(self._cached_hash, (bytes, bytearray))
            and self._cached_hash_nonce == self.nonce
            and self._cached_hash_bits == self.bits
            and self._cached_hash_mr == self.merkle_root
            and self._cached_hash_prev == self.prev_block_hash
        ):
            return self._cached_hash

        try:
            key_hint = pow_key_for_height(self.height)
            h = pow_hash_verify_light(self.header(), key_hint=key_hint)
        except Exception:
            log.exception("key_hint_err")
            h = pow_hash_verify_light(self.header(), height=self.height)
        self._cached_hash = h
        self._cached_hash_nonce = self.nonce
        self._cached_hash_bits = self.bits
        self._cached_hash_mr = self.merkle_root
        self._cached_hash_prev = self.prev_block_hash
        return h

    def is_valid(self, target: int):
        hnum = int.from_bytes(self.hash(), 'big')
        return hnum < target

    def mine(self, use_cores: int = None, stop_event: Optional[MpEvent] = None, pow_backend: str = "auto", progress_queue: Optional[mp.Queue] = None):
        self.nonce = 0
        if stop_event is not None and stop_event.is_set():
            return None

        total_cores = mp.cpu_count()
        if not isinstance(use_cores, int) or use_cores < 1:
            use_cores = 1
        num_cores = use_cores if use_cores <= total_cores else total_cores

        target = bits_to_target(self.bits)
        if target <= 0:
            return None

        default_backend = (CFG.POW_ALGO or "randomx").strip().lower()
        requested = (pow_backend or "auto").strip().lower()
        backend = requested if requested not in ("", "auto") else default_backend
        if backend in ("", "auto"):
            backend = "randomx"
        if backend != "randomx":
            raise RuntimeError(f"Unsupported PoW backend '{backend}'. Only RandomX is available.")

        pow_key = pow_key_for_height(self.height)
        if not pow_key:
            raise RuntimeError("RandomX key derivation failed; check RANDOMX_* configuration.")

        header_prefix = self.header()[:-4]
        target_be = int(target).to_bytes(32, "big", signed=False)
        threads = num_cores

        found = native_randomx_mine(
            header_prefix,
            target_be,
            pow_key,
            threads=threads,
            full_mem=bool(CFG.RANDOMX_FULL_MEM),
            large_pages=bool(CFG.RANDOMX_LARGE_PAGES),
            jit=bool(CFG.RANDOMX_JIT),
            hard_aes=bool(CFG.RANDOMX_HARD_AES),
            secure_jit=bool(CFG.RANDOMX_SECURE_JIT),
            progress_queue=progress_queue,
            progress_interval_ms=250,
            stop_event=stop_event,
        )

        if isinstance(found, tuple) and len(found) == 2:
            nonce, h = found
            self.nonce = int(nonce)
            if pow_hash_verify_light(self.header(), key_hint=pow_key) != h:
                log.error("[mine] native hash verification failed (nonce=%s)", self.nonce)
                return None
            return h
        return None


    def __repr__(self):
        return (
            f"--- Block {self.height} ---\n"
            f"PrevHash : {self.prev_block_hash.hex()}\n"
            f"Hash     : {self.hash().hex()}\n"
            f"Time     : {time.ctime(self.timestamp)}\n"
            f"Nonce    : {self.nonce}\n"
            f"Tx Count : {len(self.transactions)}\n"
        )