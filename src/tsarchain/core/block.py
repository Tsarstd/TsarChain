# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import multiprocessing as mp
import struct, time, queue, psutil
from typing import List, Optional
from multiprocessing.synchronize import Event as MpEvent


# ---------------- Local Project ----------------
from ..utils.helpers import int_to_little_endian, merkle_root, pow_hash_miner, pow_hash_verify_light, bits_to_target, pow_key_for_height
from ..core.coinbase import CoinbaseTx
from ..core.tx import Tx
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger

class BlockHeader:
    def __init__(self, version: int, prev_block_hash: bytes, merkle_root: bytes,
                 timestamp: int, bits: int, nonce: int):
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
    def __init__(self, height: int, prev_block_hash: bytes, transactions: List[Tx], version: int = 1, bits: int = CFG.INITIAL_BITS, timestamp: Optional[int] = None, nonce: int = 0):
        self.height = height
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.transactions = transactions
        self.merkle_root = merkle_root(transactions)
        self.timestamp = int(time.time()) if timestamp is None else timestamp
        self.bits = bits
        self.nonce = nonce
        short_prev = (self.prev_block_hash.hex()[:8]
              if isinstance(self.prev_block_hash, (bytes, bytearray))
              else str(self.prev_block_hash)[:8])
        self.log = get_ctx_logger("tsarchain.core(block)", height=self.height, block=short_prev)
        

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
                except Exception as e:
                    tx_obj = Tx.from_dict(tx_data)
                    get_ctx_logger("tsarchain.core.block").exception("[Block.from_dict] Failed to parse CoinbaseTx, fallback to Tx")
            else:
                tx_obj = Tx.from_dict(tx_data)
            tx_list.append(tx_obj)
        prev_hash_bytes = (
            bytes.fromhex(data["prev_block_hash"])
            if not isinstance(data["prev_block_hash"], bytes)
            else data["prev_block_hash"])
        
        return cls(
            height=data["height"],
            prev_block_hash=prev_hash_bytes,
            transactions=tx_list,
            timestamp=data.get("timestamp"),
            nonce=data.get("nonce"),
            bits=cls._parse_bits(data.get("bits")),
            version=data.get("version", 1),)

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
        return pow_hash_verify_light(self.header(), height=self.height)

    def is_valid(self, target: int):
        hnum = int.from_bytes(self.hash(), 'big')
        return hnum < target

    def mine(self, use_cores: int = None, stop_event: Optional[MpEvent] = None, pow_backend: str = "auto", progress_queue: Optional[mp.Queue] = None):
        self.nonce = 0
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
        
        self.log.info(
            "[mine] Mining with %s/%s cores, Target: %s, Backend=%s",
            num_cores,
            total_cores,
            hex(target),
            backend,
        )

        header_without_nonce = self.header()[:-4]
        start_time = time.time()
        result_queue = mp.Queue()
        processes: list[mp.Process] = []
        found_event = mp.Event()
        created_local_stop = False
        if stop_event is None:
            stop_event = mp.Event()
            created_local_stop = True

        worker_target = type(self).mine_worker_randomx
        
        if num_cores == 1:
            nonce = 0
            max_nonce = (2**32 - 1)
            hash_count = 0
            last_report_time = time.time()
            header = bytearray(header_without_nonce)
            header.extend(b"\x00\x00\x00\x00")
            nonce_offset = len(header) - 4
            while nonce <= max_nonce:
                if stop_event is not None and stop_event.is_set():
                    return None
                struct.pack_into("<I", header, nonce_offset, nonce & 0xFFFFFFFF)
                block_hash = pow_hash_miner(header, key_hint=pow_key)
                if int.from_bytes(block_hash, "big") < target:
                    self.nonce = nonce & 0xFFFFFFFF
                    
                    # LIGHT verification to prevent second dataset in parent
                    if pow_hash_verify_light(self.header(), key_hint=pow_key) != block_hash:
                        return None
                    self.log.info("[mine] Block mined: nonce=%s, hash=%s", self.nonce, block_hash.hex())
                    return block_hash
                
                # progress every ~5 second
                now = time.time()
                hash_count += 1
                if now - last_report_time >= 5.0:
                    if progress_queue is not None:
                        try:
                            hps = hash_count / max(1e-9, (now - last_total_print))
                        except NameError:
                            hps = hash_count / max(1e-9, (now - last_report_time))
                        try:
                            progress_queue.put(('TOTAL_HPS', float(hps)))
                        except Exception:
                            pass
                    hash_count = 0
                    last_report_time = now
                nonce += 1
            return None

        cpu_ids = list(range(total_cores))
        for i in range(num_cores):
            p = mp.Process(
                target=worker_target,
                args=(i, num_cores, header_without_nonce, target,
                      result_queue, found_event, stop_event, pow_key))
            p.daemon = True
            p.start()
            processes.append(p)

            try:
                proc = psutil.Process(p.pid)
                if hasattr(proc, "cpu_affinity"):
                    proc.cpu_affinity([cpu_ids[i % len(cpu_ids)]])
                if hasattr(psutil, "HIGH_PRIORITY_CLASS"):
                    proc.nice(psutil.HIGH_PRIORITY_CLASS)
            except Exception:
                self.log.exception("[mine] psutil affinity/nice failed for pid=%s", p.pid)

        alive_after_launch = sum(1 for p in processes if p.is_alive())
        if alive_after_launch < num_cores:
            self.log.warning("[mine] Only %s/%s worker alive.", alive_after_launch, num_cores)

        timeout_sec = 3600
        deadline = start_time + timeout_sec
        nonce, found_hash = None, None
        total_hps_accum = 0.0
        reports_since_print = 0
        last_total_print = time.time()
        REPORT_WINDOW = 15

        try:
            while True:
                if stop_event.is_set():
                    return None

                try:
                    msg = result_queue.get(timeout=0.2)
                except queue.Empty:
                    alive_now = sum(1 for p in processes if p.is_alive())
                    if alive_now == 0 and not found_event.is_set():
                        return None
                    if time.time() >= deadline:
                        return None
                    nowp = time.time()
                    if (nowp - last_total_print) >= REPORT_WINDOW and reports_since_print > 0:
                        #self.log.trace("[mine] ⛏️ Total Hashrate: %s H/s", f"{total_hps_accum:,.0f}")
                        if progress_queue is not None:
                            try:
                                progress_queue.put(('TOTAL_HPS', total_hps_accum))
                            except Exception:
                                pass
                        total_hps_accum = 0.0
                        reports_since_print = 0
                        last_total_print = nowp
                    continue

                if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == 'PROGRESS':
                    try:
                        total_hps_accum += float(msg[1])
                        reports_since_print += 1
                    except Exception:
                        pass
                    nowp = time.time()
                    if reports_since_print >= num_cores or (nowp - last_total_print) >= REPORT_WINDOW:
                        #self.log.trace("[mine] ⛏️ Total Hashrate: %s H/s", f"{total_hps_accum:,.0f}")
                        if progress_queue is not None:
                            try:
                                progress_queue.put(('TOTAL_HPS', total_hps_accum))
                            except Exception:
                                pass
                        total_hps_accum = 0.0
                        reports_since_print = 0
                        last_total_print = nowp
                    continue

                if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == 'ERR':
                    self.log.error("[mine] Worker error: %s", msg[1])
                    continue

                nonce, found_hash = msg
                break

            elapsed = time.time() - start_time
            if nonce is not None and found_hash:
                self.nonce = nonce
                if pow_hash_verify_light(self.header(), key_hint=pow_key) != found_hash:
                    return None
                self.log.info("[mine] Block mined: nonce=%s, hash=%s (time=%.2fs)", self.nonce, found_hash.hex(), elapsed)
                return found_hash
            else:
                self.log.warning("[mine] Mining failed: no valid nonce found (time=%.2fs)", elapsed)
                return None

        finally:
            try:
                found_event.set()
                if created_local_stop:
                    stop_event.set()
            except Exception:
                pass

            for p in processes:
                try:
                    p.join(timeout=1.0)
                except Exception:
                    pass

            for p in processes:
                if p.is_alive():
                    try:
                        p.terminate()
                        p.join(timeout=1.0)
                    except Exception:
                        self.log.exception("[mine] terminate failed pid=%s", p.pid)

            for p in processes:
                if p.is_alive():
                    try:
                        p.kill()
                    except Exception:
                        self.log.exception("[mine] kill failed pid=%s", p.pid)

            try:
                result_queue.close()
            except Exception:
                pass
            try:
                result_queue.join_thread()
            except Exception:
                pass

    # ==== RandomX workers: kirim ('PROGRESS', hps) setiap ~5 detik ====

    @staticmethod
    def mine_worker_randomx(start_nonce, step, header_template, target, result_queue, found_event: MpEvent, stop_event: MpEvent, pow_key: bytes):
        try:
            nonce = start_nonce
            max_nonce = (2**32 - 1)
            hash_count = 0
            last_report_time = time.time()

            header = bytearray(header_template)
            header.extend(b"\x00\x00\x00\x00")
            nonce_offset = len(header) - 4

            while nonce <= max_nonce:
                if stop_event.is_set() or found_event.is_set():
                    break

                struct.pack_into("<I", header, nonce_offset, nonce & 0xFFFFFFFF)
                block_hash = pow_hash_miner(header, key_hint=pow_key)
                hash_int = int.from_bytes(block_hash, "big")
                hash_count += 1

                now = time.time()
                if now - last_report_time >= 5.0:
                    if stop_event.is_set() or found_event.is_set():
                        break
                    elapsed = now - last_report_time
                    hps = (hash_count / elapsed) if elapsed > 0 else 0.0
                    try:
                        result_queue.put(('PROGRESS', hps))
                    except Exception:
                        pass
                    last_report_time = now
                    hash_count = 0

                if hash_int < target:
                    if not found_event.is_set() and not stop_event.is_set():
                        found_event.set()
                        result_queue.put((nonce & 0xFFFFFFFF, block_hash))
                    return

                nonce += step

            if not stop_event.is_set() and not found_event.is_set():
                result_queue.put((None, None))

        except KeyboardInterrupt:
            try:
                stop_event.set()
            except Exception:
                pass
            return
        
        except Exception as e:
            try:
                result_queue.put(('ERR', f"RX-Core {start_nonce % max(1, step)} -> {e!r}"))
            except Exception:
                pass


    def __repr__(self):
        return (
            f"--- Block {self.height} ---\n"
            f"PrevHash : {self.prev_block_hash.hex()}\n"
            f"Hash     : {self.hash().hex()}\n"
            f"Time     : {time.ctime(self.timestamp)}\n"
            f"Nonce    : {self.nonce}\n"
            f"Tx Count : {len(self.transactions)}\n"
        )
