# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE and TRADEMARKS.md
# Refs: BIP173

"""
TsarChain — CLI Miner (Light, Stateless)

Role
- Mining with in-memory chain; no on-disk chain persistence.
- Stateless tip-sync: only pulls latest tip + a small header window for difficulty.
- Mines empty blocks (coinbase only); no mempool handling or tx inclusion.

Intended environment
- Dedicated mining rigs.

Safety & behavior
- Sync-gated: starts hashing only after at least 1 peer and a retrieved tip window.
- Validates header/consensus core locally for the mined block (prev-hash, target, timestamp).
- Mines empty blocks (coinbase only).
- Reorg-safe: refreshes tip window each round before hashing.

Notes
- For full-node duties and transaction inclusion, use `cli_node_miner.py`.
"""

from __future__ import annotations

import argparse, errno, signal, time, threading, queue, os, sys
import multiprocessing as mp
from datetime import datetime

# ---------- Local Project ----------
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network
from tsarchain.core.block import Block
from tsarchain.core.coinbase import CoinbaseTx
from tsarchain.utils import config as CFG

from tsarchain.utils.cosmetic import interface as COL
from tsarchain.utils.cosmetic.tui import MinerTUI, create_tui_logger

from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
log = get_ctx_logger("apps.cli_miner")

INTERRUPTED_ERRNOS = {
    code
    for code in (
        getattr(errno, "EINTR", None),
        getattr(errno, "WSAEINTR", None),
    )
    if code is not None
}


def _enable_siginterrupt():
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            signal.siginterrupt(sig, True)
        except Exception:
            continue


def _stamp() -> str:
    now = datetime.now()
    d = f"{now.year:04d}.{now.month:02d}.{now.day:02d}"
    t = f"{now.hour:02d}.{now.minute:02d}.{now.second:02d}"
    return f"{COL.BOLD}{COL.bg_rgb_color(43, 128, 197)} {d} {COL.RESET}{COL.BOLD}{COL.bg_rgb_color(197, 168, 43)} {t} {COL.RESET}"

def clog(message: str, color: str = COL.GREY):
    if 'tui_logger' in globals():
        tui_logger(f"{_stamp()} : {color}{message}{COL.RESET}")
    else:
        print(f"{_stamp()} : {color}{message}{COL.RESET}")

def human_hps(hps: float) -> str:
    hps = float(hps)
    units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s"]
    i = 0
    while hps >= 1000.0 and i < len(units)-1:
        hps /= 1000.0
        i += 1
    if hps >= 100:
        return f"{hps:,.0f} {units[i]}"
    if hps >= 10:
        return f"{hps:,.1f} {units[i]}"
    return f"{hps:,.2f} {units[i]}"

class HashrateReporter(threading.Thread):
    def __init__(self, q: mp.Queue, name="HashrateReporter"):
        super().__init__(name=name, daemon=True)
        self.q = q
        self.stop_event = mp.Event()

    def run(self):
        last_line = ""
        while not self.stop_event.is_set():
            try:
                msg = self.q.get(timeout=1.0)
            except queue.Empty:
                continue
            if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == "TOTAL_HPS":
                hps = human_hps(msg[1])
                line = f"Hashrate ~ {hps} {COL.DIM}{COL.RESET}"
                if line != last_line:
                    clog(line, color=COL.CYAN)
                    last_line = line


def _register_bootstrap_peers(network: Network) -> int:
    fallback_nodes = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
    count = 0
    for peer in fallback_nodes:
        if not peer:
            continue
        network.persistent_peers.add(peer)
        network.peers.add(peer)
        count += 1
    return count


class LightMiner:
    def __init__(
        self,
        address: str,
        cores: int,
        *,
        progress_queue: mp.Queue | None = None,
        tui: MinerTUI | None = None,
    ):
        self.address = address
        self.cores = cores
        self.blockchain: Blockchain | None = None
        self.network: Network | None = None
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self._progress_q: mp.Queue = progress_queue or mp.Queue()
        self.tui = tui
        self.tip_height: int = -1
        self._best_peer: tuple[str, int] | None = None

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        _enable_siginterrupt()

    # -------- lifecycle --------
    def _handle_signal(self, signum, _frame):
        clog(f"[signal] Received {signum}; stopping miner...", color=COL.BG_YELLOW)
        log.info("Ctrl+C / signal %s received - stopping light miner loop", signum)
        self.mining_alive = False
        self.cancel_mining.set()

    def validate_address(self) -> bool:
        if not self.address or not self.address.lower().startswith("tsar1"):
            clog("Error: Address must start with 'tsar1...' (bech32)")
            return False
        return True

    def start_node(self) -> bool:
        try:
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=True,  # <-- no disk persistence, only RAM
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            clog(f"Connected to TsarChain Network...")
            return True
        except Exception as exc:
            clog(f"Failed to connect: {exc}")
            return False

    def _disable_sync_loop(self) -> None:
        """Stop background header/full sync from running a full chain download."""
        if not self.network:
            return
        self.network.sync_with_peers = lambda: None  # type: ignore[assignment]
        self.network.request_sync = lambda fast=False: None  # type: ignore[assignment]
        self.network._sync_event.clear()
        self.network._sync_fast_until = 0.0

    def _pick_peer(self) -> tuple[str, int] | None:
        if not self.network:
            return None
        peers = list(getattr(self.network, "peers", ()))
        if not peers:
            peers = list(getattr(self.network, "persistent_peers", ()))
        if not peers:
            return None
        peers.sort(key=lambda p: self.network.peer_scores.get(p, 0), reverse=True)
        return peers[0]

    def _hello_peer(self, peer: tuple[str, int]) -> dict | None:
        if not self.network:
            return None
        payload = {
            "type": "HELLO",
            "role": "NODE_MINER",
            "height": max(-1, self.tip_height),
            "port": getattr(self.network, "port", 0),
            "peers": [],
        }
        resp = self.network._rpc_request(peer, payload, timeout=max(8.0, CFG.SYNC_TIMEOUT))
        if resp and resp.get("type") == "HELLO_RESPONSE":
            self.network.peers.add(peer)
            self.network.outbound_peers.add(peer)
            self.network.peer_scores.setdefault(peer, CFG.PEER_SCORE_START)
            h = int(resp.get("height", -1))
            self.network._peer_best_height[peer] = h
        return resp

    def _fetch_tip_height(self, peer: tuple[str, int]) -> int:
        resp = self._hello_peer(peer)
        height = -1
        if resp:
            height = int(resp.get("height", -1))
        if height >= 0:
            return height
        if not self.network:
            return -1
        info = self.network._rpc_request(peer, {"type": "GET_INFO"}, timeout=max(8.0, CFG.SYNC_TIMEOUT))
        if info and isinstance(info, dict):
            return int(info.get("height", -1))
        return -1

    def _fetch_recent_blocks(self, peer: tuple[str, int], tip_height: int) -> list[dict]:
        if not self.network or tip_height < 0:
            return []
        window = max(2, int(CFG.LWMA_WINDOW) + 2)
        start_h = max(0, tip_height - window + 1)
        heights = list(range(start_h, tip_height + 1))
        chunk_size = max(1, min(256, int(CFG.BLOCK_DOWNLOAD_BATCH_MAX)))
        blocks: list[dict] = []
        for i in range(0, len(heights), chunk_size):
            chunk = heights[i : i + chunk_size]
            payload = {"type": "GET_BLOCKS", "heights": chunk, "port": getattr(self.network, "port", 0)}
            resp = self.network._rpc_request(peer, payload, timeout=max(15.0, CFG.SYNC_TIMEOUT))
            if not resp or resp.get("type") != "BLOCKS":
                return []
            items = resp.get("blocks") or []
            if not isinstance(items, list):
                return []
            blocks.extend(items)
        blocks.sort(key=lambda b: int(b.get("height", 0)))
        return blocks

    def _get_block_hash(self, peer: tuple[str, int], height: int) -> str | None:
        if not self.network or height < 0:
            return None
        payload = {"type": "GET_BLOCK_HASH", "height": int(height), "port": getattr(self.network, "port", 0)}
        resp = self.network._rpc_request(peer, payload, timeout=max(6.0, CFG.SYNC_TIMEOUT))
        if resp and resp.get("type") == "BLOCK":
            hx = resp.get("hash")
            if isinstance(hx, str) and hx:
                return hx.lower()
        return None

    def _headers_from_blocks(self, blocks: list[dict]):
        class HeaderView:
            __slots__ = ("height", "bits", "timestamp")

            def __init__(self, height: int, bits: int, timestamp: int):
                self.height = height
                self.bits = bits
                self.timestamp = timestamp

        views = []
        for obj in blocks:
            h = int(obj.get("height", -1))
            bits_raw = obj.get("bits", CFG.MAX_BITS)
            bits_val = Block._parse_bits(bits_raw)  # type: ignore[arg-type]
            ts = int(obj.get("timestamp", 0) or 0)
            views.append(HeaderView(h, bits_val, ts))
        return views

    def _compute_expected_bits(self, headers, next_height: int) -> int:
        if not headers:
            return int(CFG.MAX_BITS)
        return int(self.blockchain._expected_bits_on_prefix(headers, next_height))  # type: ignore[attr-defined]

    def _median_time(self, headers) -> int:
        if not headers:
            return int(time.time())
        window = headers[-min(len(headers), int(CFG.MTP_WINDOWS)) :]
        ts_sorted = sorted(int(getattr(h, "timestamp", 0) or 0) for h in window)
        if not ts_sorted:
            return int(time.time())
        return ts_sorted[len(ts_sorted) // 2]

    def _build_empty_block(self, tip_block: dict, next_height: int, expected_bits: int, mtp_ts: int) -> Block | None:
        if not self.blockchain:
            return None
        prev_hex = str(tip_block.get("hash") or "").strip()
        if not prev_hex:
            return None
        prev_hash = bytes.fromhex(prev_hex)
        ts_tip = int(tip_block.get("timestamp", 0) or 0)
        now_ts = int(time.time())
        timestamp = max(now_ts, ts_tip + 1, int(mtp_ts) + 1)
        reward = 0
        reward = int(self.blockchain.get_block_reward(next_height))
        if reward <= 0:
            clog(f"[mining] reward is zero at height {next_height}; stopping.")
            self.mining_alive = False
            return None

        coinbase = CoinbaseTx(to_address=self.address, reward=reward, height=next_height)
        coinbase.compute_txid()
        block = Block(
            height=next_height,
            prev_block_hash=prev_hash,
            transactions=[coinbase],
            bits=int(expected_bits),
            timestamp=timestamp,
        )
        return block

    def _mine_block_runner(self, candidate: Block, result: dict):
        """Worker to mine a block so main loop can react instantly to Ctrl+C."""
        h = candidate.mine(
            use_cores=self.cores,
            stop_event=self.cancel_mining,
            pow_backend="randomx",
            progress_queue=self._progress_q,
        )
        result["hash"] = h

    def start_mining(self, timeout: int = 600) -> bool:
        if not self.validate_address():
            return False
        if not self.start_node():
            return False
        self._disable_sync_loop()

        clog("=== Mining Informations ===")
        clog(f"Address : {self.address}")
        clog(f"Cores   : {self.cores}")
        mode_label = "FULL-MEM (+2.5GB)" if bool(CFG.RANDOMX_FULL_MEM) else "LIGHT"
        clog(f"RandomX : {mode_label}")
        clog("NOTE    : Stateless mode. Fetches tip window only; mines empty blocks.", color=COL.BG_YELLOW)

        reporter = HashrateReporter(self._progress_q)
        reporter.start()

        while self.mining_alive:
            try:
                peer = self._pick_peer()
                if not peer:
                    clog("[sync] Waiting for peer connection...", color=COL.BG_YELLOW)
                    time.sleep(2)
                    continue

                tip_h = self._fetch_tip_height(peer)
                if tip_h < 0:
                    clog(f"[sync] Failed to fetch tip height from {peer}", color=COL.BG_YELLOW)
                    time.sleep(2)
                    continue

                self.tip_height = tip_h
                blocks = self._fetch_recent_blocks(peer, tip_h)
                if not blocks:
                    clog(f"[sync] Failed to fetch recent blocks from {peer}", color=COL.BG_YELLOW)
                    time.sleep(2)
                    continue

                tip_block = blocks[-1]
                headers = self._headers_from_blocks(blocks)
                expected_bits = self._compute_expected_bits(headers, tip_h + 1)
                mtp_ts = self._median_time(headers)
                candidate = self._build_empty_block(tip_block, tip_h + 1, expected_bits, mtp_ts)
                if not candidate:
                    time.sleep(1)
                    continue

                tip_hash = str(tip_block.get("hash") or "").strip().lower()
                self._best_peer = peer
                tip_hex = str(tip_block.get("hash", ""))[:18]
                clog(f"[sync] Tip {tip_h} {tip_hex}... -> target bits {hex(expected_bits)}")
                clog(f"[mining] Mining empty block at height {candidate.height}")

                result_holder: dict = {}
                mine_thread = threading.Thread(
                    target=self._mine_block_runner,
                    args=(candidate, result_holder),
                    name="LightMineWorker",
                    daemon=True,
                )
                mine_thread.start()

                cancel_logged = False
                while mine_thread.is_alive() and self.mining_alive:
                    mine_thread.join(timeout=0.5)
                    if self.cancel_mining.is_set() and not cancel_logged:
                        clog("[mining] Cancellation requested; waiting for miner thread to stop...", color=COL.BG_YELLOW)
                        log.info("Cancellation requested; waiting for light miner thread to stop...")
                        cancel_logged = True

                if mine_thread.is_alive():
                    mine_thread.join(timeout=2.0)

                h = result_holder.get("hash")
                exc = result_holder.get("exc")
                if exc:
                    raise exc

                if not self.mining_alive or self.cancel_mining.is_set():
                    break
                if not h:
                    time.sleep(1)
                    continue

                if self.tui is not None:
                    self.tui.note_block_mined(getattr(candidate, "height", None))

                clog(
                    f"Block mined at height {candidate.height}: {candidate.hash().hex()[:18]}... (empty block, coinbase only)"
                )
                # Re-validate tip before broadcast to avoid stale height/hash
                current_h = self._fetch_tip_height(peer)
                current_hash = self._get_block_hash(peer, current_h) if current_h >= 0 else None
                if current_h > tip_h:
                    clog(f"[broadcast] Tip advanced to {current_h}; dropping stale block {candidate.height}", color=COL.BG_YELLOW)
                    continue
                if current_h == tip_h and current_hash and tip_hash and current_hash != tip_hash:
                    clog("[broadcast] Tip hash changed at same height; dropping stale block", color=COL.BG_YELLOW)
                    continue

                sent = self.network.publish_block(candidate, exclude=None, force=True) if self.network else 0
                if sent <= 0:
                    clog("[broadcast] No peers reached when publishing block.", color=COL.BG_YELLOW)

            except KeyboardInterrupt:
                self.mining_alive = False
                self.cancel_mining.set()
                clog("[signal] Mining interrupted by user; stopping workers...", color=COL.BG_YELLOW)
                log.info("Mining loop interrupted by KeyboardInterrupt (Ctrl+C).")
            except Exception as exc:
                if isinstance(exc, OSError) and getattr(exc, "errno", None) in INTERRUPTED_ERRNOS:
                    clog("[mining] Interrupted system call; stopping miners...", color=COL.BG_YELLOW)
                    self.mining_alive = False
                    self.cancel_mining.set()
                    break
                clog(f"[mining] Error: {exc}")
                time.sleep(1)
        reporter.stop_event.set()
        return True

    def shutdown(self):
        self.mining_alive = False
        self.cancel_mining.set()
        if self.network:
            self.network.shutdown()
            self.network = None
        clog("[light-node] Shutdown complete.", color=COL.BG_YELLOW)
        log.info("Light miner stopped (cleanup complete).")

def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain Stateless CLI Miner (RandomX)")
    parser.add_argument("--address", help="Miner payout address (tsar1...)")
    parser.add_argument("--cores", type=int, help="CPU cores to dedicate")
    parser.add_argument("--timeout", type=int, default=600, help="Sync timeout (seconds)")
    parser.add_argument("--rx-full", action="store_true", help="Enable RandomX FULL MEMORY mode (+2.5GB dataset)")
    parser.add_argument("--rx-light", action="store_true", help="Force RandomX LIGHT mode (~<2.5GB, lower RAM)")
    return parser.parse_args()

def main():
    args = parse_args()
    address = args.address
    cores = args.cores
    if not address or not cores:
        COL.print_banner()
        COL.print_system_snapshot(cores_hint=None)
        addr_prompt, cores_prompt = COL.get_user_input()
        address = address or addr_prompt
        cores = cores or cores_prompt

    # Decide RandomX memory mode
    if args.rx_full and args.rx_light:
        clog("Cannot set both --rx-full and --rx-light. Choose one.")
        sys.exit(2)
    if args.rx_full:
        rx_full_mem = True
    elif args.rx_light:
        rx_full_mem = False
    else:
        rx_full_mem = COL.prompt_rx_full_mem()

    # Apply runtime override so mining respects the chosen mode
    CFG.RANDOMX_FULL_MEM = bool(rx_full_mem)
    os.environ["TSAR_RANDOMX_FULL_MEM"] = "1" if rx_full_mem else "0"
    mode_label = "FULL-MEM (+2.5GB)" if CFG.RANDOMX_FULL_MEM else "LIGHT"

    progress_q: mp.Queue = mp.Queue()
    miner: LightMiner | None = None

    tui = MinerTUI(
        address=address,
        cores=max(1, int(cores)),
        mode=" Mining...",
        randomx_mode=mode_label,
        hashrate_queue=progress_q,
        chain_height_fn=lambda: int(getattr(miner, "tip_height", -1)) if miner else -1,
        peer_counts_fn=lambda: (
            len(getattr(miner.network, "inbound_peers", ())) if miner and miner.network else 0,
            len(getattr(miner.network, "outbound_peers", ())) if miner and miner.network else 0,
        ),
    )
    tui.start()
    global tui_logger
    tui_logger = create_tui_logger(tui)
    
    miner = LightMiner(
        address=address,
        cores=max(1, int(cores)),
        progress_queue=progress_q,
        tui=tui,
    )
    try:
        miner.start_mining(timeout=max(120, int(args.timeout or 600)))
    except KeyboardInterrupt:
        miner.cancel_mining.set()
        clog("Interrupted by user.", color=COL.BG_YELLOW)
    finally:
        miner.shutdown()
        tui.stop()

if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    main()
