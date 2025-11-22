# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE and TRADEMARKS.md
# Refs: BIP173

"""
TsarChain — CLI Miner (Light, Stateless)

Role
- Mining with in-memory chain; no on-disk chain persistence.
- Ephemeral mempool: accepts/validates tx from peers but not persisted.
- Keeps a small pending queue to retry broadcast if peers are absent.

Intended environment
- Dedicated mining rigs.

Safety & behavior
- Sync-gated: starts hashing only after at least 1 peer and caught-up tip.
- Validates header/consensus core locally (prev-hash, target, timestamp, etc.).
- Typically mines empty/near-empty blocks; any tx included come from ephemeral mempool.
- Reorg-safe: stops current job when best tip changes.

Notes
- For full-node duties and transaction inclusion, use `cli_node_miner.py`.
"""

from __future__ import annotations

import argparse, errno, signal, time, threading, queue, os, sys
import multiprocessing as mp
import tempfile
from datetime import datetime

# ---------- Local Project ----------
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network
from tsarchain.utils import config as CFG

from tsarchain.utils.cosmetic import interface as COL
from tsarchain.utils.cosmetic.tui import MinerTUI, create_tui_logger

from tsarchain.utils.tsar_logging import setup_logging

INTERRUPTED_ERRNOS = {
    code
    for code in (
        getattr(errno, "EINTR", None),
        getattr(errno, "WSAEINTR", None),
    )
    if code is not None
}

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
    try:
        hps = float(hps)
    except Exception:
        return "? H/s"
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
        try :
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
        except Exception:
            pass


def _register_bootstrap_peers(network: Network) -> int:
    fallback_nodes = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
    count = 0
    for peer in fallback_nodes:
        if not peer:
            continue
        try:
            network.persistent_peers.add(peer)
            network.peers.add(peer)
            count += 1
        except Exception:
            continue
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
        self._pending_blocks: list = []
        self._pending_block_hashes: set[str] = set()

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    # -------- lifecycle --------
    def _handle_signal(self, signum, _frame):
        clog(f"[signal] Received {signum}; stopping miner...", color=COL.BG_YELLOW)
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

    def _ensure_ephemeral_mempool(self) -> None:
        if not self.blockchain or not hasattr(self.blockchain, "attach_mempool"):
            return
        try:
            from tsarchain.mempool.pool import TxPoolDB
        except Exception:
            return
        try:
            tmp_path = os.path.join(
                tempfile.gettempdir(),
                f"tsar_mempool_tmp_{os.getpid()}_{int(time.time())}.json",
            )
            pool = TxPoolDB(
                filepath=tmp_path,
                max_size_mb=getattr(CFG, "MEMPOOL_MAX_SIZE", 1 * 1024 * 1024),
                utxo_store=self.blockchain._ensure_utxodb(),  # type: ignore[attr-defined]
                inherit_state=False,
            )
            self.blockchain.attach_mempool(pool)  # type: ignore[arg-type]
        except Exception:
            pass

    def _queue_block_for_broadcast(self, block) -> None:
        try:
            hx = block.hash().hex()
        except Exception:
            hx = None
        if hx and hx in self._pending_block_hashes:
            return
        self._pending_blocks.append(block)
        if hx:
            self._pending_block_hashes.add(hx)
        # batasi backlog supaya tidak tak terbatas
        while len(self._pending_blocks) > 5:
            old = self._pending_blocks.pop(0)
            try:
                h_old = old.hash().hex()
                self._pending_block_hashes.discard(h_old)
            except Exception:
                pass
        clog(f"[broadcast] queued mined block (backlog={len(self._pending_blocks)})", color=COL.BG_YELLOW)

    def _flush_pending_blocks(self) -> None:
        if not self.network or not self._pending_blocks:
            return
        remaining = []
        for blk in self._pending_blocks:
            try:
                sent = self.network.publish_block(blk, exclude=None, force=True)
                if sent and sent > 0:
                    clog(f"[broadcast] pending block sent to {sent} peers")
                    try:
                        self._pending_block_hashes.discard(blk.hash().hex())
                    except Exception:
                        pass
                    continue
            except Exception as exc:
                clog(f"[broadcast] retry failed: {exc}")
            remaining.append(blk)
        self._pending_blocks = remaining

    def wait_for_sync(self, timeout: int = 600) -> bool:
        if not self.blockchain or not self.network:
            return False
        clog("[sync] Requesting latest tip height for mining...")
        start = time.time()
        notified_no_peer = False
        last_progress: tuple[int, int] = (-2, -2)

        while self.mining_alive and (time.time() - start) < timeout:
            try:
                peers = getattr(self.network, "peers", set()) or set()
                inbound = getattr(self.network, "inbound_peers", set()) or set()
                outbound = getattr(self.network, "outbound_peers", set()) or set()
                active_peers = bool(peers or inbound or outbound)

                if not active_peers:
                    if not notified_no_peer:
                        clog("[sync] Waiting for peer connection...", color=COL.BG_YELLOW)
                        notified_no_peer = True
                    time.sleep(2)
                    continue

                self.network.request_sync(fast=True)
                notified_no_peer = False

                try:
                    height = int(getattr(self.blockchain, "height", -1))
                except Exception:
                    height = -1

                best_height = -1
                if hasattr(self.network, "get_best_peer_height"):
                    try:
                        best_height = int(self.network.get_best_peer_height())
                    except Exception:
                        best_height = -1

                caught_up = False
                if hasattr(self.network, "is_caught_up"):
                    try:
                        caught_up = self.network.is_caught_up(freshness=20.0, height_slack=0)
                    except Exception:
                        caught_up = False

                if not caught_up and height >= 0 and best_height >= 0:
                    caught_up = (best_height - height) <= 0

                if caught_up and height >= 0:
                    if best_height < height:
                        best_height = height
                    clog(f"[sync] Chain synced to height {height}")
                    return True

                if best_height >= 0:
                    progress = (height, best_height)
                    if progress != last_progress:
                        clog(f"[sync] progress: local {height}, best peer {best_height}")
                        last_progress = progress

                time.sleep(2)

            except Exception as exc:
                clog(f"[sync] Error: {exc}")
                time.sleep(2)
                
        clog("[sync] Failed to obtain chain tip within timeout.")
        return False

    def start_mining(self, timeout: int = 600) -> bool:
        if not self.validate_address():
            return False
        if not self.start_node():
            return False
        self._ensure_ephemeral_mempool()
        if not self.wait_for_sync(timeout=timeout):
            return False

        current_height = int(getattr(self.blockchain, "height", -1))
        if current_height < 0:
            clog("[sync] No chain data available from peers; cannot strating mining")
            return False

        clog("=== Mining Informations ===")
        clog(f"Address : {self.address}")
        clog(f"Cores   : {self.cores}")
        try:
            mode_label = "FULL-MEM (+2.5GB)" if bool(CFG.RANDOMX_FULL_MEM) else "LIGHT"
            clog(f"RandomX : {mode_label}")
        except Exception:
            pass
        
        clog("NOTE    : No local DB is kept. Use cli_node_miner.py for full-node duties.", color=COL.BG_YELLOW)

        while self.mining_alive:
            try:
                # kirim ulang backlog jika ada
                self._flush_pending_blocks()
                if self.network and self.network.peers:
                    self.network.request_sync(fast=True)

                block = self.blockchain.mine_block(
                    miner_address=self.address,
                    use_cores=self.cores,
                    cancel_event=self.cancel_mining,
                    pow_backend="randomx",
                    progress_queue=self._progress_q,  # TOTAL_HPS -> TUI
                )

                if not self.mining_alive:
                    break

                if block:
                    if self.tui is not None:
                        try:
                            self.tui.note_block_mined(getattr(block, "height", None))
                        except Exception:
                            pass

                    h = getattr(block, "height", "?")
                    clog(f"Block mined at height {h} : {block.hash().hex()[:18]}…  broadcasting...")
                    try:
                        sent = self.network.publish_block(block, exclude=None, force=True) if self.network else 0
                        if sent <= 0:
                            clog("[broadcast] No peers reached; forcing fast sync.", color=COL.BG_YELLOW)
                            self._queue_block_for_broadcast(block)
                            if self.network:
                                self.network.request_sync(fast=True)
                    except Exception as exc:
                        clog(f"[broadcast] Error: {exc}")
                        self._queue_block_for_broadcast(block)
            except KeyboardInterrupt:
                self.mining_alive = False
                self.cancel_mining.set()
                clog("[signal] Mining interrupted by user; stopping workers...", color=COL.BG_YELLOW)
            except Exception as exc:
                if isinstance(exc, OSError) and getattr(exc, "errno", None) in INTERRUPTED_ERRNOS:
                    clog("[mining] Interrupted system call; stopping miners...", color=COL.BG_YELLOW)
                    self.mining_alive = False
                    self.cancel_mining.set()
                    break
                clog(f"[mining] Error: {exc}")
                time.sleep(1)
        return True

    def shutdown(self):
        self.mining_alive = False
        self.cancel_mining.set()
        if self.network:
            try:
                self.network.shutdown()
            except Exception:
                pass
            self.network = None
        clog("[light-node] Shutdown complete.", color=COL.BG_YELLOW)


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
        chain_height_fn=lambda: int(getattr(miner.blockchain, "height", -1))
        if miner and miner.blockchain
        else -1,
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
