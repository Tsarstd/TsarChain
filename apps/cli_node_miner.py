# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

"""
TsarChain — Full Node CLI Miner

Role
- Runs a full node with on-disk persistence.
- Receives/maintains mempool and includes transactions in mined blocks.

Intended environment
- VPS / always-on servers.

Key flags
--node-only     : Run as full node only (no mining) — still relays mempool & chain.
--no-bootstrap  : Skip snapshot fast-sync; use default block-by-block sync.

Safety & behavior
- Validates headers, difficulty, timestamps, and full block rules.
- Keeps local DB, mempool policies apply (size/fees/sanity checks).
- Reorg-safe: cancels current work and re-mines on new best tip.

Notes
- For mining-only rigs without mempool, use `cli_miner.py`.
"""
from __future__ import annotations

import argparse, time, signal, threading, errno, queue, os, sys
import multiprocessing as mp
from datetime import datetime

# ---------------- Local Project ----------------
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network
from tsarchain.utils import config as CFG
from tsarchain.utils.bootstrap import maybe_bootstrap_snapshot

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
    return f"{COL.BOLD}{COL.GREY} {d} {COL.RESET}{COL.BOLD}{COL.GREY} {t} {COL.RESET}"

def clog(message: str, color: str = COL.GREY):
    if 'tui_logger' in globals():
        tui_logger(f"{_stamp()}{color}{message}{COL.RESET}")
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
                        clog(line)
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


def _run_snapshot_bootstrap(context: str, enabled: bool):
    if not enabled:
        return None

    def _printer(message: str):
        clog(f"[Bootstrap] {message}")

    result = maybe_bootstrap_snapshot(context=context, progress_cb=_printer)
    if result.status == "failed":
        clog(f"[Bootstrap] Snapshot bootstrap failed: {result.reason}. Continuing with normal sync.")
    elif result.status == "installed":
        clog(f"[Bootstrap] Finished Instaling Snapshot")
    else:
        reason = result.reason or "no snapshot source"
        clog(f"[Bootstrap] Skipped: {reason}")
    return result


class SimpleMiner:
    def __init__(
        self,
        address: str,
        cores: int,
        bootstrap_snapshot: bool = True,
        *,
        progress_queue: mp.Queue | None = None,
        tui: MinerTUI | None = None,
    ):
        self.address = address
        self.cores = cores
        self.bootstrap_snapshot = bootstrap_snapshot
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self.blockchain = None
        self.network = None
        self._progress_q: mp.Queue = progress_queue or mp.Queue()
        self.tui = tui
        self._pending_blocks: list = []
        self._pending_block_hashes: set[str] = set()

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, _frame):
        clog(f"Received signal {signum}, shutting down...")
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()

    def validate_address(self):
        if not self.address or not self.address.lower().startswith("tsar1"):
            clog("Error: Address should start with 'tsar1...'")
            return False
        return True

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
        while len(self._pending_blocks) > 5:
            old = self._pending_blocks.pop(0)
            try:
                self._pending_block_hashes.discard(old.hash().hex())
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

    def _has_active_peers(self) -> bool:
        if not self.network:
            return False
        inbound = getattr(self.network, "inbound_peers", None) or set()
        outbound = getattr(self.network, "outbound_peers", None) or set()
        return bool(inbound or outbound)

    def start_node(self):
        try:
            _run_snapshot_bootstrap("cli", self.bootstrap_snapshot)
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=False,
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            clog(f"Node started with {peer_count} bootstrap peers")
            return True
        except Exception as exc:
            clog(f"Failed to start node: {exc}")
            return False

    def wait_for_sync(self, timeout=560):
        clog("Waiting for blockchain sync...")
        start_time = time.time()
        last_progress = (-1, -1)
        notified_no_peer = False

        while self.mining_alive and (time.time() - start_time) < timeout:
            try:
                try:
                    height = int(getattr(self.blockchain, "height", -1))
                except Exception:
                    height = -1

                active_peers = self._has_active_peers()
                if not active_peers:
                    if height >= 0:
                        clog(f"No active peers detected (local height {height}). Proceeding with local chain.")
                        return True
                    if not notified_no_peer:
                        clog("[Sync] Waiting for peer connection...")
                        notified_no_peer = True
                    time.sleep(3)
                    continue

                if self.network.peers:
                    if notified_no_peer:
                        clog("Peer connection restored, resuming sync...")
                        notified_no_peer = False
                    self.network.request_sync(fast=True)

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
                            caught_up = height >= 0
                    else:
                        caught_up = height >= 0

                    if caught_up and height >= 0:
                        if best_height < height:
                            best_height = height
                        clog(f"Chain synced to height {height}")
                        return True

                    if best_height >= 0:
                        progress = (height, best_height)
                        if progress != last_progress:
                            clog(f"Sync progress - local height: {height}, best known peer: {best_height}")
                            last_progress = progress
                else:
                    if not notified_no_peer:
                        clog("Waiting for peer connection...")
                        notified_no_peer = True
                time.sleep(2)
            except Exception as exc:
                clog(f"Sync error: {exc}")
                time.sleep(2)

        clog("Sync timeout or interrupted")
        return False

    def start_mining(self, timeout=560):
        if not self.validate_address():
            return False
        if not self.start_node():
            return False
        need_sync = True
        try:
            local_height = int(getattr(self.blockchain, "height", -1))
        except Exception:
            local_height = -1
        if not self._has_active_peers() and local_height >= 0:
            clog(f"No active peer connections detected (local height {local_height}). Skipping sync wait.")
            need_sync = False
        if need_sync and not self.wait_for_sync(timeout=timeout):
            return False
        
        clog(f"{COL.BOLD}{COL.BG_WHITE} Press {COL.RESET}{COL.BOLD}{COL.BG_RED} Ctrl+C {COL.RESET}{COL.BG_WHITE}{COL.BOLD}{COL.ORANGE} to stop mining {COL.RESET}")

        if getattr(self.blockchain, "height", -1) < 0:
            created = self.blockchain.ensure_genesis(self.address, use_cores=self.cores)
            if created:
                clog("Genesis block created")
            else:
                clog("Failed to create genesis block")
                return False

        # Mulai loop mining
        while self.mining_alive:
            try:
                self._flush_pending_blocks()
                if self.network.peers:
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
                    txs = getattr(block, "transactions", None) or []
                    confirmed = max(len(txs) - 1, 0)
                    clog(
                        f"Block mined at height {h}: {block.hash().hex()[:18]}... ( conf {confirmed} tx{'' if confirmed == 1 else 's'} from mempool)"
                    )
                    try:
                        sent = self.network.publish_block(block, exclude=None, force=True)
                        if sent <= 0:
                            self.network.request_sync(fast=True)
                            self._queue_block_for_broadcast(block)
                    except Exception as exc:
                        clog(f"Broadcast error: {exc}")
                        self._queue_block_for_broadcast(block)
            except Exception as exc:
                if isinstance(exc, OSError) and getattr(exc, "errno", None) in INTERRUPTED_ERRNOS:
                    clog("[mining] Interrupted system call; stopping miners...")
                    self.mining_alive = False
                    self.cancel_mining.set()
                    break
                clog(f"Mining error: {exc}")
                time.sleep(1)

        return True

    def stop(self):
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()
        
        if self.network:
            try:
                self.network.shutdown()
            except Exception:
                pass

        clog("Miner stopped")


class NodeRunner:
    def __init__(self, bootstrap_snapshot: bool = True):
        self.blockchain = None
        self.network = None
        self.running = True
        self._last_chain_height = -1
        self._sync_ready = False
        self.bootstrap_snapshot = bootstrap_snapshot
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, *_args):
        clog("Stopping node...")
        self.running = False

    def _has_active_peers(self) -> bool:
        if not self.network:
            return False
        try:
            peers = getattr(self.network, "peers", set()) or set()
            inbound = getattr(self.network, "inbound_peers", set()) or set()
            outbound = getattr(self.network, "outbound_peers", set()) or set()
            return bool(peers or inbound or outbound)
        except Exception:
            return False

    def start(self):
        clog("Starting TsarChain node (no mining)...")
        try:
            _run_snapshot_bootstrap("cli", self.bootstrap_snapshot)
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=False,
                use_cores=None,
                miner_address=None,
            )
            
            try:
                self._last_chain_height = int(getattr(self.blockchain, "height", -1))
            except Exception:
                self._last_chain_height = -1
            clog(f"Local chain height: {self._last_chain_height}")
            
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            clog(f"Node online on port {self.network.port}, bootstrap peers: {peer_count}")

            # == Early fast-sync ==
            def _early_sync():
                for _ in range(5):
                    try:
                        self.network.request_sync(fast=True)
                    except Exception:
                        pass
                    time.sleep(1.0)
            threading.Thread(target=_early_sync, daemon=True).start()

            # == Background sync daemon ==
            threading.Thread(target=self._sync_daemon, daemon=True).start()

            while self.running:
                time.sleep(2)
                
        except Exception as exc:
            clog(f"Node error: {exc}")
            
        finally:
            self.shutdown()

    def _sync_daemon(self):
        last_status = ""
        while self.running and self.blockchain and self.network:
            try:
                # No peers yet
                if not self._has_active_peers():
                    msg = "[Sync] Waiting for peer connection..."
                    if msg != last_status:
                        clog(msg)
                        last_status = msg
                    self._sync_ready = False
                    time.sleep(5)
                    continue

                # Have peers — request fast sync
                self.network.request_sync(fast=True)

                # Heights
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

                # Progress print (only when changed)
                if height != self._last_chain_height:
                    if height >= 0:
                        clog(f"[Sync] Chain height now {height}")
                    self._last_chain_height = height

                peer_sync_map = getattr(self.network, "_peer_last_sync", {}) or {}
                latest_sync = max(peer_sync_map.values()) if peer_sync_map else 0.0
                synced_recently = latest_sync and (time.time() - latest_sync) < 10
                if not self._sync_ready and height >= 0 and synced_recently:
                    self._sync_ready = True
                    clog("Chain has been confirmed. Node is live (no mining).")

                try:
                    inb = len(getattr(self.network, "inbound_peers", ()))
                    outb = len(getattr(self.network, "outbound_peers", ()))
                    known = len(getattr(self.network, "peers", ()))
                except Exception:
                    inb = outb = known = 0
                    
                status = f"[peers in={inb} out={outb} known={known}] local={height} best={best_height if best_height>=0 else 'syncing...'}"
                if status != last_status:
                    clog(status)
                    last_status = status

            except Exception as e:
                clog(f"[node-only] sync error: {e}")
            time.sleep(5)

    def shutdown(self):
        if self.network:
            try:
                self.network.shutdown()
            except Exception:
                pass
            self.network = None
        clog("Node stopped.")

def choose_mode() -> int:
    print(f"{COL.BOLD}{COL.TXT_HEADER}{COL.BG_HEADER}       Please Choose Mode       {COL.RESET}")
    print(f"{COL.BOLD}{COL.TXT_INFO}{COL.BG_YELLOW} 0 {COL.RESET}{COL.BOLD}{COL.BG_ORANGE} Mining Mode {COL.RESET}  {COL.BOLD}{COL.TXT_INFO}{COL.BG_GREEN} 1 {COL.BOLD}{COL.TXT_INFO}{COL.BG_BLUE} Node Only {COL.RESET}")
    while True:
        try:
            sel = input(f"{COL.BOLD}{COL.TXT_INFO}{COL.BG_WHITE} Select {COL.RESET}{COL.BOLD}{COL.TXT_INFO}{COL.BG_YELLOW} 0 {COL.RESET}{COL.BOLD}{COL.TXT_INFO}{COL.BG_GREEN} 1 {COL.RESET} ").strip()
        except EOFError:
            print(f"\033[1A\033[2K{COL.BOLD}{COL.DIM}{COL.TXT_INFO}{COL.BG_WHITE} You're Choosing: {COL.RESET}{COL.TXT_INFO}{COL.BG_YELLOW} 0 {COL.RESET}{COL.BOLD}{COL.BG_ORANGE} Mining Mode {COL.RESET}")
            return 0
        
        if sel == "0":
            print(f"\033[1A\033[2K{COL.BOLD}{COL.TXT_INFO}{COL.BG_GREY} ------------------------------ {COL.RESET}")
            print(f"{COL.RESET}{COL.BOLD}{COL.BG_ORANGE}           Mining Mode          {COL.RESET}")
            return 0
        elif sel == "1":
            print(f"\033[1A\033[2K{COL.BOLD}{COL.TXT_INFO}{COL.BG_GREY} ------------------------------ {COL.RESET}")
            print(f"{COL.BOLD}{COL.TXT_INFO}{COL.BG_BLUE}            Node Only           {COL.RESET}")
            print(f" ")
            return 1
        else:
            print(f"{COL.BOLD}{COL.TXT_HEADER}{COL.BG_HEADER} Invalid {COL.RESET}{COL.BOLD}{COL.TXT_INFO}{COL.BG_WHITE} Enter 0 or 1 {COL.RESET}")
        
def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain CLI miner / node runner")
    parser.add_argument("--address", help="Miner payout address (tsar1...)")
    parser.add_argument("--cores", type=int, help="CPU cores to use for mining")
    parser.add_argument("--node-only", action="store_true", help="Run node without mining")
    parser.add_argument("--timeout", type=int, default=560, help="Sync timeout in seconds (mining mode)")
    parser.add_argument("--no-bootstrap", action="store_true", help="Skip snapshot bootstrap download")
    parser.add_argument("--rx-full", action="store_true", help="Enable RandomX FULL MEMORY mode (+2.5GB dataset)")
    parser.add_argument("--rx-light", action="store_true", help="Force RandomX LIGHT mode (~<2.5GB, lower RAM)")
    return parser.parse_args()

def main():
    args = parse_args()
    mode_selected = None
    if not args.node_only:
        # Interactive mode selection
        try:
            COL.print_banner()
            COL.print_system_snapshot(cores_hint=None)
            mode_selected = choose_mode()
        except Exception:
            mode_selected = 0

    if args.node_only or mode_selected == 1:
        runner = NodeRunner(bootstrap_snapshot=not args.no_bootstrap)
        runner.start()
        return

    address = args.address
    cores = args.cores

    if not address or not cores:
        input_address, input_cores = COL.get_user_input()
        address = address or input_address
        cores = cores or input_cores

    # Decide RandomX memory mode (mining mode only)
    if args.rx_full and args.rx_light:
        clog("Cannot set both --rx-full and --rx-light. Choose one.")
        sys.exit(2)
    if args.rx_full:
        rx_full_mem = True
    elif args.rx_light:
        rx_full_mem = False
    else:
        rx_full_mem = COL.prompt_rx_full_mem()
    CFG.RANDOMX_FULL_MEM = bool(rx_full_mem)
    os.environ["TSAR_RANDOMX_FULL_MEM"] = "1" if rx_full_mem else "0"
    mode_label = "FULL-MEM (+2.5GB)" if CFG.RANDOMX_FULL_MEM else "LIGHT"

    # --- TUI + progress queue ---
    progress_q: mp.Queue = mp.Queue()
    miner: SimpleMiner | None = None

    tui = MinerTUI(
        address=address,
        cores=cores,
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
    
    miner = SimpleMiner(
        address=address,
        cores=cores,
        bootstrap_snapshot=not args.no_bootstrap,
        progress_queue=progress_q,
        tui=tui,
    )
    try:
        miner.start_mining(timeout=args.timeout)
    except KeyboardInterrupt:
        clog("Interrupted by user")
    except Exception as exc:
        clog(f"Fatal error: {exc}")
    finally:
        miner.stop()
        tui.stop()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    main()
