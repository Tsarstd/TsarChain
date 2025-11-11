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

import argparse, time, signal, threading, psutil, errno, queue, colorama, platform, shutil, subprocess, os, sys
import multiprocessing as mp
from datetime import datetime

# ---------------- Local Project ----------------
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network
from tsarchain.utils import config as CFG
from tsarchain.utils.bootstrap import maybe_bootstrap_snapshot
from tsarchain.utils.helpers import print_banner

from tsarchain.utils.tsar_logging import setup_logging

INTERRUPTED_ERRNOS = {
    code
    for code in (
        getattr(errno, "EINTR", None),
        getattr(errno, "WSAEINTR", None),
    )
    if code is not None
}

# ---------- Simple color + timestamp utilities ----------

colorama.init()
RESET  = "\033[0m"
BLUE   = "\033[34m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"

def _stamp() -> str:
    now = datetime.now()
    d = f"{now.year:04d}.{now.month:02d}.{now.day:02d}"
    t = f"{now.hour:02d}.{now.minute:02d}.{now.second:02d}"
    return f"[{BLUE}{d}{RESET}] - [{YELLOW}{t}{RESET}]"

def clog(message: str, color: str = GREEN):
    print(f"{_stamp()} : {color}{message}{RESET}")

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

def _human_bytes(n: int) -> str:
    try:
        n = float(n)
    except Exception:
        return "?"
    for unit in ("B","KB","MB","GB","TB","PB","EB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} ZB"

def _cpu_brand() -> str:
    try:
        sysname = platform.system()
        if sysname == "Windows":
            # Registry
            try:
                import winreg  # type: ignore
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                    name, _ = winreg.QueryValueEx(k, "ProcessorNameString")
                    name = " ".join(str(name).split())
                    if name:
                        return name
            except Exception:
                pass

            # WMIC
            try:
                out = subprocess.check_output(
                    ["wmic", "cpu", "get", "Name"],
                    stderr=subprocess.DEVNULL
                )
                lines = [l.strip() for l in out.decode(errors="ignore").splitlines() if l.strip()]
                if len(lines) >= 2:
                    name = " ".join(lines[1].split())
                    if name:
                        return name
            except Exception:
                pass

            # PowerShell
            try:
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name"],
                    stderr=subprocess.DEVNULL
                )
                name = " ".join(out.decode(errors="ignore").strip().split())
                if name:
                    return name
            except Exception:
                pass
        
        if sysname == "Darwin":
            try:
                out = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"])
                return out.decode().strip()
            except Exception:
                pass
            
        elif sysname == "Linux":
            try:
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":", 1)[1].strip()
            except Exception:
                pass
            
            # lscpu
            try:
                out = subprocess.check_output(["lscpu"], stderr=subprocess.DEVNULL)
                for line in out.decode(errors="ignore").splitlines():
                    if "Model name:" in line:
                        name = " ".join(line.split(":", 1)[1].strip().split())
                        if name:
                            return name
            except Exception:
                pass
            
        # Windows / fallback
        name = platform.processor() or getattr(platform.uname(), "processor", "") or ""
        name = " ".join(str(name).strip().split())
        return name or "Unknown CPU"
    except Exception:
        return "Unknown CPU"

def print_system_snapshot(cores_hint: int | None = None):
    try:
        uname = platform.uname()
        vm = psutil.virtual_memory()
        du = shutil.disk_usage("/")  # root fs
        freq = None
        try:
            freq = psutil.cpu_freq()
        except Exception:
            pass

        phys = psutil.cpu_count(logical=False) or 0
        logi = psutil.cpu_count(logical=True) or 0
        try:
            la = os.getloadavg()  # Unix
            la_str = f"{la[0]:.2f} {la[1]:.2f} {la[2]:.2f}"
        except Exception:
            la_str = "n/a"

        clog("System snapshot:", color=CYAN)
        clog(f"  CPU     : {_cpu_brand()}")
        line_core = f"  Cores   : {phys} phys / {logi} logical"
        if cores_hint:
            line_core += f"  |  use {cores_hint}"
        clog(line_core)
        if freq:
            try:
                base = f"{(freq.min or 0)/1000:.2f}"
                cur  = f"{(freq.current or 0)/1000:.2f}"
                mx   = f"{(freq.max or 0)/1000:.2f}"
                clog(f"  Speed   : {cur} GHz (base ~{base} / boost ~{mx})")
            except Exception:
                pass
        clog(f"  RAM     : {_human_bytes(vm.total)} total, {_human_bytes(vm.available)} free")
        clog(f"  Disk    : {_human_bytes(du.free)} free of {_human_bytes(du.total)}")
        clog(f"  OS      : {uname.system} {uname.release} ({uname.machine})")
        clog(f"  Python  : {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
        clog("-" * 50)
    except Exception as e:
        clog(f"[snapshot] failed: {e}", color=YELLOW)


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
                    line = f"Hashrate ~ {hps} {DIM}{RESET}"
                    if line != last_line:
                        clog(line, color=CYAN)
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
        clog(f"[Bootstrap] Snapshot bootstrap failed: {result.reason}. Continuing with normal sync.", color=YELLOW)
    elif result.status == "installed":
        clog(f"[Bootstrap] Snapshot installed at height {result.height or '?'}")
    else:
        reason = result.reason or "no snapshot source"
        clog(f"[Bootstrap] Skipped: {reason}")
    return result


class SimpleMiner:
    def __init__(self, address, cores, bootstrap_snapshot: bool = True):
        self.address = address
        self.cores = cores
        self.bootstrap_snapshot = bootstrap_snapshot
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self.blockchain = None
        self.network = None
        self._progress_q: mp.Queue | None = None
        self._hr_thread: HashrateReporter | None = None

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, _frame):
        clog(f"Received signal {signum}, shutting down...", color=YELLOW)
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()

    def validate_address(self):
        if not self.address or not self.address.lower().startswith("tsar1"):
            clog("Error: Address should start with 'tsar1...'", color=RED)
            return False
        return True

    def _has_active_peers(self) -> bool:
        if not self.network:
            return False
        inbound = getattr(self.network, "inbound_peers", None) or set()
        outbound = getattr(self.network, "outbound_peers", None) or set()
        return bool(inbound or outbound)

    def start_node(self):
        clog("Starting node...")
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
            clog(f"Failed to start node: {exc}", color=RED)
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
                        clog(f"No active peers detected (local height {height}). Proceeding with local chain.", color=YELLOW)
                        return True
                    if not notified_no_peer:
                        clog("[Sync] Waiting for peer connection...", color=YELLOW)
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
                        clog("Waiting for peer connection...", color=YELLOW)
                        notified_no_peer = True
                time.sleep(2)
            except Exception as exc:
                clog(f"Sync error: {exc}", color=RED)
                time.sleep(2)

        clog("Sync timeout or interrupted", color=RED)
        return False

    def _start_hashrate_thread(self):
        if self._progress_q is None:
            self._progress_q = mp.Queue()

        self._hr_thread = HashrateReporter(self._progress_q, self.cancel_mining)
        self._hr_thread.start()

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
            clog(f"No active peer connections detected (local height {local_height}). Skipping sync wait.", color=YELLOW)
            need_sync = False
        if need_sync and not self.wait_for_sync(timeout=timeout):
            return False

        clog("Starting mining with:", color=CYAN)
        clog(f"  Address: {self.address}")
        clog(f"  Cores:   {self.cores}")
        clog("Press Ctrl+C to stop mining", color=YELLOW)
        clog("-" * 50)

        if getattr(self.blockchain, "height", -1) < 0:
            created = self.blockchain.ensure_genesis(self.address, use_cores=self.cores)
            if created:
                clog("Genesis block created")
            else:
                clog("Failed to create genesis block", color=RED)
                return False

        # Start hashrate reporter (prints every ~10–15s)
        self._start_hashrate_thread()

        while self.mining_alive:
            try:
                if self.network.peers:
                    self.network.request_sync(fast=True)

                block = self.blockchain.mine_block(
                    miner_address=self.address,
                    use_cores=self.cores,
                    cancel_event=self.cancel_mining,
                    pow_backend="randomx",
                    progress_queue=self._progress_q,
                )

                if not self.mining_alive:
                    break

                if block:
                    clog(f"Block mined ( height :{getattr(block, 'height')}): {block.hash().hex()[:18]}…  broadcasting...")
                    try:
                        sent = self.network.publish_block(block, exclude=None, force=True)
                        if sent <= 0:
                            self.network.request_sync(fast=True)
                    except Exception as exc:
                        clog(f"Broadcast error: {exc}", color=RED)
            except Exception as exc:
                if isinstance(exc, OSError) and getattr(exc, "errno", None) in INTERRUPTED_ERRNOS:
                    clog("[mining] Interrupted system call; stopping miners...", color=YELLOW)
                    self.mining_alive = False
                    self.cancel_mining.set()
                    break
                clog(f"Mining error: {exc}", color=RED)
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

        clog("Miner stopped", color=YELLOW)


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
        clog("Stopping node...", color=YELLOW)
        self.running = False

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

            # == Early fast-sync kick (mirror miner_gui) ==
            def _early_sync():
                for _ in range(5):
                    try:
                        self.network.request_sync(fast=True)
                    except Exception:
                        pass
                    time.sleep(1.0)
            threading.Thread(target=_early_sync, daemon=True).start()

            # == Background sync daemon (mirror miner_gui logic, but CLI prints) ==
            threading.Thread(target=self._sync_daemon, daemon=True).start()

            clog("Press Ctrl+C to stop.", color=YELLOW)
            while self.running:
                time.sleep(2)
                
        except Exception as exc:
            clog(f"Node error: {exc}", color=RED)
            
        finally:
            self.shutdown()

    def _sync_daemon(self):
        last_status = ""
        while self.running and self.blockchain and self.network:
            try:
                # No peers yet
                if not getattr(self.network, "peers", None):
                    msg = "[Sync] Waiting for peer connection..."
                    if msg != last_status:
                        clog(msg, color=YELLOW)
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
                import time as _t
                latest_sync = max(peer_sync_map.values()) if peer_sync_map else 0.0
                synced_recently = latest_sync and (_t.time() - latest_sync) < 10
                if not self._sync_ready and height >= 0 and synced_recently:
                    self._sync_ready = True
                    clog("Chain has been confirmed. Node is live (no mining).")

                try:
                    inb = len(getattr(self.network, "inbound_peers", ()))
                    outb = len(getattr(self.network, "outbound_peers", ()))
                    known = len(getattr(self.network, "peers", ()))
                except Exception:
                    inb = outb = known = 0
                    
                status = f"[peers in={inb} out={outb} known={known}] local={height} best={best_height if best_height>=0 else '?'}"
                if status != last_status:
                    clog(status)
                    last_status = status

            except Exception as e:
                clog(f"[node-only] sync error: {e}", color=RED)
            time.sleep(5)

    def shutdown(self):
        if self.network:
            try:
                self.network.shutdown()
            except Exception:
                pass
            self.network = None
        clog("Node stopped.", color=YELLOW)

def get_user_input():
    clog("Please enter your mining details:")
    clog("-" * 40)

    while True:
        address = input("Miner address (tsar1...): ").strip()
        if address and address.lower().startswith("tsar1"):
            break
        clog("Error: Address must start with 'tsar1...'", color=YELLOW)
        clog("Example: tsar1qyourwalletaddresshere", color=YELLOW)

    while True:
        cores = psutil.cpu_count(logical=True)
        cores_input = input(f"CPU cores to use [{cores}]: ").strip()
        if not cores_input:
            cores = 1
            break
        try:
            cores = int(cores_input)
            if cores > 0:
                break
            clog("Error: Cores must be a positive number", color=YELLOW)
        except ValueError:
            clog("Error: Please enter a valid number", color=YELLOW)
    return address, cores

def choose_mode() -> int:
    """
    Interactive mode chooser.
    Returns:
      0 -> Mining Mode
      1 -> Node Only (no mining)
    """
    clog("Please Choose Mode :")
    clog("[0] Mining Mode   [1] Node Only ( no mining )")
    while True:
        try:
            sel = input("Select [0/1]: ").strip()
        except EOFError:
            # Non-interactive environment: default to Mining
            return 0
        if sel in ("0", "1"):
            return int(sel)
        clog("Invalid selection. Enter 0 or 1.", color=YELLOW)
        
def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain CLI miner / node runner")
    parser.add_argument("--address", help="Miner payout address (tsar1...)")
    parser.add_argument("--cores", type=int, help="CPU cores to use for mining")
    parser.add_argument("--node-only", action="store_true", help="Run node without mining")
    parser.add_argument("--timeout", type=int, default=560, help="Sync timeout in seconds (mining mode)")
    parser.add_argument("--no-bootstrap", action="store_true", help="Skip snapshot bootstrap download")
    return parser.parse_args()


def main():
    args = parse_args()
    #setup_logging()
    mode_selected = None
    if not args.node_only:
        # Interactive mode selection
        try:
            print_banner()
            print_system_snapshot(cores_hint=None)
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
        input_address, input_cores = get_user_input()
        address = address or input_address
        cores = cores or input_cores

    miner = SimpleMiner(address, cores, bootstrap_snapshot=not args.no_bootstrap)

    try:
        miner.start_mining(timeout=args.timeout)
    except KeyboardInterrupt:
        clog("Interrupted by user", color=YELLOW)
    except Exception as exc:
        clog(f"Fatal error: {exc}", color=RED)
    finally:
        miner.stop()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    main()
