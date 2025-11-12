# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE and TRADEMARKS.md

"""
TsarChain — CLI Miner (Light)

Role
- Mining only: no mempool/transaction processing, no full DB persistence.

Intended environment
- Dedicated mining rigs.

Safety & behavior
- Sync-gated: starts hashing only after at least 1 peer and caught-up tip.
- Validates header/consensus core locally (prev-hash, target, timestamp, etc.).
- Typically mines empty/near-empty blocks (lower fee capture by design).
- Reorg-safe: stops current job when best tip changes.

Notes
- For full-node duties and transaction inclusion, use `cli_node_miner.py`.
"""

import argparse, psutil, errno, signal, time, threading, queue, colorama, platform, shutil, subprocess, os, sys
import multiprocessing as mp
from datetime import datetime

# ---------- Local Project ----------
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network
from tsarchain.utils import config as CFG
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
        clog("-" * 40, color=RED)
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


class LightMiner:
    """
    Miner that keeps blockchain/UTXO data only in-memory.
    It relies on peers for the latest tip and does not create/persist genesis locally.
    """
    def __init__(self, address: str, cores: int):
        self.address = address
        self.cores = cores
        self.blockchain: Blockchain | None = None
        self.network: Network | None = None
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self._progress_q: mp.Queue | None = None
        self._hr_thread: HashrateReporter | None = None

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    # -------- lifecycle --------
    def _handle_signal(self, signum, _frame):
        clog(f"[signal] Received {signum}; stopping miner...", color=YELLOW)
        self.mining_alive = False
        self.cancel_mining.set()

    def validate_address(self) -> bool:
        if not self.address or not self.address.lower().startswith("tsar1"):
            clog("Error: Address must start with 'tsar1...' (bech32)", color=RED)
            return False
        return True

    def start_node(self) -> bool:
        clog("Starting to Connect Tsarchain Network...")
        try:
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=True,  # <-- no disk persistence, only RAM
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            clog(f"Connected to TsarChain Network [{peer_count} bootstrap peers]")
            return True
        except Exception as exc:
            clog(f"Failed to connect: {exc}", color=RED)
            return False

    def wait_for_sync(self, timeout: int = 600) -> bool:
        if not self.blockchain or not self.network:
            return False
        clog("[sync] Requesting latest tip height for mining...")
        start = time.time()
        notified_no_peer = False
        last_height = -2

        while self.mining_alive and (time.time() - start) < timeout:
            try:
                peers_known = bool(getattr(self.network, "peers", None))
                if peers_known:
                    self.network.request_sync(fast=True)
                else:
                    if not notified_no_peer:
                        clog("[sync] Waiting for peer connection...", color=YELLOW)
                        notified_no_peer = True

                try:
                    height = int(getattr(self.blockchain, "height", -1))
                except Exception:
                    height = -1

                if height >= 0 and peers_known:
                    if height != last_height:
                        clog("[sync] tip height received...starting mining")
                        last_height = height
                    return True
                time.sleep(2)
                
            except Exception as exc:
                clog(f"[sync] Error: {exc}", color=RED)
                time.sleep(2)
                
        clog("[sync] Failed to obtain chain tip within timeout.", color=RED)
        return False

    def _start_hashrate_thread(self):
        if self._progress_q is None:
            self._progress_q = mp.Queue()

        self._hr_thread = HashrateReporter(self._progress_q, self.cancel_mining)
        self._hr_thread.start()

    def start_mining(self, timeout: int = 600) -> bool:
        if not self.validate_address():
            return False
        if not self.start_node():
            return False
        if not self.wait_for_sync(timeout=timeout):
            return False

        current_height = int(getattr(self.blockchain, "height", -1))
        if current_height < 0:
            clog("[sync] No chain data available from peers; cannot strating mining", color=RED)
            return False

        clog("=== Mining Informations ===", color=CYAN)
        clog(f"Address : {self.address}")
        clog(f"Cores   : {self.cores}")
        try:
            mode_label = "FULL-MEM (+2.5GB)" if bool(CFG.RANDOMX_FULL_MEM) else "LIGHT"
            clog(f"RandomX : {mode_label}")
        except Exception:
            pass
        
        clog("NOTE    : No local DB is kept. Use cli_node_miner.py for full-node duties.", color=YELLOW)

        # Start hashrate reporter (prints every ~10–15s when Block.mine emits progress)
        self._start_hashrate_thread()

        while self.mining_alive:
            try:
                if self.network and self.network.peers:
                    self.network.request_sync(fast=True)

                block = self.blockchain.mine_block(
                    miner_address=self.address,
                    use_cores=self.cores,
                    cancel_event=self.cancel_mining,
                    pow_backend="randomx",
                    progress_queue=self._progress_q,  # << enable TOTAL_HPS feed
                )

                if not self.mining_alive:
                    break

                if block:
                    h = getattr(block, "height", "?")
                    clog(f"Block mined at height {h} : {block.hash().hex()[:18]}…  broadcasting...")
                    try:
                        sent = self.network.publish_block(block, exclude=None, force=True) if self.network else 0
                        if sent <= 0:
                            clog("[broadcast] No peers reached; forcing fast sync.", color=YELLOW)
                            if self.network:
                                self.network.request_sync(fast=True)
                    except Exception as exc:
                        clog(f"[broadcast] Error: {exc}", color=RED)
            except KeyboardInterrupt:
                self.mining_alive = False
                self.cancel_mining.set()
                clog("[signal] Mining interrupted by user; stopping workers...", color=YELLOW)
            except Exception as exc:
                if isinstance(exc, OSError) and getattr(exc, "errno", None) in INTERRUPTED_ERRNOS:
                    clog("[mining] Interrupted system call; stopping miners...", color=YELLOW)
                    self.mining_alive = False
                    self.cancel_mining.set()
                    break
                clog(f"[mining] Error: {exc}", color=RED)
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
        clog("[light-node] Shutdown complete.", color=YELLOW)


# -------- CLI helpers --------
def _prompt_address_and_cores() -> tuple[str, int]:
    print_banner()
    clog("CLI Miner (RandomX)")
    clog("Only mines + validates tip. For full node duties use cli_node_miner.py.")
    print_system_snapshot(cores_hint=None)
    clog("Please enter your mining details:", color=CYAN)
    clog("-" * 40, color=RED)

    while True:
        addr = input("Miner address (tsar1...): ").strip()
        if addr.lower().startswith("tsar1"):
            break
        clog("Invalid address. Example: tsar1qyourwalletaddresshere", color=YELLOW)

    while True:
        core_default = psutil.cpu_count(logical=True)
        entry = input(f"CPU cores to use [{core_default}]: ").strip()
        if not entry:
            cores = max(1, core_default or 1)
            break
        try:
            cores = int(entry)
            if cores > 0:
                break
            clog("Cores must be positive.", color=YELLOW)
        except ValueError:
            clog("Enter a number.", color=YELLOW)

    return addr, cores

def _prompt_rx_full_mem() -> bool:
    clog("RandomX Memory Boost", color=CYAN)
    clog("-" * 40, color=RED)
    clog("if you choose 'y' your PC will consume 2.5GB - 7GB RAM Usage")
    clog("if you choose 'N' RAM Usage will stable in 2.5GB")
    clog("-" * 40, color=RED)
    while True:
        ans = input("Enable RandomX FULL MEMORY mode (+2.5GB)? [y/N]: ").strip().lower()
        if ans in ("y", "yes", "1"):
            return True
        if ans in ("n", "no", "0", ""):
            return False
        clog("Please answer y or n.", color=YELLOW)


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
        addr_prompt, cores_prompt = _prompt_address_and_cores()
        address = address or addr_prompt
        cores = cores or cores_prompt
    
    if not address or not cores:
        addr_prompt, cores_prompt = _prompt_address_and_cores()
        address = address or addr_prompt
        cores = cores or cores_prompt

    # Decide RandomX memory mode
    if args.rx_full and args.rx_light:
        clog("Cannot set both --rx-full and --rx-light. Choose one.", color=RED)
        sys.exit(2)
    if args.rx_full:
        rx_full_mem = True
    elif args.rx_light:
        rx_full_mem = False
    else:
        rx_full_mem = _prompt_rx_full_mem()

    # Apply runtime override so mining respects the chosen mode
    CFG.RANDOMX_FULL_MEM = bool(rx_full_mem)
    os.environ["TSAR_RANDOMX_FULL_MEM"] = "1" if rx_full_mem else "0"
    mode_label = "FULL-MEM (+2.5GB)" if CFG.RANDOMX_FULL_MEM else "LIGHT"
    clog(f"RandomX mode set to: {mode_label}")

    miner = LightMiner(address=address, cores=max(1, int(cores)))
    try:
        miner.start_mining(timeout=max(120, int(args.timeout or 600)))
    except KeyboardInterrupt:
        miner.cancel_mining.set()
        clog("Interrupted by user.", color=YELLOW)
    finally:
        miner.shutdown()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    main()
