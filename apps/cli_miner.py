# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE and TRADEMARKS.md

"""
Stateless CLI miner: keeps blockchain data in-memory only (no full DB persistence).
Intended for VPS / mining rigs. For full-node duties use cli_node_miner.py
"""

import argparse, psutil, errno, signal, time, threading, queue, colorama
import multiprocessing as mp
from datetime import datetime

# ---------- Imports from project ----------

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
                line = f"Hashrate ~ {hps} {DIM}{RESET}"
                if line != last_line:
                    clog(line, color=CYAN)
                    last_line = line


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
        clog("[light-node] Starting stateless mining node...")
        try:
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=True,  # <-- no disk persistence, only RAM
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            clog(f"[light-node] Connected to {peer_count} bootstrap peers (stateless mode)")
            return True
        except Exception as exc:
            clog(f"[light-node] Failed to start: {exc}", color=RED)
            return False

    def _best_peer_height(self) -> int:
        if not self.network:
            return -1
        getter = getattr(self.network, "get_best_peer_height", None)
        if getter is None:
            return -1
        try:
            return int(getter())
        except Exception:
            return -1

    def wait_for_sync(self, timeout: int = 600) -> bool:
        if not self.blockchain or not self.network:
            return False
        clog("[sync] Waiting for latest tip from peers (stateless miner)...")
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

                best_height = self._best_peer_height()
                if height >= 0 and peers_known:
                    if height != last_height:
                        clog(f"[sync] Local tip height {height} (peer best {best_height if best_height >= 0 else '?'})")
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
            clog("[sync] No chain data available from peers; cannot mine in stateless mode.", color=RED)
            return False

        clog("=== Stateless RandomX Miner ===", color=CYAN)
        clog(f"Address : {self.address}")
        clog(f"Cores   : {self.cores}")
        clog(f"Tip     : {current_height}")
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
    clog("-" * 48)

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


def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain Stateless CLI Miner (RandomX)")
    parser.add_argument("--address", help="Miner payout address (tsar1...)")
    parser.add_argument("--cores", type=int, help="CPU cores to dedicate")
    parser.add_argument("--timeout", type=int, default=600, help="Sync timeout (seconds)")
    return parser.parse_args()


def main():
    args = parse_args()
    address = args.address
    cores = args.cores
    if not address or not cores:
        addr_prompt, cores_prompt = _prompt_address_and_cores()
        address = address or addr_prompt
        cores = cores or cores_prompt

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
