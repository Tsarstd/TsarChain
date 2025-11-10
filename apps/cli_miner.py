# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE and TRADEMARKS.md

"""
Stateless CLI miner: keeps blockchain data in-memory only (no full DB persistence).
Intended for VPS / mining rigs. For full-node duties use cli_node_miner.py
"""

import argparse
import errno
import multiprocessing as mp
import signal
import time

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

try:
    import psutil

    HAVE_PSUTIL = True
except Exception:
    psutil = None
    HAVE_PSUTIL = False


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

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    # -------- lifecycle --------
    def _handle_signal(self, signum, _frame):
        print(f"\n[signal] Received {signum}; stopping miner...")
        self.mining_alive = False
        self.cancel_mining.set()

    def validate_address(self) -> bool:
        if not self.address or not self.address.lower().startswith("tsar1"):
            print("Error: Address must start with 'tsar1...' (bech32)")
            return False
        return True

    def start_node(self) -> bool:
        print("[light-node] Starting stateless mining node...")
        try:
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=True,  # <-- no disk persistence, only RAM
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            print(f"[light-node] Connected to {peer_count} bootstrap peers (stateless mode)")
            return True
        except Exception as exc:
            print(f"[light-node] Failed to start: {exc}")
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
        print("[sync] Waiting for latest tip from peers (stateless miner)...")
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
                        print("[sync] Waiting for peer connection...")
                        notified_no_peer = True

                try:
                    height = int(getattr(self.blockchain, "height", -1))
                except Exception:
                    height = -1

                best_height = self._best_peer_height()
                if height >= 0 and peers_known:
                    if height != last_height:
                        print(f"[sync] Local tip height {height} (peer best {best_height if best_height >= 0 else '?'})")
                        last_height = height
                    return True

                time.sleep(2)
            except Exception as exc:
                print(f"[sync] Error: {exc}")
                time.sleep(2)
        print("[sync] Failed to obtain chain tip within timeout.")
        return False

    def start_mining(self, timeout: int = 600) -> bool:
        if not self.validate_address():
            return False
        if not self.start_node():
            return False
        if not self.wait_for_sync(timeout=timeout):
            return False

        current_height = int(getattr(self.blockchain, "height", -1))
        if current_height < 0:
            print("[sync] No chain data available from peers; cannot mine in stateless mode.")
            return False

        print("\n=== Stateless RandomX Miner ===")
        print(f"Address : {self.address}")
        print(f"Cores   : {self.cores}")
        print("Tip     :", current_height)
        print("NOTE    : No local DB is kept. Use cli_node_miner.py for full-node duties.")

        while self.mining_alive:
            try:
                if self.network and self.network.peers:
                    self.network.request_sync(fast=True)

                block = self.blockchain.mine_block(
                    miner_address=self.address,
                    use_cores=self.cores,
                    cancel_event=self.cancel_mining,
                    pow_backend="randomx",
                    progress_queue=None,
                )

                if not self.mining_alive:
                    break

                if block:
                    h = getattr(block, "height", "?")
                    print(f"[+] Block mined at height {h}: {block.hash().hex()[:18]}…  broadcasting...")
                    try:
                        sent = self.network.publish_block(block, exclude=None, force=True) if self.network else 0
                        if sent <= 0:
                            print("[broadcast] No peers reached; forcing fast sync.")
                            if self.network:
                                self.network.request_sync(fast=True)
                    except Exception as exc:
                        print(f"[broadcast] Error: {exc}")
            except KeyboardInterrupt:
                self.mining_alive = False
                self.cancel_mining.set()
                print("\n[signal] Mining interrupted by user; stopping workers...")
            except Exception as exc:
                if isinstance(exc, OSError) and getattr(exc, "errno", None) in INTERRUPTED_ERRNOS:
                    print("[mining] Interrupted system call; stopping miners...")
                    self.mining_alive = False
                    self.cancel_mining.set()
                    break
                print(f"[mining] Error: {exc}")
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
        print("[light-node] Shutdown complete.")


# -------- CLI helpers --------
def _prompt_address_and_cores() -> tuple[str, int]:
    print_banner()
    print("CLI Miner (RandomX)")
    print("Only mines + validates tip. For full node duties use cli_node_miner.py.")
    print("-" * 48)

    while True:
        addr = input("Miner address (tsar1...): ").strip()
        if addr.lower().startswith("tsar1"):
            break
        print("Invalid address. Example: tsar1qyourwalletaddresshere")

    while True:
        core_default = psutil.cpu_count(logical=True) if HAVE_PSUTIL else mp.cpu_count()
        entry = input(f"CPU cores to use [{core_default}]: ").strip()
        if not entry:
            cores = max(1, core_default or 1)
            break
        try:
            cores = int(entry)
            if cores > 0:
                break
            print("Cores must be positive.")
        except ValueError:
            print("Enter a number.")

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
        print("\nInterrupted by user.")
    finally:
        miner.shutdown()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    main()
