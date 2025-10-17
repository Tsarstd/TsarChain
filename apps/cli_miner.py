# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

import argparse
import time
import multiprocessing as mp
import signal

# ---------------- Local Project ----------------
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import print_banner

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    psutil = None
    HAVE_PSUTIL = False


def _register_bootstrap_peers(network: Network) -> int:
    fallback_nodes = tuple(getattr(CFG, "BOOTSTRAP_NODES", ()) or (CFG.BOOTSTRAP_NODE,))
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


class SimpleMiner:
    def __init__(self, address, cores):
        self.address = address
        self.cores = cores
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self.blockchain = None
        self.network = None

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, _frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()

    def validate_address(self):
        if not self.address or not self.address.lower().startswith("tsar1"):
            print("Error: Address should start with 'tsar1...'")
            return False
        return True

    def start_node(self):
        print("Starting node...")
        try:
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=False,
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            print(f"Node started with {peer_count} bootstrap peers")
            return True
        except Exception as exc:
            print(f"Failed to start node: {exc}")
            return False

    def wait_for_sync(self, timeout=560):
        print("Waiting for blockchain sync...")
        start_time = time.time()
        last_progress = (-1, -1)
        notified_no_peer = False

        while self.mining_alive and (time.time() - start_time) < timeout:
            try:
                if self.network.peers:
                    if notified_no_peer:
                        print("Peer connection restored, resuming sync...")
                        notified_no_peer = False
                    self.network.request_sync(fast=True)

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
                            caught_up = height >= 0
                    else:
                        caught_up = height >= 0

                    if caught_up and height >= 0:
                        if best_height < height:
                            best_height = height
                        print(f"Chain synced to height {height}")
                        return True

                    if best_height >= 0:
                        progress = (height, best_height)
                        if progress != last_progress:
                            print(f"Sync progress - local height: {height}, best known peer: {best_height}")
                            last_progress = progress
                else:
                    if not notified_no_peer:
                        print("Waiting for peer connection...")
                        notified_no_peer = True
                time.sleep(2)
            except Exception as exc:
                print(f"Sync error: {exc}")
                time.sleep(2)

        print("Sync timeout or interrupted")
        return False

    def start_mining(self, timeout=560):
        if not self.validate_address():
            return False
        if not self.start_node():
            return False
        if not self.wait_for_sync(timeout=timeout):
            return False

        print("Starting mining with:")
        print(f"  Address: {self.address}")
        print(f"  Cores:   {self.cores}")
        print("Press Ctrl+C to stop mining")
        print("-" * 50)

        if getattr(self.blockchain, "height", -1) < 0:
            created = self.blockchain.ensure_genesis(self.address, use_cores=self.cores)
            if created:
                print("[+] Genesis block created")
            else:
                print("[-] Failed to create genesis block")
                return False

        while self.mining_alive:
            try:
                if self.network.peers:
                    self.network.request_sync(fast=True)

                block = self.blockchain.mine_block(
                    miner_address=self.address,
                    use_cores=self.cores,
                    cancel_event=self.cancel_mining,
                    pow_backend="numba",
                    progress_queue=None,
                )

                if not self.mining_alive:
                    break

                if block:
                    print(f"[+] Block mined: {block.hash().hex()[:18]}…")
                    try:
                        sent = self.network.publish_block(block, exclude=None, force=True)
                        if sent <= 0:
                            print("Warning: block broadcast reached 0 peers, triggering fast resync request.")
                            self.network.request_sync(fast=True)
                    except Exception as exc:
                        print(f"Broadcast error: {exc}")
            except Exception as exc:
                print(f"[-] Mining error: {exc}")
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

        print("Miner stopped")


class NodeRunner:
    def __init__(self):
        self.blockchain = None
        self.network = None
        self.running = True
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, *_args):
        print("\nStopping node...")
        self.running = False

    def start(self):
        print_banner()
        print("Starting TsarChain node (no mining)...")
        try:
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE,
                in_memory=False,
                use_cores=None,
                miner_address=None,
            )
            print(f"Local chain height: {self.blockchain.height}")
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            print(f"Node online on port {self.network.port}, bootstrap peers: {peer_count}")
            print("Press Ctrl+C to stop.")
            while self.running:
                time.sleep(2)
        except Exception as exc:
            print(f"Node error: {exc}")
        finally:
            self.shutdown()

    def shutdown(self):
        if self.network:
            try:
                self.network.shutdown()
            except Exception:
                pass
            self.network = None
        print("Node stopped.")


def get_user_input():
    print_banner()
    print("Please enter your mining details:")
    print("-" * 40)

    while True:
        address = input("Miner address (tsar1...): ").strip()
        if address and address.lower().startswith("tsar1"):
            break
        print("Error: Address must start with 'tsar1...'")
        print("Example: tsar1qyourwalletaddresshere")

    while True:
        cores = psutil.cpu_count(logical=True) if HAVE_PSUTIL else mp.cpu_count()
        cores_input = input(f"CPU cores to use [{cores}]: ").strip()
        if not cores_input:
            cores = 1
            break
        try:
            cores = int(cores_input)
            if cores > 0:
                break
            print("Error: Cores must be a positive number")
        except ValueError:
            print("Error: Please enter a valid number")

    return address, cores


def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain CLI miner / node runner")
    parser.add_argument("--address", help="Miner payout address (tsar1...)")
    parser.add_argument("--cores", type=int, help="CPU cores to use for mining")
    parser.add_argument("--node-only", action="store_true", help="Run node without mining")
    parser.add_argument("--timeout", type=int, default=560, help="Sync timeout in seconds (mining mode)")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.node_only:
        runner = NodeRunner()
        runner.start()
        return

    address = args.address
    cores = args.cores

    if not address or not cores:
        input_address, input_cores = get_user_input()
        address = address or input_address
        cores = cores or input_cores

    miner = SimpleMiner(address, cores)

    try:
        miner.start_mining(timeout=args.timeout)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as exc:
        print(f"Fatal error: {exc}")
    finally:
        miner.stop()


if __name__ == "__main__":
    mp.freeze_support()
    main()
