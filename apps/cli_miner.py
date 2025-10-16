# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

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


class SimpleMiner:
    def __init__(self, address, cores):
        self.address = address
        self.cores = cores
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self.blockchain = None
        self.network = None
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()
    
    def validate_address(self):
        if not self.address or not self.address.lower().startswith("tsar1"):
            print(f"Error: Address should start with 'tsar1...'")
            return False
        return True
    
    def start_node(self):
        print("Starting node...")
        try:
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE, 
                in_memory=False,
                use_cores=self.cores, 
                miner_address=self.address
            )
            self.network = Network(blockchain=self.blockchain)
            
            # Add bootstrap nodes
            fallback_nodes = tuple(getattr(CFG, "BOOTSTRAP_NODES", ()) or (CFG.BOOTSTRAP_NODE,))
            for peer in fallback_nodes:
                self.network.persistent_peers.add(peer)
                self.network.peers.add(peer)
                
            print(f"Node started with {len(fallback_nodes)} bootstrap peers")
            return True
            
        except Exception as e:
            print(f"Failed to start node: {e}")
            return False
    
    def wait_for_sync(self, timeout=60):
        print("Waiting for blockchain sync...")
        start_time = time.time()
        
        while self.mining_alive and (time.time() - start_time) < timeout:
            try:
                if self.network.peers:
                    self.network.request_sync(fast=True)
                    
                    height = getattr(self.blockchain, "height", -1)
                    if height >= 0:
                        print(f"Chain synced to height {height}")
                        return True
                
                time.sleep(2)
            except Exception as e:
                print(f"Sync error: {e}")
                time.sleep(2)
        
        print("Sync timeout or interrupted")
        return False
    
    def start_mining(self):
        if not self.validate_address():
            return False
            
        if not self.start_node():
            return False
            
        if not self.wait_for_sync():
            return False
        
        print(f"Starting mining with:")
        print(f"  Address: {self.address}")
        print(f"  Cores: {self.cores}")
        print("Press Ctrl+C to stop mining")
        print("-" * 50)
        
        # Ensure genesis block exists
        if getattr(self.blockchain, "height", -1) < 0:
            created = self.blockchain.ensure_genesis(self.address, use_cores=self.cores)
            if created:
                print("[+] Genesis block created")
            else:
                print("[-] Failed to create genesis block")
                return False
        
        # Mining loop
        block_count = 0
        while self.mining_alive:
            try:
                if self.network.peers:
                    self.network.request_sync(fast=True)
                
                block = self.blockchain.mine_block(
                    miner_address=self.address,
                    use_cores=self.cores,
                    cancel_event=self.cancel_mining,
                    pow_backend="numba",
                    progress_queue=None
                )
                
                if not self.mining_alive:
                    break
                    
                if block:
                    block_count += 1
                    print(f"[+] Block #{block_count} mined: {block.hash().hex()[:16]}…")
                    
                    # Broadcast new block
                    try:
                        msg = {"type": "NEW_BLOCK", "data": block.to_dict(), "port": self.network.port}
                        for peer in list(self.network.peers):
                            self.network.broadcast._send(peer, msg)
                    except Exception as e:
                        print(f"Broadcast error: {e}")
                        
            except Exception as e:
                print(f"[-] Mining error: {e}")
                time.sleep(1)
        
        return True
    
    def stop(self):
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()
        
        if self.network:
            try:
                self.network.shutdown()
            except:
                pass
        
        print("Miner stopped")

def get_user_input():
    print_banner()
    print("Please enter your mining details:")
    print("-" * 40)
    
    # Get address
    while True:
        address = input("Miner address (tsar1...): ").strip()
        if address and address.lower().startswith("tsar1"):
            break
        else:
            print("Error: Address must start with 'tsar1...'")
            print("Example: tsar1qyourwalletaddresshere")
    
    # Get cores
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
            else:
                print("Error: Cores must be a positive number")
        except ValueError:
            print("Error: Please enter a valid number")
    
    return address, cores

def main():
    address, cores = get_user_input()
    miner = SimpleMiner(address, cores)
    
    try:
        miner.start_mining()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Fatal error: {e}")
    finally:
        miner.stop()

if __name__ == "__main__":
    mp.freeze_support()
    main()