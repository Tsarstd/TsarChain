# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import argparse, re, sys, time, threading
import multiprocessing as mp

from tsarchain.utils.helpers import print_banner
from tsarchain.utils import config as CFG
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network

IPPORT_RE = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})$")

def parse_bootstrap(raw: str | None) -> tuple[str, int] | None:
    if not raw:
        return None
    m = IPPORT_RE.match(raw.strip())
    if not m:
        raise ValueError("Bootstrap harus format ip:port, contoh 157.45.14.12:64215")
    ip, port = m.group(1), int(m.group(2))
    if not (0 < port <= 65535):
        raise ValueError("Invalid Port")
    return ip, port

def start_node(blockchain: Blockchain, bootstrap: tuple[str, int] | None) -> tuple[Network, threading.Event]:
    net = Network(blockchain=blockchain)

    if bootstrap:
        try:
            net.persistent_peers.clear()
            net.peers.clear()
        except Exception:
            pass
        net.persistent_peers.add(bootstrap)
        net.peers.add(bootstrap)
        print(f"[Network] Manual bootstrap: {bootstrap[0]}:{bootstrap[1]}")
    else:
        fallback_nodes = tuple(getattr(CFG, "BOOTSTRAP_NODES", ()) or (CFG.BOOTSTRAP_NODE,))
        for peer in fallback_nodes:
            try:
                net.persistent_peers.add(peer)
                net.peers.add(peer)
            except Exception:
                pass
        try:
            if fallback_nodes:
                host, port = fallback_nodes[0]
                extra = f" (+{len(fallback_nodes)-1} alt)" if len(fallback_nodes) > 1 else ""
                print(f"[Network] Using config bootstrap: {host}:{port}{extra}")
            else:
                print("[Network] No bootstrap peers configured")
        except Exception:
            print("[Network] Using config bootstrap")

    print(f"[Network] Node started on port {getattr(net, 'port', '?')}")

    stop_evt = threading.Event()

    def sync_daemon():
        while not stop_evt.is_set():
            try:
                if net.peers:
                    net.request_sync()
            except Exception as e:
                print(f"[Sync] {e}")
            time.sleep(20)

    threading.Thread(target=sync_daemon, daemon=True).start()
    return net, stop_evt


def mining_loop(blockchain: Blockchain, network: Network, address: str,
                use_cores: int, pow_backend: str,
                cancel_evt, progress_q: mp.Queue):
    
    while not cancel_evt.is_set():
        try:
            if (getattr(blockchain, "height", -1) or -1) < 0:
                if not CFG.ALLOW_AUTO_GENESIS:
                    print("Auto-genesis disabled!!, waiting for peer sync…")
                    try:
                        if network and network.peers:
                            network.request_sync()
                    except Exception:
                        pass
                    time.sleep(3)
                    continue
                else:
                    try:
                        created = blockchain.ensure_genesis(address, use_cores=use_cores)
                        if created:
                            print("Genesis Block Created")
                    except Exception as e:
                        print(f"ensure_genesis failed: {e}")
                        time.sleep(2)
                        continue
                    
            if network and network.peers:
                try:
                    network.request_sync()
                except Exception:
                    pass
                time.sleep(1)

            blk = blockchain.mine_block(
                miner_address=address.strip(),
                use_cores=use_cores,
                cancel_event=cancel_evt,
                pow_backend=pow_backend,
                progress_queue=progress_q
            )
            if cancel_evt.is_set():
                break
            if blk:
                try:
                    h = blk.hash().hex()
                    print(f"[+] Block mined: {h[:16]}… height={getattr(blk, 'height', '?')}")
                except Exception:
                    print("[+] Block mined")

                try:
                    msg = {"type": "NEW_BLOCK", "data": blk.to_dict(), "port": getattr(network, 'port', None)}
                    for peer in list(getattr(network, 'peers', []) or []):
                        try:
                            network.broadcast._send(peer, msg)
                        except Exception:
                            pass
                except Exception:
                    pass

                try:
                    for tx in (getattr(blk, "transactions", []) or [])[1:]:
                        try:
                            network.broadcast.mempool.remove_tx(tx.txid.hex())
                        except Exception:
                            pass
                    try:
                        pool = network.broadcast.mempool.load_pool()
                        network.broadcast.mempool.save_pool(pool)
                    except Exception:
                        pass
                except Exception as e:
                    print(f"[Mempool] prune error: {e}")

        except Exception as e:
            print(f"[-] Mining: {e}")
            time.sleep(1)


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="TsarChain Minimal Mining CLI")
    parser.add_argument("-a", "--address", help="Miner address (tsar1…)", default=None)
    parser.add_argument("-c", "--cores", type=int, help="Jumlah core CPU yang dipakai", default=None)
    parser.add_argument("--bootstrap", help="Bootstrap peer ip:port (opsional)")
    parser.add_argument("--no-mine", action="store_true", help="Jalankan tanpa mining (seed-only)")

    args = parser.parse_args()

    # ====== Input interaktif bila tidak diberikan via arg ======
    address = args.address or input("Address (tsar1…): ").strip()
    pow_backend = "numba"
    
    if not address.lower().startswith("tsar1"):
        print("Address must prefix 'tsar1'.")
        sys.exit(2)

    if args.cores is None:
        try:
            import psutil
            cores = max(1, (psutil.cpu_count(logical=True) or 1) - 1)
        except Exception:
            import multiprocessing as _mp
            cores = max(1, (_mp.cpu_count() or 1) - 1)
        raw = input(f"CPU cores [{cores}]: ").strip()
        if raw:
            try:
                cores = max(1, int(raw))
            except Exception:
                print("Input cores tidak valid, pakai default.")
    else:
        cores = max(1, int(args.cores))

    # ====== Bootstrap parsing ======
    try:
        bootstrap = parse_bootstrap(args.bootstrap) if args.bootstrap else None
    except Exception as e:
        print(f"Bootstrap error: {e}")
        sys.exit(2)

    # ====== Init blockchain ======
    bc = Blockchain(db_path=CFG.BLOCK_FILE, in_memory=False, use_cores=cores, miner_address=address)

    if (getattr(bc, "height", -1) or -1) < 0:
        if CFG.ALLOW_AUTO_GENESIS:
            print("[Genesis] Chain empty → creating genesis (Allowed)…")
            try:
                created = bc.ensure_genesis(address, use_cores=cores)
                print("Genesis Block Created" if created else "[Genesis] Already present/locked")
            except Exception as e:
                print(f"Create Genesis Block Failed: {e}. Will wait for peer sync.")
        else:
            print("Auto-genesis disabled!!. Will wait for peer sync.")

    # ====== Start mining (kecuali --no-mine) ======
    net = None
    node_stop_evt = None
    if not args.no_mine:
        if net is None:
            net, node_stop_evt = start_node(bc, bootstrap)

        cancel_evt = mp.Event()
        progress_q = mp.Queue()

        t = threading.Thread(
            target=mining_loop,
            args=(bc, net, address, cores, pow_backend, cancel_evt, progress_q),
            daemon=True
        )
        t.start()

        print(f"[*] Mining started → addr={address} backend={pow_backend} cores={cores}")
        print("[*] Ctrl+C for stop.")

        try:
            last_print = 0.0
            while True:
                try:
                    tag, val = progress_q.get(timeout=1.0)
                    if tag == "TOTAL_HPS":
                        now = time.time()
                        if now - last_print >= 0.5:
                            try:
                                hps = float(val)
                                print(f"\r⛏️  {hps:,.0f} H/s", end="", flush=True)
                                last_print = now
                            except Exception:
                                pass
                except Exception:
                    pass
        except KeyboardInterrupt:
            print("\n[!] Shutting down…")
            cancel_evt.set()
            t.join(timeout=3.0)

    else:
        print("[Info] Mode seed-only (no mining). Ctrl+C for stop.")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n[!] Shutting down…")

    # ====== Stop node sync daemon ======
    try:
        if node_stop_evt:
            node_stop_evt.set()
    except Exception:
        pass


if __name__ == "__main__":
    main()
