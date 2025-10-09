#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# TsarChain Minimal Mining CLI

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
    """Start node + background sync daemon."""
    net = Network(blockchain=blockchain)

    if bootstrap:
        # Prioritaskan peer manual
        try:
            net.persistent_peers.clear()
            net.peers.clear()
        except Exception:
            pass
        net.persistent_peers.add(bootstrap)
        net.peers.add(bootstrap)
        print(f"[Network] Manual bootstrap: {bootstrap[0]}:{bootstrap[1]}")
    else:
        # Fallback ke config
        fallback = CFG.BOOTSTRAP_DEV if CFG.IS_DEV else CFG.BOOTSTRAP_PROD
        net.persistent_peers.add(fallback)
        net.peers.add(fallback)
        try:
            print(f"[Network] Using config bootstrap: {fallback[0]}:{fallback[1]}")
        except Exception:
            print("[Network] Using config bootstrap")

    print(f"[Network] Node started on port {getattr(net, 'port', '?')}")

    stop_evt = threading.Event()

    def sync_daemon():
        while not stop_evt.is_set():
            try:
                if net.peers:
                    net.sync_with_peers()
            except Exception as e:
                print(f"[Sync] {e}")
            time.sleep(20)

    threading.Thread(target=sync_daemon, daemon=True).start()
    return net, stop_evt


def mining_loop(blockchain: Blockchain, network: Network, address: str,
                use_cores: int, pow_backend: str,
                cancel_evt, progress_q):
    """Loop penambangan dengan broadcast block baru (mirror dari GUI)."""
    while not cancel_evt.is_set():
        try:
            if network and network.peers:
                try:
                    network.sync_with_peers()
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

                # Broadcast block ke peers (seperti di GUI)
                try:
                    msg = {"type": "NEW_BLOCK", "data": blk.to_dict(), "port": getattr(network, 'port', None)}
                    for peer in list(getattr(network, 'peers', []) or []):
                        try:
                            network.broadcast._send(peer, msg)
                        except Exception:
                            pass
                except Exception:
                    pass

                # Prune mempool tx yang sudah masuk block (mirror GUI)
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
    print_banner()  # banner CLI buatanmu

    parser = argparse.ArgumentParser(description="TsarChain Minimal Mining CLI")
    parser.add_argument("-a", "--address", help="Miner address (tsar1…)", default=None)
    parser.add_argument("-c", "--cores", type=int, help="Jumlah core CPU yang dipakai", default=None)
    parser.add_argument("--bootstrap", help="Bootstrap peer ip:port (opsional)")
    parser.add_argument("--pow-backend", choices=["numba", "python"], default="numba")
    # Toggle start node & start mining
    parser.add_argument("--no-node", action="store_true", help="Jalankan tanpa start node (tidak disarankan)")
    parser.add_argument("--no-mine", action="store_true", help="Jalankan tanpa mining (seed-only)")
    # Genesis otomatis saat chain kosong:
    parser.add_argument("--no-genesis", action="store_true", help="Jangan auto-create genesis walau chain kosong")

    args = parser.parse_args()

    # ====== Input interaktif bila tidak diberikan via arg ======
    address = args.address or input("Address (tsar1…): ").strip()
    if not address.lower().startswith("tsar1"):
        print("Address harus prefix 'tsar1'.")
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
    # auto_create_genesis=False -> kita kendalikan sendiri sesuai kondisi
    bc = Blockchain(
        db_path=CFG.BLOCK_FILE,
        in_memory=False,
        use_cores=cores,
        auto_create_genesis=False
    )

    # Auto-create genesis kalau height < 0 dan tidak di-disable
    if (getattr(bc, "height", -1) or -1) < 0 and not args.no_genesis:
        print("[Genesis] Chain kosong → membuat genesis block…")
        created = bc.ensure_genesis(address, use_cores=cores)
        print("[Genesis] Done" if created else "[Genesis] Sudah ada")

    # ====== Start node (kecuali --no-node) ======
    net = None
    node_stop_evt = None
    if not args.no_node:
        net, node_stop_evt = start_node(bc, bootstrap)
    else:
        print("[Warn] --no-node aktif: mining tanpa node tidak disarankan.")

    # ====== Start mining (kecuali --no-mine) ======
    if not args.no_mine:
        if net is None:
            # paksa start node agar mining berjalan sehat
            net, node_stop_evt = start_node(bc, bootstrap)

        cancel_evt = mp.Event()
        progress_q = mp.Queue()

        t = threading.Thread(
            target=mining_loop,
            args=(bc, net, address, cores, args.pow_backend, cancel_evt, progress_q),
            daemon=True
        )
        t.start()

        print(f"[*] Mining started → addr={address} backend={args.pow_backend} cores={cores}")
        print("[*] Tekan Ctrl+C untuk berhenti.")

        try:
            last_print = 0.0
            while True:
                try:
                    tag, val = progress_q.get(timeout=1.0)
                    if tag == "TOTAL_HPS":
                        now = time.time()
                        # batasi spam output
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
        print("[Info] Mode seed-only (tanpa mining). Tekan Ctrl+C untuk keluar.")
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
