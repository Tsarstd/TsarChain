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

import os
import sys
import argparse
import multiprocessing as mp
from datetime import datetime

# ---------------- Local Project ----------------
from tsarchain.utils import config as CFG
from tsarchain.utils.cosmetic import interface as COL
from tsarchain.miner.orchestrator import NodeRunner, SimpleMiner, set_clog_func
from tsarchain.utils.cosmetic.tui import MinerTUI, create_tui_logger
from tsarchain.utils.cosmetic.thread_check import get_thread_monitor

from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
log = get_ctx_logger("apps.cli_node_miner")

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

def show_thread_report():
    monitor = get_thread_monitor()
    monitor.print_thread_report(detailed=True)

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
            print(" ")
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
    parser.add_argument("--thread-report", action="store_true", help="Show thread report and exit")
    return parser.parse_args()

def _normalize_cores(cores: int | None) -> int | None:
    cpu_total = mp.cpu_count()
    if cores is None:
        return cpu_total or 1
    cores_int = int(cores)
    if cores_int <= 0:
        return None
    if cpu_total:
        cores_int = min(cores_int, cpu_total)
    return cores_int

def main():
    args = parse_args()
    set_clog_func(clog)
    
    if args.thread_report:
        show_thread_report()
        return
    
    mode_selected = None
    if not args.node_only:
        # Interactive mode selection
        COL.print_banner()
        COL.print_system_snapshot(cores_hint=None)
        mode_selected = choose_mode()

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

    cores = _normalize_cores(cores)
    if cores is None:
        clog("Invalid --cores value. Please provide a positive integer.")
        sys.exit(2)

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
    
    miner = SimpleMiner(
        address=address,
        cores=cores,
        bootstrap_snapshot=not args.no_bootstrap,
        progress_queue=progress_q,
    )

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
    
    miner.tui = tui
    tui.start()
    global tui_logger
    tui_logger = create_tui_logger(tui)

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
    setup_logging("logging/node.log", force=True)
    main()
