# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: BIP141; BIP173

from __future__ import annotations

import sys
import argparse
import threading
from datetime import datetime
import multiprocessing as mp

from rich.console import Console
from tsarchain.utils import config as CFG
from archivist.archivist_orchestrator import ArchivistOrchestrator

from archivist.cosmetic_archivist import (
    print_banner,
    print_system_snapshot,
    get_user_input,
    _enable_windows_vt100,
    format_files_table,
    format_pool_table,
    ArchivistTUI,
    create_tui_logger,
)
from archivist.cosmetic_archivist.interface import (
    BOLD, GREY, GREEN, RED, CYAN, YELLOW, RESET
)

from tsarchain.utils.thread_check import get_thread_monitor
from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
log = get_ctx_logger("apps.cli_archivist")

REFRESH_SEC = 30
tui_logger = None


def _stamp() -> str:
    now = datetime.now()
    d = f"{now.year:04d}.{now.month:02d}.{now.day:02d}"
    t = f"{now.hour:02d}.{now.minute:02d}.{now.second:02d}"
    return f"{BOLD}{GREY} {d} {RESET}{BOLD}{GREY} {t} {RESET}"


def clog(message: str, color: str = GREY, error: bool = False):
    global tui_logger
    prefix_color = RED if error else color
    formatted = f"{_stamp()} : {prefix_color}{message}{RESET}"
    if tui_logger is not None:
        tui_logger(formatted)
    else:
        print(formatted)


class ArchivistCLI:
    def __init__(
        self,
        *,
        address: str,
        target_node: tuple[str, int],
        refresh_sec: int = REFRESH_SEC,
        enable_tui: bool = True,
    ):
        self._print_lock = threading.Lock()
        self._stop = threading.Event()
        self.enable_tui = enable_tui
        self.target_node = target_node
        self.address = address
        self.refresh_sec = refresh_sec

        self.orchestrator = ArchivistOrchestrator(
            address=address,
            target_node=target_node,
            refresh_sec=refresh_sec,
            log_callback=self._orchestrator_log,
            update_callback=self._trigger_dashboard_update
        )
        self.tui: ArchivistTUI | None = None

    # ---------- logging & updates ----------
    def _orchestrator_log(self, msg: str, error: bool = False) -> None:
        clog(msg, color=RED if error else CYAN, error=error)

    def _trigger_dashboard_update(self) -> None:
        if self.tui:
            self.tui.force_refresh()

    # ---------- commands ----------
    def _print_files_table(self) -> None:
        idx = self.orchestrator.last_index or {}
        files = idx.get("files") if isinstance(idx, dict) else {}
        files = files if isinstance(files, dict) else {}
        table = format_files_table(files)
        Console().print(table)

    def _print_pool_table(self) -> None:
        table = format_pool_table(self.orchestrator.pool_data)
        Console().print(table)

    def command_loop(self) -> None:
        if not self.enable_tui:
            clog("Command: status | files | pool | reconnect | quit", color=YELLOW)

        while not self._stop.is_set():
            try:
                cmd = input().strip() if self.enable_tui else input("archivist> ").strip()
            except (KeyboardInterrupt, EOFError):
                clog("Closing Archivist node...", color=YELLOW)
                self._stop.set()
                break

            if not cmd:
                continue

            if cmd in ("quit", "exit", "q"):
                self._stop.set()
                break

            if cmd in ("1", "dashboard", "dash", "status", "stats"):
                if self.tui:
                    self.tui.set_active_tab("dashboard")
                else:
                    info = self.orchestrator.last_info or {}
                    idx = self.orchestrator.last_index or {}
                    clog(f"Status: Tip={info.get('height', '-')} Peers={info.get('peers', '-')} Files={len(idx.get('files', {}))} Bytes={idx.get('bytes_used', 0)}", color=GREEN)
                continue

            if cmd in ("2", "files", "list-files", "index"):
                if self.tui:
                    self.tui.set_active_tab("files")
                else:
                    self._print_files_table()
                continue

            if cmd in ("3", "pool", "list", "posts"):
                if self.tui:
                    self.tui.set_active_tab("pool")
                else:
                    self._print_pool_table()
                continue

            if cmd in ("4", "threads", "thread"):
                if self.tui:
                    self.tui.set_active_tab("threads")
                else:
                    show_thread_report()
                continue

            if cmd in ("reconnect", "retry"):
                clog("Attempting manual reconnect to target node...", color=CYAN)
                if self.orchestrator.attempt_reconnect():
                    clog("Reconnected successfully!", color=GREEN)
                    self.orchestrator.refresh_once()
                else:
                    clog("Reconnection failed.", color=RED, error=True)
                continue

            clog("Available commands: [1] dashboard | [2] files | [3] pool | [4] threads | reconnect | quit", color=YELLOW)

    # ---------- lifecycle ----------
    def start(self) -> None:
        global tui_logger
        _enable_windows_vt100()

        if self.enable_tui:
            self.tui = ArchivistTUI(
                address=self.address,
                target_node=self.target_node,
                refresh_sec=self.refresh_sec,
                orchestrator=self.orchestrator,
            )
            self.tui.start()
            tui_logger = create_tui_logger(self.tui)

        clog(f"Starting Sovereign Storage Archivist Node (address: {self.address})...", color=GREEN)

        if not self.orchestrator.start():
            clog("Failed to start orchestrator connection to node!", color=RED, error=True)
            if self.tui:
                self.tui.stop()
                tui_logger = None
            return

        clog(f"Connected to node {self.target_node[0]}:{self.target_node[1]}", color=GREEN)

        try:
            self.command_loop()
        except KeyboardInterrupt:
            clog("Interrupted by user", color=YELLOW)
        finally:
            if self.tui:
                self.tui.stop()
                tui_logger = None

    def stop(self) -> None:
        global tui_logger
        self._stop.set()
        self.orchestrator.stop()
        if self.tui:
            self.tui.stop()
            tui_logger = None


def show_thread_report() -> None:
    monitor = get_thread_monitor()
    monitor.print_thread_report(detailed=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TsarChain CLI Archivist Node")
    parser.add_argument("--address", help="Payout storage Address (tsar1...)")
    parser.add_argument("--host", help="Target node host IP", default=None)
    parser.add_argument("--port", type=int, help="Target node RPC port", default=None)
    parser.add_argument("--refresh", type=int, help="Interval refresh status in seconds", default=REFRESH_SEC)
    parser.add_argument("--no-tui", action="store_true", help="Disable Rich TUI dashboard and run in plain console mode")
    parser.add_argument("--thread-report", action="store_true", help="Show active thread health report and exit")
    parser.add_argument("-y", "--yes", action="store_true", help="Non-interactive mode (use defaults and CLI args)")
    return parser.parse_args()


def main() -> None:
    _enable_windows_vt100()
    args = parse_args()

    if args.thread_report:
        show_thread_report()
        return

    is_interactive = sys.stdin.isatty() and not args.yes
    address = (args.address or "").strip()
    host = args.host
    port = args.port

    if is_interactive and not address:
        print_banner()
        print_system_snapshot()
        wiz_addr, wiz_host, wiz_port = get_user_input()
        address = wiz_addr
        host = host or wiz_host
        port = port or wiz_port

    if not address or not address.lower().startswith(CFG.ADDRESS_PREFIX):
        clog(f"Error: Payout address is required and must start with '{CFG.ADDRESS_PREFIX}...'", color=RED, error=True)
        sys.exit(2)

    target_host = host or CFG.BOOTSTRAP_NODE[0]
    target_port = int(port or CFG.BOOTSTRAP_NODE[1])

    enable_tui = not args.no_tui

    cli = ArchivistCLI(
        address=address,
        target_node=(target_host, target_port),
        refresh_sec=args.refresh,
        enable_tui=enable_tui,
    )

    try:
        cli.start()
    finally:
        cli.stop()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging("logging/archivist.log", force=True)
    main()
