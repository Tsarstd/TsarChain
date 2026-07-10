# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

from __future__ import annotations

import sys
import argparse
import threading
import multiprocessing as mp
from typing import Any, Dict

from tsarchain.utils import config as CFG
from archivist.archivist_orchestrator import ArchivistOrchestrator

from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
log = get_ctx_logger("apps.cli_archivist")

REFRESH_SEC = 30

def _fmt_bytes(n: Any) -> str:
    size = float(n)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for u in units:
        if size < 1024.0 or u == units[-1]:
            return f"{size:.2f} {u}" if u != "B" else f"{int(size)} {u}"
        size /= 1024.0


class ArchivistCLI:
    def __init__(
        self,
        *,
        address: str,
        target_node: tuple[str, int],
        refresh_sec: int = REFRESH_SEC,
    ):
        self._print_lock = threading.Lock()
        self._last_dashboard: str = ""
        self._stop = threading.Event()

        self.orchestrator = ArchivistOrchestrator(
            address=address,
            target_node=target_node,
            refresh_sec=refresh_sec,
            log_callback=self._log,
            update_callback=self._trigger_dashboard_update
        )

    # ---------- logging ----------
    def _log(self, msg: str, error: bool = False) -> None:
        with self._print_lock:
            prefix = "[err]" if error else "[info]"
            print(f"{prefix} {msg}")
            sys.stdout.flush()

    def _trigger_dashboard_update(self) -> None:
        self._print_dashboard()

    # ---------- rendering ----------
    def _print_dashboard(self, force: bool = False) -> None:
        info = self.orchestrator.last_info or {}
        idx = self.orchestrator.last_index or {}
        files = idx.get("files") if isinstance(idx, dict) else None
        files = files if isinstance(files, dict) else {}

        used = _fmt_bytes(idx.get("bytes_used", 0))
        file_count = len(files) if isinstance(files, dict) else 0
        peers = info.get("peers", "-") if isinstance(info, dict) else "-"
        tip = info.get("height") if isinstance(info, dict) else "-"

        header = f"Archivist CLI | tip={tip} peers={peers} files={file_count} used={used}"

        lines = [header, "-" * len(header)]

        buf = "\n".join(lines)
        if not force and buf == self._last_dashboard:
            return
        self._last_dashboard = buf
        with self._print_lock:
            print(buf)
            sys.stdout.flush()

    def _format_files_table(self, files: Dict[str, Any]) -> str:
        headers = ["graffiti_id", "size", "paid", "expire", "state"]
        widths = [64, 12, 6, 10, 10]
        rows: list[list[str]] = []
        for gid, meta in list(files.items())[:10]:
            art_id = str(meta.get("art_id") or gid)
            display_id = art_id[:64] if len(art_id) > 64 else art_id
            rows.append([
                display_id,
                f"{int(meta.get('size_bytes', 0)):,}",
                "yes" if meta.get("paid") else "no",
                str(meta.get("expire_at_height", "-")),
                str(meta.get("state", "-")),
            ])
        if not rows:
            return "(no file yet)"
        table = [" ".join(h.ljust(w) for h, w in zip(headers, widths))]
        for r in rows:
            table.append(" ".join(val.ljust(w) for val, w in zip(r, widths)))
        return "\n".join(table)

    def _format_pool_table(self, pool_data: Dict[str, Any]) -> str:
        if not pool_data:
            return "(pool not available)"
        headers = ["art_id", "pool", "size", "creator", "comments"]
        widths = [64, 16, 12, 64, 10]
        table = [" ".join(h.ljust(w) for h, w in zip(headers, widths))]
        for aid, entry in list(pool_data.items())[:64]:
            stats = entry.get("stats") or {}
            file_meta = entry.get("file") or {}
            creator = (entry.get("post", {}).get("creator") or "")[:64]
            pool_bal = float(stats.get("pool_balance", 0)) / float(CFG.TSAR)
            size_bytes = int(file_meta.get("size_bytes", 0))
            table.append(" ".join([
                (aid[:64]).ljust(widths[0]),
                f"{pool_bal:.8f}".ljust(widths[1]),
                f"{size_bytes:,}".ljust(widths[2]),
                creator.ljust(widths[3]),
                str(stats.get("comments", 0)).ljust(widths[4]),
            ]))
        return "\n".join(table)

    # ---------- commands ----------
    def _print_pool_table(self) -> None:
        lines = self._format_pool_table(self.orchestrator.pool_data)
        with self._print_lock:
            print(lines if isinstance(lines, str) else "")
            sys.stdout.flush()

    def command_loop(self) -> None:
        self._log("Command: status | pool | reconnect | quit")
        while not self._stop.is_set():
            try:
                cmd = input("archivist> ").strip()
            except (KeyboardInterrupt, EOFError):
                self._log("Closing...")
                self._stop.set()
                break
            
            if not cmd:
                continue
            
            if cmd in ("quit", "exit", "q"):
                self._stop.set()
                break
            
            if cmd in ("status", "stats"):
                self._print_dashboard(force=True)
                continue
            
            if cmd in ("pool", "list"):
                self._print_pool_table()
                continue
            
            if cmd in ("reconnect", "retry"):
                if self.orchestrator.attempt_reconnect():
                    self._log("Reconnected.")
                    self.orchestrator.refresh_once()
                else:
                    self._log("Reconnection failed.", error=True)
                continue
            
            self._log("Unknown command. Use: status | pool | reconnect | quit")

    # ---------- lifecycle ----------
    def start(self) -> None:
        if not self.orchestrator.start():
            return
        self._print_dashboard(force=True)
        self.command_loop()

    def stop(self) -> None:
        self._stop.set()
        self.orchestrator.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TsarChain Archivist CLI (headless)")
    parser.add_argument("--address", help="Payout storage Address(tsar1...)")
    parser.add_argument("--host", help="Target node host", default=None)
    parser.add_argument("--port", type=int, help="Target node port", default=None)
    parser.add_argument("--refresh", type=int, help="Interval refresh status (second)", default=REFRESH_SEC)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    address = (args.address or "").strip()
    if not address:
        try:
            address = input("Input payout address (tsar1...): ").strip()
        except EOFError:
            address = ""
    if not address or not address.lower().startswith(CFG.ADDRESS_PREFIX):
        print("Payout address must be filled in and start with the correct prefix. (tsar1...).")
        sys.exit(2)

    host = args.host or CFG.BOOTSTRAP_NODE[0]
    port = args.port or CFG.BOOTSTRAP_NODE[1]

    cli = ArchivistCLI(address=address, target_node=(host, int(port)), refresh_sec=args.refresh)
    try:
        cli.start()
    finally:
        cli.stop()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging("logging/archivist.log", force=True)
    main()
