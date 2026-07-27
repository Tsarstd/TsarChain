# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

from __future__ import annotations

import sys
import time
import psutil
import threading
from collections import deque
from typing import Any

from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.console import Console

from .interface import _enable_windows_vt100, human_bytes
from tsarchain.utils.thread_check import get_thread_monitor


class ArchivistTUI:
    def __init__(
        self,
        *,
        address: str = "",
        target_node: tuple[str, int] = ("127.0.0.1", 39000),
        refresh_sec: int = 30,
        orchestrator: Any = None,
        show_threads: bool = True,
    ) -> None:
        _enable_windows_vt100()

        self.address = address
        self.target_node = target_node
        self.refresh_sec = refresh_sec
        self.orchestrator = orchestrator
        self.show_threads = show_threads
        self.thread_monitor = get_thread_monitor() if show_threads else None

        self._stop_event = threading.Event()
        self._render_lock = threading.Lock()

        self._start_ts = time.time()
        self._last_cpu_percent = 0.0
        self._last_cpu_update = 0.0

        self.log_lines: deque[str] = deque(maxlen=200)
        self.console = Console(file=sys.stdout, force_terminal=True, legacy_windows=False)
        self._live: Live | None = None

    def add_log(self, message: str) -> None:
        with self._render_lock:
            self.log_lines.append(message)

    def start(self) -> None:
        if self._live is not None:
            return

        psutil.cpu_percent(interval=None)

        try:
            self.console.clear()
        except Exception:
            pass

        self._live = Live(
            get_renderable=self._make_layout,
            console=self.console,
            refresh_per_second=2,
            vertical_overflow="crop",
            transient=False,
            screen=True,
        )
        self._live.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None
        try:
            sys.stdout.write("\033[?25h\033[0m")
            sys.stdout.flush()
        except Exception:
            pass

    def force_refresh(self) -> None:
        if self._live is not None:
            try:
                self._live.refresh()
            except Exception:
                pass

    def _make_layout(self) -> Layout:
        term_height = self.console.height or 24
        term_height = max(18, term_height)
        body_size = 7  # 5 content rows + 2 border lines

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", size=body_size),
            Layout(name="logs", ratio=1),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1),
        )

        # Extract stats from orchestrator if present
        info = getattr(self.orchestrator, "last_info", {}) or {}
        idx = getattr(self.orchestrator, "last_index", {}) or {}
        files = idx.get("files") if isinstance(idx, dict) else {}
        files = files if isinstance(files, dict) else {}

        connected = bool(getattr(self.orchestrator, "connected", False))
        bytes_used = idx.get("bytes_used", 0) if isinstance(idx, dict) else 0
        file_count = len(files)
        peers_cnt = info.get("peers", "-") if isinstance(info, dict) else "-"
        tip_height = info.get("height", "-") if isinstance(info, dict) else "-"
        pending_paid_cnt = len(getattr(self.orchestrator, "pending_paid", set()) or ())
        pool_cnt = len(getattr(self.orchestrator, "pool_data", {}) or {})

        # 1. Header Panel
        conn_status = "[bold green]Connected[/bold green]" if connected else "[bold red]Connecting...[/bold red]"
        addr_short = f"{self.address[:10]}...{self.address[-6:]}" if len(self.address) > 20 else (self.address or "N/A")
        node_str = f"{self.target_node[0]}:{self.target_node[1]}"

        header_text = Text.from_markup(
            f"[bold cyan]TsarChain Sovereign Storage Archivist[/bold cyan]  |  "
            f"Node: [bold yellow]{node_str}[/bold yellow] ({conn_status})  |  "
            f"Address: [bold white]{addr_short}[/bold white]  |  "
            f"Refresh: [bold green]{self.refresh_sec}s[/bold green]"
        )
        header_text.no_wrap = True
        header_text.overflow = "ellipsis"
        layout["header"].update(Panel(Align.center(header_text), border_style="cyan"))

        # 2. Left Panel: Storage & Retention Metrics
        left_table = Table(show_header=False, box=None, padding=(0, 1))
        left_table.add_column("Metric", style="bold cyan", no_wrap=True)
        left_table.add_column("Value", style="bold white", no_wrap=True)

        left_table.add_row("Storage Bytes Used", f"[bold green]{human_bytes(bytes_used)}[/bold green]")
        left_table.add_row("Managed File Count", f"[bold white]{file_count} file(s)[/bold white]")
        left_table.add_row("Pending Payouts", f"[bold yellow]{pending_paid_cnt} pending[/bold yellow]")
        left_table.add_row("Active Pool Posts", f"[bold gold1]{pool_cnt} post(s)[/bold gold1]")
        left_table.add_row("Auto-Payout Guard", "[bold green]Enabled & Active[/bold green]")
        layout["left"].update(Panel(left_table, title="[bold gold1]Storage & Retention Status[/bold gold1]", border_style="cyan"))

        # 3. Right Panel: Network & System Health
        uptime = int(time.time() - self._start_ts)
        up_h = uptime // 3600
        up_m = (uptime % 3600) // 60
        up_s = uptime % 60
        uptime_str = f"{up_h:02d}:{up_m:02d}:{up_s:02d}"

        now = time.time()
        if now - self._last_cpu_update > 1.5:
            self._last_cpu_percent = psutil.cpu_percent(interval=None)
            self._last_cpu_update = now
        cpu_pct = self._last_cpu_percent
        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")

        thread_str = "N/A"
        if self.show_threads and self.thread_monitor:
            try:
                tc = self.thread_monitor.get_thread_counts()
                thread_str = f"{tc['alive']} alive / {tc['total']} total"
            except Exception:
                pass

        right_table = Table(show_header=False, box=None, padding=(0, 1))
        right_table.add_column("Metric", style="bold cyan", no_wrap=True)
        right_table.add_column("Value", style="bold white", no_wrap=True)

        right_table.add_row("Chain Tip Height", f"[bold green]{tip_height}[/bold green]")
        right_table.add_row("P2P Node Peers", f"[bold white]{peers_cnt}[/bold white]")
        right_table.add_row("Active Threads", f"[bold yellow]{thread_str}[/bold yellow]")
        right_table.add_row("Memory (RAM)", f"{human_bytes(vm.used)} / {human_bytes(vm.total)} ({vm.percent:.0f}%)")
        right_table.add_row("Disk Free Space", f"{human_bytes(du.free)} / {human_bytes(du.total)}")
        right_table.add_row("CPU Load / Uptime", f"{cpu_pct:.0f}%  |  {uptime_str}")
        layout["right"].update(Panel(right_table, title="[bold dodger_blue1]Network & System Health[/bold dodger_blue1]", border_style="dodger_blue1"))

        # 4. Logs Stream Panel
        with self._render_lock:
            max_log_visible = max(2, term_height - 3 - body_size - 2)
            recent_logs = list(self.log_lines)[-max_log_visible:] if self.log_lines else []
            log_text = "\n".join(recent_logs) if recent_logs else "[dim]Waiting for storage & P2P network events...[/dim]"

        log_renderable = Text.from_ansi(log_text)
        log_renderable.no_wrap = True
        log_renderable.overflow = "ellipsis"
        layout["logs"].update(Panel(log_renderable, title="[bold white]Live Storage & P2P Activity Stream[/bold white]", border_style="grey50"))

        return layout


def create_tui_logger(tui: ArchivistTUI | None):
    def _log(line: str) -> None:
        if tui is not None and tui._live is not None:
            tui.add_log(line)
        else:
            print(line)
    return _log
