# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import sys
import time
import queue
import psutil
import threading
from collections import deque
from typing import Callable, Optional

from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.console import Console

from tsarchain.utils.thread_check import get_thread_monitor


def _enable_windows_vt100() -> None:
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            
            kernel32.GetStdHandle.argtypes = [ctypes.c_ulong]
            kernel32.GetStdHandle.restype = ctypes.c_void_p
            kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            kernel32.GetConsoleMode.restype = ctypes.c_int
            kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            kernel32.SetConsoleMode.restype = ctypes.c_int
            kernel32.CreateFileW.argtypes = [
                ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p
            ]
            kernel32.CreateFileW.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int

            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            DISABLE_NEWLINE_AUTO_RETURN = 0x0008

            # 1. Try standard output handle (-11) and standard error handle (-12)
            for std_handle in (0xFFFFFFF5, 0xFFFFFFF4):
                h_out = kernel32.GetStdHandle(std_handle)
                if h_out and h_out != ctypes.c_void_p(-1).value:
                    mode = ctypes.c_ulong()
                    if kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
                        kernel32.SetConsoleMode(
                            h_out, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
                        )

            # 2. Try direct CONOUT$ handle (crucial for compiled PyInstaller .exe on Windows CMD/PowerShell)
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            h_conout = kernel32.CreateFileW(
                "CONOUT$",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if h_conout and h_conout != ctypes.c_void_p(-1).value:
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(h_conout, ctypes.byref(mode)):
                    kernel32.SetConsoleMode(
                        h_conout, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
                    )
                kernel32.CloseHandle(h_conout)
        except Exception:
            pass


def _human_bytes(n: float) -> str:
    try:
        n = float(n)
    except Exception:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} EB"


def _human_hps(hps: float) -> str:
    try:
        hps = float(hps)
    except Exception:
        return "? H/s"
    units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s"]
    i = 0
    while hps >= 1000.0 and i < len(units) - 1:
        hps /= 1000.0
        i += 1
    if hps >= 100:
        return f"{hps:,.0f} {units[i]}"
    if hps >= 10:
        return f"{hps:,.1f} {units[i]}"
    return f"{hps:,.2f} {units[i]}"


class MinerTUI:
    def __init__(
        self,
        *,
        address: str = "",
        cores: int = 0,
        mode: str = "",
        randomx_mode: str = "",
        hashrate_queue: "queue.Queue | None" = None,
        chain_height_fn: Optional[Callable[[], int]] = None,
        peer_counts_fn: Optional[Callable[[], tuple[int, int]]] = None,
        mempool_count_fn: Optional[Callable[[], int]] = None,
        show_threads: bool = True,
        node_only: bool = False,
    ) -> None:

        _enable_windows_vt100()

        self.address = address
        self.cores = cores
        self.mode = mode
        self.randomx_mode = randomx_mode
        self.hashrate_queue = hashrate_queue
        self.chain_height_fn = chain_height_fn
        self.peer_counts_fn = peer_counts_fn
        self.mempool_count_fn = mempool_count_fn
        self.node_only = node_only

        self._stop_event = threading.Event()
        self._render_lock = threading.Lock()
        self._hashrate_thread: threading.Thread | None = None

        self._last_hashrate = 0.0
        self._blocks_mined = 0
        self._start_ts = time.time()
        self._last_cpu_percent = 0.0
        self._last_cpu_update = 0.0

        self.show_threads = show_threads
        self.thread_monitor = get_thread_monitor() if show_threads else None

        self.log_lines: deque[str] = deque(maxlen=200)
        self.console = Console(file=sys.stdout, force_terminal=True, legacy_windows=False)
        self._live: Live | None = None

    # ---- public helpers ----

    def add_log(self, message: str) -> None:
        with self._render_lock:
            self.log_lines.append(message)

    def start(self) -> None:
        if self._live is not None:
            return

        psutil.cpu_percent(interval=None)

        if self.hashrate_queue is not None:
            self._hashrate_thread = threading.Thread(
                target=self._hashrate_loop,
                name="TsarTUI-Hashrate",
                daemon=True,
            )
            self._hashrate_thread.start()

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



    def reset_uptime(self) -> None:
        with self._render_lock:
            self._start_ts = time.time()

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

    def note_block_mined(self, _height: int | None = None) -> None:
        self._blocks_mined += 1

    def set_hashrate(self, hps: float) -> None:
        self._last_hashrate = float(hps)

    def force_refresh(self) -> None:
        if self._live is not None:
            try:
                self._live.refresh()
            except Exception:
                pass

    # ---- internal loops ----

    def _hashrate_loop(self) -> None:
        q = self.hashrate_queue
        if q is None:
            return
        while not self._stop_event.is_set():
            try:
                msg = q.get(timeout=1.0)
            except queue.Empty:
                continue
            except Exception:
                break
            if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == "TOTAL_HPS":
                self.set_hashrate(msg[1])

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

        # 1. Header Panel
        if self.node_only:
            header_text = Text.from_markup(
                f"[bold cyan]TsarChain Sovereign Full Node[/bold cyan]  |  "
                f"Role: [bold blue]Relay & Mempool Node[/bold blue]  |  "
                f"Mining Engine: [bold grey50]Disabled[/bold grey50]"
            )
            border_color = "dodger_blue1"
        else:
            addr_short = f"{self.address[:10]}...{self.address[-6:]}" if len(self.address) > 20 else (self.address or "Node Only")
            header_text = Text.from_markup(
                f"[bold orange1]TsarChain Full Node & Miner[/bold orange1]  |  "
                f"Mode: [bold yellow]{self.mode or 'Active'}[/bold yellow]  |  "
                f"Address: [bold white]{addr_short}[/bold white]  |  "
                f"RandomX: [bold cyan]{self.randomx_mode or 'Default'}[/bold cyan]"
            )
            border_color = "orange1"
        header_text.no_wrap = True
        header_text.overflow = "ellipsis"
        layout["header"].update(Panel(Align.center(header_text), border_style=border_color))

        # 2. System & Node/Mining Metrics Panel
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

        peers_in, peers_out = 0, 0
        if callable(self.peer_counts_fn):
            try:
                res = self.peer_counts_fn()
                if res:
                    peers_in, peers_out = res
            except Exception:
                pass

        height = -1
        if callable(self.chain_height_fn):
            try:
                height = self.chain_height_fn()
            except Exception:
                pass

        thread_str = "N/A"
        if self.show_threads and self.thread_monitor:
            try:
                tc = self.thread_monitor.get_thread_counts()
                thread_str = f"{tc['alive']} alive / {tc['total']} total"
            except Exception:
                pass

        mempool_cnt = 0
        if callable(self.mempool_count_fn):
            try:
                mempool_cnt = self.mempool_count_fn() or 0
            except Exception:
                pass

        left_table = Table(show_header=False, box=None, padding=(0, 1))
        left_table.add_column("Metric", style="bold cyan", no_wrap=True)
        left_table.add_column("Value", style="bold white", no_wrap=True)

        if self.node_only:
            left_table.add_row("Node Mode", "[bold blue]Relay & Mempool[/bold blue]")
            left_table.add_row("Chain Tip Height", f"[bold green]{height if height >= 0 else 'Syncing...'}[/bold green]")
            left_table.add_row("Mempool Pending", f"[bold yellow]{mempool_cnt} txs[/bold yellow]")
            left_table.add_row("Memory (RAM)", f"{_human_bytes(vm.used)} / {_human_bytes(vm.total)} ({vm.percent:.0f}%)")
            left_table.add_row("Uptime", uptime_str)
            layout["left"].update(Panel(left_table, title="[bold cyan]Node Status & Sync[/bold cyan]", border_style="cyan"))
        else:
            left_table.add_row("Hashrate", f"[bold green]{_human_hps(self._last_hashrate)}[/bold green]")
            left_table.add_row("Blocks Mined", f"[bold gold1]{self._blocks_mined}[/bold gold1]")
            left_table.add_row("CPU Power", f"{self.cores} cores ({cpu_pct:.0f}%)")
            left_table.add_row("Memory (RAM)", f"{_human_bytes(vm.used)} / {_human_bytes(vm.total)} ({vm.percent:.0f}%)")
            left_table.add_row("Uptime", uptime_str)
            layout["left"].update(Panel(left_table, title="[bold gold1]Mining & Performance[/bold gold1]", border_style="cyan"))

        # 3. Network & Health Panel
        right_table = Table(show_header=False, box=None, padding=(0, 1))
        right_table.add_column("Metric", style="bold cyan", no_wrap=True)
        right_table.add_column("Value", style="bold white", no_wrap=True)

        if self.node_only:
            right_table.add_row("Inbound Peers", f"[bold white]{peers_in}[/bold white]")
            right_table.add_row("Outbound Peers", f"[bold white]{peers_out}[/bold white]")
            right_table.add_row("Active Threads", f"[bold yellow]{thread_str}[/bold yellow]")
            right_table.add_row("CPU Usage", f"[bold white]{cpu_pct:.0f}%[/bold white]")
            right_table.add_row("Disk Free Space", f"[bold white]{_human_bytes(du.free)} / {_human_bytes(du.total)}[/bold white]")
            layout["right"].update(Panel(right_table, title="[bold dodger_blue1]Network & System Health[/bold dodger_blue1]", border_style="dodger_blue1"))
        else:
            right_table.add_row("Chain Tip Height", f"[bold green]{height if height >= 0 else 'Syncing...'}[/bold green]")
            right_table.add_row("Inbound Peers", f"[bold white]{peers_in}[/bold white]")
            right_table.add_row("Outbound Peers", f"[bold white]{peers_out}[/bold white]")
            right_table.add_row("Active Threads", f"[bold yellow]{thread_str}[/bold yellow]")
            right_table.add_row("Disk Free Space", f"[bold white]{_human_bytes(du.free)} / {_human_bytes(du.total)}[/bold white]")
            layout["right"].update(Panel(right_table, title="[bold gold1]Network & Thread Health[/bold gold1]", border_style="magenta"))

        # 4. Logs Stream Panel
        with self._render_lock:
            max_log_visible = max(2, term_height - 3 - body_size - 2)
            recent_logs = list(self.log_lines)[-max_log_visible:] if self.log_lines else []
            log_text = "\n".join(recent_logs) if recent_logs else "[dim]Waiting for network/node events...[/dim]"

        log_renderable = Text.from_ansi(log_text)
        log_renderable.no_wrap = True
        log_renderable.overflow = "ellipsis"
        log_title = "[bold white]Live Node & P2P Activity[/bold white]" if self.node_only else "[bold white]Live Console Activity[/bold white]"
        layout["logs"].update(Panel(log_renderable, title=log_title, border_style="grey50"))

        return layout


def create_tui_logger(tui: MinerTUI | None):
    def _log(line: str) -> None:
        if tui is not None and tui._live is not None:
            tui.add_log(line)
        else:
            print(line)
    return _log
