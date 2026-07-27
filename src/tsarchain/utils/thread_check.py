# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

"""
Thread Monitoring Module for TsarChain
Real-time monitoring of active threads with TUI support across node miner and archivist.
"""

import sys
import time
import signal
import threading

from rich.table import Table
from rich.panel import Panel
from rich.console import Console

from enum import Enum
from dataclasses import dataclass
from collections import defaultdict
from typing import Dict, List, Optional


@dataclass
class ThreadInfo:
    """Information about a running thread"""
    name: str
    ident: int
    daemon: bool
    alive: bool
    is_current: bool
    cpu_time: float = 0.0
    state: str = "unknown"
    stack_info: Optional[str] = None


class ThreadState(Enum):
    """Thread states"""
    RUNNING = "running"
    SLEEPING = "sleeping"
    WAITING = "waiting"
    BLOCKED = "blocked"
    DEAD = "dead"


class ThreadMonitor:
    """Monitors and reports on thread activity"""

    def __init__(self, update_interval: float = 2.0):
        self.update_interval = update_interval
        self.threads_history: Dict[str, List[tuple[float, str]]] = defaultdict(list)
        self.last_update = time.time()
        self.monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None

    def get_all_threads(self, include_stack: bool = False) -> List[ThreadInfo]:
        threads = []
        current_ident = threading.current_thread().ident

        for thread in threading.enumerate():
            is_current = thread.ident == current_ident
            thread_info = ThreadInfo(
                name=thread.name,
                ident=thread.ident or 0,
                daemon=thread.daemon,
                alive=thread.is_alive(),
                is_current=is_current,
                state=self._get_thread_state(thread),
                stack_info=self._get_stack_info(thread) if include_stack else None
            )
            threads.append(thread_info)

        return threads

    def get_thread_counts(self) -> Dict[str, int]:
        """Get counts of threads by type/state"""
        threads = self.get_all_threads(include_stack=False)
        counts = {
            'total': len(threads),
            'daemon': sum(1 for t in threads if t.daemon),
            'alive': sum(1 for t in threads if t.alive),
            'user': sum(1 for t in threads if not t.daemon and t.alive),
            'mining': sum(1 for t in threads if 'mining' in t.name.lower() or 'mine' in t.name.lower()),
            'network': sum(1 for t in threads if 'network' in t.name.lower() or 'peer' in t.name.lower()),
            'sync': sum(1 for t in threads if 'sync' in t.name.lower()),
            'rpc': sum(1 for t in threads if 'rpc' in t.name.lower()),
            'archivist': sum(1 for t in threads if any(k in t.name.lower() for k in ('archivist', 'retention', 'storage', 'heartbeat'))),
        }

        # Add states
        state_counts = defaultdict(int)
        for t in threads:
            state_counts[t.state] += 1
        counts.update(state_counts)

        return counts

    def check_for_deadlocks(self) -> List[str]:
        """Check for potential deadlocks (simple heuristic)"""
        warnings = []
        threads = self.get_all_threads()

        now = time.time()
        if now - self.last_update > 5:
            for thread in threads:
                if thread.alive and thread.state == ThreadState.BLOCKED.value:
                    thread_key = f"{thread.name}_{thread.ident}"
                    history = self.threads_history.get(thread_key, [])
                    # Flag only if thread has been in 'blocked' state continuously for at least 5 monitoring updates
                    if len(history) >= 5 and all(st == ThreadState.BLOCKED.value for _, st in history[-5:]):
                        warnings.append(f"Thread {thread.name} stuck in {thread.state}")

        return warnings

    def _get_thread_state(self, thread: threading.Thread) -> str:
        """Get human-readable thread state"""
        try:
            if hasattr(thread, '_is_stopped') and getattr(thread, '_is_stopped', False):
                return ThreadState.DEAD.value

            if not thread.is_alive():
                return ThreadState.DEAD.value

            if hasattr(thread, '_waiting'):
                return ThreadState.WAITING.value

            return ThreadState.RUNNING.value

        except Exception:
            return "unknown"

    def _get_stack_info(self, thread: threading.Thread) -> Optional[str]:
        """Get stack trace for thread (if available)"""
        try:
            import traceback
            frame = sys._current_frames().get(thread.ident)
            if frame:
                stack = traceback.extract_stack(frame)
                if stack:
                    top_frame = stack[-1]
                    return f"{top_frame.filename}:{top_frame.lineno} in {top_frame.name}"
        except (KeyError, AttributeError):
            pass
        return None

    def start_monitoring(self) -> None:
        """Start background thread monitoring"""
        if self.monitoring:
            return

        self.monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            name="ThreadMonitor",
            daemon=True
        )
        self._monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop background monitoring"""
        self.monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)

    def _monitoring_loop(self) -> None:
        """Background monitoring loop"""
        while self.monitoring:
            try:
                threads = self.get_all_threads()
                now = time.time()
                for thread in threads:
                    thread_key = f"{thread.name}_{thread.ident}"
                    self.threads_history[thread_key].append((now, thread.state))
                    if len(self.threads_history[thread_key]) > 10:
                        self.threads_history[thread_key] = self.threads_history[thread_key][-10:]

                self.last_update = now
                time.sleep(self.update_interval)

            except Exception:
                time.sleep(self.update_interval)

    def print_thread_report(self, detailed: bool = False) -> None:
        """Print a report of current threads using Rich formatting"""
        threads = self.get_all_threads(include_stack=detailed)
        counts = self.get_thread_counts()
        console = Console()

        table = Table(title=f"Thread Health Report (Total: {counts['total']} | Alive: {counts['alive']} | Daemon: {counts['daemon']})", border_style="cyan")
        table.add_column("#", justify="right", style="bold dim", no_wrap=True)
        table.add_column("Thread Name", style="bold white")
        table.add_column("ID", style="dim")
        table.add_column("State", justify="center")
        table.add_column("Type", justify="center")
        if detailed:
            table.add_column("Stack Info", style="italic grey70")

        for i, thread in enumerate(threads, 1):
            if thread.alive:
                state_style = "[bold green]RUNNING[/bold green]" if thread.state == "running" else f"[green]{thread.state.upper()}[/green]"
            else:
                state_style = "[bold red]DEAD[/bold red]"

            tags = []
            if thread.daemon:
                tags.append("[yellow]DAEMON[/yellow]")
            if thread.is_current:
                tags.append("[bold cyan]CURRENT[/bold cyan]")
            type_str = " ".join(tags) if tags else "[dim]USER[/dim]"

            row = [str(i), thread.name, str(thread.ident), state_style, type_str]
            if detailed:
                row.append(thread.stack_info or "-")
            table.add_row(*row)

        console.print(table)

        warnings = self.check_for_deadlocks()
        if warnings:
            warn_msg = "\n".join(f"[bold red]⚠ {w}[/bold red]" for w in warnings)
            console.print(Panel(warn_msg, title="[bold red]WARNINGS[/bold red]", border_style="red"))


_thread_monitor: Optional[ThreadMonitor] = None


def get_thread_monitor() -> ThreadMonitor:
    """Get or create global thread monitor instance"""
    global _thread_monitor
    if _thread_monitor is None:
        _thread_monitor = ThreadMonitor()
    return _thread_monitor


def start_thread_monitoring() -> ThreadMonitor:
    """Start global thread monitoring"""
    monitor = get_thread_monitor()
    monitor.start_monitoring()
    return monitor


def stop_thread_monitoring() -> None:
    """Stop global thread monitoring"""
    global _thread_monitor
    if _thread_monitor:
        _thread_monitor.stop_monitoring()


def register_thread_monitoring_signal() -> None:
    def handle_thread_dump(signum, frame):
        monitor = get_thread_monitor()
        monitor.print_thread_report(detailed=True)

    try:
        signal.signal(signal.SIGUSR1, handle_thread_dump)
    except (AttributeError, ValueError):
        pass
