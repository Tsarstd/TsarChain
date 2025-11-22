# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import sys
import time
import psutil
import threading
import shutil
import queue
from typing import Callable, Optional

from ..cosmetic import interface as COL


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
    ) -> None:
        self.address = address
        self.cores = cores
        self.mode = mode
        self.randomx_mode = randomx_mode
        self.hashrate_queue = hashrate_queue
        self.chain_height_fn = chain_height_fn
        self.peer_counts_fn = peer_counts_fn

        self._stop_event = threading.Event()
        self._render_lock = threading.Lock()
        self._render_thread: threading.Thread | None = None
        self._hashrate_thread: threading.Thread | None = None

        self._last_len = 0
        self._last_hashrate = 0.0
        self._blocks_mined = 0
        self._start_ts = time.time()
        self._first_render = True

    # ---- public helpers ----

    def start(self) -> None:
        if self._render_thread is not None:
            return

        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

        if self.hashrate_queue is not None:
            self._hashrate_thread = threading.Thread(
                target=self._hashrate_loop,
                name="TsarTUI-Hashrate",
                daemon=True,
            )
            self._hashrate_thread.start()

        self._render_thread = threading.Thread(
            target=self._render_loop,
            name="TsarTUI-Render",
            daemon=True,
        )
        self._render_thread.start()
        
    def reset_uptime(self) -> None:
        with self._render_lock:
            self._start_ts = time.time()

    def stop(self) -> None:
        self._stop_event.set()

    def note_block_mined(self, _height: int | None = None) -> None:
        self._blocks_mined += 1

    def set_hashrate(self, hps: float) -> None:
        try:
            self._last_hashrate = float(hps)
        except Exception:
            pass

    def force_refresh(self) -> None:
        try:
            self._render_once()
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

    def _render_loop(self) -> None:
        while not self._stop_event.is_set():
            self._render_once()
            time.sleep(1.0)
        try:
            sys.stdout.write("\r" + " " * self._last_len + "\r\n")
            sys.stdout.flush()
        except Exception:
            pass

    def _render_once(self) -> None:
        with self._render_lock:
            cpu_pct = None
            mem_used = mem_total = mem_pct = None
            try:
                cpu_pct = psutil.cpu_percent(interval=None)
            except Exception:
                pass
            try:
                vm = psutil.virtual_memory()
                mem_used = vm.used
                mem_total = vm.total
                mem_pct = vm.percent
            except Exception:
                pass

            if callable(self.peer_counts_fn):
                try:
                    peers_in, peers_out = self.peer_counts_fn()
                except Exception:
                    peers_in = peers_out = None

            uptime = int(time.time() - self._start_ts)
            up_h = uptime // 3600
            up_m = (uptime % 3600) // 60
            up_s = uptime % 60
            uptime_str = f"{up_h:02d}:{up_m:02d}:{up_s:02d}"

            parts: list[str] = []
            if self.mode:
                parts.append(f"{COL.BOLD}{COL.DIM}{COL.BG_YELLOW}{self.mode}{COL.RESET}")
            if peers_in is not None and peers_out is not None:
                parts.append(f"peers: {peers_in}/{peers_out}")
            parts.append(f"{_human_hps(self._last_hashrate)}")
            if cpu_pct is not None:
                parts.append(f"CPU: {cpu_pct:.0f}%")
            if mem_used is not None and mem_total is not None and mem_pct is not None:
                parts.append(
                    f"{_human_bytes(mem_used)}/{_human_bytes(mem_total)} ({mem_pct:.0f}%)"
                )
                
            parts.append(f"Uptime {uptime_str}")
            line = (f" | ").join(parts)
            try:
                width = shutil.get_terminal_size((120, 20)).columns
            except Exception:
                width = 120
            if len(line) > width:
                line = line[: width - 1]

            if self._first_render:
                sys.stdout.write("\n")
                self._first_render = False

            buf = "\r" + line
            padding = max(0, self._last_len - len(line))
            if padding:
                buf += " " * padding
            self._last_len = len(line)

            try:
                sys.stdout.write(buf)
                sys.stdout.flush()
            except Exception:
                pass


def create_tui_logger(tui: MinerTUI | None):
    def _log(line: str) -> None:
        if tui is not None:
            sys.stdout.write("\r" + " " * tui._last_len + "\r")
            print(line)
            tui.force_refresh()
        else:
            print(line)
    return _log
