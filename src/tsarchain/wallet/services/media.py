# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain

from __future__ import annotations

import os
import sys
import vlc
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.services.media")

def _fmt_ms(ms: int | float | None) -> str:
    total = max(0, int(ms) // 1000)
    m, s = divmod(total, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"

class TkVLCPlayer:
    """
    Pembungkus mini-player VLC untuk Tkinter.
    - menyediakan frame video + kontrol play/pause, seek, dan volume.
    - panggil .load(path) lalu .frame bisa dipasang ke layout.
    """

    def __init__(
        self,
        master,
        *,
        width: Optional[int] = 50,
        height: Optional[int] = 50,
        max_width: Optional[int] = None,
        max_height: Optional[int] = None,
        bg: str = "#0f0f0f",
        fg: str = "#f5f5f5",
        accent: str = "#2ea3ff",
        poll_ms: int = 200,
        init_volume: int = 40,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        if vlc is None:
            raise RuntimeError("python-vlc tidak tersedia")

        w_default = int(width) if width else 50
        h_default = int(height) if height else 50
        self.master = master
        self.frame = tk.Frame(master, bg=bg)
        self.video_panel = tk.Frame(self.frame, bg="black", width=w_default, height=h_default)
        self.video_panel.pack(fill="both", expand=True)
        self.video_panel.pack_propagate(False)

        controls = tk.Frame(self.frame, bg=bg)
        controls.pack(fill="x", pady=(6, 0))

        self.play_label = tk.StringVar(value="Play")
        self.play_btn = tk.Button(
            controls,
            textvariable=self.play_label,
            command=self.toggle_play,
            bg=bg,
            fg=fg,
            activebackground=accent,
            activeforeground=bg,
            relief="raised",
        )
        self.play_btn.pack(side="left", padx=(0, 6))

        self.pos_var = tk.DoubleVar(value=0.0)
        self.pos_scale = ttk.Scale(
            controls,
            from_=0,
            to=1000,
            orient="horizontal",
            variable=self.pos_var,
            command=self._on_seek_move,
        )
        self.pos_scale.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.pos_scale.bind("<ButtonPress-1>", self._on_seek_press)
        self.pos_scale.bind("<ButtonRelease-1>", self._on_seek_release)

        self.time_var = tk.StringVar(value="00:00 / 00:00")
        self.time_label = tk.Label(
            controls, textvariable=self.time_var, bg=bg, fg=fg, font=("Consolas", 9)
        )
        self.time_label.pack(side="left", padx=(0, 8))

        vol_wrap = tk.Frame(controls, bg=bg)
        vol_wrap.pack(side="left")
        tk.Label(vol_wrap, text="Vol", bg=bg, fg=fg, font=("Consolas", 9)).pack(
            side="left", padx=(0, 4)
        )
        self.volume_var = tk.DoubleVar(value=float(init_volume))
        self.volume_scale = ttk.Scale(
            vol_wrap,
            from_=0,
            to=100,
            orient="horizontal",
            variable=self.volume_var,
            command=self._on_volume,
        )
        self.volume_scale.pack(side="left", fill="x")

        self._on_error = on_error
        self._poll_ms = max(80, int(poll_ms))
        self._user_dragging = False
        self._updating_pos = False
        self._duration_ms = 0
        self._timer = None
        self._disposed = False
        self._ended = False
        self._last_video_size: tuple[int, int] = (w_default, h_default)
        self._max_width = int(max_width) if max_width else None
        self._max_height = int(max_height) if max_height else None

        self._instance = vlc.Instance("--quiet")
        self._player = self._instance.media_player_new()
        em = self._player.event_manager()
        em.event_attach(vlc.EventType.MediaPlayerEndReached, self._handle_end)

        self._attach_handle()

    # ---------- public API ----------
    def load(self, path: str, autoplay: bool = True):
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        media = self._instance.media_new(path)
        self._player.set_media(media)
        self._attach_handle()
        self._ended = False
        if autoplay:
            self.play()
        else:
            self._update_play_label()
            self._start_poll()

    def toggle_play(self):
        playing = self._player.is_playing()
        if playing:
            self.pause()
        else:
            self.play()

    def play(self):
        # Jika sudah end, reset ke awal agar bisa replay.
        if self._ended:
            self._player.stop()
            self._player.set_time(0)
            self._ended = False
        self._player.play()
        self._player.audio_set_volume(int(self.volume_var.get()))
        self._update_play_label()
        self._start_poll()

    def pause(self):
        self._player.pause()
        self._update_play_label()

    def dispose(self):
        self._disposed = True
        if self._timer is not None:
            self.frame.after_cancel(self._timer)
        self._timer = None
        self._player.stop()
        self._player.release()
        self._instance.release()
        if self.frame.winfo_exists():
            self.frame.destroy()

    # ---------- internal helpers ----------
    def _emit_error(self, msg: str):
        if callable(self._on_error):
            self._on_error(msg)

    def _attach_handle(self):
        try:
            self.video_panel.update_idletasks()
            win_id = self.video_panel.winfo_id()
            if sys.platform.startswith("win"):
                self._player.set_hwnd(win_id)
            elif sys.platform == "darwin":
                self._player.set_nsobject(win_id)
            else:
                self._player.set_xwindow(win_id)
        except Exception as exc:
            log.exception("Unhandled exception")
            self._emit_error(f"attach_failed:{exc}")

    def _start_poll(self):
        if self._timer is not None:
            return
        if self._disposed:
            return
        self._timer = self.frame.after(self._poll_ms, self._poll)

    def _poll(self):
        self._timer = None
        if self._disposed:
            return
        try:
            length = self._player.get_length()
            if length and length > 0:
                self._duration_ms = length
            pos = self._player.get_time()
            self._update_time_label(pos, self._duration_ms)
            if not self._user_dragging and self._duration_ms > 0:
                self._set_slider(pos)
            self._update_play_label()
            self._maybe_update_video_size()
        finally:
            if self._disposed:
                return
            self._timer = self.frame.after(self._poll_ms, self._poll)

    def _set_slider(self, ms_val: int | float):
        if self._duration_ms <= 0:
            return
        self._updating_pos = True
        ratio = max(0.0, min(1.0, float(ms_val) / float(self._duration_ms)))
        self.pos_var.set(ratio * 1000.0)
        self._updating_pos = False

    def _seek_to_slider(self):
        if self._duration_ms <= 0:
            return
        ratio = max(0.0, min(1.0, float(self.pos_var.get()) / 1000.0))
        target_ms = int(ratio * self._duration_ms)
        self._player.set_time(target_ms)

    def _on_volume(self, _value: str | float | None = None):
        self._player.audio_set_volume(int(float(self.volume_var.get())))

    def _on_seek_press(self, _event=None):
        self._user_dragging = True

    def _on_seek_release(self, _event=None):
        self._user_dragging = False
        self._seek_to_slider()

    def _on_seek_move(self, _value: str | float | None = None):
        if not self._updating_pos:
            self._user_dragging = True

    def _update_time_label(self, pos_ms: int | float, total_ms: int | float):
        self.time_var.set(f"{_fmt_ms(pos_ms)} / {_fmt_ms(total_ms)}")

    def _update_play_label(self, paused: bool | None = None):
        playing = self._player.is_playing()
        if paused is True:
            playing = False
        self.play_label.set("Pause" if playing else "Play")

    def _handle_end(self, _event=None):
        self.frame.after(0, self._on_end_main)

    def _on_end_main(self):
        self._ended = True
        if self._duration_ms > 0:
            self._set_slider(self._duration_ms)
        self._player.set_time(0)
        self._set_slider(0)
        self._update_play_label(paused=True)

    def _maybe_update_video_size(self):
        w, h = self._player.video_get_size(0)
        if not w or not h:
            return
        target_w, target_h = w, h
        if self._max_width or self._max_height:
            max_w = self._max_width or w
            max_h = self._max_height or h
            scale = min(max_w / w, max_h / h, 1.0)
            target_w = max(1, int(w * scale))
            target_h = max(1, int(h * scale))
        if (target_w, target_h) == self._last_video_size:
            return
        self._last_video_size = (target_w, target_h)
        self.video_panel.config(width=target_w, height=target_h)
