# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import tkinter as tk

from tsarchain.utils import config as CFG
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.ui_utils")

def center_window(win: tk.Toplevel, parent: tk.Misc | None = None) -> None:
    win.update_idletasks()
    if parent is None:
        parent = getattr(win, "master", None)

    px = py = 0
    pw = win.winfo_screenwidth()
    ph = win.winfo_screenheight()

    if parent is not None:
        parent.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        if pw <= 1 or ph <= 1:
            pw = parent.winfo_reqwidth()
            ph = parent.winfo_reqheight()

    ww = win.winfo_width()
    wh = win.winfo_height()
    if ww <= 1 or wh <= 1:
        ww = max(win.winfo_reqwidth(), 200)
        wh = max(win.winfo_reqheight(), 120)

    x = int(px + max((pw - ww) / 2, 0))
    y = int(py + max((ph - wh) / 2, 0))
    win.geometry(f"+{x}+{y}")

def show_toast(app_instance, text: str, ms: int = 1800, kind: str = "info") -> None:
    if isinstance(ms, str):
        kind = ms
        ms = 1800
    ms = int(ms)
    toasts = getattr(app_instance, "_toasts", None)
    if toasts is None:
        toasts = []
        app_instance._toasts = toasts
    app_instance.root.update_idletasks()
    tw = tk.Toplevel(app_instance.root)
    tw.withdraw()
    tw.overrideredirect(True)
    tw.attributes("-topmost", True)
    tw.attributes("-alpha", 0.96)

    theme_set = getattr(app_instance, "theme_set", None)
    palette = getattr(theme_set, "palette", None) if theme_set else None
    warn_color = palette.warning if palette else "#f5a524"
    error_color = palette.danger if palette else "#f1633f"
    info_color = getattr(app_instance, "accent", "#ff6b00")
    border = {"info": info_color, "warn": warn_color, "error": error_color}.get(kind, info_color)
    bg = getattr(app_instance, "panel_bg", "#161a1f")
    fg = getattr(app_instance, "fg", "#f2f5f7")
    w, h = 320, 52
    rx = app_instance.root.winfo_rootx(); ry = app_instance.root.winfo_rooty()
    rw = app_instance.root.winfo_width();  rh = app_instance.root.winfo_height()
    y_offset = len(app_instance._toasts) * (h + 6)
    x = rx + rw - (w + 18)
    y = ry + rh - (h + 18) - y_offset
    tw.geometry(f"{w}x{h}+{x}+{y}")

    wrapper = tk.Frame(tw, bg=border, bd=0, highlightthickness=0)
    wrapper.pack(fill="both", expand=True)
    inner = tk.Frame(wrapper, bg=bg, bd=0, highlightthickness=0)
    inner.pack(fill="both", expand=True, padx=1, pady=1)

    lbl = tk.Label(inner, text=text, bg=bg, fg=fg, font=("Consolas", 10), anchor="w", justify="left")
    lbl.pack(fill="both", expand=True, padx=12, pady=10)

    app_instance._toasts.append(tw)
    tw.deiconify()

    def _close():
        tw.destroy()
        if tw in app_instance._toasts:
            app_instance._toasts.remove(tw)

    tw.after(ms, _close)


def enable_treeview_hover(app_instance, tree, hover_bg: str | None = None) -> None:
    if hover_bg is None:
        bg = (getattr(app_instance, "bg", "#0f1115") or "").lower()
        hover_bg = "#1e2630" if int(bg.replace("#", "")[:2], 16) < 0x88 else "#e9eef7"

    tree.tag_configure("HOVER", background=hover_bg)
    state = {"last": None}

    def _apply_hover(iid: str | None):
        if state["last"]:
            old_tags = set(tree.item(state["last"], "tags") or ())
            if "HOVER" in old_tags:
                old_tags.remove("HOVER")
                tree.item(state["last"], tags=tuple(old_tags))
        state["last"] = iid
        if iid:
            tags = set(tree.item(iid, "tags") or ())
            tags.add("HOVER")
            tree.item(iid, tags=tuple(tags))

    def on_motion(e):
        iid = tree.identify_row(e.y)
        if iid != state["last"]:
            _apply_hover(iid)

    def on_leave(_e):
        _apply_hover(None)

    tree.bind("<Motion>", on_motion, add="+")
    tree.bind("<Leave>", on_leave, add="+")

def insert_treeview_chunked(app_instance, tv, rows: list[tuple[tuple, tuple]], start: int = 0, chunk: int = -1) -> None:
    if chunk == -1:
        chunk = CFG.GUI_TV_CHUNK
    end = min(start + chunk, len(rows))
    insert = tv.insert
    for vals, tags in rows[start:end]:
        insert("", tk.END, values=vals, tags=tags)
    if end < len(rows):
        app_instance.root.after(0, insert_treeview_chunked, app_instance, tv, rows, end, chunk)

