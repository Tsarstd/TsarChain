# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
import tkinter as tk


def center_window(win: tk.Toplevel, parent: tk.Misc | None = None) -> None:
    try:
        win.update_idletasks()
        if parent is None:
            parent = getattr(win, "master", None)

        px = py = 0
        pw = win.winfo_screenwidth()
        ph = win.winfo_screenheight()

        if parent is not None:
            try:
                parent.update_idletasks()
                px = parent.winfo_rootx()
                py = parent.winfo_rooty()
                pw = parent.winfo_width()
                ph = parent.winfo_height()
                if pw <= 1 or ph <= 1:
                    pw = parent.winfo_reqwidth()
                    ph = parent.winfo_reqheight()
            except Exception:
                try:
                    px = parent.winfo_rootx()
                    py = parent.winfo_rooty()
                except Exception:
                    px = py = 0
                pw = win.winfo_screenwidth()
                ph = win.winfo_screenheight()

        ww = win.winfo_width()
        wh = win.winfo_height()
        if ww <= 1 or wh <= 1:
            ww = max(win.winfo_reqwidth(), 200)
            wh = max(win.winfo_reqheight(), 120)

        x = int(px + max((pw - ww) / 2, 0))
        y = int(py + max((ph - wh) / 2, 0))
        win.geometry(f"+{x}+{y}")
    except Exception:
        pass

