# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio

import tkinter as tk
from ..theme import FONT

class SidebarNavigator:
    def __init__(self, root: tk.Tk, sidebar_frame: tk.Frame, app_instance, bg: str, active_bg: str, fg: str, active_fg: str, accent: str):
        self.root = root
        self.sidebar = sidebar_frame
        self.app = app_instance
        self.bg = bg
        self.active_bg = active_bg
        self.fg = fg
        self.active_fg = active_fg
        self.accent = accent
        self.buttons = {}
        
        # Build Title
        tk.Label(self.sidebar, text="Kremlin", bg=self.bg, fg=self.accent,
                 font=(FONT, 17, "bold")).pack(pady=(12, 6))

    def add_button(self, text: str, tab_id: str, on_click) -> tk.Button:
        btn = tk.Button(
            self.sidebar,
            text=text,
            command=lambda: (on_click(), self.app._activate_tab(tab_id)),
            bg=self.bg,
            fg=self.fg,
            font=(FONT, 10, "bold"),
            bd=0,
            relief=tk.FLAT,
            padx=8,
            pady=8,
            highlightthickness=0,
            cursor="hand2",
            activebackground=self.active_bg,
            activeforeground=self.active_fg,
        )

        def _hover_in(_e):
            try:
                active_tab = self.app._active_tab
            except AttributeError:
                active_tab = ""
            if tab_id != active_tab:
                btn.configure(bg=self.active_bg, fg=self.active_fg)

        def _hover_out(_e):
            try:
                active_tab = self.app._active_tab
            except AttributeError:
                active_tab = ""
            if tab_id != active_tab:
                btn.configure(bg=self.bg, fg=self.fg)

        btn.bind("<Enter>", _hover_in)
        btn.bind("<Leave>", _hover_out)

        self.buttons[tab_id] = btn
        btn.pack(pady=(12, 6))
        return btn
        
    def add_theme_toggle(self, on_toggle) -> None:
        tk.Button(
            self.sidebar,
            text="Switch Theme",
            command=on_toggle,
            bg=self.bg,
            fg=self.fg,
            bd=0,
            relief=tk.FLAT,
            padx=8,
            pady=8,
            highlightthickness=0,
            cursor="hand2",
            activebackground=self.active_bg,
            activeforeground=self.active_fg,
        ).pack(side=tk.BOTTOM, pady=10)
        
    def add_connection_status(self, initial_color: str) -> tk.Label:
        self.conn_status = tk.Label(self.sidebar, text="Offline", bg=self.bg,
                                    fg=initial_color, font=(FONT, 9, "bold"))
        self.conn_status.pack(side=tk.BOTTOM, pady=(0, 12))
        return self.conn_status

    def refresh_styles(self, active_tab: str, new_bg: str, new_active_bg: str, new_fg: str, new_active_fg: str) -> None:
        self.bg = new_bg
        self.active_bg = new_active_bg
        self.fg = new_fg
        self.active_fg = new_active_fg
        
        for tab_id, btn in self.buttons.items():
            if not btn or not btn.winfo_exists():
                continue
            if tab_id == active_tab:
                btn.configure(
                    bg=self.active_bg,
                    fg=self.active_fg,
                    activebackground=self.active_bg,
                    activeforeground=self.active_fg,
                )
            else:
                btn.configure(
                    bg=self.bg,
                    fg=self.fg,
                    activebackground=self.active_bg,
                    activeforeground=self.active_fg,
                )
