# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import os
import tkinter as tk
from typing import Optional

from kremlin.ui_utils import center_window
from kremlin.tab_ui.wallet_tab import load_registry
from kremlin.security.data_security import list_addresses_in_keystore, WALLET_FILE

class PasswordLockscreen(tk.Toplevel):
    def __init__(self, root: tk.Tk):
        super().__init__(root)
        self.result: Optional[str] = None
        self.configure(bg="#121212")
        self.geometry("1070x700")
        self.title("Unlock Wallet")
        self.resizable(False, False)

        lbl = tk.Label(
            self,
            text="Enter the keystore password to open the wallet.",
            bg="#121212",
            fg="#ff5e00",
            font=("Consolas", 16, "bold"),
        )
        lbl.pack(pady=(40, 12))

        self.entry = tk.Entry(self, font=("Consolas", 14), width=32, bg="#0f0f0f", fg="#ff5e00", show="*")
        self.entry.pack(pady=12)
        self.entry.bind("<Return>", self.on_unlock)

        self.error_var = tk.StringVar(value="")
        tk.Label(
            self,
            textvariable=self.error_var,
            bg="#121212",
            fg="#ff5e00",
            font=("Consolas", 11),
        ).pack(pady=(0, 18))

        btn_frame = tk.Frame(self, bg="#121212")
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame,
            text="Unlock",
            font=("Consolas", 12),
            bg="#ff5e00",
            fg="#fff",
            command=self.on_unlock,
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            btn_frame,
            text="Exit",
            font=("Consolas", 12),
            bg="#444",
            fg="#fff",
            command=self.on_cancel,
        ).pack(side=tk.LEFT, padx=10)

        center_window(self, root)
        self.entry.focus_set()

    def on_unlock(self, _event=None) -> None:
        pwd = self.entry.get().strip()
        if not pwd:
            self.error_var.set("Password is required.")
            return
        try:
            _ = list_addresses_in_keystore(pwd)
        except Exception:
            self.error_var.set("Incorrect password. Please try again.")
            self.entry.delete(0, "end")
            return

        self.result = pwd
        self.destroy()

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()
        
def should_show_password_lock() -> bool:
    if load_registry():
        return True
    return os.path.exists(WALLET_FILE) and os.path.getsize(WALLET_FILE) > 0

def show_password_lockscreen(root: tk.Tk) -> Optional[str]:
    lock = PasswordLockscreen(root)
    root.wait_window(lock)
    return lock.result
