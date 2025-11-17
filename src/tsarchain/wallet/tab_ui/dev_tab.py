# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

from typing import TYPE_CHECKING

import tkinter as tk
from tkinter import scrolledtext

if TYPE_CHECKING:
    from apps.kremlin import KremlinWalletGUI


class DevTab(tk.Frame):
    def __init__(self, app: "KremlinWalletGUI", master: tk.Misc | None = None):
        super().__init__(master, bg=app.bg)
        self.app = app
        self.dev_text: scrolledtext.ScrolledText | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        top = tk.Frame(self, bg=self.app.bg)
        top.pack(fill=tk.X, padx=12, pady=8)
        tk.Label(
            top,
            text="Built by Tsar Studio | Open Source on GitHub",
            bg=self.app.bg,
            fg=self.app.accent,
            font=("Consolas", 8, "bold"),
        ).pack(side=tk.RIGHT)
        tk.Label(
            top,
            text="Kremlin Wallet v.1",
            bg=self.app.bg,
            fg=self.app.accent,
            font=("Consolas", 8, "bold"),
        ).pack(side=tk.LEFT)

        info_area = tk.Frame(self, bg=self.app.bg)
        info_area.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        tk.Label(
            info_area,
            text="🌐Tsar Chain🌐",
            bg=self.app.bg,
            fg=self.app.accent,
            font=("Segoe UI", 40, "bold"),
        ).pack(pady=(0, 0))
        tk.Label(
            info_area,
            text="--- Long Live The Voice Sovereignty Monetary System ---\n",
            bg=self.app.bg,
            fg=self.app.accent,
            font=("Consolas", 12, "bold"),
        ).pack(pady=(0, 0))

        tk.Button(self, text="Open Log Viewer", command=self.app._open_log_viewer).pack(side=tk.RIGHT, padx=4)

        self.dev_text = scrolledtext.ScrolledText(
            info_area,
            height=10,
            bg=self.app.panel_bg,
            fg=self.app.fg,
            insertbackground=self.app.fg,
            font=("Consolas", 11),
        )
        self.dev_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        self._populate_text()

    def _populate_text(self) -> None:
        if not self.dev_text:
            return
        palette = getattr(self.app.theme_set, "palette", None)
        alert_color = palette.danger if palette else self.app.accent
        status_color = palette.success if palette else self.app.accent

        self.dev_text.tag_configure("title", font=("Consolas", 16, "bold"), foreground=self.app.accent)
        self.dev_text.tag_configure("center", justify="center")
        self.dev_text.tag_configure("info", font=("Consolas", 10), foreground=self.app.muted)
        self.dev_text.tag_configure("alert", font=("Consolas", 13, "bold"), foreground=alert_color)
        self.dev_text.tag_configure("status", font=("Consolas", 10, "bold"), foreground=status_color)
        self.dev_text.tag_configure("on_develop", font=("Consolas", 10, "bold"), foreground=self.app.accent)
        self.dev_text.tag_configure("dev", font=("Consolas", 10, "bold"), foreground=self.app.accent)

        self.dev_text.insert(tk.END, "\nWhat is TsarChain?\n", ("title", "center"))
        self.dev_text.insert(tk.END, "----------------------------------\n\n", ("info", "center"))
        self.dev_text.insert(tk.END, "⚠️ This is a Voice Sovereignty chain ⚠️\n\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "A from-scratch, UTXO-based L1 that records **expressive value** graffiti, testimony, evidence—immutably.\n"
            "You pay a small TSAR fee to publish; miners timestamp it; the network verifies it forever.\n"
            "No gatekeepers. No permission. Just math, proof, and a public memory that cannot be silenced.\n",
            ("info", "center"),
        )
        self.dev_text.insert(tk.END, "\nIs \"Graffiti\" an NFT Platform?\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "\nNo. Graffiti is a permanent on-chain record—expression treated as value, not a tradable collectible.\n"
            "Each graffiti is paid with TSAR as a fee for speech; miners timestamp it, and the network verifies it forever.\n"
            "No drops, No royalties, No lamborghini, No mint/burn mechanics\nthis layer is for public memory, not marketplace hype.\n",
            ("info", "center"),
        )
        self.dev_text.insert(tk.END, "\n⚠️ Status ⚠️\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "\n-- Wallet generation (with SegWit Bech32) --\n-- Address prefix 'tsar1' --\n-- Genesis block --\n"
            "-- Proof-of-Work --\n-- Chat Feature (3XDH & Double Rachet) --\n-- Coinbase reward --\n-- UTXO system --\n-- SegWit transactions --\n"
            "-- Fee mechanism --\n-- Mempool --\n-- Multi-node networking --\n-- Transaction & block validation --\n"
            "-- Chain validation --\n",
            ("status", "center"),
        )
        self.dev_text.insert(tk.END, "\n⚠️ On Development ⚠️\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "\n-- Storage Node --\n-- Graffiti --\n-- Some Security --\n-- Some UI/UX Wallet --\n"
            "-- etc. --\n",
            ("on_develop", "center"),
        )
        self.dev_text.insert(tk.END, "\n⚠️ Disclaimer ⚠️\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "\nPublished data becomes part of the chain and cannot be removed.\n"
            "By submitting graffiti or transactions, you accept full responsibility for your content and its legality.\n"
            "This network preserves records. it does not moderate speech.\n",
            ("info", "center"),
        )
        self.dev_text.insert(tk.END, "\nDeveloper Note\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "TsarChain is a lab for Voice Sovereignty.\nan engineering study of how speech can be treated as value and time-stamped as public memory.\n",
            ("info", "center"),
        )
        self.dev_text.insert(tk.END, "> We don’t sell coins. we mint courage <", ("dev", "center"))
        self.dev_text.config(state="disabled")
