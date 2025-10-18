# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import re
import tkinter as tk
from typing import Callable, Dict, Any, Optional, Sequence, List
from tkinter import ttk, messagebox as mb

# ---------------- Local Project (Wallet Only) ----------------
from .send_service import SendService
from .theme import SendTheme

# ---------------- Local Project (With Node) ----------------
from ..utils import config as CFG


class SendTab:
    # ----- Prefill helpers (used by GraffitiTab) -----
    def set_recipient(self, addr: str) -> None:
        try:
            self.to_var.set((addr or '').strip().lower())
            if getattr(self, 'to_entry', None):
                self.to_entry.icursor('end')
            self._refresh_state()
        except Exception:
            pass

    def set_amount(self, amount_text: str) -> None:
        try:
            txt = (str(amount_text or '').strip())
            if re.fullmatch(r"\d+", txt):
                tsar = int(txt) / float(CFG.TSAR)
                txt = ("{:.8f}".format(tsar)).rstrip('0').rstrip('.')
            self.amount_var.set(txt)
            self._amt_placeholder_active = False
            if getattr(self, 'amount_entry', None):
                self.amount_entry.config(fg=self.palette["accent"])
            self._refresh_state()
        except Exception:
            pass

    def set_opret_hex(self, opret_hex: str) -> None:
        try:
            self._opret_hex = (opret_hex or '').strip().lower()
            try:
                b = bytes.fromhex(self._opret_hex) if self._opret_hex else b''
                self._append_log(f"[graffiti] OP_RETURN prepared ({len(b)} bytes)")
            except Exception:
                pass
        except Exception:
            self._opret_hex = None


    def __init__(
        self,
        root: tk.Misc,
        *,
        rpc_send: Callable[[Dict[str, Any], Callable[[Optional[Dict[str, Any]]], None]], None],
        ask_password: Callable[[str], Optional[str]],
        toast: Callable[..., None],
        addresses_provider: Callable[[], List[str]] = lambda: [],
        contact_manager: Any | None = None,
        busy_request: Callable[[str, Sequence[tk.Widget], Dict[str, Any], Callable[[Optional[Dict[str, Any]]], None]], None] | None = None,
        theme: SendTheme,
        on_sent: Callable[[str], None] | None = None,
    ) -> None:
        
        self.root = root
        self.rpc_send = rpc_send
        self.ask_password = ask_password
        self.addresses_provider = addresses_provider
        self.contact_mgr = contact_manager
        self._request_locked = busy_request
        self.on_sent = on_sent or (lambda _addr: None)

        def _toaster(msg: str, kind: str = "info") -> None:
            try:
                return toast(msg, kind)
            except TypeError:
                try:
                    return toast(msg)
                except Exception:
                    pass
            except Exception:
                pass
        self._toast = _toaster

        self.theme = theme
        self.palette = {
            "bg": theme.bg,
            "panel_bg": theme.panel_bg,
            "fg": theme.fg,
            "muted": theme.muted,
            "accent": theme.accent,
            "border": theme.border,
            "card": theme.card_bg,
            "slider_trough": theme.slider_trough,
        }

        self._success_color = theme.success
        self._warning_color = theme.warning
        self._danger_color = theme.danger

    def update_theme(self, theme: SendTheme) -> None:
        self.theme = theme
        self.palette.update({
            "bg": theme.bg,
            "panel_bg": theme.panel_bg,
            "fg": theme.fg,
            "muted": theme.muted,
            "accent": theme.accent,
            "border": theme.border,
            "card": theme.card_bg,
            "slider_trough": theme.slider_trough,
        })

        # Services & state
        self.svc = SendService()
        self._frame: ttk.Frame | None = None
        self._send_widgets: list[tk.Widget] = []

        # Inputs
        self.from_var = tk.StringVar()
        self.to_var = tk.StringVar()
        self.amount_var = tk.StringVar()
        self.fee_rate_var = tk.StringVar(value=str(CFG.MIN_FEE_RATE_SATVB))

        # Inline error labels
        self.from_err = tk.StringVar()
        self.to_err = tk.StringVar()
        self.amount_err = tk.StringVar()

        # Live estimates
        self.vbytes_var = tk.StringVar(value="-")
        self.fee_sat_var = tk.StringVar(value="-")
        self.fee_tsar_var = tk.StringVar(value="-")
        self.total_tsar_var = tk.StringVar(value="-")

        # Spendable cache per address
        self._bal_cache: Dict[str, Dict[str, int]] = {}

        # Widgets that we need later
        self.btn_review: tk.Button | None = None
        self.log_text: tk.Text | None = None
        self.fee_scale: tk.Scale | None = None
        self.fee_entry: tk.Entry | None = None
        self.to_entry: tk.Entry | None = None
        self.amount_entry: tk.Entry | None = None
        self.from_combo: ttk.Combobox | None = None
        self.from_spend_lbl: tk.Label | None = None
        
        self._amt_hint = "0"
        self._amt_placeholder_active = True
        self._amt_shell: tk.Frame | None = None

    # ===== Public lifecycle =====
    def build(self, parent: tk.Misc) -> ttk.Frame:
        p = self.palette
        fr = ttk.Frame(parent, style="Tsar.TFrame")
        fr.pack(fill=tk.BOTH, expand=True)
        fr.pack_propagate(False)

        root = tk.Frame(fr, bg=p["bg"])  # canvas
        root.pack(fill="both", expand=True)
        root.grid_columnconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=1)
        root.grid_columnconfigure(2, weight=1)

        card = self._card(root)
        card.grid(row=0, column=1, sticky="nsew", padx=16, pady=(16, 8))

        # === Activity Log ===
        log = self._activity_log(root)
        log.grid(row=1, column=1, sticky="nsew", padx=16, pady=(8, 16))
        root.grid_rowconfigure(1, weight=1)

        # Wire traces for live validation
        for var in (self.to_var, self.amount_var, self.fee_rate_var):
            var.trace_add("write", lambda *_: self._refresh_state())

        self._frame = fr
        try:
            self.on_wallets_changed(self.addresses_provider())
        except Exception as e:
            self._append_log(f"[init] wallets error: {e}")
        try:
            self._refresh_spendable()
        except Exception as e:
            self._append_log(f"[init] spendable error: {e}")
        try:
            self._refresh_state()
        except Exception as e:
            self._append_log(f"[init] state error: {e}")
        return fr

    def on_wallets_changed(self, wallets: Sequence[str]) -> None:
        try:
            values = list(wallets or [])
            self.from_combo["values"] = values
            cur = (self.from_var.get() or "")
            if not values:
                self.from_var.set("")
            elif cur not in values:
                self.from_var.set(values[0])
            self._refresh_spendable()
        except Exception:
            pass

    def on_activated(self) -> None:
        self.on_wallets_changed(self.addresses_provider())
        self._refresh_spendable()
        self._refresh_state()

    # ===== UI building blocks =====
    def _card(self, parent: tk.Misc) -> tk.Frame:
        p = self.palette
        card = tk.Frame(parent, bg=p["card"], bd=1, highlightthickness=1,
                        highlightbackground=p["border"], highlightcolor=p["border"])
        
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)

        # Header
        head = tk.Frame(card, bg=p["card"]) 
        head.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 6))
        tk.Label(head, text="♜Payment Gate♜", bg=p["card"], fg=p["accent"],
                 font=("Segoe UI", 36, "bold")).pack(anchor="center")
        tk.Label(head, text="Follow 3 quick steps to send", bg=p["card"], fg=p["muted"],
                 font=("Consolas", 13, "italic")).pack(anchor="center")

        # Content grid: left (wizard) + right (summary)
        grid = tk.Frame(card, bg=p["card"]) 
        grid.grid(row=1, column=0, sticky="nsew", padx=16, pady=(6, 12))
        grid.grid_columnconfigure(0, weight=1)
        grid.grid_columnconfigure(1, weight=0)

        # Left — Steps
        steps = tk.Frame(grid, bg=p["card"]) 
        steps.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        self._build_step_from(steps)
        self._sep(steps)
        self._build_step_to(steps)
        self._sep(steps)
        self._build_step_amount(steps)

        # Right — Summary
        self._build_summary(grid)

        # Bottom — Review & Send
        bottom = tk.Frame(card, bg=p["card"]) 
        bottom.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        self.btn_review = tk.Button(
            bottom,
            text="Review & Send",
            bg=p["accent"], fg="#fff", bd=0, relief=tk.RIDGE, cursor="hand2",
            command=self._on_review_clicked, width=18
        )
        self.btn_review.pack(pady=(4, 0))

        return card

    def _sep(self, parent: tk.Misc) -> None:
        tk.Frame(parent, height=1, bg=self.palette["border"]).pack(fill="x", pady=8)

    # --- Step 1: From ---
    def _build_step_from(self, parent: tk.Misc) -> None:
        p = self.palette
        box = tk.Frame(parent, bg=p["card"]) 
        box.pack(fill="x")

        self._step_title(box, 1, "Choose wallet (From)")

        row = tk.Frame(box, bg=p["card"]) 
        row.pack(fill="x")

        tk.Label(row, text="From", bg=p["card"], fg=p["fg"]).pack(side="left", padx=(0, 10))
        self.from_combo = ttk.Combobox(row, textvariable=self.from_var, state="readonly", width=52)
        self.from_combo.pack(side="left", fill="x", expand=True)
        self.from_combo.bind("<<ComboboxSelected>>", lambda _e=None: self._on_from_change())

        tk.Button(row, text="Refresh", command=self._refresh_spendable, bg=p["panel_bg"], fg=p["fg"], bd=0,
                  relief=tk.FLAT, cursor="hand2", width=8).pack(side="left", padx=(8, 0))

        self.from_spend_lbl = tk.Label(box, text="", bg=p["card"], fg=self._success_color, font=("Consolas", 10, "bold"))
        self.from_spend_lbl.pack(anchor="w", pady=(4, 0))
        tk.Label(box, textvariable=self.from_err, bg=p["card"], fg=self._danger_color, font=("Consolas", 9)).pack(anchor="w")

    # --- Step 2: To ---
    def _build_step_to(self, parent: tk.Misc) -> None:
        p = self.palette
        box = tk.Frame(parent, bg=p["card"]) 
        box.pack(fill="x")

        self._step_title(box, 2, "Recipient address (To)")

        row = tk.Frame(box, bg=p["card"]) 
        row.pack(fill="x")
        row.grid_columnconfigure(1, weight=1)

        tk.Label(row, text="Send To", bg=p["card"], fg=p["fg"]).grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.to_entry = tk.Entry(row, textvariable=self.to_var, bg=p["panel_bg"], fg=p["fg"], insertbackground=p["fg"]) 
        self.to_entry.grid(row=0, column=1, sticky="ew")

        tk.Button(row, text="Paste", command=self._paste_to, bg=p["panel_bg"], fg=p["fg"], bd=0, relief=tk.FLAT,
                  cursor="hand2", width=6).grid(row=0, column=2, padx=(8, 0))
        tk.Button(row, text="Contacts", command=self._open_contact_picker_send, bg=p["accent"], fg="#fff", bd=0,
                  relief=tk.FLAT, cursor="hand2").grid(row=0, column=3, padx=(8, 0))

        hint = tk.Label(box, text="Example: tsar1…", bg=p["card"], fg=p["muted"], font=("Consolas", 9))
        hint.pack(anchor="w", pady=(2, 0))
        tk.Label(box, textvariable=self.to_err, bg=p["card"], fg=self._danger_color, font=("Consolas", 9)).pack(anchor="w")

    # --- Step 3: Amount & Fee ---
    def _build_step_amount(self, parent: tk.Misc) -> None:
        p = self.palette
        box = tk.Frame(parent, bg=p["card"]) 
        box.pack(fill="x")

        self._step_title(box, 3, "Amount & Fee")

        # Big centered amount input
        amt_wrap = tk.Frame(box, bg=p["card"]) 
        amt_wrap.pack(fill="x", pady=(4, 2))

        self._amt_shell = tk.Frame(
            amt_wrap, bg=p["card"], highlightthickness=1,
            highlightbackground=p["border"], highlightcolor=p["accent"], bd=0)
        self._amt_shell.pack(fill="x", padx=8)

        self.amount_entry = tk.Entry(
            self._amt_shell, textvariable=self.amount_var, justify="center",
            font=("Consolas", 32, "bold"),
            bg=p["card"], fg=p["muted"],
            insertbackground=p["fg"], relief="flat")
        self.amount_entry.pack(fill="x", padx=10, pady=6)
        
        # Placeholder logic
        self.amount_entry.bind("<FocusIn>", self._on_amount_focus_in)
        self.amount_entry.bind("<FocusOut>", self._on_amount_focus_out)
        self._set_amount_placeholder()

        tk.Label(amt_wrap, text="TSAR", bg=p["card"], fg=p["muted"], font=("Consolas", 10, "bold")).pack()

        # Quick % buttons
        btns = tk.Frame(box, bg=p["card"]) 
        btns.pack()
        for label, frac in (("25%", 0.25), ("50%", 0.5), ("75%", 0.75), ("ALL", 1.0)):
            tk.Button(btns, text=label, command=lambda f=frac: self._fill_percent(f), bg=p["panel_bg"], fg=p["fg"],
                      bd=0, relief=tk.FLAT, cursor="hand2", width=6).pack(side="left", padx=6, pady=2)

        # Fee slider + numeric entry
        fee_box = tk.Frame(box, bg=p["card"]) 
        fee_box.pack(fill="x", pady=(8, 0))

        tk.Label(fee_box, text="Fee rate (sat/vB)", bg=p["card"], fg=p["fg"]).grid(row=0, column=0, sticky="w")

        # Scale  - map MIN..MAX (integers). Keep step=1 for clarity
        self.fee_scale = tk.Scale(
            fee_box,
            from_=CFG.MIN_FEE_RATE_SATVB,
            to=CFG.MAX_FEE_RATE_SATVB,
            orient="horizontal",
            showvalue=False,
            bg=p["card"],
            troughcolor=p["slider_trough"],
            highlightthickness=0,
            sliderrelief=tk.FLAT,
            length=260,
            command=lambda _val: self._on_fee_scale(),
        )
        try:
            self.fee_scale.set(float(self.fee_rate_var.get()))
        except Exception:
            self.fee_scale.set(CFG.MIN_FEE_RATE_SATVB)
        self.fee_scale.grid(row=0, column=1, sticky="w", padx=(10, 8))

        self.fee_entry = tk.Entry(
            fee_box, textvariable=self.fee_rate_var, width=7, bg=p["panel_bg"], fg=p["fg"], insertbackground=p["fg"]
        )
        self.fee_entry.grid(row=0, column=2, sticky="w")

        # Speed labels
        speed = tk.Frame(box, bg=p["card"]) 
        speed.pack(fill="x")
        tk.Label(speed, text=f"min {CFG.MIN_FEE_RATE_SATVB} — Slow", bg=p["card"], fg=p["muted"], font=("Consolas", 8))\
            .pack(side="left", padx=(2, 0))
        tk.Label(speed, text=f"Fast — max {CFG.MAX_FEE_RATE_SATVB}", bg=p["card"], fg=p["muted"], font=("Consolas", 8))\
            .pack(side="right", padx=(0, 2))

        tk.Label(box, textvariable=self.amount_err, bg=p["card"], fg=self._danger_color, font=("Consolas", 9)).pack(anchor="w")

    def _step_title(self, parent: tk.Misc, n: int, title: str) -> None:
        p = self.palette
        row = tk.Frame(parent, bg=p["card"]) 
        row.pack(fill="x", pady=(0, 4))
        badge = tk.Label(row, text=str(n), bg=p["accent"], fg="#fff", width=2, font=("Segoe UI", 10, "bold"))
        badge.pack(side="left")
        tk.Label(row, text=title, bg=p["card"], fg=p["fg"], font=("Segoe UI", 11, "bold")).pack(side="left", padx=8)

    def _build_summary(self, grid_parent: tk.Misc) -> None:
        p = self.palette
        wrap = tk.Frame(grid_parent, bg=p["card"]) 
        wrap.grid(row=0, column=1, sticky="n")

        card = tk.Frame(wrap, bg=p["card"], bd=1, highlightthickness=1,
                        highlightbackground=p["border"], highlightcolor=p["border"]) 
        card.pack(anchor="ne")

        tk.Label(card, text="Summary", bg=p["card"], fg=p["fg"], font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        self._kv_row(card, 1, "Estimated size", self.vbytes_var)
        self._kv_row(card, 2, "Fee (sat)", self.fee_sat_var)
        self._kv_row(card, 3, "Fee (TSAR)", self.fee_tsar_var)
        self._kv_row(card, 4, "Total spend (TSAR)", self.total_tsar_var)

    def _kv_row(self, parent: tk.Misc, r: int, k: str, v_var: tk.StringVar) -> None:
        p = self.palette
        tk.Label(parent, text=f"{k}:", bg=p["card"], fg=p["muted"]).grid(row=r, column=0, sticky="w", padx=12)
        tk.Label(parent, textvariable=v_var, bg=p["card"], fg=p["fg"]).grid(row=r, column=1, sticky="e", padx=12)

    def _activity_log(self, parent: tk.Misc) -> tk.Frame:
        p = self.palette
        log_card = tk.Frame(parent, bg=p["card"], bd=1, highlightthickness=1,
                            highlightbackground=p["border"], highlightcolor=p["border"]) 
        border = tk.Frame(log_card, bg=p["border"]) 
        border.pack(fill="both", expand=True, padx=1, pady=1)
        inner = tk.Frame(border, bg=p["card"]) 
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text="Activity", bg=p["card"], fg=p["fg"], font=("Segoe UI", 10, "bold"))\
            .pack(anchor="w", padx=10, pady=(8, 0))

        self.log_text = tk.Text(inner, bg=p["card"], fg=p["fg"], insertbackground=p["fg"], relief="flat",
                                 borderwidth=0, wrap="word", cursor="arrow")
        self.log_text.pack(fill="both", expand=True, padx=12, pady=(4, 10))

        # Wheel scroll (no visible scrollbar)
        def _wheel(e):
            if getattr(e, "delta", 0) != 0:
                self.log_text.yview_scroll(-int(e.delta / 120), "units")
            else:
                self.log_text.yview_scroll(1 if getattr(e, "num", 0) == 5 else -1, "units")
            return "break"
        self.log_text.bind("<MouseWheel>", _wheel)
        self.log_text.bind("<Button-4>", _wheel)
        self.log_text.bind("<Button-5>", _wheel)

        return log_card
    
    def _set_amount_placeholder(self) -> None:
        try:
            self._amt_placeholder_active = True
            self.amount_var.set(self._amt_hint)
            if self.amount_entry:
                self.amount_entry.config(fg=self.palette["muted"])
        except Exception:
            pass

    def _on_amount_focus_in(self, _e=None) -> None:
        try:
            # focus ring
            if self._amt_shell:
                self._amt_shell.config(highlightbackground=self.palette["accent"])
            # bersihkan placeholder saat klik
            if self._amt_placeholder_active:
                self.amount_var.set("")
                if self.amount_entry:
                    self.amount_entry.config(fg=self.palette["accent"])
                self._amt_placeholder_active = False
        except Exception:
            pass

    def _on_amount_focus_out(self, _e=None) -> None:
        try:
            if self._amt_shell:
                self._amt_shell.config(highlightbackground=self.palette["border"])
            txt = (self.amount_var.get() or "").strip()
            if txt == "":
                self._set_amount_placeholder()
            else:
                if self.amount_entry:
                    self.amount_entry.config(fg=self.palette["accent"])
            self._refresh_state()
        except Exception:
            pass


    # ===== Internals =====
    def _paste_to(self) -> None:
        try:
            text = self.root.clipboard_get()
        except Exception:
            text = ""
        if text:
            self.to_var.set((text or "").strip())
            self._toast("Pasted", "info")

    def _open_contact_picker_send(self) -> None:
        if not self.contact_mgr:
            self._toast("Contacts module not available", "warn")
            return

        def _on_pick(addr: str, alias: str) -> None:
            try:
                self.to_var.set(addr.strip().lower())
                self._toast(f"To: {alias}", "info")
                self._refresh_state()
            except Exception:
                pass

        try:
            self.contact_mgr.pick_contact(title="Contacts (Send)", on_pick=_on_pick)
        except TypeError:
            self.contact_mgr.pick_contact(title="Contacts (Send)", on_pick=_on_pick, presence_provider=None)

    def _append_log(self, text: str) -> None:
        try:
            if not self.log_text:
                return
            self.log_text.insert(tk.END, text.rstrip() + "\n")
            self.log_text.see(tk.END)
        except Exception:
            pass

    # Balance lookup (Spendable)
    def _refresh_spendable(self) -> None:
        addr = (self.from_var.get() or "").strip().lower()
        if not addr:
            if self.from_spend_lbl:
                self.from_spend_lbl.config(text="")
            self.from_err.set("Please choose a wallet.")
            return
        self.from_err.set("")

        def _on_resp(resp: Optional[Dict[str, Any]]) -> None:
            try:
                data = None
                if resp and isinstance(resp, dict):
                    if "items" in resp and isinstance(resp["items"], dict):
                        data = resp["items"].get(addr)
                    elif "spendable" in resp:
                        data = resp
                if not data:
                    if self.from_spend_lbl:
                        self.from_spend_lbl.config(text="")
                    return

                spendable = int(data.get("spendable", 0))
                self._bal_cache[addr] = data
                ts = spendable / CFG.TSAR
                label = f"Spendable: {ts:.8f}".rstrip("0").rstrip(".") + " TSAR"
                if self.from_spend_lbl:
                    self.from_spend_lbl.config(text=label)
            except Exception:
                pass

        msg = {"type": "GET_BALANCES", "addresses": [addr]}
        widgets = self._send_widgets or []
        if self._request_locked:
            self._request_locked("wallet_balances", widgets, msg, _on_resp)
        else:
            self.rpc_send(msg, _on_resp)

    # Quick amount helpers
    def _fill_percent(self, frac: float) -> None:
        try:
            addr = (self.from_var.get() or "").strip().lower()
            sp = int(self._bal_cache.get(addr, {}).get("spendable", 0))
            fee_rate = self.svc.clamp_fee_rate(float(self.fee_rate_var.get() or 0))
            vbytes = self._estimate_vbytes_safe()
            est_fee = int(round(vbytes * fee_rate))
            usable = max(sp - est_fee, 0)
            atoms = int(round(usable * frac))
            ts = atoms / CFG.TSAR
            self.amount_var.set(("{:.8f}".format(ts)).rstrip("0").rstrip("."))
        except Exception:
            pass
        self._amt_placeholder_active = False
        if self.amount_entry:
            self.amount_entry.config(fg=self.palette["accent"])
        self._refresh_state()

    def _estimate_vbytes_safe(self) -> int:
        try:
            return int(self.svc.estimate_vbytes(n_inputs=2))
        except TypeError:
            return int(self.svc.estimate_vbytes(2, 2))
        except Exception:
            return 200

    def _estimate_fee_now(self) -> tuple[int, int]:
        try:
            fee_rate = self.svc.clamp_fee_rate(float(self.fee_rate_var.get() or 0))
        except Exception:
            fee_rate = float(CFG.MIN_FEE_RATE_SATVB)
        vbytes = self._estimate_vbytes_safe()
        fee_sat = int(round(vbytes * fee_rate))
        return vbytes, fee_sat

    def _on_fee_scale(self) -> None:
        # Keep entry in sync when user drags the slider
        try:
            val = float(self.fee_scale.get())
        except Exception:
            val = float(CFG.MIN_FEE_RATE_SATVB)
        self.fee_rate_var.set(str(int(val)))
        self._refresh_state()

    def _refresh_state(self) -> None:
        # Estimates
        vbytes, fee_sat = self._estimate_fee_now()
        self.vbytes_var.set(str(vbytes))
        self.fee_sat_var.set(str(fee_sat))
        self.fee_tsar_var.set("{:.8f}".format(fee_sat / CFG.TSAR).rstrip("0").rstrip("."))

        try:
            atoms_for_total, _ = self.svc.parse_amount_str((self.amount_var.get() or "").strip())
        except Exception:
            atoms_for_total = 0
        total_tsar = (atoms_for_total + fee_sat) / CFG.TSAR
        self.total_tsar_var.set("{:.8f}".format(total_tsar).rstrip("0").rstrip("."))

        # Validations
        ok = True

        src = (self.from_var.get() or "").strip().lower()
        if not src:
            self.from_err.set("Please choose a wallet.")
            ok = False
        else:
            self.from_err.set("")

        dst = (self.to_var.get() or "").strip().lower()
        if not dst:
            self.to_err.set("Enter recipient address.")
            ok = False
        elif not dst.startswith("tsar1") or len(dst) < 44:
            self.to_err.set("Address looks invalid (must start with tsar1, length ~44).")
            ok = False
        else:
            self.to_err.set("")

        try:
            text = (self.amount_var.get() or "").strip()
            if self._amt_placeholder_active or text == "":
                atoms = 0
                self.amount_err.set("")
                ok = False
            else:
                atoms, _ = self.svc.parse_amount_str(text)
                if atoms <= 0:
                    raise ValueError
                self.amount_err.set("")
        except Exception:
            atoms = 0
            self.amount_err.set("Enter a valid amount greater than 0.")
            ok = False

        try:
            fr = self.svc.clamp_fee_rate(float(self.fee_rate_var.get() or 0))
            if fr < CFG.MIN_FEE_RATE_SATVB or fr > CFG.MAX_FEE_RATE_SATVB:
                ok = False
        except Exception:
            ok = False

        spendable = int(self._bal_cache.get(src, {}).get("spendable", 0))
        if atoms + fee_sat > spendable:
            self.amount_err.set("Not enough balance for amount + fee.")
            ok = False

        # Enable/disable send
        try:
            self.btn_review.configure(state=("normal" if ok else "disabled"))
        except Exception:
            pass

        # Keep slider in sync if user typed fee manually
        try:
            if self.fee_scale and self.fee_entry and self.fee_entry.focus_get() is self.fee_entry:
                val = float(self.fee_rate_var.get() or CFG.MIN_FEE_RATE_SATVB)
                self.fee_scale.set(val)
        except Exception:
            pass

        # Track for busy‑lock management
        self._send_widgets = [
            *(w for w in (self.from_combo, self.to_entry, self.amount_entry, self.fee_entry, self.btn_review) if w),
        ]

    def _on_from_change(self) -> None:
        self._refresh_spendable()
        self._refresh_state()

    def _on_review_clicked(self) -> None:
        src = (self.from_var.get() or "").strip().lower()
        dst = (self.to_var.get() or "").strip().lower()
        try:
            atoms, _ = self.svc.parse_amount_str((self.amount_var.get() or "").strip())
        except Exception:
            atoms = -1

        if (not src) or (not dst) or atoms <= 0:
            self._toast("Invalid input", "warn")
            return

        # Build confirmation text
        amount_tsar = atoms / CFG.TSAR
        vbytes, fee_sat = self._estimate_fee_now()
        total_tsar = (atoms + fee_sat) / CFG.TSAR
        msg = (
            "Please review your transaction:\n\n"
            f"From: {src}\n"
            f"To  : {dst}\n"
            f"Amount: {amount_tsar:.8f} TSAR\n"
            f"Fee   : {fee_sat} sat  (~{fee_sat/CFG.TSAR:.8f} TSAR)\n"
            f"Size  : ~{vbytes} vB\n"
            f"Total : {total_tsar:.8f} TSAR\n\n"
            "Continue?"
        )
        if not mb.askyesno("Review & Send", msg, parent=self._frame):
            return

        pwd = self.ask_password(src)
        if not pwd:
            self._toast("Cancelled.", "info")
            return

        # Lock UI
        for w in self._send_widgets:
            try: w.configure(state="disabled")
            except Exception: pass
        try: self.root.config(cursor="watch")
        except Exception: pass

        try:
            self._send_safety = self.root.after(12000, lambda: on_done())
        except Exception:
            self._send_safety = None

        on_done = self._make_unlocker(lambda: self._after_send_done(src))

        def on_error(emsg: str) -> None:
            try:
                self._append_log(f"[ERROR] {emsg}")
                self._toast(emsg, "error")
            finally:
                on_done()

        def on_broadcasted(res) -> None:
            try:
                if isinstance(res, str):
                    txid = res
                elif isinstance(res, dict):
                    txid = res.get("txid") or res.get("hash") or res.get("id") or ""
                else:
                    txid = str(res)
                self._append_log(f"[OK] Broadcasted TXID: {txid}")

                try:
                    mb.showinfo("Broadcast Success", f"Transaction broadcasted.\n\nTXID:\n{txid}")
                except Exception:
                    pass
                
                self._toast(f"Broadcasted: {txid[:12]}…", "info")
            finally:
                on_done()

        # Fire
        try:
            import inspect
            _extra = {}
            try:
                if 'opret_hex' in inspect.signature(self.svc.create_sign_broadcast).parameters and getattr(self, '_opret_hex', None):
                    _extra['opret_hex'] = self._opret_hex
            except Exception:
                pass
            self.svc.create_sign_broadcast(
                from_addr=src,
                to_addr=dst,
                amount_sats=atoms,
                password_provider=lambda _addr: pwd,
                rpc_send=self.rpc_send,
                fee_rate=float(self.fee_rate_var.get() or CFG.MIN_FEE_RATE_SATVB),
                on_progress=lambda m: self._append_log(m),
                on_done=on_broadcasted, **_extra)
        except Exception as e:
            on_error(f"Send failed: {e!r}")

    def _make_unlocker(self, after: Callable[[], None]) -> Callable[[], None]:
        def _u():
            try:
                try:
                    if getattr(self, "_send_safety", None):
                        self.root.after_cancel(self._send_safety)
                        self._send_safety = None
                except Exception:
                    pass

                for w in self._send_widgets:
                    try: w.configure(state="normal")
                    except Exception: pass
                self.root.config(cursor="")
            finally:
                after()
        return _u

    def _after_send_done(self, src_addr: str) -> None:
        try:
            self._refresh_spendable()
            self.amount_var.set("")
            self._set_amount_placeholder()
            self._refresh_state()
            self._append_log("[*] Done.")
            try:
                if self.to_entry:
                    self.to_entry.focus_set()
            except Exception:
                pass
        except Exception:
            pass
        try:
            self.on_sent(src_addr)
        except Exception:
            pass
