# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import tkinter as tk
import time, os, json, hashlib
from typing import Optional
from tkinter import ttk, messagebox
from tkinter import font as tkfont
from datetime import datetime


from tsarchain.wallet.chat_security import ChatManager
from ..utils import config as CFG


class ChatTab:
    def __init__(self, root, chat_mgr: ChatManager, rpc_send, palette, toast_cb, get_wallets_cb, contact_mgr=None, logger=None):
        self.root = root
        self.chat_mgr = chat_mgr
        self.rpc_send = rpc_send
        self.toast = toast_cb
        self.get_wallets_cb = get_wallets_cb
        self.contact_mgr = contact_mgr
        self.log = logger
        self.set_palette(palette or {})
        # internal state moved from light_wallet
        self.chat_verified_var = tk.StringVar(value="Unverified ❌")
        self.chat_sas_var = tk.StringVar(value="••••••")
        self.chat_textsize_var = tk.StringVar(value="Medium")
        self.chat_context_var = tk.StringVar(value="")
        self._chat_online = False
        self._chat_poll_job = None
        self._typing_after = None
        self._chat_priv_cache = {}
        self._msg_meta_map = {}
        self._chat_key_ttl_sec = 15 * 60
        self.chat_blocked = set()
        self.contacts = getattr(self.contact_mgr, "contacts", {}) if self.contact_mgr else {}
        self.parent = None
        self.frame = None
        # fonts (safe defaults)
        self.font_chat_meta_peer = tkfont.Font(family="Segoe UI", size=10)
        self.font_chat_meta_me = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self.chat_font = tkfont.Font(family="Segoe UI", size=11)
        self.chat_font_mono = tkfont.Font(family="Consolas", size=11)
        self.chat_font_body = tkfont.Font(family="Segoe UI", size=12)

    def set_palette(self, palette: dict):
        self.bg = palette.get("bg", "#0e141a")
        self.panel_bg = palette.get("panel_bg", "#141b23")
        self.fg = palette.get("fg", "#e5e7eb")
        self.muted = palette.get("muted", "#9ca3af")
        self.accent = palette.get("accent", "#4ade80")

    def build(self, parent) -> None:
        self.parent = parent
        f = tk.Frame(parent, bg=self.bg)
        self.frame = f
        f.pack(fill=tk.BOTH, expand=True)

        # ---- state vars
        self.chat_verified_var = tk.StringVar(value="Unverified ❌")
        self.chat_sas_var = tk.StringVar(value="••••••")
        self.chat_textsize_var = tk.StringVar(
            value=getattr(self, "chat_textsize_var", tk.StringVar(value="Medium")).get()
        )
        self.chat_context_var = tk.StringVar(value="")
        
        try:
            wallets = list(self.get_wallets_cb() or [])
        except Exception:
            wallets = []

        # ======= TOP BAR =======
        top = tk.Frame(f, bg=self.bg)
        
        if not hasattr(self, "chat_from_var"):
            self.chat_from_var = tk.StringVar(value=(wallets[0] if wallets else ""))

        top.pack(fill=tk.X, padx=12, pady=8)

        sec = tk.Frame(top, bg=self.bg)
        sec.pack(side=tk.LEFT, padx=8)

        tk.Label(sec, text="Text:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT, padx=(10, 2))
        size_combo = ttk.Combobox(
            sec, values=["Small", "Medium", "Large"], state="readonly", width=8,
            textvariable=self.chat_textsize_var
        )
        size_combo.pack(side=tk.LEFT, padx=4)
        size_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_chat_textsize(self.chat_textsize_var.get()))
        self._apply_chat_textsize(self.chat_textsize_var.get())

        tk.Button(sec, text="Show SAS", command=self._chat_show_sas,
                bg=self.panel_bg, fg=self.fg).pack(side=tk.LEFT, padx=6)

        self.chat_addr_label = tk.Label(sec, text="", bg=self.bg, fg=self.fg, font=("Consolas", 10))
        self.chat_logout_btn = tk.Button(sec, text="Logout", command=self._chat_logout,
                                        bg=self.panel_bg, fg=self.fg)
        try:
            self.chat_addr_label.pack_forget()
            self.chat_logout_btn.pack_forget()
        except Exception:
            pass

        # To / Contacts
        to_area = tk.Frame(top, bg=self.bg)
        to_area.pack(side=tk.LEFT, padx=8)
        tk.Button(to_area, text="📇 Contacts", command=self._open_contact_picker_chat, bg=self.panel_bg, fg=self.fg,
            bd=0, relief=tk.FLAT, padx=8, pady=4, highlightthickness=0, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 6))

        self._build_chat_to_controls(to_area)

        # ======= BODY (log + input) =======
        body = tk.Frame(f, bg=self.bg)
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 12))

        # Log area
        log_wrap = tk.Frame(body, bg=self.bg)
        log_wrap.pack(fill=tk.BOTH, expand=True)

        self.chat_log = tk.Text(
            log_wrap, wrap="word", bg=self.bg, fg=self.fg, insertbackground=self.fg,
            relief="flat", borderwidth=0, height=18
        )
        self.chat_log.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        self._init_chat_tags_and_fonts()
        self._chat_setup_bottom_align()
        self.chat_log.tag_configure("bubble_peer", background="#15212b")
        self.chat_log.tag_configure("bubble_me",   background="#3d6839")
        self.chat_log.tag_configure("hdr_peer")  # left default
        self.chat_log.tag_configure("hdr_me", justify="right")
        try:
            self.chat_log.tag_configure("meta_peer", foreground="#a0a7ad",
                                        font=self.font_chat_meta_peer, justify="left")
            self.chat_log.tag_configure("meta_me", foreground="#a0a7ad",
                                        font=self.font_chat_meta_me, justify="right")
        except Exception:
            pass

        # scrollbar
        vsb = ttk.Scrollbar(log_wrap, orient="vertical", command=self.chat_log.yview)
        self.chat_log.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # badge online/offline + context
        self.chat_offline_badge = tk.Label(
            body, text="● Offline", bg=self.bg, fg="#d41c1c", font=("Segoe UI", 9, "bold")
        )
        self.chat_offline_badge.pack(anchor="e", padx=2, pady=(2, 0))

        ctx = tk.Label(
            body, textvariable=self.chat_context_var, bg=self.bg, fg="#9c9797",
            font=("Consolas", 9, "italic")
        )
        ctx.pack(fill=tk.X, pady=(2, 0))

        # Input
        entryfrm = tk.Frame(body, bg=self.bg)
        entryfrm.pack(fill=tk.X, pady=(6, 0))

        self.chat_input = tk.Text(
            entryfrm, height=3, wrap="word", bg=self.panel_bg, fg=self.fg,
            insertbackground=self.fg, relief="flat"
        )
        self.chat_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.chat_entry = self.chat_input  # alias, dipakai di _chat_update_send_state

        self.typing_var = tk.StringVar(value="")
        self.typing_lbl = tk.Label(
            entryfrm, textvariable=self.typing_var, bg=self.bg, fg="#a0a7ad",
            font=("Segoe UI", 9, "italic")
        )
        self.typing_lbl.pack(side=tk.RIGHT, padx=6)

        def _on_type(_e=None):
            self.typing_var.set("typing.")
            if getattr(self, "_typing_after", None):
                try: self.root.after_cancel(self._typing_after)
                except Exception: pass
            self._typing_after = self.root.after(1200, lambda: self.typing_var.set(""))

        def _chat_enter_to_send(_e=None):
            self._chat_send(); return "break"

        def _chat_shift_enter(_e=None):
            self.chat_input.insert(tk.INSERT, "\n"); return "break"

        self.chat_input.bind("<Key>", _on_type)
        self.chat_input.bind("<Return>", _chat_enter_to_send)
        self.chat_input.bind("<Shift-Return>", _chat_shift_enter)

        self.chat_send_btn = tk.Button(
            entryfrm, text="Send", command=self._chat_send,
            bg=self.accent, fg="#000000", font=("Segoe UI", 10, "bold"),
            state=tk.DISABLED
        )
        self.chat_send_btn.pack(side=tk.LEFT, padx=(8, 0))

        # ======= HERO OVERLAY =======
        self.chat_hero = tk.Frame(self.frame, bg=self.bg)
        header = tk.Frame(self.chat_hero, bg=self.bg); header.pack(side="top", pady=(10, 0))
        tk.Label(header, text="♜Kremlin Chat♜", bg=self.bg, fg=self.accent,
                font=("Segoe UI", 60, "bold")).pack(side="top")
        tk.Label(header, text="Encrypted whispers for underground creators.",
                bg=self.bg, fg="#C4A231", font=("Consolas", 18, "italic")).pack(side="top", pady=(0, 30))
        body_wrap = tk.Frame(self.chat_hero, bg=self.bg); body_wrap.pack(fill="both", expand=True, padx=16, pady=16)
        grid = tk.Frame(body_wrap, bg=self.bg); grid.pack(fill="both", expand=True)
        grid.grid_columnconfigure(0, weight=1); grid.grid_columnconfigure(1, weight=3); grid.grid_columnconfigure(2, weight=1)
        center = tk.Frame(grid, bg=self.bg); center.grid(row=0, column=1, sticky="nsew")
        card = tk.Frame(center, bg=self.panel_bg, bd=1, highlightthickness=1, highlightbackground="#2a2f36", highlightcolor="#2a2f36")
        card.pack(fill="x", expand=False, padx=12, pady=6)
        inner = tk.Frame(card, bg=self.panel_bg); inner.pack(fill="x", padx=16, pady=16)

        tk.Label(inner, text="Choose your address:", bg=self.panel_bg, fg=self.fg, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 6))
        self.chat_hero_addr_var = tk.StringVar(value=(wallets[0] if wallets else ""))
        self.chat_hero_addr_combo = ttk.Combobox(inner, values=wallets, textvariable=self.chat_hero_addr_var, state="readonly", width=64)
        self.chat_hero_addr_combo.pack(fill="x")
        tk.Button(inner, text="Go Online", command=self._chat_login_from_hero,
                bg=self.accent, fg="#000", font=("Segoe UI", 11, "bold")).pack(pady=(12, 0))

        # ---- final init
        self._chat_state_load()
        self._update_chat_context()
        self._chat_enter_hero()          # default: offline → hero overlay
        self._chat_update_send_state()


    def _build_chat_to_controls(self, parent):
        if not hasattr(self, "chat_to_var"):
            self.chat_to_var = tk.StringVar(value="")
        if not hasattr(self, "selected_friend_var"):
            self.selected_friend_var = tk.StringVar(value="(not yet selected)")

        tk.Label(parent, textvariable=self.selected_friend_var, bg=self.bg, fg=self.fg)\
            .pack(side=tk.LEFT, padx=8)

        # Sinkronisasi saat nilai "To" berubah
        def _on_to_change(*_):
            raw = (self.chat_to_var.get() or "").strip().lower()
            if not raw:
                self.selected_friend_var.set("(not yet selected)")
            else:
                alias = self._alias_label(raw) if hasattr(self, "_alias_label") else raw
                disp = f"{alias} - {raw[:10]}-{raw[-6:]}" if len(raw) > 20 else f"{alias}"
                self.selected_friend_var.set(disp)
            try:
                self._chat_update_security_badges()
            except Exception:
                pass
            try:
                self._update_chat_context()
            except Exception:
                pass
            try:
                self._chat_update_send_state()
            except Exception:
                pass

        try:
            self.chat_to_var.trace_add("write", lambda *_: _on_to_change())
        except Exception:
            pass
        try:
            self.chat_from_var.trace_add("write", lambda *_: (self._chat_update_security_badges(),
                                                            self._update_chat_context()))
        except Exception:
            pass

        self._sync_selected_friend()
        return

    def _sync_selected_friend(self):
        raw = (self.chat_to_var.get() or "").strip().lower()
        if not raw:
            self.selected_friend_var.set("(not yet selected)")
            return
        alias = self._alias_label(raw)
        disp = f"{alias} - {raw[:10]}-{raw[-6:]}" if len(raw) > 20 else f"{alias}"
        self.selected_friend_var.set(disp)

    def _open_contact_picker_chat(self) -> None:
        if not self.contact_mgr:
            self.toast("Contacts module not available", "warn")
            return
        def _on_pick(addr: str, alias: str) -> None:
            self.chat_to_var.set((addr or "").strip().lower())
            self._sync_selected_friend()
            self._update_chat_context()
            self._chat_update_send_state()
            self.toast(f"To: {alias}", "info")
        try:
            self.contact_mgr.pick_contact(title="Contacts (Chat)", on_pick=_on_pick)
        except TypeError:
            self.contact_mgr.pick_contact(title="Contacts (Chat)", on_pick=_on_pick, presence_provider=None)
        except Exception:
            pass

    def _apply_chat_textsize(self, size_label: str) -> None:
        label = (size_label or "medium").strip().lower()
        table = {
            "small": {"body": 11, "meta": 9},
            "medium": {"body": 13, "meta": 10},
            "large": {"body": 15, "meta": 12},
        }
        cfg = table["medium"]
        for key, value in table.items():
            if label.startswith(key):
                cfg = value
                break

        body_sz = cfg["body"]
        meta_sz = cfg["meta"]
        self.chat_font_size = body_sz

        for attr, size in (
            ("font_chat_body", body_sz),
            ("font_chat_meta_peer", meta_sz),
            ("font_chat_meta_me", meta_sz),
        ):
            font_obj = getattr(self, attr, None)
            if font_obj is not None:
                try:
                    font_obj.configure(size=size)
                except Exception:
                    pass

        try:
            if getattr(self, "chat_font", None):
                self.chat_font.configure(size=body_sz)
            if getattr(self, "chat_font_bold", None):
                self.chat_font_bold.configure(size=body_sz, weight="bold")
            if getattr(self, "chat_font_small", None):
                self.chat_font_small.configure(size=max(9, meta_sz))
            if getattr(self, "chat_font_mono", None):
                self.chat_font_mono.configure(size=body_sz)
        except Exception:
            self._init_chat_tags_and_fonts()

        try:
            self._chat_reflow_bubbles()
        except Exception:
            if hasattr(self, "log"):
                self.log.debug("[chat] bubble reflow skipped", exc_info=True)
        try:
            self._chat_bottom_align()
        except Exception:
            if hasattr(self, "log"):
                self.log.debug("[chat] bottom align skipped", exc_info=True)

        txt = getattr(self, "chat_log", None)
        if txt is not None:
            try:
                txt.tag_configure("peer", lmargin1=14, lmargin2=14)
                txt.tag_configure("me", lmargin1=120, lmargin2=120)
            except Exception:
                pass

        try:
            self._chat_state_save()
        except Exception:
            if hasattr(self, "log"):
                self.log.debug("[chat] save textsize failed", exc_info=True)

    def _init_chat_tags_and_fonts(self):
        # --- Font setup (fallback aman) ---
        base_family = "Segoe UI"
        mono_family = "Consolas"
        self.chat_font_size = getattr(self, "chat_font_size", 11)

        try:
            self.chat_font = getattr(self, "chat_font", tkfont.Font(family=base_family, size=self.chat_font_size))
            self.chat_font_bold = getattr(self, "chat_font_bold", tkfont.Font(family=base_family, size=self.chat_font_size, weight="bold"))
            self.chat_font_small = getattr(self, "chat_font_small", tkfont.Font(family=base_family, size=max(9, self.chat_font_size - 1)))
            self.chat_font_large = getattr(self, "chat_font_large", tkfont.Font(family=base_family, size=self.chat_font_size + 2))
            self.chat_font_mono = getattr(self, "chat_font_mono", tkfont.Font(family=mono_family, size=self.chat_font_size))
        except Exception:
            # fallback kalau font init gagal
            self.chat_font = None
            self.chat_font_bold = None
            self.chat_font_small = None
            self.chat_font_large = None
            self.chat_font_mono = None

        txt = getattr(self, "chat_log", None)
        if not txt:
            return

        # --- Warna tema (fallback jika atribut belum ada) ---
        bg = getattr(self, "bg", "#0f1115")
        fg = getattr(self, "fg", "#e8e8e8")
        panel = getattr(self, "panel_bg", "#171a21")
        # accent = getattr(self, "accent", "#F5A524")  # tidak dipakai di tag saat ini

        # Hapus dan definisikan ulang tag (aman jika belum ada)
        for tag in ("me", "peer", "sys", "ts", "bold", "code", "warn", "error"):
            try:
                txt.tag_delete(tag)
            except Exception:
                pass

        # Margin bubble
        pad_left = 14
        me_indent = 120  # bubble pesan kita (kanan) dimajukan dari kiri

        # Peer bubble (kiri)
        txt.tag_configure("peer",
                        lmargin1=pad_left, lmargin2=pad_left, rmargin=40,
                        spacing1=4, spacing3=6,
                        foreground=fg, justify="left")

        # Me bubble (kanan)
        txt.tag_configure("me",
                        lmargin1=me_indent, lmargin2=me_indent, rmargin=12,
                        spacing1=4, spacing3=6,
                        foreground=fg, justify="right")

        # System/info line
        txt.tag_configure("sys",
                        lmargin1=pad_left, lmargin2=pad_left, rmargin=12,
                        foreground="#9aa1a9", justify="center")

        # Timestamp kecil
        txt.tag_configure("ts",
                        foreground="#9aa1a9",
                        font=self.chat_font_small if self.chat_font_small else None)

        # Gaya tambahan
        txt.tag_configure("bold", font=self.chat_font_bold if self.chat_font_bold else None)
        txt.tag_configure("code", font=self.chat_font_mono if self.chat_font_mono else None, background=panel)
        txt.tag_configure("warn", foreground="#ffc107")
        txt.tag_configure("error", foreground="#ff4d4f")

        # Set default font untuk widget
        try:
            if self.chat_font:
                txt.configure(font=self.chat_font)
            txt.configure(cursor="arrow")
        except Exception:
            pass

    def _chat_enter_hero(self):
        try:
            self.chat_addr_label.pack_forget()
            self.chat_logout_btn.pack_forget()
        except Exception:
            pass
        try:
            if getattr(self, "_chat_poll_job", None):
                self.root.after_cancel(self._chat_poll_job)
            self._chat_poll_job = None
        except Exception:
            pass
        try:
            self.chat_hero.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)
        except Exception:
            self.chat_hero.pack(fill="both", expand=True)
        try:
            self.chat_offline_badge.config(text="● Offline", fg="#d41c1c")
        except Exception:
            pass

    def _chat_enter_compact(self):
        try:
            self.chat_hero.place_forget()
        except Exception:
            try: self.chat_hero.pack_forget()
            except Exception: pass
        try:
            from_addr = (self.chat_from_var.get() or "").strip().lower()
            self.chat_addr_label.config(text=f"Address: {self._alias_label(from_addr) or self._mask_addr(from_addr)}")
            self.chat_addr_label.pack(side=tk.LEFT, padx=(12, 0))
            self.chat_logout_btn.pack(side=tk.LEFT, padx=(6, 0))
        except Exception:
            pass
        self._update_chat_context()

    def _chat_login_from_hero(self):
        addr = (self.chat_hero_addr_var.get() or "").strip().lower()
        if not addr:
            self.toast("Pilih address dulu.", kind="warn")
            return
        self.chat_from_var.set(addr)
        self._chat_toggle_online()

    def _chat_logout(self):
        addr = (self.chat_from_var.get() or "").strip().lower()
        try:
            if addr:
                self.chat_mgr.priv_cache.pop(addr, None)
        except Exception:
            pass
        try:
            if getattr(self, "_chat_poll_job", None):
                self.root.after_cancel(self._chat_poll_job)
        except Exception:
            pass
        self._chat_poll_job = None
        self._chat_set_online_ui(False)
        self.toast("Logged out.", kind="info")
        self._chat_enter_hero()

    def _chat_state_load(self):
        try:
            p = CFG.CHAT_STATE
            if os.path.exists(p):
                data = json.load(open(p, "r", encoding="utf-8"))
                self.chat_blocked = set(data.get("blocked", []))
                self.chat_mgr.pub_cache.update(data.get("pubcache", {}) or {})
                tsz = data.get("textsize")
                if tsz:
                    self.chat_textsize_var.set(tsz)
        except Exception:
            pass

    def _chat_state_save(self):
        try:
            data = {
                "blocked": sorted(self.chat_blocked),
                "pubcache": self.chat_mgr.pub_cache,
                "textsize": self.chat_textsize_var.get(),}
            json.dump(data, open(CFG.CHAT_STATE, "w", encoding="utf-8"))
        except Exception:
            pass

    def _chat_set_online_ui(self, on: bool) -> None:
        self._chat_online = bool(on)
        from_addr = (self.chat_from_var.get() or "").strip().lower()
        from_name = self._alias_label(from_addr) or self._mask_addr(from_addr)
        state_label = "Online" if on else "Offline"
        state_color = "#17c964" if on else "#d41c1c"
        status_text = f"Address: {from_name} • {state_label}"

        try:
            if getattr(self, "chat_addr_label", None):
                self.chat_addr_label.config(text=status_text, fg=state_color)
        except Exception:
            pass

        try:
            badge = getattr(self, "chat_offline_badge", None)
            if badge is not None:
                badge.config(text=f"● {state_label}", fg=state_color)
            if on:
                self._chat_enter_compact()
            else:
                self._chat_enter_hero()
        except Exception:
            pass

        self._chat_update_send_state()
        self._update_chat_context()

    def _chat_toggle_online(self) -> None:
        addr = (self.chat_from_var.get() or "").strip().lower()
        if not addr:
            self.toast("Input Target Address First!.", kind="warn")
            return

        if not self._chat_online:
            priv, err = self.chat_mgr.try_unlock(addr)
            if err:
                msg = None
                if "Wallet file not found" in err:
                    msg = "Keystore not present. Create or import a wallet first."
                elif "Keystore empty" in err:
                    msg = "Keystore is empty. Create or import a wallet first."
                elif "Account locked" in err or "Too many failed attempts" in err:
                    msg = err
                elif "Invalid password" in err:
                    msg = "Password salah atau file keystore korup."
                else:
                    msg = f"Gagal unlock: {err}"
                self.toast(msg, kind="error")
                return

            def _on(resp):
                if resp and resp.get("type") == "CHAT_REGISTERED":
                    self._chat_set_online_ui(True)
                    self.toast("Online •", kind="info")
                    self._chat_schedule_next(800)
                else:
                    self.toast(f"Failed Register: {resp}", kind="error")

            self.chat_mgr.register(addr, _on)
            return

        if not messagebox.askyesno("Go Offline", "Are you sure you want to go offline?"):
            return
        try:
            a = addr.strip().lower()
            self.chat_mgr.priv_cache.pop(a, None)
        except Exception:
            pass
        try:
            if getattr(self, "_chat_poll_job", None):
                self.root.after_cancel(self._chat_poll_job)
        except Exception:
            pass
        self._chat_poll_job = None
        self._chat_set_online_ui(False)
        self.toast("Offline.", kind="info")

    def _chat_reflow_bubbles(self, *_):
        txt = getattr(self, "chat_log", None)
        if txt is None:
            return
        try:
            w = int(txt.winfo_width())
        except Exception:
            return
        if w <= 0:
            return
        pad = 12
        frac = getattr(self, "_bubble_frac", 0.62)
        max_w = max(180, int(w * frac))
        max_w = min(max_w, w - pad * 2)
        l_peer = pad
        r_peer = max(pad, w - (l_peer + max_w))
        r_me = pad
        l_me = max(pad, w - (r_me + max_w))
        try:
            txt.tag_configure(
                "bubble_peer",
                lmargin1=l_peer, lmargin2=l_peer,
                rmargin=r_peer, justify="left",
            )
            txt.tag_configure(
                "bubble_me",
                lmargin1=l_me, lmargin2=l_me,
                rmargin=r_me, justify="right",
            )
        except Exception:
            if hasattr(self, "log"):
                self.log.debug("[chat] bubble tag update skipped", exc_info=True)

    def _chat_setup_bottom_align(self):
        txt = getattr(self, "chat_log", None)
        if not txt:
            return

        try:
            if "content_start" not in txt.mark_names():
                txt.mark_set("content_start", "1.0")
        except Exception:
            pass

        def _on_config(_event=None):
            try:
                self._chat_bottom_align()
            except Exception:
                if hasattr(self, "log"):
                    self.log.debug("[chat] bottom align skipped", exc_info=True)
            try:
                self._chat_reflow_bubbles()
            except Exception:
                if hasattr(self, "log"):
                    self.log.debug("[chat] bubble reflow skipped", exc_info=True)

        txt.bind("<Configure>", _on_config, add="+")
        self._chat_bottom_align()

    def _chat_bottom_align(self, *_):
        txt = getattr(self, "chat_log", None)
        if not txt:
            return

        try:
            state = txt.cget("state")
        except Exception:
            state = None

        try:
            if state == tk.DISABLED:
                txt.configure(state=tk.NORMAL)
            if "content_start" not in txt.mark_names():
                txt.mark_set("content_start", "1.0")
            txt.see(tk.END)
        finally:
            if state == tk.DISABLED:
                try:
                    txt.configure(state=tk.DISABLED)
                except Exception:
                    pass

    def _chat_append_line(self, line: str, tag: str = "peer") -> None:
        txt = getattr(self, "chat_log", None)
        if txt is None:
            return
        try:
            txt.configure(state="normal")
        except Exception:
            return
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            txt.insert(tk.END, f"[{ts}] {line}\n", (tag,))
            txt.see(tk.END)
        finally:
            try:
                self._chat_bottom_align()
            except Exception:
                if hasattr(self, "log"):
                    self.log.debug("[chat] bottom align skipped", exc_info=True)
            try:
                self._chat_reflow_bubbles()
            except Exception:
                if hasattr(self, "log"):
                    self.log.debug("[chat] bubble reflow skipped", exc_info=True)
            try:
                txt.configure(state="disabled")
            except Exception:
                pass

    def _chat_append_bubble(self, name: str, text: str, side: str, addr: str = "", mid=None, status: Optional[str] = None, ts: Optional[int] = None) -> None:
        txt = getattr(self, "chat_log", None)
        if txt is None:
            return
        try:
            txt.configure(state="normal")
        except Exception:
            return

        stat_s = stat_e = None
        try:
            if ts is None:
                ts = int(time.time())
            ts_s = datetime.fromtimestamp(ts).strftime("%H:%M")

            bubble_tag = "bubble_me" if side == "me" else "bubble_peer"
            meta_tag = "meta_me" if side == "me" else "meta_peer"
            side_tag = "me" if side == "me" else "peer"

            if side == "peer":
                avatar = self._avatar_for(addr)
                header_text = f"{avatar}  {name}  [{ts_s}]\n"
                header_tags = (bubble_tag, side_tag, "hdr_peer", meta_tag)
            else:
                header_text = f"[{ts_s}]\n"
                header_tags = (bubble_tag, side_tag, "hdr_me", meta_tag)

            start_idx = txt.index(tk.END)
            txt.insert(tk.END, header_text, header_tags)
            end_idx = txt.index(tk.END)

            safe_text = text if isinstance(text, str) else str(text)
            body = f" {safe_text} \n"
            txt.insert(tk.END, body, (bubble_tag, side_tag))

            if side == "me":
                stat_s = txt.index(tk.END)
                txt.insert(tk.END, f"{status or ''}\n", (bubble_tag, side_tag, "stat_me"))
                stat_e = txt.index(tk.END)

            txt.see(tk.END)

            if mid is not None:
                s_mark = f"m{mid}_s"
                e_mark = f"m{mid}_e"
                try:
                    txt.mark_set(s_mark, start_idx)
                    txt.mark_set(e_mark, end_idx)
                except Exception:
                    s_mark = e_mark = None

                self._msg_meta_map[mid] = {
                    "start": start_idx,
                    "end": end_idx,
                    "mark_s": s_mark,
                    "mark_e": e_mark,
                    "name": name,
                    "side": side,
                    "addr": addr,
                    "ts": ts,
                    "status": status or "",
                    "stat_s": stat_s,
                    "stat_e": stat_e,
                }
        except Exception:
            if hasattr(self, "log"):
                self.log.exception("[chat] failed to render bubble:")
        finally:
            try:
                self._chat_reflow_bubbles()
            except Exception:
                if hasattr(self, "log"):
                    self.log.debug("[chat] bubble reflow skipped", exc_info=True)
            try:
                self._chat_bottom_align()
            except Exception:
                if hasattr(self, "log"):
                    self.log.debug("[chat] bottom align skipped", exc_info=True)
            try:
                txt.configure(state="disabled")
            except Exception:
                pass

    def _chat_update_status(self, mid, new_status: str):
        ent = self._msg_meta_map.get(mid)
        if not ent:
            return
        if (ent.get("status") or "") == (new_status or ""):
            return
        if ent.get("side") != "me":
            return
        s = ent.get("stat_s"); e = ent.get("stat_e")
        if not (s and e):
            return

        self.chat_log.configure(state="normal")
        try:
            self.chat_log.delete(s, e)
            self.chat_log.insert(s, f"{new_status}\n", ("bubble_me", "stat_me"))
            ent["stat_e"] = self.chat_log.index(f"{s} lineend + 1c")
            ent["status"] = new_status
        finally:
            self.chat_log.configure(state="disabled")

    def _chat_set_verified(self, ok: bool) -> None:
        self.chat_verified_var.set("Verified ✅" if ok else "Unverified ❌")

    def _chat_update_security_badges(self) -> None:
        frm = (self.chat_from_var.get() or "").strip().lower()
        to  = (self.chat_to_var.get()   or "").strip().lower()
        exp_pub = self.chat_mgr.expected_pub_or_lookup(to)
        self._chat_set_verified(bool(exp_pub))
        try:
            sas = self.chat_mgr.sas(frm, to)
            self.chat_sas_var.set(sas)
        except Exception:
            self.chat_sas_var.set("••••••")

    def _chat_schedule_next(self, delay_ms: int = 2500) -> None:
        try:
            if hasattr(self, "_chat_poll_job") and self._chat_poll_job:
                self.root.after_cancel(self._chat_poll_job)
        except Exception:
            pass
        if not getattr(self, "_chat_online", False):
            self._chat_poll_job = None
            return
        try:
            self._chat_poll_job = self.root.after(delay_ms, self._chat_poll)
        except Exception:
            self._chat_poll_job = None

    def _chat_poll(self) -> None:
        if not getattr(self, "_chat_online", False):
            return
        addr = (self.chat_from_var.get() or "").strip().lower()
        if not addr:
            self._chat_schedule_next(3000)
            return
        def _on_items(items):
            try:
                for it in (items or []):
                    sender_addr = (it.get("from") or "").strip().lower()
                    text        = it.get("text") or ""
                    ts          = int(it.get("ts") or 0)
                    sender_name = self._alias_label(sender_addr)
                    self._chat_append_bubble(sender_name, text, "peer", sender_addr, ts=ts)
                self._chat_update_security_badges()
            except Exception:
                pass
        try:
            self.chat_mgr.poll(addr, 20, _on_items, on_done=None)
        finally:
            self._chat_schedule_next(2500)

    def _chat_register(self) -> None:
        addr = (self.chat_from_var.get() or "").strip().lower()
        if not addr:
            self.toast("Input Address firts.", kind="warn"); return

        def _on(resp):
            if resp and resp.get("type") == "CHAT_REGISTERED":
                self.toast("You Are On Now!!", kind="info")
            else:
                self.toast(f"Register failed: {resp}", kind="error")

        self.chat_mgr.register(addr, _on)

    def _chat_send(self):
        if not getattr(self, "_chat_online", False):
            self.toast("You are offline. go online first.", kind="warn")
            return
        frm_addr = (self.chat_from_var.get() or "").strip().lower()
        to_addr  = (self.chat_to_var.get()   or "").strip().lower()
        text     = (self.chat_input.get("1.0", "end").strip() or "")
        if not (frm_addr and to_addr and text):
            self.toast("Lengkapi From/To & pesan.", kind="warn"); return

        def _on_queued(mid: int, ts: int):
            me_addr = frm_addr
            me_name = self._alias_label(me_addr) or "Me"
            self._chat_append_bubble(me_name, text, "me", me_addr, mid=mid, status="•", ts=ts)
            self.chat_input.delete("1.0", "end")

        def _on_result(resp):
            st = (resp or {}).get("status")
            if st == "duplicate":
                self._chat_append_line("••• duplicate (not re-sent)", tag="sys")
            elif st == "rate_limited":
                scope = (resp or {}).get("scope") or "addr"
                self.toast(f"spam detect!! ({scope}). Try Aggain Later.", ms=1200, kind="warn")
            elif st == "mailbox_full":
                self.toast("Mailbox penerima penuh.", kind="error")
            elif st in ("queued", None):
                # already handled or a generic error
                pass
            else:
                self.toast(f"Gagal kirim: {resp}", kind="error")

        self.chat_mgr.send_message(frm_addr, to_addr, text, _on_queued, _on_result)
        
    def _chat_update_send_state(self) -> None:
        online = getattr(self, "_chat_online", False)
        has_to = bool((self.chat_to_var.get() or "").strip())
        if getattr(self, "chat_send_btn", None):
            self.chat_send_btn.config(state=(tk.NORMAL if (online and has_to) else tk.DISABLED))
            entry = getattr(self, "chat_entry", None)
            if entry:
                entry.configure(state=(tk.NORMAL if online else tk.DISABLED))
                if online:
                    try: entry.focus_set()
                    except Exception: pass
            badge = getattr(self, "chat_offline_badge", None)
            if badge:
                if online:
                    if badge.winfo_ismapped():
                        badge.pack_forget()
                else:
                    if not badge.winfo_ismapped():
                        badge.pack(side=tk.LEFT, padx=(8, 0))
            try:
                if online:
                    if self.chat_offline_badge.winfo_ismapped():
                        self.chat_offline_badge.pack_forget()
                    self.chat_entry.config(state=tk.NORMAL)
                else:
                    if not self.chat_offline_badge.winfo_ismapped():
                        self.chat_offline_badge.pack(side=tk.LEFT, padx=(8, 0))
                    self.chat_entry.config(state=tk.DISABLED)
            except Exception:
                pass
            
    def _update_chat_context(self):
        try:
            frm = (self.chat_from_var.get() or "").strip().lower()
        except Exception:
            frm = ""
        try:
            to = (self.chat_to_var.get() or "").strip().lower()
        except Exception:
            to = ""
        verified = self.chat_verified_var.get()
        sas = self.chat_sas_var.get()
        if frm and to:
            self.chat_context_var.set(f"{self._mask_addr(frm)} → {self._mask_addr(to)} | {verified} | SAS {sas}")
        elif frm:
            self.chat_context_var.set(f"{self._mask_addr(frm)} | {verified}")
        else:
            self.chat_context_var.set("")

    def _chat_show_sas(self) -> None:
        frm = (self.chat_from_var.get() or "").strip().lower()
        to  = (self.chat_to_var.get()   or "").strip().lower()
        if not (frm and to):
            messagebox.showinfo("SAS", "Pilih From & To terlebih dahulu."); return
        sas = self.chat_mgr.sas(frm, to)
        alias = self._alias_label(to)
        messagebox.showinfo(
            "Contact SAS",
            f"SAS dengan {alias}:\n\n{sas}\n\n"
            "Cocokkan 6 emoji ini via panggilan/IRL. Jika sama, kontak ini autentik.")

    def _alias_label(self, addr: str) -> str:
        a = (self.contacts or {}).get((addr or "").lower())
        return a if a else (addr or "")

    def _mask_addr(self, addr: str) -> str:
        a = (addr or "")
        return a if len(a) <= 16 else (a[:8] + ":" + a[-8:])
    
    def _avatar_for(self, addr: str) -> str:
        emojis = ["🔥","🎃","🕶️","🍕","🍿","🥂","🍌","😎"]
        h = hashlib.sha256((addr or "").encode("utf-8")).digest()[0]
        return emojis[h % len(emojis)]

    def reload_addresses(self):
        try:
            vals = list(self.get_wallets_cb())
            if hasattr(self, 'chat_hero_addr_combo'):
                self.chat_hero_addr_combo['values'] = vals
        except Exception:
            pass