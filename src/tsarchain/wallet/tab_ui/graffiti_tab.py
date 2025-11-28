# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations
import os, time, hashlib, mimetypes, threading
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from typing import Any, Dict, Optional
from tkinter import ttk, filedialog, messagebox, StringVar
import tkinter as tk

from ...contracts.graffiti import (
    build_metadata,
    build_comment_metadata,
    build_opret_hex,
    calc_upload_fee_sats,
    calc_comment_split,
    compute_art_id,
    derive_pool_address,
)
from ..services.graffiti_service import upload_graffiti
from ..theme import GraffitiTheme, lighten
from ...utils import config as CFG


# ========= Util kecil =========
def sha256_file(path: str, chunk=1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b: break
            h.update(b)
    return h.hexdigest()

def detect_mime(path: str) -> str:
    mt, _ = mimetypes.guess_type(path)
    return mt or "application/octet-stream"


# ========= Graffiti Tab (UI) =========
class GraffitiTab(ttk.Frame):
    def __init__(self, app, theme: GraffitiTheme, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = app
        self.theme = theme
        # state
        self.selected_path: str | None = None
        self.selected_sha: str | None = None
        self.selected_size: int | None = None
        self.selected_mime: str | None = None
        self.receipt_id: str | None = None
        self.opret_hex: str | None = None
        self.uploading = False
        self.assigned_storers: list[Dict[str, Any]] = []
        self.storer_info: StringVar | None = None
        self.creator_var = StringVar()
        self.creator_cb: ttk.Combobox | None = None
        self.post_send_btn: ttk.Button | None = None
        self._post_plan: Optional[Dict[str, Any]] = None
        self._active_storer: Optional[Dict[str, Any]] = None
        self.catalog_posts: list[Dict[str, Any]] = []
        self._catalog_map: dict[str, Dict[str, Any]] = {}
        self._selected_art: Optional[Dict[str, Any]] = None
        self.catalog_tree: ttk.Treeview | None = None
        self.comment_tree: ttk.Treeview | None = None
        self.comment_text: tk.Text | None = None
        self.comment_wallet_var = StringVar()
        self.comment_wallet_cb: ttk.Combobox | None = None
        self.comment_amount_var = StringVar()
        self.comment_tip_var = StringVar(value="0")
        self.comment_status_var = StringVar(value="Select artwork to comment.")
        self.catalog_status_var = StringVar(value="Catalog belum dimuat.")
        self.art_info_var = StringVar(value="Pilih karya untuk melihat detail.")
        self.comment_split_var = StringVar(value="")
        self.comment_send_btn: ttk.Button | None = None
        self._comment_plan: Optional[Dict[str, Any]] = None
        self.payout_tree: ttk.Treeview | None = None
        self.payout_status_var = StringVar(value="Payout history pending.")

        self._build_style()
        self.configure(style="Tsar.TFrame")
        self._build_ui()
        self.refresh_storers()
        self._refresh_creator_wallets()

    def _build_style(self):
        t = self.theme
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Tsar.TFrame", background=t.bg)
        style.configure("Tsar.Card.TFrame", background=t.card_bg)
        style.configure("Tsar.TLabelframe", background=t.card_bg, foreground=t.fg)
        style.configure("Tsar.TLabelframe.Label", background=t.card_bg, foreground=t.fg, font=("Consolas", 11, "bold"))
        style.configure("Tsar.Header.TLabel", background=t.bg, foreground=t.accent, font=("Consolas", 14, "bold"))
        style.configure("Tsar.Card.TLabel", background=t.card_bg, foreground=t.fg)
        style.configure("Tsar.Mono.TLabel", background=t.bg, foreground=t.muted, font=("Consolas", 10))
        style.configure("Tsar.Card.Mono.TLabel", background=t.card_bg, foreground=t.muted, font=("Consolas", 10))
        style.configure("Tsar.TButton", padding=8, background=t.accent, foreground="#ffffff")
        style.map(
            "Tsar.TButton",
            background=[("active", lighten(t.accent, 0.12)), ("disabled", t.border)],
            foreground=[("disabled", t.muted)],
        )
        style.configure("Tsar.Secondary.TButton", padding=8, background=t.card_bg, foreground=t.fg)
        style.map("Tsar.Secondary.TButton", background=[("active", lighten(t.card_bg, 0.08))])
        style.configure("Tsar.TEntry", fieldbackground=t.card_bg, foreground=t.fg, background=t.card_bg)
        style.configure("Tsar.TCombobox", fieldbackground=t.card_bg, foreground=t.fg, background=t.card_bg)
        # Progressbar styles require explicit horizontal/vertical layouts.
        try:
            h_layout = style.layout("Horizontal.TProgressbar")
            v_layout = style.layout("Vertical.TProgressbar")
        except Exception:
            h_layout = v_layout = ()
        style.layout("Horizontal.Tsar.TProgressbar", h_layout)
        style.layout("Vertical.Tsar.TProgressbar", v_layout)
        style.configure("Horizontal.Tsar.TProgressbar", troughcolor=t.card_bg, background=t.accent)
        style.configure("Vertical.Tsar.TProgressbar", troughcolor=t.card_bg, background=t.accent)
        self._style = style

    # ---- layout utama ----
    def _build_ui(self):
        root = ttk.Frame(self, padding=12, style="Tsar.TFrame")
        root.pack(fill="both", expand=True)

        # Header
        ttk.Label(root, text="Graffiti Uploader (MVP)", style="Tsar.Header.TLabel").pack(anchor="w")

        # Storage nodes (auto assigned)
        stor_fr = ttk.LabelFrame(root, text="Storage Nodes (auto)", style="Tsar.TLabelframe")
        stor_fr.pack(fill="x", pady=(8, 6))
        self.storer_info_var = StringVar(value="Scanning storage nodes...")
        ttk.Label(stor_fr, textvariable=self.storer_info_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        ttk.Button(stor_fr, text="Refresh nodes", style="Tsar.Secondary.TButton", command=self.refresh_storers)\
            .grid(row=0, column=1, padx=6, pady=(8, 2), sticky="e")

        # Creator wallet
        creator_fr = ttk.LabelFrame(root, text="Creator Wallet", style="Tsar.TLabelframe")
        creator_fr.pack(fill="x", pady=(6, 6))
        ttk.Label(creator_fr, text="Use this address to pay the POST fee:", style="Tsar.Card.Mono.TLabel")\
            .grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        self.creator_cb = ttk.Combobox(
            creator_fr,
            textvariable=self.creator_var,
            state="readonly",
            width=50,
            style="Tsar.TCombobox",
        )
        self.creator_cb.grid(row=0, column=1, padx=6, pady=(8, 2), sticky="w")
        ttk.Button(creator_fr, text="Refresh wallets", style="Tsar.Secondary.TButton", command=self._refresh_creator_wallets)\
            .grid(row=0, column=2, padx=6, pady=(8, 2), sticky="e")

        # File
        file_fr = ttk.LabelFrame(root, text="File", style="Tsar.TLabelframe")
        file_fr.pack(fill="x", pady=(6, 6))
        self.file_var = StringVar(value="(no file)")
        ttk.Label(file_fr, textvariable=self.file_var, style="Tsar.Card.Mono.TLabel").grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        ttk.Button(file_fr, text="Choose File...", style="Tsar.TButton", command=self.pick_file)\
            .grid(row=0, column=1, padx=8, pady=(8, 2), sticky="e")

        self.meta_var = StringVar(value="size: -, mime: -, sha256: -")
        ttk.Label(file_fr, textvariable=self.meta_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=1, column=0, columnspan=2, padx=8, pady=(0, 8), sticky="w")

        # Upload
        up_fr = ttk.LabelFrame(root, text="Upload → Receipt", style="Tsar.TLabelframe")
        up_fr.pack(fill="x", pady=(6, 6))
        ttk.Label(up_fr, text="Protocol computes upload fee based on file size (100KB chunks).", style="Tsar.Card.Mono.TLabel")\
            .grid(row=0, column=0, columnspan=2, padx=8, pady=(8, 2), sticky="w")

        self.upload_btn = ttk.Button(up_fr, text="Upload to storage", style="Tsar.TButton", command=self._start_upload)
        self.upload_btn.grid(row=0, column=2, padx=8, pady=(8, 2), sticky="e")

        self.pbar = ttk.Progressbar(
            up_fr,
            mode="determinate",
            length=240,
            style="Horizontal.Tsar.TProgressbar",
            maximum=100,
            value=0,
        )
        self.pbar.grid(row=1, column=0, columnspan=3, padx=8, pady=(4, 8), sticky="we")

        self.receipt_var = StringVar(value="receipt: -")
        ttk.Label(up_fr, textvariable=self.receipt_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=2, column=0, columnspan=3, padx=8, pady=(0, 8), sticky="w")

        # Post info / next steps
        post_fr = ttk.LabelFrame(root, text="Step 2 — Broadcast POST transaction", style="Tsar.TLabelframe")
        post_fr.pack(fill="x", pady=(6, 6))
        self.post_info_var = StringVar(value="Upload first to generate metadata & fee details.")
        ttk.Label(post_fr, textvariable=self.post_info_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=0, column=0, columnspan=2, padx=8, pady=(8, 4), sticky="w")
        self.post_send_btn = ttk.Button(
            post_fr,
            text="Broadcast POST now",
            style="Tsar.TButton",
            state="disabled",
            command=self._broadcast_post_tx,
        )
        self.post_send_btn.grid(row=1, column=0, padx=8, pady=(4, 8), sticky="w")
        ttk.Label(post_fr, text="Send tab is also prefilled if you prefer manual review.", style="Tsar.Card.Mono.TLabel")\
            .grid(row=1, column=1, padx=8, pady=(4, 8), sticky="e")
        ttk.Label(root, text="After upload completes, Send tab is prefilled automatically for review.", style="Tsar.Mono.TLabel").pack(anchor="w", pady=(4,0))

        # Explore & Comment
        explore_fr = ttk.LabelFrame(root, text="Explore & Comment", style="Tsar.TLabelframe")
        explore_fr.pack(fill="both", expand=True, pady=(6, 0))

        left = ttk.Frame(explore_fr, style="Tsar.Card.TFrame")
        left.pack(side=tk.LEFT, fill="both", expand=True, padx=(0, 8))
        left_top = ttk.Frame(left, style="Tsar.Card.TFrame")
        left_top.pack(fill="x")
        ttk.Button(left_top, text="Refresh Catalog", style="Tsar.TButton", command=self._refresh_catalog).pack(side=tk.LEFT, padx=4, pady=4)
        ttk.Label(left_top, textvariable=self.catalog_status_var, style="Tsar.Card.Mono.TLabel").pack(side=tk.LEFT, padx=4)
        tree_holder = ttk.Frame(left, style="Tsar.Card.TFrame")
        tree_holder.pack(fill="both", expand=True, padx=4, pady=4)
        cols = ("art_id", "creator", "height", "size")
        self.catalog_tree = ttk.Treeview(tree_holder, columns=cols, show="headings", height=6)
        for c, w in [("art_id", 160), ("creator", 120), ("height", 70), ("size", 80)]:
            self.catalog_tree.heading(c, text=c)
            self.catalog_tree.column(c, width=w, stretch=(c == "art_id"))
        catalog_scroll = ttk.Scrollbar(tree_holder, orient=tk.VERTICAL, command=self.catalog_tree.yview)
        self.catalog_tree.configure(yscrollcommand=catalog_scroll.set)
        self.catalog_tree.pack(side=tk.LEFT, fill="both", expand=True)
        catalog_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.catalog_tree.bind("<<TreeviewSelect>>", lambda _e: self._on_catalog_select())

        right = ttk.Frame(explore_fr, style="Tsar.Card.TFrame")
        right.pack(side=tk.LEFT, fill="both", expand=True)
        
        art_info_frame = ttk.Frame(right, style="Tsar.Card.TFrame")
        art_info_frame.pack(fill="x", padx=4, pady=(4, 2))
        art_info_box = tk.Text(art_info_frame, height=4, wrap="word", borderwidth=0, background=self.theme.card_bg,
                               foreground=self.theme.fg, font=("Consolas", 10))
        art_info_box.pack(fill="x")
        art_info_box.configure(state="disabled")
        self.art_info_box = art_info_box

        pane = ttk.Panedwindow(right, orient=tk.VERTICAL)
        pane.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        notebook_holder = ttk.Frame(pane, style="Tsar.Card.TFrame")
        pane.add(notebook_holder, weight=3)
        notebook = ttk.Notebook(notebook_holder)
        notebook.pack(fill="both", expand=True)

        comments_tab = ttk.Frame(notebook)
        notebook.add(comments_tab, text="Comments")
        cols_c = ("time", "from", "amt", "excerpt")
        comment_wrap = ttk.Frame(comments_tab)
        comment_wrap.pack(fill="both", expand=True, padx=4, pady=4)
        self.comment_tree = ttk.Treeview(comment_wrap, columns=cols_c, show="headings", height=4)
        for c, w in [("time", 110), ("from", 130), ("amt", 80), ("excerpt", 220)]:
            self.comment_tree.heading(c, text=c)
            self.comment_tree.column(c, width=w, stretch=(c == "excerpt"))
        comment_scroll = ttk.Scrollbar(comment_wrap, orient=tk.VERTICAL, command=self.comment_tree.yview)
        self.comment_tree.configure(yscrollcommand=comment_scroll.set)
        self.comment_tree.pack(side=tk.LEFT, fill="both", expand=True)
        comment_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(comments_tab, text="Refresh", style="Tsar.Secondary.TButton",
                   command=self._refresh_current_comments).pack(anchor="e", padx=6, pady=(0, 4))

        payouts_tab = ttk.Frame(notebook)
        notebook.add(payouts_tab, text="Payouts")
        cols_p = ("height", "amount", "recipient", "txid")
        payout_wrap = ttk.Frame(payouts_tab)
        payout_wrap.pack(fill="both", expand=True, padx=4, pady=4)
        self.payout_tree = ttk.Treeview(payout_wrap, columns=cols_p, show="headings", height=3)
        for c, w in [("height", 70), ("amount", 110), ("recipient", 140), ("txid", 220)]:
            self.payout_tree.heading(c, text=c)
            self.payout_tree.column(c, width=w, stretch=(c == "txid"))
        payout_scroll = ttk.Scrollbar(payout_wrap, orient=tk.VERTICAL, command=self.payout_tree.yview)
        self.payout_tree.configure(yscrollcommand=payout_scroll.set)
        self.payout_tree.pack(side=tk.LEFT, fill="both", expand=True)
        payout_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(payouts_tab, text="Refresh", style="Tsar.Secondary.TButton",
                   command=lambda: self._refresh_payouts_for((self._selected_art or {}).get("art_id"))).pack(anchor="e", padx=6, pady=(0, 2))
        ttk.Label(payouts_tab, textvariable=self.payout_status_var, style="Tsar.Card.Mono.TLabel").pack(anchor="w", padx=6, pady=(0, 4))

        form_holder = ttk.Frame(pane, style="Tsar.Card.TFrame")
        pane.add(form_holder, weight=1)
        form = ttk.LabelFrame(form_holder, text="Write Comment", style="Tsar.TLabelframe")
        form.pack(fill="both", expand=True, padx=4, pady=4)
        row1 = ttk.Frame(form, style="Tsar.Card.TFrame"); row1.pack(fill="x", padx=6, pady=(4, 2))
        ttk.Label(row1, text="Commenter Wallet:", style="Tsar.Card.TLabel").pack(side=tk.LEFT)
        
        self.comment_wallet_cb = ttk.Combobox(row1, textvariable=self.comment_wallet_var, state="readonly", width=36, style="Tsar.TCombobox")
        self.comment_wallet_cb.pack(side=tk.LEFT, padx=6, fill="x", expand=True)
        row2 = ttk.Frame(form, style="Tsar.Card.TFrame"); row2.pack(fill="x", padx=6, pady=(2, 2))
        ttk.Label(row2, text="Base Amount (TSAR):", width=18, style="Tsar.Card.TLabel").pack(side=tk.LEFT)
        
        amt_entry = ttk.Entry(row2, textvariable=self.comment_amount_var, width=14, style="Tsar.TEntry")
        amt_entry.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(row2, text="Tip (TSAR):", style="Tsar.Card.TLabel").pack(side=tk.LEFT)
        
        tip_entry = ttk.Entry(row2, textvariable=self.comment_tip_var, width=10, style="Tsar.TEntry")
        tip_entry.pack(side=tk.LEFT)
        self.comment_split_var.set("")
        ttk.Label(form, textvariable=self.comment_split_var, style="Tsar.Card.Mono.TLabel").pack(anchor="w", padx=6, pady=(0, 2))
        self.comment_text = tk.Text(form, height=3, wrap="word")
        self.comment_text.pack(fill="x", padx=6, pady=(2, 2))
        btn_row = ttk.Frame(form, style="Tsar.Card.TFrame"); btn_row.pack(fill="x", padx=6, pady=(2, 4))
        
        self.comment_send_btn = ttk.Button(btn_row, text="Comment", style="Tsar.TButton",
                                           state="disabled", command=self._broadcast_comment_tx)
        self.comment_send_btn.pack(side=tk.LEFT)
        
        ttk.Label(form, textvariable=self.comment_status_var, style="Tsar.Card.Mono.TLabel").pack(anchor="w", padx=6, pady=(2, 0))

        self.comment_amount_var.set(self._format_tsar(CFG.GRAFFITI_COMMENT_MIN_FEE))
        self.comment_amount_var.trace_add("write", lambda *_: self._update_comment_split_preview())
        self.comment_tip_var.trace_add("write", lambda *_: self._update_comment_split_preview())
        self._update_comment_split_preview()
        self._refresh_catalog()

    def apply_theme(self, theme: GraffitiTheme) -> None:
        self.theme = theme
        self._build_style()
        self.configure(style="Tsar.TFrame")
        for child in list(self.winfo_children()):
            try:
                child.destroy()
            except Exception:
                pass
        self._build_ui()
        self.refresh_storers()
        self._refresh_creator_wallets()

    # ---- actions ----
    def refresh_storers(self):
        if not self.storer_info_var:
            return
        rpc = getattr(self.app, "rpc", None)
        if not rpc:
            self.storer_info_var.set("Wallet offline - cannot fetch nodes.")
            return

        self.storer_info_var.set("Refreshing storage nodes...")

        def handle(resp: Optional[Dict[str, Any]]):
            storers = (resp or {}).get("storers") or []
            usable = []
            for meta in storers:
                try:
                    port = int(meta.get("port") or 0)
                except Exception:
                    port = 0
                if port <= 0:
                    continue
                usable.append(meta)
            usable.sort(key=lambda m: int(m.get("trusted") or 0) * 1_000_000 + int(m.get("last_seen", 0)), reverse=True)
            limit = max(1, int(CFG.GRAFFITI_REPLICATION_R))
            assigned = usable[:limit]
            self.assigned_storers = assigned
            if not assigned:
                self.storer_info_var.set("No storage nodes available. Ensure Archivist nodes are online.")
                return
            desc = []
            for meta in assigned:
                addr = str(meta.get("addr") or "")[:10]
                flag = "[trusted] " if meta.get("trusted") else ""
                desc.append(f"{flag}{addr}...@{meta.get('ip')}:{meta.get('port')}")
            self.storer_info_var.set(f"Using {len(assigned)} node(s): " + "; ".join(desc))

        rpc.send_async({"type": "STOR_LIST"}, handle)

    def _refresh_creator_wallets(self):
        if not self.creator_cb:
            return
        wallets = list(getattr(self.app, "wallets", []) or [])
        self.creator_cb["values"] = wallets
        if wallets:
            current = self.creator_var.get()
            if current and current in wallets:
                self.creator_cb.set(current)
            else:
                self.creator_cb.current(0)
                self.creator_var.set(wallets[0])
        else:
            self.creator_cb.set("")
            self.creator_var.set("")
        if self.comment_wallet_cb:
            self.comment_wallet_cb["values"] = wallets
            if wallets:
                current = self.comment_wallet_var.get()
                if current and current in wallets:
                    self.comment_wallet_cb.set(current)
                else:
                    self.comment_wallet_cb.current(0)
                    self.comment_wallet_var.set(wallets[0])
            else:
                self.comment_wallet_cb.set("")
                self.comment_wallet_var.set("")

    def pick_file(self):
        path = filedialog.askopenfilename(title="Select file for Graffiti")
        if not path:
            return
        self.selected_path = path
        self.file_var.set(path)

        # compute
        try:
            size = os.path.getsize(path)
            mime = detect_mime(path)
            sha = sha256_file(path)
        except Exception as e:
            messagebox.showerror("Graffiti", f"Failed to read file: {e}")
            return

        self.selected_size = size
        self.selected_mime = mime
        self.selected_sha = sha
        self.meta_var.set(f"size: {size} bytes, mime: {mime}, sha256: {sha[:16]}...")
        self.receipt_id = None
        self.receipt_var.set("receipt: -")
        self.opret_hex = None
        if self.post_info_var:
            self.post_info_var.set("Upload first to generate metadata & fee details.")

    def _start_upload(self):
        if self.uploading:
            return
        if not self.selected_path or not self.selected_sha or self.selected_size is None or not self.selected_mime:
            messagebox.showwarning("Graffiti", "Select a file first.")
            return
        if not self.assigned_storers:
            messagebox.showwarning("Graffiti", "No storage node selected. Refresh nodes first.")
            return
        storer = self.assigned_storers[0]
        creator_addr = (self.creator_var.get() or "").strip()
        if not creator_addr:
            messagebox.showwarning("Graffiti", "Select a creator wallet first.")
            return
        try:
            art_id = compute_art_id(self.selected_sha, creator_addr)
        except Exception as exc:
            messagebox.showerror("Graffiti", f"Failed to compute art_id: {exc}")
            return

        self.uploading = True
        self.upload_btn["state"] = "disabled"
        self._post_plan = None
        if self.post_send_btn:
            self.post_send_btn.config(state="disabled")
        self.opret_hex = None
        self.receipt_id = None
        self.pbar["value"] = 0
        self.receipt_var.set("Uploading to storage...")
        if self.post_info_var:
            self.post_info_var.set("Uploading to storage node...")

        path = self.selected_path
        sha = self.selected_sha
        gid = f"{sha}_{int(time.time())}"
        self._active_storer = storer

        def progress(sent: int, total: int):
            self.after(0, lambda: self._update_progress(sent, total))

        def work():
            try:
                res = upload_graffiti(
                    storer_meta=storer,
                    file_path=path,
                    graffiti_id=gid,
                    sha256_hex=sha,
                    art_id=art_id,
                    progress_cb=progress,
                )
            except Exception as exc:
                res = {"status": "error", "reason": str(exc)}
            self.after(0, lambda: self._handle_upload_result(res))

        threading.Thread(target=work, daemon=True).start()

    def _update_progress(self, sent: int, total: int) -> None:
        total = max(total, 1)
        pct = min(100.0, (sent / total) * 100.0)
        self.pbar["value"] = pct
        self.receipt_var.set(f"Uploading: {sent:,}/{total:,} bytes")

    def _handle_upload_result(self, res: Optional[Dict[str, Any]]) -> None:
        self.uploading = False
        self.upload_btn["state"] = "normal"
        if not isinstance(res, dict) or res.get("status") != "ok":
            self.pbar["value"] = 0
            detail = (res or {}).get("reason") or (res or {}).get("error") or (res or {}).get("stage") or "upload_failed"
            extra = (res or {}).get("resp") or {}
            if isinstance(extra, dict) and extra.get("reason"):
                detail = f"{detail} ({extra.get('reason')})"
            messagebox.showerror("Graffiti", f"Upload failed: {detail}")
            self.receipt_var.set("receipt: -")
            return

        receipt = res.get("receipt") or {}
        fallback_sha = (self.selected_sha or "")[:12]
        rcpt_id = receipt.get("id") or receipt.get("receipt_id") or f"rcpt-{fallback_sha or int(time.time())}"
        self.receipt_id = rcpt_id
        self.receipt_var.set(f"receipt: {rcpt_id}")
        self.pbar["value"] = 100
        try:
            self._prepare_post_tx(res)
        except Exception as exc:
            messagebox.showerror("Graffiti", f"Prepare POST failed: {exc}")

    def _prepare_post_tx(self, upload_result: Dict[str, Any]) -> None:
        if not (self.selected_sha and self.selected_size is not None and self.selected_mime and self.receipt_id):
            raise RuntimeError("upload metadata incomplete")
        storer_meta = upload_result.get("storer") or {}
        storer_addr = str(storer_meta.get("addr") or storer_meta.get("address") or "").strip().lower()
        creator = (self.creator_var.get() or "").strip().lower()
        if not creator:
            raise RuntimeError("creator wallet belum dipilih")
        meta = build_metadata(
            sha256_hex=self.selected_sha,
            size_bytes=int(self.selected_size),
            mime=self.selected_mime,
            storer_addr=storer_addr or "unknown",
            receipt_id=self.receipt_id,
            creator_addr=creator,
        )
        opret_hex = build_opret_hex(meta)
        self.opret_hex = opret_hex

        art_id = compute_art_id(self.selected_sha, creator)
        pool_addr = derive_pool_address(art_id)
        fee_sats = calc_upload_fee_sats(int(self.selected_size))
        tsar_fee = fee_sats / CFG.TSAR
        self._post_plan = {
            "pool_addr": pool_addr,
            "fee_sats": fee_sats,
            "opret_hex": opret_hex,
            "art_id": art_id,
        }
        info = f"Pool: {pool_addr} | Fee: {tsar_fee:.8f} TSAR ({fee_sats} sats)."
        if self.post_info_var:
            self.post_info_var.set(info + " Ready to broadcast.")
        if self.post_send_btn:
            self.post_send_btn.config(state="normal")

        try:
            self.app.send_tab.set_recipient(pool_addr)
            self.app.send_tab.set_amount(str(fee_sats))
            self.app.send_tab.set_opret_hex(opret_hex)
        except Exception as exc:
            raise RuntimeError(f"prefill send tab failed: {exc}") from exc

    def _broadcast_post_tx(self) -> None:
        plan = self._post_plan
        if not plan:
            messagebox.showwarning("Graffiti", "Upload terlebih dahulu sebelum broadcast.")
            return
        creator = (self.creator_var.get() or "").strip().lower()
        if not creator:
            messagebox.showwarning("Graffiti", "Pilih wallet creator terlebih dahulu.")
            return
        svc = getattr(self.app, "send_svc", None)
        rpc_send = getattr(self.app, "rpc_send", None)
        if not rpc_send:
            rpc = getattr(self.app, "rpc", None)
            rpc_send = getattr(rpc, "send_async", None)
        if not svc or not rpc_send:
            messagebox.showerror("Graffiti", "Send service tidak tersedia.")
            return
        self.post_info_var.set("Broadcasting POST transaction...")
        if self.post_send_btn:
            self.post_send_btn.config(state="disabled")

        def on_progress(msg: str) -> None:
            try:
                self.post_info_var.set(msg)
            except Exception:
                pass

        def on_done(resp: Optional[Dict[str, Any]]) -> None:
            def _update():
                if isinstance(resp, dict) and resp.get("status") in (None, "ok"):
                    txid = resp.get("txid") or resp.get("data", {}).get("txid") or "?"
                    self.post_info_var.set(f"POST broadcasted (txid: {txid})")
                    self._post_plan = None
                else:
                    self.post_info_var.set(f"POST failed: {resp}")
                    if self.post_send_btn:
                        self.post_send_btn.config(state="normal")
            self.after(0, _update)

        try:
            fee_rate = None
            try:
                fee_rate = int(getattr(self.app.send_tab, "fee_rate_var", None).get())
            except Exception:
                fee_rate = None
            ask_pwd = getattr(self.app, "_ask_password", None)
            if ask_pwd:
                pw_provider = lambda addr: ask_pwd("Unlock Address", f"Enter password for {addr}:")
            else:
                pw_provider = lambda _addr: None
            svc.create_sign_broadcast(
                from_addr=creator,
                to_addr=plan["pool_addr"],
                amount_sats=plan["fee_sats"],
                password_provider=pw_provider,
                rpc_send=rpc_send,
                fee_rate=fee_rate,
                on_progress=on_progress,
                on_done=on_done,
                opret_hex=plan["opret_hex"],
            )
        except Exception as exc:
            messagebox.showerror("Graffiti", f"Broadcast gagal: {exc}")
            if self.post_send_btn:
                self.post_send_btn.config(state="normal")

    def _refresh_catalog(self) -> None:
        rpc = getattr(self.app, "rpc", None)
        if not rpc:
            self.catalog_status_var.set("Wallet offline.")
            return
        self.catalog_status_var.set("Memuat catalog...")
        def handle(resp: Optional[Dict[str, Any]]):
            self.after(0, lambda: self._apply_catalog(resp))
        try:
            rpc.send_async({"type": "GRAFFITI_GET_POSTS", "limit": 200}, handle)
        except Exception:
            self.catalog_status_var.set("RPC error")

    def _apply_catalog(self, resp: Optional[Dict[str, Any]]) -> None:
        try:
            posts = (resp or {}).get("posts") or []
        except Exception:
            posts = []
        self.catalog_posts = list(posts)
        self._catalog_map = {}
        if self.catalog_tree:
            self.catalog_tree.delete(*self.catalog_tree.get_children())
            for post in posts:
                art_id = str(post.get("art_id") or "")
                if not art_id:
                    continue
                self._catalog_map[art_id] = post
                creator = (post.get("creator") or "")[:18]
                size = int(post.get("size", post.get("size_bytes", 0)) or 0)
                sz_str = f"{size:,} B"
                self.catalog_tree.insert("", tk.END, iid=art_id, values=(
                    art_id[:16] + "..." if len(art_id) > 19 else art_id,
                    creator or "-",
                    int(post.get("block_height") or 0),
                    sz_str,
                ))
            children = self.catalog_tree.get_children()
            if children:
                self.catalog_tree.selection_set(children[0])
                self.catalog_tree.focus(children[0])
                self._on_catalog_select()
        self.catalog_status_var.set(f"{len(self.catalog_posts)} karya")

    def _on_catalog_select(self) -> None:
        if not self.catalog_tree:
            return
        sel = self.catalog_tree.selection()
        if not sel:
            return
        try:
            iid = sel[0]
        except IndexError:
            return
        art_obj = self._catalog_map.get(iid)
        if art_obj:
            self._set_selected_art(art_obj)

    def _set_selected_art(self, art: Dict[str, Any]) -> None:
        self._selected_art = art
        art_id = str(art.get("art_id") or "")
        creator = str(art.get("creator") or "")
        sha = str(art.get("sha256") or "")[:16]
        pool = str(art.get("pool_address") or derive_pool_address(art_id))
        size = int(art.get("size") or art.get("size_bytes") or 0)
        block_h = int(art.get("block_height") or 0)
        stats = art.get("stats") or {}
        pool_balance = stats.get("pool_balance", 0)
        info = "\n".join([
            f"Art ID: {art_id}",
            f"Creator: {creator or '-'}",
            f"Block Height: {block_h}",
            f"Size: {size:,} bytes | sha256: {sha}...",
            f"Pool Address: {pool}",
            f"Pool Balance: {self._format_tsar(pool_balance)} TSAR | Comments: {stats.get('comments',0)}",
            f"Creator paid: {self._format_tsar(stats.get('creator_paid',0))} TSAR | Storage paid: {self._format_tsar(stats.get('storage_paid',0))} TSAR",
        ])
        if getattr(self, "art_info_box", None):
            self.art_info_box.configure(state="normal")
            self.art_info_box.delete("1.0", tk.END)
            self.art_info_box.insert("1.0", info)
            self.art_info_box.configure(state="disabled")
        if self.comment_send_btn:
            self.comment_send_btn.config(state="normal")
        self.comment_status_var.set("Ready to comment.")
        self._update_comment_split_preview()
        self._refresh_comments_for(art_id)
        self._refresh_payouts_for(art_id)

    def _refresh_current_comments(self) -> None:
        if self._selected_art:
            self._refresh_comments_for(self._selected_art.get("art_id"))

    def _refresh_comments_for(self, art_id: Optional[str]) -> None:
        if not art_id:
            return
        rpc = getattr(self.app, "rpc", None)
        if not rpc:
            return
        def handle(resp: Optional[Dict[str, Any]]):
            self.after(0, lambda: self._apply_comments(resp))
        try:
            rpc.send_async({"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id, "limit": 100}, handle)
        except Exception:
            pass

    def _apply_comments(self, resp: Optional[Dict[str, Any]]) -> None:
        if not self.comment_tree:
            return
        comments = []
        try:
            comments = (resp or {}).get("comments") or []
        except Exception:
            comments = []
        self.comment_tree.delete(*self.comment_tree.get_children())
        for entry in comments:
            ts = self._format_ts(entry.get("ts"))
            commenter = (entry.get("commenter") or entry.get("creator") or "")[:20]
            amt_tsar = self._format_tsar(entry.get("amount", 0))
            excerpt = self._decode_comment_hex(entry.get("comment"))
            self.comment_tree.insert("", tk.END, values=(ts, commenter, f"{amt_tsar} TSAR", excerpt))
        if not comments:
            self.comment_status_var.set("Belum ada komentar untuk karya ini.")

    def _decode_comment_hex(self, comment_hex: Optional[str]) -> str:
        try:
            raw = bytes.fromhex(comment_hex or "")
            text = raw.decode("utf-8", errors="replace")
            return text[:80] + ("..." if len(text) > 80 else "")
        except Exception:
            return "(invalid comment)"

    def _format_ts(self, ts_value: Any) -> str:
        try:
            ts = int(ts_value)
        except Exception:
            return "-"
        if ts <= 0:
            return "-"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

    def _format_tsar(self, sats: Any) -> str:
        try:
            dec = Decimal(int(sats)) / Decimal(CFG.TSAR)
        except Exception:
            return "0"
        
        quant = Decimal("1").scaleb(-CFG.MAX_DECIMALS)
        val = dec.quantize(quant, rounding=ROUND_DOWN)
        txt = format(val, "f").rstrip("0").rstrip(".")
        return txt or "0"

    def _refresh_payouts_for(self, art_id: Optional[str]) -> None:
        if not art_id:
            return
        
        rpc = getattr(self.app, "rpc", None)
        if not rpc:
            return
        
        def handle(resp: Optional[Dict[str, Any]]):
            self.after(0, lambda: self._apply_payouts(resp))
        try:
            rpc.send_async({"type":"GRAFFITI_GET_PAYOUTS","art_id": art_id}, handle)
        except Exception:
            self.payout_status_var.set("RPC payout error")

    def _apply_payouts(self, resp: Optional[Dict[str, Any]]) -> None:
        if not self.payout_tree:
            return
        
        rows = []
        try:
            rows = (resp or {}).get("payouts") or []
        except Exception:
            rows = []
        self.payout_tree.delete(*self.payout_tree.get_children())
        for entry in rows:
            amt = self._format_tsar(entry.get("amount", 0))
            rec = entry.get("recipients") or {}
            recipient = ",".join(rec.keys()) or "-"
            txid = entry.get("txid") or "-"
            self.payout_tree.insert("", tk.END, values=(
                entry.get("block_height") or "-",
                f"{amt} TSAR",
                recipient[:24],
                txid[:32] + ("..." if txid and len(txid) > 32 else "")
            ))
        if rows:
            self.payout_status_var.set(f"{len(rows)} payout record(s) ditemukan.")
        else:
            self.payout_status_var.set("Belum ada payout untuk karya ini.")

    def _parse_amount_str(self, raw: str, default: int) -> int:
        txt = (raw or "").strip()
        if not txt:
            return int(default)
        txt = txt.replace(" ", "").replace(",", ".")
        if txt.startswith("."):
            txt = "0" + txt
        try:
            dec = Decimal(txt)
        except InvalidOperation:
            raise ValueError("Format jumlah tidak valid")
        if dec <= 0:
            raise ValueError("Jumlah harus > 0")
        
        quant = Decimal("1").scaleb(-CFG.MAX_DECIMALS)
        dec_q = dec.quantize(quant, rounding=ROUND_DOWN)
        sats = int(dec_q * Decimal(CFG.TSAR))
        if sats <= 0:
            raise ValueError("Jumlah terlalu kecil")
        
        return sats

    def _update_comment_split_preview(self) -> None:
        try:
            base = self._parse_amount_str(self.comment_amount_var.get(), int(CFG.GRAFFITI_COMMENT_MIN_FEE))
        except Exception as exc:
            self.comment_split_var.set(f"Amount error: {exc}")
            return
        
        try:
            tip = self._parse_amount_str(self.comment_tip_var.get(), 0) if self.comment_tip_var.get().strip() else 0
        except Exception as exc:
            self.comment_split_var.set(f"Tip error: {exc}")
            return
        
        split = calc_comment_split(base, tip)
        creator = self._format_tsar(split["creator_total"])
        storage = self._format_tsar(split["storage"])
        miner = self._format_tsar(split["miner"])
        self.comment_split_var.set(f"Creator: {creator} TSAR | Storage pool: {storage} TSAR | Miner fee: {miner} TSAR")

    def _broadcast_comment_tx(self) -> None:
        art = self._selected_art
        if not art:
            messagebox.showwarning("Graffiti", "Pilih karya terlebih dahulu.")
            return
        
        commenter = (self.comment_wallet_var.get() or "").strip().lower()
        if not commenter:
            messagebox.showwarning("Graffiti", "Pilih wallet untuk komentar.")
            return
        
        comment_txt = self.comment_text.get("1.0", tk.END).strip() if self.comment_text else ""
        if not comment_txt:
            messagebox.showwarning("Graffiti", "Teks komentar belum diisi.")
            return
        try:
            base_sats = self._parse_amount_str(self.comment_amount_var.get(), int(CFG.GRAFFITI_COMMENT_MIN_FEE))
        except Exception as exc:
            messagebox.showerror("Graffiti", f"Jumlah komentar tidak valid: {exc}")
            return
        
        if base_sats < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
            base_sats = int(CFG.GRAFFITI_COMMENT_MIN_FEE)
        try:
            tip_sats = self._parse_amount_str(self.comment_tip_var.get(), 0) if self.comment_tip_var.get().strip() else 0
        except Exception as exc:
            messagebox.showerror("Graffiti", f"Tip tidak valid: {exc}")
            return
        
        creator_addr = str(art.get("creator") or "").strip().lower()
        if not creator_addr:
            messagebox.showwarning("Graffiti", "Creator address tidak tersedia untuk karya ini.")
            return
        
        pool_addr = str(art.get("pool_address") or derive_pool_address(art.get("art_id"))).strip().lower()
        try:
            meta = build_comment_metadata(
                art_id=str(art.get("art_id") or ""),
                comment_text=comment_txt,
                amount_sats=base_sats,
                creator_addr=creator_addr,
                commenter_addr=commenter,
                tip_sats=tip_sats,
            )
        except ValueError as exc:
            messagebox.showerror("Graffiti", f"Metadata komentar invalid: {exc}")
            return
        
        opret_hex = build_opret_hex(meta)
        split = calc_comment_split(base_sats, tip_sats)
        outputs = []
        if split["creator_total"] > 0:
            outputs.append({"address": creator_addr, "amount": split["creator_total"]})
        if split["storage"] > 0:
            outputs.append({"address": pool_addr, "amount": split["storage"]})
        if not outputs:
            messagebox.showerror("Graffiti", "Tidak ada output pembayaran yang valid.")
            return
        
        svc = getattr(self.app, "send_svc", None)
        rpc_send = getattr(self.app, "rpc_send", None)
        if not rpc_send:
            rpc_send = getattr(getattr(self.app, "rpc", None), "send_async", None)
        if not svc or not rpc_send:
            messagebox.showerror("Graffiti", "Send service tidak tersedia.")
            return
        
        fee_rate = None
        try:
            fee_rate = int(getattr(self.app.send_tab, "fee_rate_var", None).get())
        except Exception:
            fee_rate = None
        ask_pwd = getattr(self.app, "_ask_password", None)
        if ask_pwd:
            pw_provider = lambda addr: ask_pwd("Unlock Address", f"Masukkan password untuk {addr}:")
        else:
            pw_provider = lambda _addr: None

        self.comment_status_var.set("Broadcasting COMMENT transaction...")
        if self.comment_send_btn:
            self.comment_send_btn.config(state="disabled")

        def on_progress(msg: str) -> None:
            self.comment_status_var.set(msg)

        def on_done(resp: Optional[Dict[str, Any]]) -> None:
            def finish():
                if isinstance(resp, dict) and resp.get("status") in (None, "ok"):
                    txid = resp.get("txid") or resp.get("data", {}).get("txid") or "?"
                    self.comment_status_var.set(f"COMMENT broadcasted (txid: {txid})")
                    if self.comment_text:
                        self.comment_text.delete("1.0", tk.END)
                    self._refresh_current_comments()
                else:
                    self.comment_status_var.set(f"COMMENT failed: {resp}")
                if self.comment_send_btn:
                    self.comment_send_btn.config(state="normal")
            self.after(0, finish)

        try:
            svc.create_sign_broadcast(
                from_addr=commenter,
                to_addr="",
                amount_sats=0,
                password_provider=pw_provider,
                rpc_send=rpc_send,
                fee_rate=fee_rate,
                on_progress=on_progress,
                on_done=on_done,
                opret_hex=opret_hex,
                extra_outputs=outputs,
            )
        except Exception as exc:
            messagebox.showerror("Graffiti", f"Broadcast COMMENT gagal: {exc}")
            if self.comment_send_btn:
                self.comment_send_btn.config(state="normal")

    def apply_theme(self, theme: GraffitiTheme) -> None:
        """Rebuild the tab using a new theme palette."""
        self.theme = theme
        self._build_style()
        for child in list(self.winfo_children()):
            try:
                child.destroy()
            except Exception:
                pass
        self._build_ui()
        self.refresh_storers()
