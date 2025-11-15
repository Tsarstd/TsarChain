# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations
import os, time, hashlib, mimetypes, threading
from typing import Any, Dict, Optional
from tkinter import ttk, filedialog, messagebox, StringVar
import tkinter as tk

from .graffiti import (
    build_metadata,
    build_opret_hex,
    calc_upload_fee_sats,
    compute_art_id,
    derive_pool_address,
)
from .storage_client import upload_graffiti
from .theme import GraffitiTheme, lighten
from ..utils import config as CFG


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
        meta = build_metadata(
            sha256_hex=self.selected_sha,
            size_bytes=int(self.selected_size),
            mime=self.selected_mime,
            storer_addr=storer_addr or "unknown",
            receipt_id=self.receipt_id,
        )
        opret_hex = build_opret_hex(meta)
        self.opret_hex = opret_hex

        art_id = compute_art_id(self.selected_sha)
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

        if hasattr(self.app, "switch_tab"):
            self.app.switch_tab("send")

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
