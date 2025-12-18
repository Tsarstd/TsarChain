# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations
import time, threading
from decimal import Decimal, ROUND_DOWN
from typing import Any, Dict, Optional
from tkinter import ttk, filedialog, messagebox, StringVar
import tkinter as tk
from PIL import Image, ImageTk

from ...contracts.graffiti import calc_comment_split, calc_upload_fee_sats, derive_pool_address
from ..services.graffiti_service import (
    build_comment_plan,
    build_post_plan,
    build_upload_context,
    filter_online_storers,
    parse_amount_str,
    read_graffiti_file_info,
    select_upload_storers,
    upload_graffiti,
)
from ..services.media import TkVLCPlayer
from ..theme import GraffitiTheme, lighten
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.tab_ui.graffiti_tab")


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
        self._upload_candidates: list[Dict[str, Any]] = []
        self._active_storer: Optional[Dict[str, Any]] = None
        
        self._upload_ctx: dict[str, Any] = {}
        self.creator_var = StringVar()
        self.creator_cb: ttk.Combobox | None = None
        self.cost_info_var = StringVar(value="Pilih file untuk menampilkan biaya & detail.")
        self.preview_status_var = StringVar(value="Belum ada preview.")
        self.preview_frame: tk.Frame | None = None
        self._preview_img_ref = None
        self._video_player: TkVLCPlayer | None = None
        self._catalog_map_local: dict[str, Dict[str, Any]] = {}

        self.post_send_btn: ttk.Button | None = None
        self._post_plan: Optional[Dict[str, Any]] = None
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
        h_layout = style.layout("Horizontal.TProgressbar")
        v_layout = style.layout("Vertical.TProgressbar")
        style.layout("Horizontal.Tsar.TProgressbar", h_layout)
        style.layout("Vertical.Tsar.TProgressbar", v_layout)
        style.configure("Horizontal.Tsar.TProgressbar", troughcolor=t.card_bg, background=t.accent)
        style.configure("Vertical.Tsar.TProgressbar", troughcolor=t.card_bg, background=t.accent)
        self._style = style

    # ---- layout utama ----
    def _build_ui(self):
        root = ttk.Frame(self, padding=12, style="Tsar.TFrame")
        root.pack(fill="both", expand=True)

        header_row = ttk.Frame(root, style="Tsar.TFrame")
        header_row.pack(fill="x")
        ttk.Label(header_row, text="Graffiti Uploader", style="Tsar.Header.TLabel").pack(side=tk.LEFT, anchor="w")
        ttk.Button(header_row, text="View Catalog", style="Tsar.Secondary.TButton", command=self._open_creator_catalog)\
            .pack(side=tk.RIGHT, padx=4)
        ttk.Label(root, text="Alur: pilih wallet -> pilih & preview file -> upload & sign.", style="Tsar.Card.Mono.TLabel")\
            .pack(anchor="w", pady=(2, 8))

        # 1) Creator wallet
        creator_fr = ttk.LabelFrame(root, text="1) Wallet Creator", style="Tsar.TLabelframe")
        creator_fr.pack(fill="x", pady=(4, 6))
        ttk.Label(creator_fr, text="Gunakan alamat ini untuk membayar POST fee:", style="Tsar.Card.Mono.TLabel")\
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

        # 2) File + Preview
        file_fr = ttk.LabelFrame(root, text="2) Media & Preview", style="Tsar.TLabelframe")
        file_fr.pack(fill="both", expand=True, pady=(6, 6))
        file_fr.columnconfigure(0, weight=1)
        file_fr.columnconfigure(1, weight=0)

        self.file_var = StringVar(value="(belum ada file)")
        ttk.Label(file_fr, textvariable=self.file_var, style="Tsar.Card.Mono.TLabel").grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        ttk.Button(file_fr, text="Pilih File...", style="Tsar.TButton", command=self.pick_file)\
            .grid(row=0, column=1, padx=8, pady=(8, 2), sticky="e")

        self.meta_var = StringVar(value="size: -, mime: -, sha256: -")
        ttk.Label(file_fr, textvariable=self.meta_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=1, column=0, columnspan=2, padx=8, pady=(0, 4), sticky="w")
        ttk.Label(file_fr, textvariable=self.cost_info_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=2, column=0, columnspan=2, padx=8, pady=(0, 6), sticky="w")

        preview_shell = ttk.Frame(file_fr, style="Tsar.Card.TFrame")
        preview_shell.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=8, pady=(2, 8))
        preview_shell.rowconfigure(0, weight=1)
        preview_shell.columnconfigure(0, weight=1)
        self.preview_frame = tk.Frame(preview_shell, background=self.theme.card_bg, height=260)
        self.preview_frame.grid(row=0, column=0, sticky="nsew")
        ttk.Label(self.preview_frame, textvariable=self.preview_status_var, style="Tsar.Card.Mono.TLabel")\
            .pack(anchor="center", pady=8)

        # 3) Upload & Broadcast
        post_fr = ttk.LabelFrame(root, text="3) Upload & Broadcast POST", style="Tsar.TLabelframe")
        post_fr.pack(fill="x", pady=(2, 4))
        self.post_info_var = StringVar(value="Pilih file, lalu upload. Password akan diminta saat sign.")
        ttk.Label(post_fr, textvariable=self.post_info_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=0, column=0, columnspan=3, padx=8, pady=(8, 4), sticky="w")
        self.post_send_btn = ttk.Button(
            post_fr,
            text="Upload & Broadcast POST",
            style="Tsar.TButton",
            state="disabled",
            command=self._start_upload_and_broadcast,
        )
        self.post_send_btn.grid(row=1, column=0, padx=8, pady=(4, 8), sticky="w")
        ttk.Label(post_fr, text="Send tab akan di-prefill untuk review manual bila perlu.", style="Tsar.Card.Mono.TLabel")\
            .grid(row=1, column=1, padx=8, pady=(4, 8), sticky="e")
        self.pbar = ttk.Progressbar(
            post_fr,
            mode="determinate",
            length=320,
            style="Horizontal.Tsar.TProgressbar",
            maximum=100,
            value=0,
        )
        self.pbar.grid(row=2, column=0, columnspan=3, padx=8, pady=(0, 6), sticky="we")
        self.receipt_var = StringVar(value="receipt: -")
        ttk.Label(post_fr, textvariable=self.receipt_var, style="Tsar.Card.Mono.TLabel")\
            .grid(row=3, column=0, columnspan=3, padx=8, pady=(0, 8), sticky="w")

    # ---- actions ----
    def refresh_storers(self):
        rpc = getattr(self.app, "rpc", None)
        if not rpc:
            return

        def handle(resp: Optional[Dict[str, Any]]):
            self.assigned_storers = select_upload_storers(resp, replication_r=CFG.GRAFFITI_REPLICATION_R)
        rpc.send_async({"type": "STOR_LIST"}, handle)

    def _fetch_storers_sync(self) -> list[Dict[str, Any]]:
        rpc = getattr(self.app, "rpc", None)
        if not rpc or not hasattr(rpc, "send"):
            return []
        resp = rpc.send({"type": "STOR_LIST"}) or {}
        return select_upload_storers(resp, replication_r=CFG.GRAFFITI_REPLICATION_R)

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

    def _clear_preview(self) -> None:
        """Bersihkan preview media (image/video)."""
        if self._video_player:
            try:
                self._video_player.dispose()
                log.debug("graffiti_tab: video player disposed")
            except Exception:
                log.debug("graffiti_tab: dispose video player failed", exc_info=True)
            self._video_player = None
        self._preview_img_ref = None
        if self.preview_frame and self.preview_frame.winfo_exists():
            for child in list(self.preview_frame.winfo_children()):
                child.destroy()
        if self.preview_status_var:
            self.preview_status_var.set("Belum ada preview.")

    def _render_preview(self) -> None:
        """Render preview for selected file (image/mp4)."""
        if not self.preview_frame or not self.selected_path or not self.selected_mime:
            return
        self._clear_preview()
        path = self.selected_path
        mime = (self.selected_mime or "").lower()
        log.debug("graffiti_tab: render preview path=%s mime=%s", path, mime)

        # Video (mp4)
        if "video" in mime or path.lower().endswith(".mp4"):
            container = tk.Frame(self.preview_frame, bg=self.theme.card_bg)
            container.pack(fill="both", expand=True)
            player = TkVLCPlayer(
                container,
                bg=self.theme.card_bg,
                fg=self.theme.fg,
                accent=self.theme.accent,
                on_error=lambda msg: self.preview_status_var.set(msg),
            )
            player.frame.pack(fill="both", expand=True, pady=6)
            try:
                player.load(path, autoplay=True)
            except Exception:
                tk.Label(
                    container,
                    text="Video preview failed to load.",
                    bg=self.theme.card_bg,
                    fg=self.theme.muted,
                    font=("Consolas", 10),
                ).pack(anchor="center", pady=8)
            self._video_player = player
            return

        # Image
        try:
            img = Image.open(path)
            img.thumbnail((720, 420))
            photo = ImageTk.PhotoImage(img)
            self._preview_img_ref = photo
            tk.Label(self.preview_frame, image=photo, bg=self.theme.card_bg).pack(pady=6)
            self.preview_status_var.set("Preview gambar.")
        except Exception:
            log.debug("graffiti_tab: load image preview failed", exc_info=True)
            tk.Label(
                self.preview_frame,
                text="Preview gambar gagal dimuat.",
                bg=self.theme.card_bg,
                fg=self.theme.muted,
                font=("Consolas", 10),
            ).pack(anchor="center", pady=8)

    def _update_cost_info(self) -> None:
        """Calculate upload cost info based on size."""
        if not self.cost_info_var:
            return
        if not self.selected_size or not self.selected_mime:
            self.cost_info_var.set("Select a file to display costs.")
            return
        fee_sats = calc_upload_fee_sats(int(self.selected_size))
        fee_tsar = fee_sats / CFG.TSAR
        self.cost_info_var.set(f"Est. fee: {fee_tsar:.8f} TSAR")

    def _open_creator_catalog(self) -> None:
        """Open the catalog of works for the current wallet creator."""
        creator = (self.creator_var.get() or "").strip().lower()
        rpc = getattr(self.app, "rpc", None)
        if not creator:
            messagebox.showinfo("Graffiti", "Select the wallet creator first.")
            return
        if not rpc or not hasattr(rpc, "send_async"):
            messagebox.showwarning("Graffiti", "Offline wallet or RPC is not available.")
            return

        log.debug("graffiti_tab: open catalog for creator=%s", creator)
        top = tk.Toplevel(self)
        top.title(f"Catalog - {creator[:64]}")
        top.configure(bg=self.theme.bg)
        cols = ("art_id", "height", "size", "comments")
        tv = ttk.Treeview(top, columns=cols, show="headings", height=12)
        for c, w in [("art_id", 420), ("height", 70), ("size", 120), ("comments", 90)]:
            tv.heading(c, text=c)
            tv.column(c, width=w, stretch=(c == "art_id"))
        tv.pack(fill="both", expand=True, padx=8, pady=8)
        status_var = StringVar(value="Load catalog...")
        ttk.Label(top, textvariable=status_var, style="Tsar.Card.Mono.TLabel").pack(anchor="w", padx=8, pady=(0, 8))
        self._catalog_map_local = {}

        menu = tk.Menu(top, tearoff=0)
        def _show_menu(event):
            iid = tv.identify_row(event.y)
            if not iid:
                return
            tv.selection_set(iid)
            art_obj = self._catalog_map_local.get(iid, {})
            art_id_full = art_obj.get("art_id") or iid
            def _copy():
                top.clipboard_clear()
                top.clipboard_append(art_id_full)
                status_var.set("Art ID copied.")
                log.debug("graffiti_tab: copy art_id=%s", art_id_full)
            def _open():
                log.debug("graffiti_tab: open in explorer art_id=%s", art_id_full)
                app = getattr(self, "app", None)
                try:
                    if app:
                        app.switch_tab("explorer")
                        panel = getattr(app, "explore_panel", None)
                        if panel and hasattr(panel, "navigate_to_art"):
                            panel.navigate_to_art(art_id_full)
                except Exception:
                    log.debug("graffiti_tab: open explorer failed", exc_info=True)
            menu.delete(0, tk.END)
            menu.add_command(label="Copy art id", command=_copy)
            menu.add_command(label="Open in Explorer", command=_open)
            menu.tk_popup(event.x_root, event.y_root)
        tv.bind("<Button-3>", _show_menu)

        def handle(resp: Optional[Dict[str, Any]]):
            def apply():
                posts = (resp or {}).get("posts") or []
                filtered = [p for p in posts if (p.get("creator") or "").strip().lower() == creator]
                tv.delete(*tv.get_children())
                for post in filtered:
                    aid_full = str(post.get("art_id") or "")[:64]
                    height = int(post.get("block_height") or 0)
                    size = int(post.get("size") or post.get("size_bytes") or 0)
                    comments = int((post.get("stats") or {}).get("comments", 0))
                    tv.insert("", tk.END, iid=aid_full, values=(aid_full, height, f"{size:,} B", comments))
                    self._catalog_map_local[aid_full] = post
                status_var.set(f"{len(filtered)} karya ditemukan untuk {creator}.")
                log.debug("graffiti_tab: catalog loaded items=%s creator=%s", len(filtered), creator)
            self.after(0, apply)

        rpc.send_async({"type": "GRAFFITI_GET_POSTS", "limit": 200}, handle)

    def pick_file(self):
        path = filedialog.askopenfilename(title="Select file for Graffiti")
        if not path:
            return
        self.selected_path = path
        self.file_var.set(path)

        # compute
        try:
            info = read_graffiti_file_info(path)
        except Exception as e:
            log.exception("Unhandled exception")
            messagebox.showerror("Graffiti", f"Failed to read file: {e}")
            return

        self.selected_size = info.get("size")
        self.selected_mime = info.get("mime")
        self.selected_sha = info.get("sha")
        self.meta_var.set(
            f"size: {self.selected_size} bytes, file: {self.selected_mime}, sha256: {self.selected_sha[:64]}"
        )
        log.debug(
            "graffiti_tab: file selected path=%s size=%s mime=%s sha=%s",
            path,
            self.selected_size,
            self.selected_mime,
            self.selected_sha,
        )
        self._render_preview()
        self._update_cost_info()
        self.receipt_id = None
        self.receipt_var.set("receipt: -")
        self.opret_hex = None
        if self.post_info_var:
            self.post_info_var.set("The file is ready. Click Upload & Broadcast when ready.")
        if self.post_send_btn:
            self.post_send_btn.config(state="normal")

    def _start_upload_and_broadcast(self):
        if self.uploading:
            return
        if not self.selected_path or not self.selected_sha or self.selected_size is None or not self.selected_mime:
            messagebox.showwarning("Graffiti", "Select a file first.")
            return
        storers = self._fetch_storers_sync()
        online = filter_online_storers(storers)
        if not online:
            messagebox.showerror("Graffiti", "Storage node unavailable. Please try again when a storage node is online.")
            return
        self.assigned_storers = online
        storer = online[0]
        creator_addr = (self.creator_var.get() or "").strip()
        if not creator_addr:
            messagebox.showwarning("Graffiti", "Select a creator wallet first.")
            return
        try:
            upload_ctx = build_upload_context(self.selected_sha, creator_addr)
        except Exception as exc:
            log.exception("Unhandled exception")
            messagebox.showerror("Graffiti", f"Failed to compute art_id: {exc}")
            return

        gid = upload_ctx.get("graffiti_id")
        receipt_id = upload_ctx.get("receipt_id")
        art_id = upload_ctx.get("art_id")
        self._upload_candidates = list(online)
        self._upload_ctx = {"gid": gid, "receipt_id": receipt_id, "art_id": art_id}
        self.uploading = True
        self._post_plan = None
        if self.post_send_btn:
            self.post_send_btn.config(state="disabled")
        self.opret_hex = None
        self.receipt_id = None
        self.pbar["value"] = 0
        self.receipt_var.set("receipt: -")
        if self.post_info_var:
            self.post_info_var.set("Signing POST transaction...")

        try:
            self._prepare_post_plan_preupload(storer, receipt_id, art_id)
        except Exception as exc:
            log.exception("Unhandled exception")
            self.uploading = False
            if self.post_send_btn:
                self.post_send_btn.config(state="normal")
            messagebox.showerror("Graffiti", f"Prepare POST failed: {exc}")
            return

        def after_broadcast(txid: str):
            self.post_info_var.set(f"POST broadcasted (txid: {txid}), uploading blob...")
            self._begin_upload_after_sign(txid)

        self._broadcast_post_tx(auto=True, after_success=after_broadcast)

    def _begin_upload_after_sign(self, txid: str) -> None:
        if not self._upload_candidates:
            self._reset_upload_state(f"Upload failed: no storage node available (txid: {txid})")
            return
        
        storer = self._upload_candidates.pop(0)
        gid = self._upload_ctx.get("gid")
        receipt_id = self._upload_ctx.get("receipt_id")
        art_id = self._upload_ctx.get("art_id")
        path = self.selected_path
        sha = self.selected_sha
        self._active_storer = storer

        def progress(sent: int, total: int):
            self.after(0, lambda: self._update_progress(sent, total))

        def work():
            res = upload_graffiti(
                storer_meta=storer,
                file_path=path,
                graffiti_id=gid,
                sha256_hex=sha,
                art_id=art_id,
                receipt_id=receipt_id,
                progress_cb=progress,
            )
            self.after(0, lambda: self._handle_upload_result(res, trigger_broadcast=False, txid=txid))

        threading.Thread(target=work, daemon=True).start()

    def _update_progress(self, sent: int, total: int) -> None:
        total = max(total, 1)
        pct = min(100.0, (sent / total) * 100.0)
        self.pbar["value"] = pct
        self.receipt_var.set(f"Uploading: {sent:,}/{total:,} bytes")

    def _handle_upload_result(self, res: Optional[Dict[str, Any]], *, trigger_broadcast: bool = True, txid: Optional[str] = None) -> None:
        self.uploading = False
        if self.post_send_btn:
            self.post_send_btn.config(state="disabled" if trigger_broadcast else "normal")
        if not isinstance(res, dict) or res.get("status") != "ok":
            self.pbar["value"] = 0
            detail = (res or {}).get("reason") or (res or {}).get("error") or (res or {}).get("stage") or "upload_failed"
            extra = (res or {}).get("resp") or {}
            if isinstance(extra, dict) and extra.get("reason"):
                detail = f"{detail} ({extra.get('reason')})"
            messagebox.showerror("Graffiti", f"Upload failed: {detail}")
            self.receipt_var.set("receipt: -")
            if self._upload_candidates:
                if self.post_info_var:
                    self.post_info_var.set("Retrying upload on another storage node...")
                self.uploading = True
                self._begin_upload_after_sign(txid or "")
                return
            self._reset_upload_state("Upload failed. No storage node reachable.")
            return

        receipt = res.get("receipt") or {}
        fallback_sha = (self.selected_sha or "")[:12]
        rcpt_id = receipt.get("id") or receipt.get("receipt_id") or f"rcpt-{fallback_sha or int(time.time())}"
        self.receipt_id = rcpt_id
        self.receipt_var.set(f"receipt: {rcpt_id}")
        self.pbar["value"] = 100
        try:
            if trigger_broadcast:
                self._prepare_post_tx(res)
                self._broadcast_post_tx(auto=True)
            else:
                if txid:
                    self.post_info_var.set(f"Upload complete (txid: {txid})")
                else:
                    self.post_info_var.set("Upload complete.")
        except Exception as exc:
            log.exception("Unhandled exception")
            messagebox.showerror("Graffiti", f"Prepare POST failed: {exc}")

    def _prepare_post_plan_preupload(self, storer_meta: Dict[str, Any], receipt_id: str, art_id: str) -> None:
        if not (self.selected_sha and self.selected_size is not None and self.selected_mime):
            raise RuntimeError("upload metadata incomplete")
        creator = (self.creator_var.get() or "").strip().lower()
        plan = build_post_plan(
            sha256_hex=self.selected_sha,
            size_bytes=int(self.selected_size),
            mime=self.selected_mime,
            creator_addr=creator,
            storer_meta=storer_meta,
            receipt_id=receipt_id,
            art_id=art_id,
        )
        self.opret_hex = plan["opret_hex"]
        self._post_plan = plan
        info = f"Pool: {plan['pool_addr']} | Fee: {plan['tsar_fee']:.8f} TSAR ({plan['fee_sats']} sats)."
        if self.post_info_var:
            self.post_info_var.set(info + " Ready to sign.")

    def _prepare_post_tx(self, upload_result: Dict[str, Any]) -> None:
        if not (self.selected_sha and self.selected_size is not None and self.selected_mime and self.receipt_id):
            raise RuntimeError("upload metadata incomplete")
        storer_meta = upload_result.get("storer") or {}
        creator = (self.creator_var.get() or "").strip().lower()
        plan = build_post_plan(
            sha256_hex=self.selected_sha,
            size_bytes=int(self.selected_size),
            mime=self.selected_mime,
            creator_addr=creator,
            storer_meta=storer_meta,
            receipt_id=self.receipt_id,
        )
        self.opret_hex = plan["opret_hex"]
        self._post_plan = plan
        info = f"Pool: {plan['pool_addr']} | Fee: {plan['tsar_fee']:.8f} TSAR ({plan['fee_sats']} sats)."
        if self.post_info_var:
            self.post_info_var.set(info + " Ready to broadcast.")

        try:
            self.app.send_tab.set_recipient(plan["pool_addr"])
            self.app.send_tab.set_amount(str(plan["fee_sats"]))
            self.app.send_tab.set_opret_hex(plan["opret_hex"])
        except Exception as exc:
            log.exception("Unhandled exception")
            raise RuntimeError(f"prefill send tab failed: {exc}") from exc

    def _broadcast_post_tx(self, auto: bool = False, after_success=None) -> None:
        plan = self._post_plan
        if not plan:
            if not auto:
                messagebox.showwarning("Graffiti", "Upload first before broadcast.")
            return
        creator = (self.creator_var.get() or "").strip().lower()
        if not creator:
            messagebox.showwarning("Graffiti", "Select the wallet creator first.")
            return
        svc = getattr(self.app, "send_svc", None)
        rpc_send = getattr(self.app, "rpc_send", None)
        if not rpc_send:
            rpc = getattr(self.app, "rpc", None)
            rpc_send = getattr(rpc, "send_async", None)
        if not svc or not rpc_send:
            messagebox.showerror("Graffiti", "Send service is not available.")
            return
        self.post_info_var.set("Broadcasting POST transaction...")
        if self.post_send_btn:
            self.post_send_btn.config(state="disabled")

        def on_progress(msg: str) -> None:
            self.post_info_var.set(msg)

        def on_done(resp: Optional[Dict[str, Any]]) -> None:
            def _update():
                if isinstance(resp, dict) and resp.get("status") in (None, "ok"):
                    txid = resp.get("txid") or resp.get("data", {}).get("txid") or "?"
                    self.post_info_var.set(f"POST broadcasted (txid: {txid})")
                    self._post_plan = None
                    if after_success:
                        after_success(txid)
                else:
                    self.post_info_var.set(f"POST failed: {resp}")
                    self.uploading = False
                    self._upload_candidates = []
                    if self.post_send_btn:
                        self.post_send_btn.config(state="normal")
            self.after(0, _update)

        try:
            fee_rate = int(getattr(self.app.send_tab, "fee_rate_var", None).get())
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
            log.exception("Unhandled exception")
            messagebox.showerror("Graffiti", f"Broadcast failed: {exc}")
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
        rpc.send_async({"type": "GRAFFITI_GET_POSTS", "limit": 200}, handle)

    def _apply_catalog(self, resp: Optional[Dict[str, Any]]) -> None:
        posts = (resp or {}).get("posts") or []
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
        iid = sel[0]
        art_obj = self._catalog_map.get(iid)
        if art_obj:
            self._set_selected_art(art_obj)

    def _set_selected_art(self, art: Dict[str, Any]) -> None:
        self._selected_art = art
        art_id = str(art.get("art_id") or "")
        creator = str(art.get("creator") or "")
        sha = str(art.get("sha256") or "")[:64]
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
        rpc.send_async({"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id, "limit": 100}, handle)

    def _apply_comments(self, resp: Optional[Dict[str, Any]]) -> None:
        if not self.comment_tree:
            return
        comments = (resp or {}).get("comments") or []
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
        raw = bytes.fromhex(comment_hex or "")
        text = raw.decode("utf-8", errors="replace")
        return text[:80] + ("..." if len(text) > 80 else "")

    def _format_ts(self, ts_value: Any) -> str:
        ts = int(ts_value)
        if ts <= 0:
            return "-"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

    def _format_tsar(self, sats: Any) -> str:
        dec = Decimal(int(sats)) / Decimal(CFG.TSAR)
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
        rpc.send_async({"type":"GRAFFITI_GET_PAYOUTS","art_id": art_id}, handle)

    def _apply_payouts(self, resp: Optional[Dict[str, Any]]) -> None:
        if not self.payout_tree:
            return
        
        rows = (resp or {}).get("payouts") or []
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

    def _update_comment_split_preview(self) -> None:
        base = parse_amount_str(self.comment_amount_var.get(), int(CFG.GRAFFITI_COMMENT_MIN_FEE))
        tip = parse_amount_str(self.comment_tip_var.get(), 0) if self.comment_tip_var.get().strip() else 0
        split = calc_comment_split(base, tip)
        creator = self._format_tsar(split["creator_total"])
        storage = self._format_tsar(split["storage"])
        miner = self._format_tsar(split["miner"])
        self.comment_split_var.set(f"Creator: {creator} TSAR | Storage pool: {storage} TSAR | Miner fee: {miner} TSAR")

    def _broadcast_comment_tx(self) -> None:
        commenter = (self.comment_wallet_var.get() or "").strip().lower()
        comment_txt = self.comment_text.get("1.0", tk.END).strip() if self.comment_text else ""
        try:
            plan = build_comment_plan(
                art=self._selected_art,
                commenter_addr=commenter,
                base_amount_raw=self.comment_amount_var.get(),
                tip_amount_raw=self.comment_tip_var.get(),
                comment_text=comment_txt,
            )
        except ValueError as exc:
            msg = str(exc)
            box = messagebox.showwarning if "Pilih" in msg or "belum" in msg else messagebox.showerror
            box("Graffiti", msg)
            return
        except Exception as exc:
            log.exception("Unhandled exception")
            messagebox.showerror("Graffiti", f"Metadata komentar invalid: {exc}")
            return

        opret_hex = plan["opret_hex"]
        outputs = plan["outputs"]
        svc = getattr(self.app, "send_svc", None)
        rpc_send = getattr(self.app, "rpc_send", None)
        if not rpc_send:
            rpc_send = getattr(getattr(self.app, "rpc", None), "send_async", None)
        if not svc or not rpc_send:
            messagebox.showerror("Graffiti", "Send service tidak tersedia.")
            return
        
        fee_rate = int(getattr(self.app.send_tab, "fee_rate_var", None).get())
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
            log.exception("Unhandled exception")
            messagebox.showerror("Graffiti", f"Broadcast COMMENT gagal: {exc}")
            if self.comment_send_btn:
                self.comment_send_btn.config(state="normal")

    def apply_theme(self, theme: GraffitiTheme) -> None:
        """Rebuild the tab using a new theme palette."""
        self.theme = theme
        self._build_style()
        for child in list(self.winfo_children()):
            child.destroy()
        self._build_ui()
        self._refresh_creator_wallets()
        self.refresh_storers()
        self._clear_preview()
        log.debug("graffiti_tab: theme applied and UI rebuilt")
