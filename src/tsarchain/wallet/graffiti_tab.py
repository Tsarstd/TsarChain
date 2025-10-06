# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from __future__ import annotations
import os, time, hashlib, mimetypes, threading
from tkinter import ttk, filedialog, messagebox, StringVar
import tkinter as tk

from .graffiti import build_metadata, build_opret_hex


# ========= Stub API (ganti dengan RPC ke node/storage nanti) =========
class DummyStorageAPI:
    def list_storers(self):
        # (name, addr) — addr dipakai untuk prefill recipient
        return [
            ("Sputnik Storer #1", "tsar1q62xtpyn82zmlkysa6tjd8p3pcgc6hwy9g2xysw"),
            ("Gulag Storer #2",  "tsar1qvjf2mjupugy7es4rdfp4pa8gp58sd76nqreggl"),
        ]

    def upload_stub(self, path: str, sha_hex: str, size: int, mime: str):
        # Simulasi upload: delay, lalu kembalikan receipt
        time.sleep(1.2)
        return f"rcpt-{sha_hex[:12]}-{int(time.time())}"


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
    def __init__(self, app, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = app
        self.api = DummyStorageAPI()

        # state
        self.selected_path: str | None = None
        self.selected_sha: str | None = None
        self.selected_size: int | None = None
        self.selected_mime: str | None = None
        self.selected_storer_addr: str | None = None
        self.receipt_id: str | None = None
        self.opret_hex: str | None = None

        self._build_style()
        self._build_ui()
        self.refresh_storers()

    # ---- styling sederhana (dark + orange accent) ----
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Tsar.TButton", padding=8)
        style.configure("Tsar.TLabelframe.Label", font=("Consolas", 11, "bold"))
        style.configure("Tsar.Header.TLabel", font=("Consolas", 14, "bold"))
        style.configure("Tsar.Mono.TLabel", font=("Consolas", 10))

    # ---- layout utama ----
    def _build_ui(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)

        # Header
        ttk.Label(root, text="Graffiti Uploader (MVP)", style="Tsar.Header.TLabel").pack(anchor="w")

        # Storer
        stor_fr = ttk.LabelFrame(root, text="Storer", style="Tsar.TLabelframe")
        stor_fr.pack(fill="x", pady=(8, 6))
        self.storer_var = StringVar()
        self.storer_map = {}  # name -> addr

        self.storer_cb = ttk.Combobox(stor_fr, textvariable=self.storer_var, state="readonly", width=50)
        self.storer_cb.grid(row=0, column=0, padx=(8, 6), pady=8, sticky="w")
        ttk.Button(stor_fr, text="Refresh", style="Tsar.TButton", command=self.refresh_storers)\
            .grid(row=0, column=1, padx=6, pady=8, sticky="w")

        # File
        file_fr = ttk.LabelFrame(root, text="File", style="Tsar.TLabelframe")
        file_fr.pack(fill="x", pady=(6, 6))
        self.file_var = StringVar(value="(no file)")
        ttk.Label(file_fr, textvariable=self.file_var, style="Tsar.Mono.TLabel").grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        ttk.Button(file_fr, text="Choose File…", style="Tsar.TButton", command=self.pick_file)\
            .grid(row=0, column=1, padx=8, pady=(8, 2), sticky="e")

        self.meta_var = StringVar(value="size: -, mime: -, sha256: -")
        ttk.Label(file_fr, textvariable=self.meta_var, style="Tsar.Mono.TLabel")\
            .grid(row=1, column=0, columnspan=2, padx=8, pady=(0, 8), sticky="w")

        # Tip & Upload
        up_fr = ttk.LabelFrame(root, text="Upload → Receipt (stub)", style="Tsar.TLabelframe")
        up_fr.pack(fill="x", pady=(6, 6))
        ttk.Label(up_fr, text="Tip (sats) → paid to storer address:", style="Tsar.Mono.TLabel")\
            .grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        self.tip_var = StringVar(value="1000")
        tip_entry = ttk.Entry(up_fr, textvariable=self.tip_var, width=12)
        tip_entry.grid(row=0, column=1, padx=6, pady=(8, 2), sticky="w")

        self.upload_btn = ttk.Button(up_fr, text="Upload (stub)", style="Tsar.TButton", command=self._upload_stub)
        self.upload_btn.grid(row=0, column=2, padx=8, pady=(8, 2), sticky="e")

        self.pbar = ttk.Progressbar(up_fr, mode="indeterminate", length=240)
        self.pbar.grid(row=1, column=0, columnspan=3, padx=8, pady=(4, 8), sticky="we")

        self.receipt_var = StringVar(value="receipt: -")
        ttk.Label(up_fr, textvariable=self.receipt_var, style="Tsar.Mono.TLabel")\
            .grid(row=2, column=0, columnspan=3, padx=8, pady=(0, 8), sticky="w")

        # Build OP_RETURN & Prefill
        op_fr = ttk.LabelFrame(root, text="Build OP_RETURN → Prefill Send", style="Tsar.TLabelframe")
        op_fr.pack(fill="x", pady=(6, 6))

        self.opret_info_var = StringVar(value="OP_RETURN size: -")
        ttk.Label(op_fr, textvariable=self.opret_info_var, style="Tsar.Mono.TLabel")\
            .grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")

        self.build_btn = ttk.Button(op_fr, text="Build Metadata + OP_RETURN", style="Tsar.TButton", command=self._build_opret, state="disabled")
        self.build_btn.grid(row=0, column=1, padx=8, pady=(8, 2), sticky="e")

        self.prefill_btn = ttk.Button(op_fr, text="Prefill Send", style="Tsar.TButton", command=self._prefill_send, state="disabled")
        self.prefill_btn.grid(row=0, column=2, padx=8, pady=(8, 2), sticky="e")

        # Feed hint
        ttk.Label(root, text="Tip: After broadcast, check Graffiti Feed on Explorer tab.", style="Tsar.Mono.TLabel").pack(anchor="w", pady=(4,0))

    # ---- actions ----
    def refresh_storers(self):
        storers = self.api.list_storers()
        names = []
        self.storer_map.clear()
        for name, addr in storers:
            names.append(name)
            self.storer_map[name] = addr
        self.storer_cb["values"] = names
        if names:
            self.storer_cb.current(0)
            self.selected_storer_addr = self.storer_map[names[0]]

        def on_sel(event=None):
            name = self.storer_var.get()
            self.selected_storer_addr = self.storer_map.get(name)
        self.storer_cb.bind("<<ComboboxSelected>>", on_sel)

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
        self.meta_var.set(f"size: {size} bytes, mime: {mime}, sha256: {sha[:16]}…")
        self.receipt_id = None
        self.receipt_var.set("receipt: -")
        self.build_btn["state"] = "disabled"
        self.prefill_btn["state"] = "disabled"
        self.opret_hex = None
        self.opret_info_var.set("OP_RETURN size: -")

    def _upload_stub(self):
        if not self.selected_path or not self.selected_sha or not self.selected_size or not self.selected_mime:
            messagebox.showwarning("Graffiti", "Select a file first.")
            return
        if not self.selected_storer_addr:
            messagebox.showwarning("Graffiti", "Select a storer first.")
            return

        self.upload_btn["state"] = "disabled"
        self.pbar.start(12)

        def work():
            try:
                rcpt = self.api.upload_stub(self.selected_path, self.selected_sha, self.selected_size, self.selected_mime)
                self.receipt_id = rcpt
                self.after(0, lambda: self.receipt_var.set(f"receipt: {rcpt}"))
                self.after(0, lambda: self.build_btn.config(state="normal"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Graffiti", f"Upload failed: {e}"))
            finally:
                self.after(0, lambda: (self.pbar.stop(), self.upload_btn.config(state="normal")))

        threading.Thread(target=work, daemon=True).start()

    def _build_opret(self):
        if not (self.selected_sha and self.selected_size is not None and self.selected_mime and self.receipt_id):
            messagebox.showwarning("Graffiti", "Upload (stub) first to get a receipt.")
            return
        if not self.selected_storer_addr:
            messagebox.showwarning("Graffiti", "Select a storer first.")
            return
        try:
            meta = build_metadata(
                sha256_hex=self.selected_sha,
                size_bytes=int(self.selected_size),
                mime=self.selected_mime,
                storer_addr=self.selected_storer_addr,
                receipt_id=self.receipt_id,
            )
            opret_hex = build_opret_hex(meta)
            self.opret_hex = opret_hex
            self.opret_info_var.set(f"OP_RETURN size: {len(bytes.fromhex(opret_hex))} bytes")
            self.prefill_btn["state"] = "normal"
        except Exception as e:
            messagebox.showerror("Graffiti", f"Build OP_RETURN failed: {e}")

    def _prefill_send(self):
        if not (self.opret_hex and self.selected_storer_addr):
            messagebox.showwarning("Graffiti", "Build OP_RETURN first.")
            return
        tip = (self.tip_var.get() or "0").strip()
        if not tip.isdigit():
            messagebox.showwarning("Graffiti", "Tip must be integer (sats).")
            return

        # These setters must exist in SendTab (as we added earlier)
        try:
            self.app.send_tab.set_recipient(self.selected_storer_addr)
            self.app.send_tab.set_amount(tip)          # pay tip to storer
            self.app.send_tab.set_opret_hex(self.opret_hex)
        except Exception:
            messagebox.showerror("Graffiti", "Send tab does not expose setter methods.")
            return

        # Switch to Send tab for final review/broadcast
        if hasattr(self.app, "switch_tab"):
            self.app.switch_tab("send")
