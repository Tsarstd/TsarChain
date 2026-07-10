# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tkinter as tk
from typing import Any, Dict, List, Optional, Sequence, TYPE_CHECKING
from tkinter import filedialog, messagebox, ttk

from ..services.tx_history import HistoryService
from .wallet_tab import sat_to_tsar
from tsarchain.utils import config as CFG

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.tab_ui.history_tab")

if TYPE_CHECKING:
    from apps.wallet import KremlinWalletGUI


class HistoryController:
    def __init__(self):
        self.hist_offset = 0
        self.hist_limit = 50
        self.hist_total = 0
        self._history_rows_cache: List[Dict[str, Any]] = []

    def change_limit(self, limit: int) -> None:
        self.hist_limit = limit

    def reset_pagination(self) -> None:
        self.hist_offset = 0

    def prev_page(self) -> bool:
        if self.hist_offset <= 0:
            return False
        self.hist_offset = max(0, self.hist_offset - self.hist_limit)
        return True

    def next_page(self) -> bool:
        if self.hist_offset + self.hist_limit >= self.hist_total:
            return False
        self.hist_offset += self.hist_limit
        return True

    def update_cache(self, items: List[Dict[str, Any]], total: int) -> None:
        self._history_rows_cache = items
        self.hist_total = total

    def prepare_csv_data(self) -> list[list[Any]]:
        res = []
        for row in self._history_rows_cache:
            amt = int(row.get("amount", 0))
            from_addr = row.get("from") or row.get("address", "")
            height = "" if row.get("height") is None else int(row.get("height"))
            res.append([
                row.get("txid", ""),
                from_addr,
                row.get("to", ""),
                amt,
                amt / CFG.TSAR,
                row.get("status", ""),
                int(row.get("confirmations", 0) or 0),
                height,
                row.get("direction", ""),
            ])
        return res

class HistoryTab(tk.Frame):
    def __init__(
        self,
        app: "KremlinWalletGUI",
        history_service: HistoryService,
        master: tk.Misc | None = None,
    ):
        super().__init__(master, bg=app.bg)
        self.app = app
        self.service = history_service
        self.log = getattr(app, "log", None)
        self.address_values: list[str] = list(app.wallets or [])
        self.controller = HistoryController()

        self.history_tree: ttk.Treeview | None = None
        self.hist_info: tk.Label | None = None
        self.hist_refresh_btn: ttk.Button | None = None
        self.hist_prev_btn: ttk.Button | None = None
        self.hist_next_btn: ttk.Button | None = None
        self.history_addr_var = tk.StringVar(value=self.address_values[0] if self.address_values else "")
        self.hist_dir_var = tk.StringVar(value="all")
        self.hist_status_var = tk.StringVar(value="all")
        self.hist_limit_var = tk.IntVar(value=self.controller.hist_limit)

        self._hist_menu: tk.Menu | None = None
        self.history_addr_combo: ttk.Combobox | None = None

        self._build_ui()

    # ---------------------------------- UI ---------------------------------
    def _build_ui(self) -> None:
        top = tk.Frame(self, bg=self.app.bg)
        top.pack(fill=tk.X, padx=12, pady=8)

        tk.Label(top, text="Address:", bg=self.app.bg, fg=self.app.fg).pack(side=tk.LEFT)
        self.history_addr_combo = ttk.Combobox(
            top,
            textvariable=self.history_addr_var,
            values=self.address_values,
            state="readonly",
            width=54,
        )
        self.history_addr_combo.pack(side=tk.LEFT, padx=6)
        self.history_addr_combo.bind("<<ComboboxSelected>>", lambda _e: self._hist_on_addr_changed())
        self.history_addr_combo.bind("<Return>", lambda _e: self._hist_on_addr_changed())

        tk.Label(top, text="Direction:", bg=self.app.bg, fg=self.app.fg).pack(side=tk.LEFT, padx=(12, 2))
        hist_dir_combo = ttk.Combobox(
            top,
            textvariable=self.hist_dir_var,
            values=["all", "in", "out"],
            state="readonly",
            width=8,
        )
        hist_dir_combo.pack(side=tk.LEFT)

        tk.Label(top, text="Status:", bg=self.app.bg, fg=self.app.fg).pack(side=tk.LEFT, padx=(12, 2))
        hist_status_combo = ttk.Combobox(
            top,
            textvariable=self.hist_status_var,
            values=["all", "confirmed", "unconfirmed"],
            state="readonly",
            width=12,
        )
        hist_status_combo.pack(side=tk.LEFT)

        tk.Label(top, text="Per page:", bg=self.app.bg, fg=self.app.fg).pack(side=tk.LEFT, padx=(12, 2))
        tk.Spinbox(
            top,
            from_=10,
            to=500,
            increment=10,
            width=6,
            textvariable=self.hist_limit_var,
            command=self._hist_change_limit,
        ).pack(side=tk.LEFT)

        self.hist_refresh_btn = ttk.Button(top, text="Refresh", command=self._hist_reset_and_refresh)
        self.hist_refresh_btn.pack(side=tk.LEFT, padx=6)

        pager = tk.Frame(self, bg=self.app.bg)
        pager.pack(fill=tk.X, padx=12, pady=(0, 8))
        self.hist_info = tk.Label(pager, text="History", bg=self.app.bg, fg=self.app.fg)
        self.hist_info.pack(side=tk.LEFT)

        self.hist_next_btn = ttk.Button(pager, text="Next ⏭️", command=self._hist_next)
        self.hist_next_btn.pack(side=tk.RIGHT, padx=4)
        self.hist_prev_btn = ttk.Button(pager, text="⏮️ Prev", command=self._hist_prev)
        self.hist_prev_btn.pack(side=tk.RIGHT, padx=4)

        self._build_table()
        self._build_footer()

    def _build_table(self) -> None:
        table_frame = tk.Frame(self, bg=self.app.bg)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        cols = ("txid", "address", "to", "amount", "status", "confirmations", "height", "direction")
        tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=16)
        for c, w in [
            ("txid", 260),
            ("address", 300),
            ("to", 300),
            ("amount", 150),
            ("status", 120),
            ("confirmations", 120),
            ("height", 80),
            ("direction", 90),
        ]:
            tree.heading(c, text=c.upper())
            tree.column(c, width=w, anchor="w")
        tree.heading("address", text="FROM")
        vs = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vs.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)

        palette = getattr(self.app.theme_set, "palette", None)
        conf_color = palette.success if palette else "#17c964"
        unconf_color = palette.warning if palette else "#f5a524"
        tree.tag_configure("CONF", foreground=conf_color)
        tree.tag_configure("UNCONF", foreground=unconf_color)
        self.history_tree = tree

        self._hist_menu = tk.Menu(
            self.app.root,
            tearoff=0,
            bg=self.app.panel_bg,
            fg=self.app.fg,
            activebackground=self.app.border_color,
            activeforeground=self.app.fg,
        )
        self._hist_menu.add_command(label="Open in Explorer", command=self._hist_ctx_open)
        self._hist_menu.add_separator()
        self._hist_menu.add_command(label="Copy TXID", command=lambda: self._hist_ctx_copy(col=0))
        self._hist_menu.add_command(label="Copy FROM", command=lambda: self._hist_ctx_copy(col=1))
        self._hist_menu.add_command(label="Copy TO", command=lambda: self._hist_ctx_copy(col=2))

        def _hist_ctx_menu(event) -> None:
            iid = tree.identify_row(event.y)
            if iid:
                tree.selection_set(iid)
                self._hist_menu.tk_popup(event.x_root, event.y_root)
                self._hist_menu.grab_release()

        tree.bind("<Button-3>", _hist_ctx_menu)
        self.app._tv_enable_hover(tree)

    def _build_footer(self) -> None:
        bottom = tk.Frame(self, bg=self.app.bg)
        bottom.pack(fill=tk.X, padx=12, pady=8)
        ttk.Button(bottom, text="Export CSV", command=self._hist_export_csv).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Clear Cache", command=self._hist_clear_cache).pack(side=tk.RIGHT, padx=5)
        ttk.Button(bottom, text="📂 Open Cache File", command=self._hist_open_cache_file).pack(side=tk.RIGHT)
        ttk.Button(bottom, text="🧹 Clear All Caches", command=self._hist_clear_all_caches).pack(side=tk.RIGHT, padx=5)

    # ----------------------------------------------------------- Public API
    def reload_addresses(self, addresses: Sequence[str]) -> None:
        self.address_values = list(addresses or [])
        if not self._widget_exists(self.history_addr_combo):
            return
        self.history_addr_combo["values"] = self.address_values
        if self.address_values and self.history_addr_var.get() not in self.address_values:
            self.history_addr_var.set(self.address_values[0])
        elif not self.address_values:
            self.history_addr_var.set("")

    def ensure_address_selected(self) -> None:
        if not self.history_addr_var.get() and self.address_values:
            self.history_addr_var.set(self.address_values[0])

    def on_show(self) -> None:
        self.ensure_address_selected()
        self._render_from_cache()

    # ----------------------------------------------------- Context menu ops
    def _hist_ctx_open(self) -> None:
        if not self.history_tree:
            return
        sel = self.history_tree.selection()
        if not sel:
            return
        item = sel[0]
        txid = self.history_tree.set(item, "txid")
        if not txid:
            return
        self.app.show_explorer_frame()
        if hasattr(self.app, "explore_panel") and self.app.explore_panel:
            self.app.explore_panel.navigate_to_tx(txid)

    def _hist_ctx_copy(self, col: int = 0) -> None:
        if not self.history_tree:
            return
        sel = self.history_tree.selection()
        if not sel:
            return
        vals = self.history_tree.item(sel[0], "values")
        if not vals or col >= len(vals):
            return
        self.app.copy_to_clipboard(vals[col], label="Copied")

    # ----------------------------------------------------------- Pagination
    def _hist_change_limit(self) -> None:
        self.controller.change_limit(int(self.hist_limit_var.get()))

    def _hist_reset_and_refresh(self) -> None:
        self._hist_change_limit()
        self.controller.reset_pagination()
        self.refresh_history()

    def _hist_on_addr_changed(self) -> None:
        if self.history_tree:
            for iid in self.history_tree.get_children():
                self.history_tree.delete(iid)
        if self.hist_info:
            self.hist_info.configure(text="Loading...")
        self.controller.reset_pagination()
        self.refresh_history()

    def _hist_prev(self) -> None:
        if self.controller.prev_page():
            self.refresh_history()

    def _hist_next(self) -> None:
        if self.controller.next_page():
            self.refresh_history()

    # --------------------------------------------------------- Cache Mgmt
    def _hist_export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save history as CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        rows = self.controller.prepare_csv_data()
        with open(path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.writer(fp)
            writer.writerow(
                [
                    "txid",
                    "from",
                    "to",
                    "amount_sat",
                    "amount_tsar",
                    "status",
                    "confirmations",
                    "height",
                    "direction",
                ]
            )
            for row in rows:
                writer.writerow(row)
        messagebox.showinfo("Exported", f"Saved to {path}")

    def _hist_clear_all_caches(self) -> None:
        addrs = list(self.address_values or [])
        if not addrs:
            messagebox.showinfo("Nothing to clear", "No wallets in the list.")
            return
        if not messagebox.askyesno(
            "Clear ALL caches",
            "Delete local history cache for ALL listed addresses?\n\n"
            "This only removes local cache files on your disk.",
        ):
            return
        removed = 0
        for addr in addrs:
            if self.service.cache_clear(addr):
                removed += 1
        self._render_from_cache()
        messagebox.showinfo("Done", f"Cleared {removed} cache file(s).")

    def _hist_clear_cache(self) -> None:
        addr = self.history_addr_var.get()
        if not addr:
            messagebox.showerror("Missing", "Select address first")
            return
        if not messagebox.askyesno("Clear cache", f"Delete cached history for:\n\n{addr}\n\nLocal file only"):
            return
        ok = self.service.cache_clear(addr)
        if ok:
            self._render_from_cache()
            messagebox.showinfo("Cleared", "Local history cache removed.")
        else:
            messagebox.showerror("Error", "Failed to remove cache file.")

    def _hist_open_cache_file(self) -> None:
        addr = self.history_addr_var.get()
        if not addr:
            messagebox.showerror("Missing", "Select address first")
            return
        path = self.service.cache_path(addr)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"version": 1, "address": addr, "last_updated": 0, "items": {}}, fh, indent=2)

            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                rc = subprocess.call(["xdg-open", path])
                if rc != 0:
                    import webbrowser

                    webbrowser.open(f"file://{path}")
        except Exception as exc:
            log.exception("Unhandled exception")
            messagebox.showerror("Open failed", str(exc))

    # -------------------------------------------------------------- Loading
    def _render_from_cache(self) -> None:
        if not self.history_tree:
            return
        addr = self.history_addr_var.get()
        if not addr:
            return
        direction = self.hist_dir_var.get()
        status = self.hist_status_var.get()
        direction = None if direction == "all" else direction
        status = None if status == "all" else status
        res = self.service.cache_list(addr, direction=direction, status=status, limit=self.controller.hist_limit, offset=self.controller.hist_offset)
        items = res.get("items", [])
        total = int(res.get("total", len(items)))
        self.controller.update_cache(items, total)

        for iid in self.history_tree.get_children():
            self.history_tree.delete(iid)

        shown = len(items)
        start = 0 if self.controller.hist_total == 0 else (self.controller.hist_offset + 1)
        end = self.controller.hist_offset + shown
        if self.hist_info:
            self.hist_info.configure(text=f"Showing {start}-{end} of {self.controller.hist_total} (cached)")

        rows: list[tuple[tuple[Any, ...], tuple[str, ...]]] = []
        for entry in items:
            txid = entry.get("txid", "")
            owner = entry.get("from") or entry.get("address", "")
            to_addr = entry.get("to", "")
            amt = int(entry.get("amount", 0))
            status_txt = entry.get("status", "")
            conf = int(entry.get("confirmations", 0))
            h = entry.get("height", None)
            h = "" if h is None else int(h)
            direction_txt = entry.get("direction", "")
            tag = ("CONF",) if status_txt == "confirmed" else ("UNCONF",)
            rows.append(((txid, owner, to_addr, sat_to_tsar(amt), status_txt, conf, h, direction_txt), tag))

        self.app._tv_insert_chunked(self.history_tree, rows)

    def refresh_history(self) -> None:
        addr = self.history_addr_var.get()
        if not addr:
            messagebox.showerror("Missing", "Select address first")
            return
        if self.history_tree:
            for iid in self.history_tree.get_children():
                self.history_tree.delete(iid)
            self.history_tree.insert("", "end", values=("Loading...", "", "", "", "", "", "", ""))
        if self.hist_info:
            self.hist_info.configure(text="Loading latest history... (showing cache if any)")

        direction = self.hist_dir_var.get()
        status = self.hist_status_var.get()
        direction = None if direction == "all" else direction
        status = None if status == "all" else status
        
        self._render_from_cache()
        widgets = [w for w in (self.hist_refresh_btn, self.hist_prev_btn, self.hist_next_btn) if w]
        if not self.app._busy_start("history_list", widgets):
            return

        def _on_hist(resp: Optional[Dict[str, Any]]) -> None:
            try:
                if not resp or resp.get("type") != "TX_HISTORY":
                    messagebox.showerror("Error", f"Failed to load history: {resp}")
                    self.app._toast("Failed to Load History", ms=1800, kind="error")
                    return
                items = resp.get("items", [])
                total = resp.get("total", len(items))
                self.controller.update_cache(items, total)
                self.service.cache_merge(addr, items)
                self._render_from_cache()
            except Exception as exc:
                log.exception("Unhandled exception")
                messagebox.showerror("Error", f"Render error: {exc}")

        def _wrapped(resp: Optional[Dict[str, Any]]) -> None:
            try:
                _on_hist(resp)
            finally:
                self.app._busy_end("history_list")

        try:
            self.service.fetch_history(
                address=addr,
                limit=self.controller.hist_limit,
                offset=self.controller.hist_offset,
                direction=direction,
                status=status,
                rpc_send=self.app.rpc.send_async,
                on_done=_wrapped,
            )
        except Exception as exc:
            log.exception("Unhandled exception")
            self.app._busy_end("history_list")
            messagebox.showerror("Error", str(exc))

    # ---------------------------------------------------------- Misc helpers
    def _hist_open_detail(self, _event: Optional[tk.Event] = None) -> None:
        if not self.history_tree:
            return
        sel = self.history_tree.selection()
        if not sel:
            return
        vals = self.history_tree.item(sel[0], "values")
        txid = vals[0] if vals else ""
        if not txid:
            return
        self.app.show_explorer_frame()
        if hasattr(self.app, "explore_panel") and self.app.explore_panel:
            self.app.explore_panel._nav(f"tsar://tx/{txid}")

    @staticmethod
    def _widget_exists(widget) -> bool:
        return bool(widget) and widget.winfo_exists()
