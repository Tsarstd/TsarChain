# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

from typing import Any, Dict, Optional, TYPE_CHECKING

import tkinter as tk
import datetime as _dt
from tkinter import scrolledtext

from tsarchain.utils import config as CFG

if TYPE_CHECKING:
    from apps.wallet import KremlinWalletGUI


class NetworkController:
    @staticmethod
    def fmt_num(x: int | float | None) -> str:
        n = int(x or 0)
        return f"{n:,}".replace(",", ".")

    @staticmethod
    def fmt_tsar(sat: int | float | None) -> str:
        sat = int(sat or 0)
        whole = sat // CFG.TSAR
        frac = sat % CFG.TSAR
        if frac == 0:
            return f"{NetworkController.fmt_num(whole)} TSAR"
        sfrac = str(frac).rjust(8, "0").rstrip("0")
        return f"{NetworkController.fmt_num(whole)},{sfrac} TSAR"

    @staticmethod
    def fmt_hashrate(hps: int | float | None) -> str:
        v = float(hps or 0)
        if v >= 1e12:
            return f"{v / 1e12:.3f} TH/s".replace(",", ".")
        if v >= 1e9:
            return f"{v / 1e9:.3f} GH/s".replace(",", ".")
        if v >= 1e6:
            return f"{v / 1e6:.3f} MH/s".replace(",", ".")
        if v >= 1e3:
            return f"{v / 1e3:.3f} kH/s".replace(",", ".")
        return f"{v:.0f} H/s".replace(",", ".")

    @staticmethod
    def fmt_time(ts: int | float | None) -> str:
        if ts is None:
            return "-"
        dt = _dt.datetime.fromtimestamp(int(ts))
        return dt.strftime("%H:%M:%S")

    @staticmethod
    def fmt_last_update(last_up: Any) -> str:
        if last_up in (None, "", "-"):
            return "-"
        if isinstance(last_up, (int, float)):
            dt = _dt.datetime.fromtimestamp(int(last_up), tz=_dt.timezone.utc)
        else:
            s = str(last_up)
            dt = _dt.datetime.fromisoformat(s)

        if dt.tzinfo is None:
            dt = dt.astimezone()

        d = dt.day
        if 11 <= (d % 100) <= 13:
            suf = "th"
        else:
            suf = {1: "st", 2: "nd", 3: "rd"}.get(d % 10, "th")

        month_name = dt.strftime("%B")
        date_part = f"{month_name} {d}{suf} {dt.year}"
        time_part = dt.strftime("%H:%M:%S")

        off = dt.utcoffset() or _dt.timedelta(0)
        hours = int(round(off.total_seconds() / 3600))
        sign = "+" if hours >= 0 else "-"
        hours_abs = abs(hours)
        return f"{date_part} . {time_part} GMT {sign} {hours_abs}"

    @staticmethod
    def fmt_bytes(num_bytes: int | float | None) -> str:
        n = float(num_bytes or 0)
        units = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while n >= 1024 and i < len(units) - 1:
            n /= 1024.0
            i += 1
        if i == 0:
            return f"{int(n)} B"
        return f"{n:.2f} {units[i]}"

    @staticmethod
    def extract_peers_count(snap: Optional[Dict[str, Any]], fallback: int) -> int:
        if isinstance(snap, dict):
            peers_section = snap.get("peers")
            if isinstance(peers_section, dict):
                val = peers_section.get("count")
                if val is None:
                    val = peers_section.get("total")
                if val is None and len(peers_section) == 1:
                    val = next(iter(peers_section.values()))
                if val is not None:
                    return int(val)
            elif peers_section is not None:
                return int(peers_section)
        return int(fallback)


class NetworkTab(tk.Frame):
    def __init__(self, app: "KremlinWalletGUI", master: tk.Misc | None = None):
        super().__init__(master, bg=app.bg)
        self.app = app
        self.controller = NetworkController()
        self.net_text: scrolledtext.ScrolledText | None = None
        self._auto_job: str | None = None
        self._countdown_job: str | None = None
        self._next_refresh_sec: int = 0
        self._auto_interval_ms = 30000
        self._active = False
        self._status_label: tk.Label | None = None
        self._build_ui()

    # --------------------------------- UI ---------------------------------
    def _build_ui(self) -> None:
        top = tk.Frame(self, bg=self.app.bg)
        top.pack(fill=tk.X, padx=12, pady=8)

        self._status_label = tk.Label(
            top,
            text="Auto Refresh in 30s.",
            bg=self.app.bg,
            fg=self.app.fg,
        )
        self._status_label.pack(side=tk.LEFT, anchor="w")

        self.net_text = scrolledtext.ScrolledText(
            self,
            height=20,
            bg=self.app.panel_bg,
            fg=self.app.fg,
            insertbackground=self.app.fg,
            state="disabled",
            takefocus=1,
        )
        self.net_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        self._install_text_bindings()
        self._install_text_tags()

    def _install_text_bindings(self) -> None:
        if not self.net_text:
            return
        self.net_text.bind("<Button-1>", lambda _e: (self.net_text.focus_set(), None))
        self.net_text.bind("<Control-c>", lambda _e: (self.net_text.event_generate("<<Copy>>"), "break"))
        self.net_text.bind("<Control-a>", lambda _e: (self.net_text.tag_add("sel", "1.0", "end-1c"), "break"))
        self.net_text.bind("<<Cut>>", lambda _e: "break")
        self.net_text.bind("<<Paste>>", lambda _e: "break")
        self.net_text.bind("<Control-v>", lambda _e: "break")
        self.net_text.bind("<Button-2>", lambda _e: "break")

        copy_menu = tk.Menu(self.net_text, tearoff=False)
        copy_menu.add_command(label="Copy", command=lambda: self.net_text.event_generate("<<Copy>>"))
        self.net_text.bind("<Button-3>", lambda e: (copy_menu.tk_popup(e.x_root, e.y_root), "break"))

    def _install_text_tags(self) -> None:
        if not self.net_text:
            return
        palette = getattr(self.app.theme_set, "palette", None)
        accent = self.app.accent
        info = self.app.inf
        muted = self.app.muted
        success = palette.success if palette else "#319E4D"
        self.net_text.tag_configure("h1", font=("Segoe UI", 46, "bold"), foreground=accent, spacing3=6)
        self.net_text.tag_configure("Leaderboards", font=("Segoe UI", 36, "bold"), foreground=accent, spacing3=6)
        self.net_text.tag_configure("center", justify="center")
        self.net_text.tag_configure("h2", font=("Consolas", 17, "bold"), foreground=accent, spacing3=2)
        self.net_text.tag_configure("lab", font=("Consolas", 13, "bold"), foreground=info)
        self.net_text.tag_configure("val", font=("Consolas", 11), foreground=muted)
        self.net_text.tag_configure("mut", font=("Consolas", 10), foreground=success)
        self.net_text.tag_configure("sep", font=("Consolas", 11), foreground=accent)
        self.net_text.tag_configure("sep2", font=("Consolas", 11), foreground=muted)
        self.net_text.tag_configure("rank1", font=("Consolas", 17), foreground="#F8B31F")
        self.net_text.tag_configure("rank2", font=("Consolas", 15), foreground="#646464")
        self.net_text.tag_configure("rank3", font=("Consolas", 13), foreground="#96622D")

    # ---------------------------------------------------------------- Refresh
    def refresh_network_info(self) -> None:
        if not self.net_text:
            return

        self._net_text_enable()
        try:
            self.net_text.delete("1.0", tk.END)
            self.net_text.insert(tk.END, "[*] Requesting network info.\n")
            self._set_status("Merefresh...")
        finally:
            self._net_text_disable()

        if not self.app.busy_manager.start("netinfo", []):
            return

        pending = {"n": 2}
        store: Dict[str, Any] = {"snap": None, "peers": 0}

        def maybe_done() -> None:
            pending["n"] -= 1
            if pending["n"] <= 0:
                try:
                    self._render_network_snapshot(store.get("snap"), int(store.get("peers", 0)))
                finally:
                    self.app.busy_manager.end("netinfo")

        def on_info(resp: Optional[Dict[str, Any]]) -> None:
            try:
                if not resp:
                    self._net_text_write("[-] Failed to fetch network info\n")
                    return
                if resp.get("type") == "NETWORK_INFO" and isinstance(resp.get("data"), dict):
                    store["snap"] = resp["data"]
                else:
                    store["snap"] = {
                        "schema_version": 1,
                        "identity": {},
                        "chain": {"tip_height": resp.get("height"), "total_blocks": resp.get("blocks")},
                        "transactions": {"mempool_txs": resp.get("mempool")},
                        "utxo": {"utxo_set_size": resp.get("utxos")},
                    }
            finally:
                maybe_done()

        def on_peers(resp: Optional[Dict[str, Any]]) -> None:
            try:
                if resp and "peers" in resp:
                    store["peers"] = len(resp["peers"]) or 0
                else:
                    store["peers"] = 0
            finally:
                maybe_done()

        self.app.rpc.send_async({"type": "GET_NETWORK_INFO"}, on_info)
        self.app.rpc.send_async({"type": "GET_PEERS"}, on_peers)

        def _reschedule_after(_resp=None):
            if self._active:
                self._schedule_auto()
        self.after(0, _reschedule_after)

    def _set_status(self, text: str) -> None:
        if self._status_label:
            self._status_label.config(text=text)

    # ------------------------------------------------------------ Text helpers
    def _net_text_enable(self) -> None:
        if self.net_text:
            self.net_text.config(state="normal")

    def _net_text_disable(self) -> None:
        if self.net_text:
            self.net_text.config(state="disabled")

    def _net_text_write(self, text: str, tags: tuple[str, ...] = ()) -> None:
        if not self.net_text:
            return
        try:
            self._net_text_enable()
            self.net_text.insert(tk.END, text, tags)
        finally:
            self._net_text_disable()

    # ------------------------------------------------------------- Formatters

    # ---------------- Rendering ----------------
    def _render_network_snapshot(self, snap: Optional[Dict[str, Any]], peers_cnt: int) -> None:
        self._net_text_enable()
        self.net_text.delete("1.0", tk.END)
        if not isinstance(snap, dict):
            self.net_text.insert(tk.END, "[-] Snapshot not available\n")
            self._net_text_disable()
            return

        ident = snap.get("identity", {}) or {}
        chain = snap.get("chain", {}) or {}
        supply= snap.get("supply", {}) or {}
        txs  = snap.get("transactions", {}) or {}
        utxo = snap.get("utxo", {}) or {}
        miners = ((snap.get("miners_snapshot", {}) or {}).get("top_miners") or [])
        graffiti = snap.get("graffiti", {}) or {}
        peers_total = self.controller.extract_peers_count(snap, peers_cnt)

        # Header
        self.net_text.insert(tk.END, "🌐 Network Informations 🌐", ("h1","center"))
        self.net_text.insert(tk.END, "\n")
        # Subheader line
        last_up = snap.get("last_updated") or "-"
        schema_v = snap.get("schema_version")
        last_up_fmt = self.controller.fmt_last_update(last_up)
        sub = f"Last Update : {last_up_fmt}  |  Schema Version : {schema_v}  |  Peers : {int(peers_total)}\n"
        self.net_text.insert(tk.END, ("="*87) + "\n", ("sep","center"))
        self.net_text.insert(tk.END, sub, ("mut","center"))
        self.net_text.insert(tk.END, ("="*87) + "\n\n\n", ("sep","center"))

        # Network Identity
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "NETWORK IDENTITY\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "\nNetwork Id\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{ident.get('network_id','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Network Magic\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{ident.get('network_magic_hex','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Address Prefix\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{ident.get('address_prefix','-')}\n\n\n", ("val","center"))

        # Blockchain Informations
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "BLOCKCHAIN INFORMATIONS\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "\nGenesis Message\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('genesis_message','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Genesis Hash\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('genesis_hash','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Network Hashrate\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_hashrate(chain.get('est_network_hashrate_hps_window'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Average Block Time\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('avg_block_time_sec_window','-')} s\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Blocks\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(chain.get('total_blocks'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Tip Height\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(chain.get('tip_height'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Tip Hash\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('tip_hash','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Tip Target (hex)\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('tip_target_hex','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Tip Timestamp\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_time(chain.get('tip_timestamp'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Tip Bits\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('tip_bits','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Tip Difficulty\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(chain.get('tip_difficulty'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Block Size\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_bytes(chain.get('total_block_size_bytes'))}\n\n\n", ("val","center"))

        # Blockchain Economy
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "BLOCKCHAIN ECONOMY\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "\nMax Supply\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_tsar(supply.get('max_supply'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Circulating Supply\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_tsar(supply.get('circulating_estimate'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Coinbase Reward\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_tsar(chain.get('current_block_subsidy') or supply.get('current_block_subsidy'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Maturity Rule\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{supply.get('coinbase_maturity','-')} Block\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Immature Coinbase\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_tsar(supply.get('immature_coinbase'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Emitted Subsidy\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_tsar(supply.get('emitted_subsidy'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Current Epoch\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(supply.get('current_epoch'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Halving\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(supply.get('next_halving_height'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Block To Halving\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(supply.get('blocks_to_halving'))}\n\n\n", ("val","center"))

        # Blockchain Transactions
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "BLOCKCHAIN TRANSACTIONS\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "\nTransaction On Mempool\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(txs.get('mempool_txs'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Mempool Vbytes Estimate\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(txs.get('mempool_vbytes_estimate'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Fee's Paid\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_tsar(txs.get('total_fees_paid'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Transactions\n", ("lab","center"))
        total_txs = int(txs.get('total_txs') or 0)
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(total_txs)}\n\n", ("val","center"))

        # Show non-coinbase transactions under 'Transactions'
        noncb = int(txs.get('total_non_coinbase_txs')) if txs.get('total_non_coinbase_txs') is not None else total_txs
        self.net_text.insert(tk.END, "Transactions\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(noncb)}\n\n", ("val","center"))

        # Coinbase : total - non-coinbase
        cbt = max(total_txs - int(noncb or 0), 0)
        self.net_text.insert(tk.END, "Coinbase Transactions\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(cbt)}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "UTXO Set Size\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(utxo.get('utxo_set_size'))}\n\n\n", ("val","center"))

        # Graffiti stats
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "GRAFFITI\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "\nTotal Graffiti\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(graffiti.get('posts'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Comments\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(graffiti.get('comments'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Pool Balances\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_tsar(graffiti.get('pool_balances'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Payouts\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self.controller.fmt_num(graffiti.get('payouts'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, "Total Graffiti Storage\n", ("lab","center"))
        self.net_text.insert(
            tk.END,
            f"{self.controller.fmt_bytes(graffiti.get('total_graffiti_storage'))}\n\n",
            ("val","center"),
        )
        on_mem = int(graffiti.get("graffiti_on_mempool", 0) or 0)
        max_mem = int(CFG.MAX_GRAFFITI_ON_MEMPOOL)
        label = f"{on_mem} - (max {max_mem})"
        self.net_text.insert(tk.END, "Graffiti on Mempool\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{label}\n\n\n", ("val","center"))

        # Top Miners Leaderboards
        self.net_text.insert(tk.END, ("="*84) + "\n", ("sep","center"))
        self.net_text.insert(tk.END, "TOP #10 Miners Leaderboards\n", ("Leaderboards","center"))
        self.net_text.insert(tk.END, ("="*84) + "\n\n", ("sep","center"))
        if isinstance(miners, list) and miners:
            top = miners[:10]
            for i, (addr, found) in enumerate(top, start=1):
                if i == 1:
                    tags = ("rank1", "center")
                elif i == 2:
                    tags = ("rank2", "center")
                elif i == 3:
                    tags = ("rank3", "center")
                else:
                    tags = ("val", "center")
                self.net_text.insert(
                    tk.END,
                    f"RANK {i:>2} : ( {addr} ) Has Found : ( {self.controller.fmt_num(found)} ) Block\n",
                    tags,
                )
                if i < len(top):
                    self.net_text.insert(tk.END, ("-"*72) + "\n", ("sep2", "center"))
        self.net_text.insert(tk.END, "No Miners Data Found\n", ("mut","center"))
        self._net_text_disable()

    # ----------------------------- Auto refresh ----------------------------
    def _cancel_auto(self) -> None:
        if self._auto_job:
            self.after_cancel(self._auto_job)
            self._auto_job = None
        self._cancel_countdown()

    def _schedule_auto(self, delay_ms: int | None = None) -> None:
        self._cancel_auto()
        if not self._active:
            return
        delay = delay_ms if delay_ms is not None else self._auto_interval_ms
        self._next_refresh_sec = max(int(delay // 1000), 0)
        self._start_countdown()
        self._auto_job = self.after(delay, self._auto_tick)

    def _auto_tick(self) -> None:
        self._auto_job = None
        if not self._active:
            return
        self._next_refresh_sec = 0
        self._start_countdown()
        self.refresh_network_info()

    def on_show(self) -> None:
        self._active = True
        self._schedule_auto(delay_ms=0)

    def on_hide(self) -> None:
        self._active = False
        self._cancel_auto()

    # ----------------------------- Countdown helpers -----------------------
    def _start_countdown(self) -> None:
        self._cancel_countdown()
        if not self._active:
            return

        def _tick():
            if not self._active:
                self._countdown_job = None
                return
            if self._next_refresh_sec <= 0:
                self._set_status("Refreshing...")
                self._countdown_job = None
                return
            self._set_status(f"Auto Refresh in {self._next_refresh_sec}s")
            self._next_refresh_sec -= 1
            self._countdown_job = self.after(1000, _tick)

        _tick()

    def _cancel_countdown(self) -> None:
        if self._countdown_job:
            self.after_cancel(self._countdown_job)
            self._countdown_job = None
