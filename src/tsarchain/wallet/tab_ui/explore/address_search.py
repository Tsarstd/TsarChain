# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .main_tab import ExplorePanel


class AddressSearch:
    """Handler for fetch and render addresses in Explorer."""

    def __init__(self, panel: "ExplorePanel", fmt_tsar_amount: Callable[[Any], str]) -> None:
        self.panel = panel
        self._fmt_tsar_amount = fmt_tsar_amount

    # ---------- entrypoints ----------
    def open_address(self, addr: str) -> None:
        get_address = self.panel.providers.get("get_address")
        if not callable(get_address):
            self.panel._render_error("Provider get_address not available")
            self.panel._finish_search(False)
            return

        def worker():
            done = False
            a = get_address(addr)
            if not a:
                self.panel._ui(self.panel._render_error, "Address not found")
                return self.panel._ui(self.panel._finish_search, False)
            done = True
            self.panel._ui(self.render_address, addr, a)
            self.panel._ui(self.panel._finish_search, done)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- renderers ----------
    def render_address(self, addr: str, a: Dict) -> None:
        p = self.panel
        p._clear_text()
        spend = a.get("spendable", a.get("balance_spendable", 0)) or 0
        immature = a.get("immature", a.get("balance_immature", 0)) or 0
        pending = a.get("pending", a.get("balance_pending", 0)) or 0
        utxos = a.get("utxos") or []
        hist = a.get("history") or []

        p._section("Address")
        p._kv("Address", addr, mono=True, vtag="val_addr")
        p._kv("Spendable", self._fmt_tsar_amount(spend), mono=True, vtag="val_num")
        p._kv("Immature", self._fmt_tsar_amount(immature), mono=True, vtag="val_num")
        p._kv("Pending", self._fmt_tsar_amount(pending), mono=True, vtag="val_num")
        p._kv("UTXOs", str(len(utxos)), mono=True, vtag="val_num")

        p._section("Recent Activity")
        if not hist:
            p._writeln("No history", "muted")
        else:
            for h in hist[:300]:
                txid = h.get("txid") or h.get("id")
                amt = h.get("amount") or h.get("value")
                st = h.get("status") or "-"
                p.text.insert("end", "- ", ("mono",))
                p.text.insert("end", str(txid), ("mono", "val_hex"))
                p.text.insert("end", f"   {self._fmt_tsar_amount(amt)}", ("mono", "val_num"))

                st_tag = "confirmed" if str(st).lower().startswith("conf") else "unconfirmed"
                p.text.insert("end", "  (", ("mono",))
                p.text.insert("end", str(st), ("mono", st_tag))
                p.text.insert("end", ")\n", ("mono",))
        p._finish_render("Address")
