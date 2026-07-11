# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import tkinter as tk
from typing import Sequence, Dict, Set, Union

class BusyManager:
    def __init__(self, root: tk.Tk, toast_cb=None):
        self.root = root
        self.toast = toast_cb
        self._busy_keys: Set[str] = set()
        self._busy_widgets: Dict[str, list[tk.Widget]] = {}
        self._busy_timers: Dict[str, Union[str, int]] = {}

    def _set_enabled(self, w: tk.Widget, enabled: bool) -> None:
        if not hasattr(w, "_prev_state"):
            setattr(w, "_prev_state", w.cget("state"))
        if enabled:
            prev = getattr(w, "_prev_state", None)
            if prev is None:
                w["state"] = "normal"
            else:
                w["state"] = prev
        else:
            w["state"] = "disabled"

    def _busy_msg_for_key(self, key: str) -> str:
        if key.startswith("bal:") or key == "wallet_balances":
            return "Taking balance..."
        return {
            "send": "Sending transactions...",
            "netinfo": "Loading network info..",
            "history_list": "Loading transaction history...",
            "explorer_search": "Searching in Explorer...",
        }.get(key, "Processing...")

    def _busy_wait_msg(self, key: str) -> str:
        if key.startswith("bal:") or key == "wallet_balances":
            return "balance is still being processed .. please wait..Bro"
        return {
            "send": "Transaction is still being sent...",
            "netinfo": "Network info retrieval is still in progress...",
            "history_list": "History is still loading...",
            "explorer_search": "Search is still in progress...",
        }.get(key, "Still processing ... please wait...Bro")

    def start(self, key: str, widgets: Sequence[tk.Widget] = ()) -> bool:
        if key in self._busy_keys:
            if self.toast:
                self.toast(self._busy_wait_msg(key), ms=1500, kind="info")
            return False

        self._busy_keys.add(key)
        wl = [w for w in (widgets or []) if w]
        self._busy_widgets[key] = wl
        for w in wl:
            self._set_enabled(w, False)
        self.root.config(cursor="watch")
        
        if self.toast:
            self.toast(self._busy_msg_for_key(key), ms=1200, kind="info")
        self.root.update_idletasks()

        if key in self._busy_timers:
            self.root.after_cancel(self._busy_timers[key])
        self._busy_timers[key] = self.root.after(15000, lambda k=key: self.end(k))
        return True

    def end(self, key: str) -> None:
        tid = self._busy_timers.pop(key, None)
        if tid:
            self.root.after_cancel(tid)
        if key not in self._busy_keys:
            return
        for w in self._busy_widgets.get(key, []):
            self._set_enabled(w, True)
        self._busy_widgets.pop(key, None)
        self._busy_keys.remove(key)
        if not self._busy_keys:
            self.root.config(cursor="")
        self.root.update_idletasks()
