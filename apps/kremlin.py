# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

# ---------------- Imports (Module) ----------------
import os
import sys
import csv
import time
import json
import random
import subprocess
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox, scrolledtext, filedialog, simpledialog, ttk
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------- Local Project (Wallet Only) ----------------
from tsarchain.wallet.rpc_client import NodeClient
from tsarchain.wallet.address_management import WalletsMixin, load_registry
from tsarchain.wallet.contact_management import ContactManager
from tsarchain.wallet.chat_security import ChatManager
from tsarchain.wallet.graffiti_tab import GraffitiTab
from tsarchain.wallet.chat_tab import ChatTab
from tsarchain.wallet.send_service import SendService
from tsarchain.wallet.send_tab import SendTab
from tsarchain.wallet.tx_history import HistoryService
from tsarchain.wallet.explorer_tab import ExplorePanel
from tsarchain.wallet.data_security import list_addresses_in_keystore
from tsarchain.wallet.ui_utils import center_window

# ---------------- Local Project (With Node) ----------------
import tsarcore_native as native
from tsarchain.network.protocol import load_or_create_keypair_at
from tsarchain.storage.kv import kv_enabled, iter_prefix, batch
from tsarchain.utils import config as CFG

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import launch_gui_in_thread, setup_logging, open_log_toplevel, get_ctx_logger

# ---------------- Constants & Paths ----------------

manual_bootstrap: Optional[Tuple[str, int]] = None
try:
    os.makedirs(os.path.dirname(CFG.USER_KEY_PATH), exist_ok=True)
except Exception:
    pass

USER_ID, USER_PUB, USER_PRIV = load_or_create_keypair_at(CFG.USER_KEY_PATH)
USER_CTX = {"net_id": CFG.DEFAULT_NET_ID, "node_id": USER_ID, "pubkey": USER_PUB, "privkey": USER_PRIV}

WALLET_PEER_KEYS_PATH = os.path.join(os.path.dirname(CFG.USER_KEY_PATH), "wallet_peer_keys.json")

if not kv_enabled():
    try:
        os.makedirs(os.path.dirname(WALLET_PEER_KEYS_PATH), exist_ok=True)
    except Exception:
        pass
    
def _load_peer_keys() -> dict:
    if kv_enabled():
        m = {}
        try:
            for k, v in iter_prefix('wallet_peer_keys', b'nid:'):
                nid = k.decode('utf-8')[4:]
                m[nid] = v.decode('utf-8')
        except Exception:
            pass
        return m
    try:
        with open(WALLET_PEER_KEYS_PATH, 'r', encoding='utf-8') as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}
    
def _save_peer_keys(d: dict) -> None:
    if kv_enabled():
        try:
            with batch('wallet_peer_keys') as b:
                for nid, pk in d.items():
                    b.put(f"nid:{nid}".encode('utf-8'), pk.encode('utf-8'))
        except Exception:
            pass
        return
    try:
        tmp = WALLET_PEER_KEYS_PATH + ".tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, WALLET_PEER_KEYS_PATH)
    except Exception:
        pass

WALLET_PEER_KEYS = _load_peer_keys()

# ---------------- Utils: Amount formatting ----------------
def sat_to_tsar(amount_satoshi: Optional[int]) -> str:
    if amount_satoshi is None:
        amount_satoshi = 0
    tsar = amount_satoshi / CFG.TSAR
    s = f"{tsar:.8f}".rstrip("0").rstrip(".")
    return f"{s} TSAR"


# ---------------- Bootstrap Lock Screen ----------------
class BootstrapLockscreen(tk.Toplevel):

    def __init__(self, root: tk.Tk):
        super().__init__(root)
        self.result: Optional[Tuple[str, int]] = None
        self.configure(bg="#121212")
        self.geometry("820x540")
        self.title("TsarChain Bootstrap Setup")

        lbl = tk.Label(
            self,
            text="Enter Bootstrap IP:Port\n(or Cancel for default)",
            bg="#121212",
            fg="#ff5e00",
            font=("Consolas", 16, "bold"),
        )
        lbl.pack(pady=30)

        self.entry = tk.Entry(self, font=("Consolas", 14), width=30, bg="#121212", fg="#ff5e00")
        self.entry.pack(pady=20)

        btn_frame = tk.Frame(self, bg="#121212")
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="OK", font=("Consolas", 12), bg="#ff5e00", fg="#fff",
                  command=self.on_ok).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", font=("Consolas", 12), bg="#444", fg="#fff",
                  command=self.on_cancel).pack(side=tk.LEFT, padx=10)

        center_window(self, root)

    def on_ok(self) -> None:
        entry = self.entry.get().strip()
        if entry:
            try:
                ip, port_str = entry.split(":")
                self.result = (ip.strip(), int(port_str))
            except Exception:
                messagebox.showerror("Invalid", "Format must ip:port")
                return
        self.destroy()

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()


def show_bootstrap_lockscreen(root: tk.Tk) -> Optional[Tuple[str, int]]:
    lock = BootstrapLockscreen(root)
    root.wait_window(lock)
    return lock.result


# ---------------- Main GUI ----------------
class KremlinWalletGUI(WalletsMixin):
    def __init__(self, root: tk.Tk):
        self.root = root

        # 0) Theme & styles
        self.theme_mode = getattr(self, "theme_mode", "dark")
        self._apply_theme_palette(self.theme_mode)
        self.root.configure(bg=self.bg)
        
        self._install_styles()
        self._bind_shortcuts()
        self._busy_setup()

        root.title("Kremlin")
        root.geometry("1070x600")

        # 1) RPC client — MUST be initialized before services/tabs that use RPC
        self.rpc = NodeClient(
            cfg_module=None,
            user_ctx=USER_CTX,
            root=self.root,
            pinned_get=lambda nid: WALLET_PEER_KEYS.get(nid),
            pinned_set=lambda nid, pk: (WALLET_PEER_KEYS.__setitem__(nid, pk), _save_peer_keys(WALLET_PEER_KEYS)),
            manual_bootstrap=manual_bootstrap,
        )
        self.rpc_send  = self.rpc.send_async

        # 2) Services (can use RPC)
        self.send_svc = SendService()
        self.chat_mgr = ChatManager(
            rpc_send=self.rpc.send_async,
            password_prompt_cb=lambda addr: self._ask_password("Unlock Address", f"Enter password for {addr}:"),
        )
        self.exp_svc = HistoryService()

        # 3) State & cache
        self._chat_online = False
        self._chat_poll_job = None
        self._chat_priv_cache = self.chat_mgr.priv_cache
        self._chat_pub_cache  = self.chat_mgr.pub_cache
        self._read_sent       = self.chat_mgr.read_sent
        self._init_balance_cache()

        self.chat_textsize_var     = tk.StringVar(value="Medium")
        self.font_chat_body        = tkfont.Font(family="Segoe UI", size=13)
        self.font_chat_meta_peer   = tkfont.Font(family="Segoe UI", size=10)
        self.font_chat_meta_me     = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self._msg_meta_map = {}
        self._chat_key_ttl_sec = 15 * 60
        self.chat_blocked = set()
        self.contacts: Dict[str, str] = {}
        self._ks_pwd_cache: Optional[Tuple[str, float]] = None
        self._ks_pwd_ttl_sec = 15 * 60

        # 4) Theme vars & tab state
        self.themes = {
            "dark":  {"bg": "#121212", "panel_bg": "#1e1e1e", "fg": "#E6E6E6", "muted": "#8a8a8a", "accent": "#e06214"},
            "light": {"bg": "#6b6b6b", "panel_bg": "#dfdfdf", "fg": "#222222", "muted": "#E6E6E6", "accent": "#e06214"},
        }
        self.current_theme = "dark"
        self._apply_theme_vars()
        self._active_tab = "wallets"
        self._sidebar_buttons: dict[str, ttk.Button] = {}

        # 5) Build layout dasar
        self.wallets: List[str] = load_registry()
        self._build_layout()

        # 6) Contact manager (does not need RPC)
        self.contact_mgr = ContactManager(
            self.root,
            get_password_cb=self._get_keystore_password,
            toast_cb=lambda m: self._toast(m, kind="info"),
            palette={"bg": self.bg, "panel_bg": self.panel_bg, "fg": self.fg, "muted": self.muted, "accent": self.accent},
        )
        
        self.chat_tab = ChatTab(
            root=self.root,
            chat_mgr=self.chat_mgr,
            rpc_send=self.rpc.send,
            palette={"bg": self.bg, "panel_bg": self.panel_bg, "fg": self.fg, "muted": self.muted, "accent": self.accent},
            toast_cb=lambda m, kind="info": self._toast(m, kind),
            get_wallets_cb=lambda: list(self.wallets or []),
            contact_mgr=self.contact_mgr,
        )
        
        self.send_tab = SendTab(
            self.root,
            rpc_send=self.rpc_send,
            ask_password=lambda addr: self._ask_password("Unlock Address", f"Enter password for\n{addr}:"),
            toast=lambda m, kind="info": self._toast(m, kind),
            addresses_provider=lambda: list(self.wallets or []),
            contact_manager=getattr(self, "contact_mgr", None),
            busy_request=getattr(self, "_request_locked", None),
            palette={"bg": self.bg, "panel_bg": self.panel_bg, "fg": self.fg,
                    "muted": self.muted, "accent": self.accent, "border": "#2a2f36", "card": self.panel_bg},
            on_sent=lambda addr_from: (
                hasattr(self, "refresh_wallet_balance") and
                self.refresh_wallet_balance(addr_from, getattr(self, "last_balance_widget", None))
            ),
        )

        # 7) Build frames/tab
        self._build_wallets_frame()
        self._build_send_frame()
        self._build_network_frame()
        self._build_dev_frame()

        # 8) Activate tabs only once
        self.show_wallets_frame()
        self._activate_tab("wallets")

        # 9) Start heartbeat SETELAH network UI ada (label/status udah kebentuk)
        self._start_conn_heartbeat(interval_ms=10000)


    # ---------------- Theme / Layout ----------------
    def _apply_theme_vars(self) -> None:
        t = self.themes[self.current_theme]
        self.bg = t["bg"]
        self.panel_bg = t["panel_bg"]
        self.fg = t["fg"]
        self.muted = t["muted"]
        self.accent = t["accent"]
        
    # -------------- Theme palette & styles --------------
    def _apply_theme_palette(self, mode: str | None = None) -> None:
        if mode is None:
            mode = getattr(self, "theme_mode", "dark")
        if mode == "light":
            self.bg        = "#f7f9fc"
            self.panel_bg  = "#eef1f5"
            self.fg        = "#0f1115"
            self.muted     = "#6b7280"
            self.accent    = "#2563eb"
        else:  # dark (default)
            self.bg        = "#0f1115"
            self.panel_bg  = "#161a1f"
            self.fg        = "#f2f5f7"
            self.muted     = "#a9b1ba"
            self.accent    = "#ff6b00"

    def _install_styles(self) -> None:
        bg  = getattr(self, "bg",       "#0f1115")
        fg  = getattr(self, "fg",       "#f2f5f7")
        pbg = getattr(self, "panel_bg", "#161a1f")
        acc = getattr(self, "accent",   "#ff6b00")
        muted = getattr(self, "muted",  "#a9b1ba")
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Tsar.TFrame",      background=bg)
        style.configure("Tsar.TLabelframe", background=bg, foreground=fg)
        style.configure("Tsar.TLabelframe.Label", background=bg, foreground=fg)
        style.configure("Tsar.TLabel",      background=bg, foreground=fg)
        style.configure("Muted.TLabel",     background=bg, foreground=muted)
        style.configure("Accent.TLabel",    background=bg, foreground=acc)
        style.configure("Tsar.TButton",     background=pbg, foreground=fg, padding=6)
        style.map("Tsar.TButton",
                background=[("active", "#222831"), ("pressed", "#1b1f24")])
        try:
            style.configure("Tsar.Vertical.TScrollbar", background=pbg, troughcolor=bg)
        except Exception:
            pass
        self._style = style
        
    def _repaint_theme(self):
        def paint(w):
            cls = w.winfo_class().lower()
            try:
                if cls in ("frame",):
                    w.configure(bg=self.bg)
                elif cls in ("label",):
                    w.configure(bg=self.bg, fg=self.fg)
                elif cls in ("text",):
                    w.configure(bg=self.panel_bg, fg=self.fg, insertbackground=self.fg)
            except Exception:
                pass
            for c in w.winfo_children():
                paint(c)
        paint(self.root)

    def toggle_theme(self) -> None:
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self._apply_theme_vars()
        for widget in self.root.winfo_children():
            widget.destroy()
        self._build_layout()
        self._build_wallets_frame()
        self._build_send_frame()
        self._build_network_frame()
        self._build_dev_frame()
        self.show_wallets_frame()

    def _bind_shortcuts(self) -> None:
        self.root.bind_all("<Control-n>", lambda _e: self.create_wallet())
        self.root.bind_all("<Control-r>", lambda _e: self.refresh_all_wallets())
        self.root.bind_all("<Control-i>", lambda _e: self.import_by_mnemonic())
        self.root.bind_all("<Control-b>", lambda _e: self.backup_keystore())
        self.root.bind_all("<Control-o>", lambda _e: self.load_wallet_file())
        self.root.bind_all("<Control-s>", lambda _e: self.sync_from_keystore())
        self.root.bind_all("<Delete>",    lambda _e: self.delete_wallet_dialog())
        
        
    # --- Wallet Lock Screen helpers ---

    def _is_wallet_ready(self) -> bool:
        return bool(getattr(self, "wallets", []))

    def _build_locked_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["locked"] = f

        wrap = tk.Frame(f, bg=self.bg)
        wrap.pack(fill=tk.BOTH, expand=True)

        card = tk.Frame(wrap, bg=self.panel_bg, padx=24, pady=22)
        card.place(relx=0.5, rely=0.5, anchor="center")

        self._lock_title = tk.Label(
            card, text="🔒 Locked", bg=self.panel_bg, fg=self.accent,
            font=("Segoe UI", 18, "bold"))
        self._lock_title.pack(pady=(0, 6))

        self._lock_sub = tk.Label(
            card, text="Create or Load Your Wallet First",
            bg=self.panel_bg, fg=self.fg, font=("Segoe UI", 11))
        self._lock_sub.pack(pady=(0, 14))

        btns = tk.Frame(card, bg=self.panel_bg)
        btns.pack()
        ttk.Button(
            btns, text="Create / Load Wallet",
            command=lambda: (self.show_wallets_frame(), self._activate_tab("wallets"))
        ).pack(side=tk.LEFT, padx=6)
        ttk.Button(
            btns, text="Explore Without Wallet",
            command=lambda: (self.show_explorer_frame(), self._activate_tab("explorer"))
        ).pack(side=tk.LEFT, padx=6)

        tk.Label(
            card,
            text="Send, Chat, and History require at least one address.",
            bg=self.panel_bg, fg=self.muted, font=("Segoe UI", 9)
        ).pack(pady=(12, 0))

    def _show_locked_screen(self, source: str | None = None) -> None:
        self._hide_all_frames()
        if "locked" not in self.frames:
            self._build_locked_frame()
        title = f"🔒 {source} is Locked" if source else "🔒 Locked"
        try:
            self._lock_title.config(text=title)
            self._lock_sub.config(text="Create or Load Your Wallet First")
        except Exception:
            pass
        self.frames["locked"].pack(fill=tk.BOTH, expand=True)

    def _maybe_lock_redirect(self) -> None:
        if (not self._is_wallet_ready()) and getattr(self, "_active_tab", "") in ("send", "chat", "history"):
            self._show_locked_screen(self._active_tab.capitalize())


    # --- Sidebar active/hover state ---
    
    def _activate_tab(self, tab: str) -> None:
        self._active_tab = tab
        self._refresh_sidebar_styles()

    def _refresh_sidebar_styles(self) -> None:
        try:
            for tab, btn in getattr(self, "_sidebar_buttons", {}).items():
                if not btn or not btn.winfo_exists():
                    continue
                if tab == getattr(self, "_active_tab", ""):
                    btn.configure(
                        bg=self.accent, fg="#ffffff",
                        activebackground=self.accent, activeforeground="#ffffff")
                else:
                    btn.configure(
                        bg=self.panel_bg, fg=self.fg,
                        activebackground=self.accent, activeforeground="#ffffff")
        except Exception:
            pass

    def _create_sidebar_button(self, text: str, tab: str, on_click) -> tk.Button:
        btn = tk.Button(
            self.sidebar, text=text,
            command=lambda: (on_click(), self._activate_tab(tab)),
            bg=self.panel_bg, fg=self.fg, font=("Segoe UI", 10, "bold"),
            bd=0, relief=tk.FLAT, padx=8, pady=8, highlightthickness=0,
            cursor="hand2", activebackground=self.accent, activeforeground="#ffffff")
        def _hover_in(_e):
            if tab != getattr(self, "_active_tab", ""):
                btn.configure(bg=self.accent, fg="#ffffff")
        def _hover_out(_e):
            if tab != getattr(self, "_active_tab", ""):
                btn.configure(bg=self.panel_bg, fg=self.fg)
        btn.bind("<Enter>", _hover_in)
        btn.bind("<Leave>", _hover_out)

        if not hasattr(self, "_sidebar_buttons"):
            self._sidebar_buttons = {}
        self._sidebar_buttons[tab] = btn
        btn.pack(pady=(12, 6))
        return btn

    def _build_layout(self) -> None:
        self.sidebar = tk.Frame(self.root, bg=self.panel_bg, width=100)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.main = tk.Frame(self.root, bg=self.bg)
        self.main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(self.sidebar, text="Kremlin", bg=self.panel_bg, fg=self.accent,
                 font=("Segoe UI", 17, "bold")).pack(pady=(12, 6))

        self._sidebar_buttons = {}
        self._create_sidebar_button("Wallets",  "wallets",  self.show_wallets_frame)
        self._create_sidebar_button("Send",     "send",     self.show_send_frame)
        self._create_sidebar_button("Graffiti",  "graffiti",  self.show_graffiti_frame)
        self._create_sidebar_button("Chat",     "chat",     self.show_chat_frame)
        self._create_sidebar_button("History",  "history",  self.show_history_frame)
        self._create_sidebar_button("Explorer", "explorer", self.show_explorer_frame)
        self._create_sidebar_button("Network",  "network",  self.show_network_frame)
        self._create_sidebar_button("Dev",      "dev",      self.show_dev_frame)

        tk.Button(self.sidebar, text="Switch Theme", command=self.toggle_theme,
                bg=self.panel_bg, fg=self.fg, bd=0, relief=tk.FLAT,
                padx=8, pady=8, highlightthickness=0, cursor="hand2",
                activebackground=self.accent, activeforeground="#ffffff").pack(side=tk.BOTTOM, pady=10)

        self.conn_status = tk.Label(self.sidebar, text="Offline", bg=self.panel_bg,
                                    fg="#d41c1c", font=("Segoe UI", 9, "bold"))
        self.conn_status.pack(side=tk.BOTTOM, pady=(0, 12))

        self.frames: Dict[str, tk.Frame] = {}

        
        # ---------------- UX: Toast (non-blocking) ----------------
    def _toast(self, text: str, ms: int = 1800, kind: str = "info") -> None:
        try:
            if isinstance(ms, str):
                kind = ms
                ms = 1800
            try:
                ms = int(ms)
            except Exception:
                ms = 1800
            if not hasattr(self, "_toasts"):
                self._toasts = []
            self.root.update_idletasks()
            tw = tk.Toplevel(self.root)
            tw.withdraw()
            tw.overrideredirect(True)
            try:
                tw.attributes("-topmost", True)
                tw.attributes("-alpha", 0.96)
            except Exception:
                pass

            border = {"info": self.accent, "warn": "#f5a524", "error": "#f1633f"}.get(kind, self.accent)
            bg = self.panel_bg
            w, h = 320, 52
            rx = self.root.winfo_rootx(); ry = self.root.winfo_rooty()
            rw = self.root.winfo_width();  rh = self.root.winfo_height()
            y_offset = len(self._toasts) * (h + 6)
            x = rx + rw - (w + 18)
            y = ry + rh - (h + 18) - y_offset
            tw.geometry(f"{w}x{h}+{x}+{y}")

            wrapper = tk.Frame(tw, bg=border, bd=0, highlightthickness=0)
            wrapper.pack(fill="both", expand=True)
            inner = tk.Frame(wrapper, bg=bg, bd=0, highlightthickness=0)
            inner.pack(fill="both", expand=True, padx=1, pady=1)

            lbl = tk.Label(inner, text=text, bg=bg, fg=self.fg, font=("Consolas", 10), anchor="w", justify="left")
            lbl.pack(fill="both", expand=True, padx=12, pady=10)

            self._toasts.append(tw)
            tw.deiconify()

            def _close():
                try:
                    tw.destroy()
                except Exception:
                    pass
                try:
                    self._toasts.remove(tw)
                except Exception:
                    pass

            tw.after(ms, _close)
        except Exception:
            pass

    def _busy_msg_for_key(self, key: str) -> str:
        if key.startswith("bal:") or key == "wallet_balances":
            return "Taking balance..."
        return {
            "refresh_all": "Refreshing all balances...",
            "send": "Sending transactions...",
            "netinfo": "Loading network info..",
            "history_list": "Loading transaction history...",
            "explorer_search": "Searching in Explorer...",
        }.get(key, "Processing...")

    def _busy_wait_msg(self, key: str) -> str:
        if key.startswith("bal:") or key == "wallet_balances":
            return "balance is still being processed .. please wait..Bro"
        return {
            "refresh_all": "Balance refresh is still in progress...",
            "send": "Transaction is still being sent...",
            "netinfo": "Network info retrieval is still in progress...",
            "history_list": "History is still loading...",
            "explorer_search": "Search is still in progress...",
        }.get(key, "Still processing ... please wait...Bro")

    # ---------------- Connection status (UI + heartbeat) ----------------
    def _set_conn_status(self, ok: bool) -> None:
        try:
            if ok:
                self.conn_status.config(text="Connected", fg="#17c964")
            else:
                self.conn_status.config(text="Offline",   fg="#d41c1c")
        except Exception:
            pass

    def _start_conn_heartbeat(self, interval_ms: int = 10000) -> None:
        self._conn_hb_interval = int(max(1000, interval_ms))
        if hasattr(self, "_conn_hb_job") and self._conn_hb_job:
            try:
                self.root.after_cancel(self._conn_hb_job)
            except Exception:
                pass
            self._conn_hb_job = None

        def _next_delay() -> int:
            jitter = 0.2
            return int(self._conn_hb_interval * (1 + random.uniform(-jitter, jitter)))

        def _tick():
            self._conn_hb_job = None
            def _on(resp: Optional[Dict[str, Any]]) -> None:
                ok = bool(resp and not resp.get("error"))
                self._set_conn_status(ok)

            try:
                self.rpc.send_async({"type": "PING"}, _on)
            except Exception:
                self._set_conn_status(False)
            try:
                self._conn_hb_job = self.root.after(_next_delay(), _tick)
            except Exception:
                pass
        try:
            self._conn_hb_job = self.root.after(600, _tick)
        except Exception:
            pass

    # ---------------- Send Tab ----------------
    def _build_send_frame(self) -> None:
        fr = ttk.Frame(self.main, style="Tsar.TFrame")
        self.frames["send"] = fr
        try:
            self.send_tab.build(fr)
        except Exception as e:
            tk.Label(
                fr, text=f"Send tab failed to render: {e}",
                bg=self.bg, fg=self.accent, font=("Consolas", 11, "bold")
            ).pack(anchor="w", padx=12, pady=12)


    def reload_addresses(self) -> None:
        try:
            values = (self.wallets[:] if getattr(self, "wallets", None) else [])
            if getattr(self, "wallet_count_label", None):
                self.wallet_count_label.config(text=f"Wallets: {len(values)}")

            if getattr(self, "history_addr_combo", None) is not None:
                self.history_addr_combo["values"] = values
                if hasattr(self, "history_addr_var") and self.history_addr_var is not None:
                    if values and self.history_addr_var.get() not in values:
                        self.history_addr_var.set(values[0])
                    if not values:
                        self.history_addr_var.set("")
            try:
                self.chat_tab.reload_addresses()
            except Exception:
                pass
        except Exception:
            self.log.exception("[reload_addresses] warning:")

    def _chat_toggle_online(self) -> None:
        addr = (self.chat_from_var.get() or "").strip().lower()
        if not addr:
            self._toast("Input Target Address First!.", kind="warn")
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
                self._toast(msg, kind="error")
                return

            def _on(resp):
                if resp and resp.get("type") == "CHAT_REGISTERED":
                    self._chat_set_online_ui(True)
                    self._toast("Online •", kind="info")
                    self._chat_schedule_next(800)
                else:
                    self._toast(f"Failed Register: {resp}", kind="error")

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
        self._toast("Offline.", kind="info")
        
        # ---------------- Contact Management ----------------
    def _get_keystore_password(self) -> Optional[str]:
        if self._ks_pwd_cache and time.time() < self._ks_pwd_cache[1]:
            return self._ks_pwd_cache[0]
        pwd = simpledialog.askstring("Keystore Password", "Enter keystore password:", show="*")
        if not pwd:
            return None
        try:
            _ = list_addresses_in_keystore(pwd)
            self._ks_pwd_cache = (pwd, time.time() + self._ks_pwd_ttl_sec)
            return pwd
        except Exception as e:
            messagebox.showerror("Error", f"Wrong password: {e}")
            return None

    def _contacts_reload(self, show_toast: bool = False) -> None:
        self.contacts = self.contact_mgr.load()  # dict addr->alias
        self._refresh_contacts_ui()
        if show_toast:
            self._toast(f"Loaded {len(self.contacts)} contact(s).", kind="info")

    def _refresh_contacts_ui(self) -> None:
        pairs = self.contact_mgr.pairs()   # List[(label, addr)]
        items = [label for (label, _addr) in pairs]
        self._contact_pairs = pairs
        for name in ("send_to_combo"):
            combo = getattr(self, name, None)
            if combo is not None:
                combo["values"] = items

        # ---------------- Contacts for SEND tab ----------------
    def _sync_send_recipient_from_combo(self) -> None:
        raw = ""
        try:
            raw = (self.send_to_combo.get() or "").strip()
        except Exception:
            pass
        if not raw:
            return
        rlc = raw.lower()
        if rlc.startswith("tsar1"):
            self.send_to_var.set(rlc)
            return
        for label, addr in getattr(self, "_contact_pairs", []):
            if raw == label:
                self.send_to_var.set(addr)
                return

    def _get_send_to_addr(self) -> str:
        self._sync_send_recipient_from_combo()
        v = (self.send_to_var.get() or "").strip().lower()
        return v if v.startswith("tsar1") else ""

    # ---------------- History Frame ----------------
    def _build_history_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["history"] = f

        self.hist_offset = 0
        self.hist_limit = 50
        self.hist_total = 0

        top = tk.Frame(f, bg=self.bg)
        top.pack(fill=tk.X, padx=12, pady=8)

        tk.Label(top, text="Address:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT)
        self.history_addr_var = tk.StringVar()
        self.history_addr_combo = ttk.Combobox(
            top, textvariable=self.history_addr_var, values=self.wallets, state="readonly", width=54
        )
        self.history_addr_combo.pack(side=tk.LEFT, padx=6)
        self.history_addr_combo.bind("<<ComboboxSelected>>", lambda _e: self._hist_on_addr_changed())
        self.history_addr_combo.bind("<Return>", lambda _e: self._hist_on_addr_changed())

        tk.Label(top, text="Direction:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT, padx=(12, 2))
        self.hist_dir_var = tk.StringVar(value="all")
        self.hist_dir_combo = ttk.Combobox(top, textvariable=self.hist_dir_var, values=["all", "in", "out"],
                                           state="readonly", width=8)
        self.hist_dir_combo.pack(side=tk.LEFT)

        tk.Label(top, text="Status:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT, padx=(12, 2))
        self.hist_status_var = tk.StringVar(value="all")
        self.hist_status_combo = ttk.Combobox(
            top, textvariable=self.hist_status_var, values=["all", "confirmed", "unconfirmed"],
            state="readonly", width=12
        )
        self.hist_status_combo.pack(side=tk.LEFT)

        tk.Label(top, text="Per page:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT, padx=(12, 2))
        self.hist_limit_var = tk.IntVar(value=self.hist_limit)
        self.hist_limit_spin = tk.Spinbox(
            top, from_=10, to=500, increment=10, width=6, textvariable=self.hist_limit_var,
            command=self._hist_change_limit
        )
        self.hist_limit_spin.pack(side=tk.LEFT)

        self.hist_refresh_btn = ttk.Button(top, text="Refresh", command=self._hist_reset_and_refresh)
        self.hist_refresh_btn.pack(side=tk.LEFT, padx=6)

        pager = tk.Frame(f, bg=self.bg)
        pager.pack(fill=tk.X, padx=12, pady=(0, 8))
        self.hist_info = tk.Label(pager, text="History", bg=self.bg, fg=self.fg)
        self.hist_info.pack(side=tk.LEFT)

        self.hist_next_btn = ttk.Button(pager, text="Next ⏭️", command=self._hist_next)
        self.hist_next_btn.pack(side=tk.RIGHT, padx=4)
        self.hist_prev_btn = ttk.Button(pager, text="⏮️ Prev", command=self._hist_prev)
        self.hist_prev_btn.pack(side=tk.RIGHT, padx=4)

        table_frame = tk.Frame(f, bg=self.bg)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        cols = ("txid", "address", "to", "amount", "status", "confirmations", "height", "direction")
        self.history_tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=16)
        for c, w in [
            ("txid", 260), ("address", 300), ("to", 300), ("amount", 150),
            ("status", 120), ("confirmations", 120), ("height", 80), ("direction", 90)
        ]:
            self.history_tree.heading(c, text=c.upper())
            self.history_tree.column(c, width=w, anchor="w")
        self.history_tree.heading("address", text="FROM")

        vs = ttk.Scrollbar(table_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=vs.set)
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)

        self.history_tree.tag_configure("CONF", foreground="#17c964")
        self.history_tree.tag_configure("UNCONF", foreground="#f5a524")

        self._hist_menu = tk.Menu(self.root, tearoff=0, bg="#1b1d20", fg="#e8e8e8",
                                activebackground="#2a2f36", activeforeground="#ffffff")
        self._hist_menu.add_command(label="Open in Explorer", command=self._hist_ctx_open)
        
        def _hist_ctx_menu(event):
            tv = self.history_tree
            iid = tv.identify_row(event.y)
            if iid:
                tv.selection_set(iid)
                self._hist_menu.tk_popup(event.x_root, event.y_root)
                self._hist_menu.grab_release()
                
        self.history_tree.bind("<Button-3>", _hist_ctx_menu)
        
        self._hist_menu.add_separator()
        self._hist_menu.add_command(label="Copy TXID",   command=lambda: self._hist_ctx_copy(col=0))
        self._hist_menu.add_command(label="Copy FROM",   command=lambda: self._hist_ctx_copy(col=1))
        self._hist_menu.add_command(label="Copy TO",     command=lambda: self._hist_ctx_copy(col=2))

        self._tv_enable_hover(self.history_tree)

        self._history_rows_cache: List[Dict[str, Any]] = []

        bottom = tk.Frame(f, bg=self.bg)
        bottom.pack(fill=tk.X, padx=12, pady=8)
        ttk.Button(bottom, text="Export CSV", command=self._hist_export_csv).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Clear Cache", command=self._hist_clear_cache).pack(side=tk.RIGHT, padx=5)
        ttk.Button(bottom, text="📂 Open Cache File", command=self._hist_open_cache_file).pack(side=tk.RIGHT)
        ttk.Button(bottom, text="🧹 Clear All Caches", command=self._hist_clear_all_caches).pack(side=tk.RIGHT, padx=5)

    # ---------------- History: Context Menu & Helpers ----------------

    def _hist_ctx_open(self):
        tv = self.history_tree
        sel = tv.selection()
        if not sel: 
            return
        item = sel[0]
        try:
            txid = tv.set(item, "txid")
        except Exception:
            txid = tv.item(item, "values")[0]
        if not txid:
            return
        self.show_explorer_frame()
        self.explore_panel.navigate_to_tx(txid)
        
    def _hist_ctx_copy(self, col: int = 0) -> None:
        sel = self.history_tree.selection()
        if not sel:
            return
        vals = self.history_tree.item(sel[0], "values")
        if not vals or col >= len(vals):
            return
        self.copy_to_clipboard(vals[col], label="Copied")

    def _hist_change_limit(self) -> None:
        try:
            self.hist_limit = int(self.hist_limit_var.get())
        except Exception:
            self.hist_limit = 50

    def _hist_reset_and_refresh(self) -> None:
        self._hist_change_limit()
        self.hist_offset = 0
        self.refresh_history()
        
    def _hist_on_addr_changed(self) -> None:
        self.hist_offset = 0
        try:
            for i in self.history_tree.get_children():
                self.history_tree.delete(i)
            self.hist_info.configure(text="Loading...")
        except Exception:
            pass
        self.refresh_history()

    def _hist_prev(self) -> None:
        if self.hist_offset <= 0:
            return
        self.hist_offset = max(0, self.hist_offset - self.hist_limit)
        self.refresh_history()

    def _hist_next(self) -> None:
        if self.hist_offset + self.hist_limit >= self.hist_total:
            return
        self.hist_offset += self.hist_limit
        self.refresh_history()

    def _hist_export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save history as CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        rows = self._history_rows_cache or []
        with open(path, "w", newline="", encoding="utf-8") as fp:
            w = csv.writer(fp)
            w.writerow([
                "txid", "from", "to", "amount_sat", "amount_tsar",
                "status", "confirmations", "height", "direction"
            ])
            for r in rows:
                amt = int(r.get("amount", 0))
                from_addr = r.get("from") or r.get("address", "")
                height = "" if r.get("height") is None else int(r.get("height"))
                w.writerow([
                    r.get("txid", ""),
                    from_addr,
                    r.get("to", ""),
                    amt,
                    amt / CFG.TSAR,
                    r.get("status", ""),
                    int(r.get("confirmations", 0) or 0),
                    height,
                    r.get("direction", ""),
                ])
        messagebox.showinfo("Exported", f"Saved to {path}")

    def _hist_clear_all_caches(self) -> None:
        addrs = list(self.wallets or [])
        if not addrs:
            messagebox.showinfo("Nothing to clear", "No wallets in the list.")
            return
        if not messagebox.askyesno(
            "Clear ALL caches",
            "Delete local history cache for ALL listed addresses?\n\n"
            "This only removes local cache files on your disk."):
            return
        removed = 0
        for a in addrs:
            try:
                if HistoryService.cache_clear(a):
                    removed += 1
            except Exception:
                pass
        try:
            self._hist_render_from_cache()
        except Exception:
            pass
        messagebox.showinfo("Done", f"Cleared {removed} cache file(s).")

    def _hist_clear_cache(self) -> None:
        addr = self.history_addr_var.get()
        if not addr:
            messagebox.showerror("Missing", "Select address first")
            return
        if not messagebox.askyesno(
            "Clear cache",
            f"Delete cached history for:\n\n{addr}\n\nLocal file only"):
            return
        ok = HistoryService.cache_clear(addr)
        if ok:
            self._hist_render_from_cache()
            messagebox.showinfo("Cleared", "Local history cache removed.")
        else:
            messagebox.showerror("Error", "Failed to remove cache file.")

    def _hist_open_cache_file(self) -> None:
        addr = self.history_addr_var.get()
        if not addr:
            messagebox.showerror("Missing", "Select address first")
            return

        path = HistoryService.cache_path(addr)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"version": 1, "address": addr, "last_updated": 0, "items": {}}, f, indent=2)

            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                rc = subprocess.call(["xdg-open", path])
                if rc != 0:
                    import webbrowser
                    webbrowser.open(f"file://{path}")
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def _hist_render_from_cache(self) -> None:
        addr = self.history_addr_var.get()
        if not addr:
            return

        direction = self.hist_dir_var.get()
        status = self.hist_status_var.get()
        direction = None if direction == "all" else direction
        status = None if status == "all" else status

        try:
            res = HistoryService.cache_list(
                addr, direction=direction, status=status,
                limit=int(self.hist_limit), offset=int(self.hist_offset)
            )
        except Exception:
            self.log.exception("[cache] read error:")
            return

        items = res.get("items", [])
        self.hist_total = int(res.get("total", len(items)))

        for i in self.history_tree.get_children():
            self.history_tree.delete(i)

        shown = len(items)
        start = 0 if self.hist_total == 0 else (self.hist_offset + 1)
        end = self.hist_offset + shown
        self.hist_info.configure(text=f"Showing {start}-{end} of {self.hist_total} (cached)")

        rows: list[tuple[tuple, tuple]] = []
        for it in items:
            txid = it.get("txid", "")
            owner = it.get("from") or it.get("address", "")   # FROM
            to = it.get("to", "")
            amt = int(it.get("amount", 0))
            status_txt = it.get("status", "")
            conf = int(it.get("confirmations", 0))
            h = it.get("height", None)
            h = "" if h is None else int(h)
            direc = it.get("direction", "")
            tag = ("CONF",) if status_txt == "confirmed" else ("UNCONF",)
            rows.append((
                (txid, owner, to, sat_to_tsar(amt), status_txt, conf, h, direc),
                tag
            ))

        self._tv_insert_chunked(self.history_tree, rows)

    def refresh_history(self) -> None:
        addr = self.history_addr_var.get()
        if not addr:
            messagebox.showerror("Missing", "Select address first")
            return

        for i in self.history_tree.get_children():
            self.history_tree.delete(i)
        try:
            self.hist_info.configure(text="Loading latest history... (showing cache if any)")
        except Exception:
            pass
        try:
            self.history_tree.insert(
                "", "end",
                values=("Loading...", "", "", "", "", "", "", ""),
            )
        except Exception:
            pass

        direction = self.hist_dir_var.get()
        status = self.hist_status_var.get()
        direction = None if direction == "all" else direction
        status = None if status == "all" else status

        try:
            self._hist_render_from_cache()
        except Exception:
            pass

        def _on_hist(resp: Optional[Dict[str, Any]]) -> None:
            try:
                if not resp or resp.get("type") != "TX_HISTORY":
                    messagebox.showerror("Error", f"Failed to load history: {resp}")
                    try: self._toast("Failed to Load History", ms=1800, kind="error")
                    except Exception: pass
                    return
                items = resp.get("items", [])
                self._history_rows_cache = items
                try:
                    HistoryService.cache_merge(addr, items)
                except Exception:
                    self.log.exception("[cache] merge error:")
                try:
                    self._hist_render_from_cache()
                except Exception as e:
                    messagebox.showerror("Error", f"Render error: {e}")
            except Exception as e:
                messagebox.showerror("Error", f"Render error: {e}")

        widgets = [getattr(self, "hist_refresh_btn", None),
                getattr(self, "hist_prev_btn", None),
                getattr(self, "hist_next_btn", None)]
        if not self._busy_start("history_list", widgets):
            return

        def _wrapped_on_hist(resp):
            try:
                _on_hist(resp)
            finally:
                self._busy_end("history_list")

        try:
            self.exp_svc.fetch_history(
                address=addr,
                direction=direction,
                status=status,
                limit=int(self.hist_limit),
                rpc_send=self.rpc.send_async,
                offset=int(self.hist_offset),
                on_done=_wrapped_on_hist)
            
        except Exception as e:
            self._busy_end("history_list")
            messagebox.showerror("Error", str(e))


    def _hist_open_detail(self, _event: Optional[tk.Event] = None) -> None:
        sel = self.history_tree.selection()
        if not sel:
            return
        vals = self.history_tree.item(sel[0], "values")
        txid = vals[0] if vals else ""
        if not txid:
            return
        self.show_explorer_frame()
        if hasattr(self, "explore_panel") and self.explore_panel:
            self.explore_panel._nav(f"tsar://tx/{txid}")

    # === Explorer (BERSIH, SATU VERSI SAJA) ===

    def show_explorer_frame(self) -> None:
        self._hide_all_frames()
        if "explorer" not in self.frames:
            self._build_explorer_frame()
        self.frames["explorer"].pack(fill=tk.BOTH, expand=True)
        if hasattr(self, "explore_panel"):
            self.explore_panel.on_activated()

    def _build_explorer_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["explorer"] = f

        # Panel Explore baru
        self.explore_panel = ExplorePanel(f, app=self)
        self.explore_panel.pack(fill=tk.BOTH, expand=True)

        # ---------- helper RPC ----------
        def _rpc(payload: dict):
            try:
                return self.rpc.send(payload)
            except Exception as e:
                return {"error": str(e)}

        # ---------- Providers utk panel ----------
        def _prov_get_info():
            r = _rpc({"type": "GET_NETWORK_INFO"})
            if not isinstance(r, dict):
                return {}
            # normalize so the panel can render the overview
            tip = r.get("tip") or r.get("tip_hash")
            return {
                "network": r.get("net_id") or r.get("network_id") or "tsar-devnet-1",
                "height": r.get("height") or r.get("tip_height"),
                "difficulty": r.get("difficulty") or r.get("target") or r.get("tip_target"),
                "hashrate": r.get("hashrate") or r.get("network_hashrate"),
                "genesis": r.get("genesis_hash") or r.get("genesis"),
                "tip": tip,
            }

        def _prov_get_block(x):
            import re
            s = str(x).strip()

            if re.fullmatch(r"\d+", s):
                h = int(s)
                blk = _rpc({"type": "GET_BLOCK_BY_HEIGHT", "height": h})
                if isinstance(blk, dict) and blk and not blk.get("error"):
                    blk.setdefault("height", h)
                    if not blk.get("hash"):
                        hh = _rpc({"type": "GET_BLOCK_HASH", "height": h})
                        if isinstance(hh, dict) and hh.get("hash"):
                            blk["hash"] = hh["hash"]
                        elif isinstance(hh, str) and hh:
                            blk["hash"] = hh
                    return blk

                blk = _rpc({"type": "GET_BLOCK", "height": h})
                if isinstance(blk, dict) and blk and not blk.get("error"):
                    blk.setdefault("height", h)
                return blk

            if re.fullmatch(r"[0-9a-fA-F]{64}", s):
                for t in ("GET_BLOCK", "GET_BLOCK_BY_HASH", "GET_BLOCK_DETAIL"):
                    r = _rpc({"type": t, "hash": s})
                    if isinstance(r, dict) and r and not r.get("error"):
                        r.setdefault("hash", s)
                        return r

                r = _rpc({"type": "GET_BLOCK", "block_hash": s})
                if isinstance(r, dict) and r and not r.get("error"):
                    r.setdefault("hash", s)
                    return r
            return {"error": "not_found"}

        def _prov_get_tx(txid: str):
            r = _rpc({"type": "GET_TX_DETAIL", "txid": str(txid).lower()})
            if not isinstance(r, dict) or r.get("error"):
                for pay in ({"type": "GET_TX", "txid": str(txid).lower()},
                            {"type": "GET_TRANSACTION", "txid": str(txid).lower()},
                            {"type": "TX_GET", "txid": str(txid).lower()}):
                    rr = _rpc(pay)
                    if isinstance(rr, dict) and not rr.get("error"):
                        r = rr
                        break
                else:
                    return {"error": "not_found"}

            t = r.get("tx") or r.get("transaction") or r
            if not isinstance(t, dict):
                return {"error": "tx_bad_shape"}

            if "txid" not in t:
                t["txid"] = t.get("id") or t.get("hash") or str(txid).lower()
            if "inputs" not in t and "vin" in t:
                t["inputs"] = t.get("vin") or []
            if "outputs" not in t and "vout" in t:
                t["outputs"] = t.get("vout") or []

            if "is_coinbase" not in t:
                vin = t.get("inputs") or []
                if vin and isinstance(vin, list):
                    prev = (vin[0].get("txid") or vin[0].get("prev_txid") or "")
                    t["is_coinbase"] = (prev == "0"*64) or bool(vin[0].get("coinbase"))
            return t

        def _prov_get_address(addr: str):
            bal  = _rpc({"type": "GET_BALANCE",  "address": addr})
            bals = _rpc({"type": "GET_BALANCES", "addresses": [addr]})
            utx  = _rpc({"type": "GET_UTXOS",    "address": addr})
            his  = _rpc({"type": "GET_TX_HISTORY","address": addr})

            res = {"address": addr, "spendable": 0, "immature": 0, "pending": 0, "utxos": [], "history": []}

            def _pick_entry(d):
                if not isinstance(d, dict):
                    return None

                if any(k in d for k in ("spendable","confirmed","pending","immature")):
                    return d
                for key in ("balances","items","map"):
                    m = d.get(key)
                    if isinstance(m, dict):
                        return m.get(addr) or (list(m.values())[0] if m else {})
                if isinstance(d.get("balance"), dict):
                    return d["balance"]
                return None

            be = _pick_entry(bal) or _pick_entry(bals) or {}
            if isinstance(be, dict):
                res["spendable"] = int(be.get("spendable") or be.get("confirmed") or be.get("balance_spendable") or 0)
                res["immature"]  = int(be.get("immature")  or be.get("balance_immature")  or 0)
                res["pending"]   = int(be.get("pending")   or be.get("unconfirmed") or be.get("balance_pending") or 0)

            utxo_list = []
            if isinstance(utx, dict):
                raw = utx.get("utxos") or utx.get("items") or []
                if isinstance(raw, dict):
                    for k, v in raw.items():
                        try:
                            txid, idx = k.rsplit(":", 1); idx = int(idx)
                        except Exception:
                            txid = v.get("txid") or v.get("id") or k
                            idx  = int(v.get("index") or v.get("vout") or 0)
                        utxo_list.append({
                            "txid": txid,
                            "index": idx,
                            "amount": v.get("amount") or v.get("value") or 0,
                            "height": v.get("block_height") or v.get("height"),
                            "confirmations": v.get("confirmations"),
                        })
                elif isinstance(raw, list):
                    utxo_list = raw
            elif isinstance(utx, list):
                utxo_list = utx
            res["utxos"] = utxo_list

            if isinstance(his, list):
                res["history"] = his
            elif isinstance(his, dict):
                res["history"] = his.get("history") or his.get("items") or []

            if (res["spendable"] == 0 and res["pending"] == 0 and res["immature"] == 0) and res["utxos"]:
                try:
                    res["spendable"] = int(sum(int(u.get("amount") or 0) for u in res["utxos"]))
                except Exception:
                    pass

            return res

        def _prov_get_mempool():
            return _rpc({"type": "GET_MEMPOOL"})

        self.explore_panel.set_provider(
            get_info=_prov_get_info,
            get_block=_prov_get_block,
            get_tx=_prov_get_tx,
            get_address=_prov_get_address,
            get_mempool=_prov_get_mempool,
        )

    # ---------------- Network Frame ----------------
    
    def _build_graffiti_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["graffiti"] = f
        try:
            if GraffitiTab is None:
                raise RuntimeError("GraffitiTab missing")
            self.graffiti_tab = GraffitiTab(self, f)
            self.graffiti_tab.pack(fill="both", expand=True)
        except Exception as e:
            tk.Label(f, text=f"Graffiti UI failed: {e}", bg=self.bg, fg="red").pack(fill="both", expand=True, padx=20, pady=20)
            
    def _build_network_frame(self) -> None:
            f = tk.Frame(self.main, bg=self.bg)
            self.frames["network"] = f

            top = tk.Frame(f, bg=self.bg)
            top.pack(fill=tk.X, padx=12, pady=8)
            
            self.net_refresh_btn = tk.Button(top, text="Refresh Network Info", command=self.refresh_network_info,
                bg=self.panel_bg, fg=self.fg)
            self.net_refresh_btn.pack(side=tk.LEFT)

            self.net_text = scrolledtext.ScrolledText(f, height=20, bg=self.panel_bg, fg=self.fg, insertbackground=self.fg)
            self.net_text.bind("<Key>", lambda e: "break")
            self.net_text.bind("<<Paste>>", lambda e: "break")
            
            self.net_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

            self.net_text.tag_configure("h1",  font=("Segoe UI", 46, "bold"), foreground=self.accent, spacing3=6)
            self.net_text.tag_configure("Leaderboards",  font=("Segoe UI", 36, "bold"), foreground=self.accent, spacing3=6)
            self.net_text.tag_configure("center", justify="center")
            self.net_text.tag_configure("h2",  font=("Consolas", 17, "bold"), foreground="#F1633F", spacing3=2)
            self.net_text.tag_configure("lab", font=("Consolas", 13, "bold"), foreground="#378EC0")
            self.net_text.tag_configure("val", font=("Consolas", 11), foreground="#858585")
            self.net_text.tag_configure("mut", font=("Consolas", 10), foreground="#31C47F")
            self.net_text.tag_configure("sep", font=("Consolas", 11), foreground=self.accent)
            self.net_text.tag_configure("sep2", font=("Consolas", 11), foreground="#858585")
            # Rank-specific styles for Top #10 miners
            self.net_text.tag_configure("rank1", font=("Consolas", 17), foreground="#FFD700")  # Gold
            self.net_text.tag_configure("rank2", font=("Consolas", 15), foreground="#C0C0C0")  # Silver
            self.net_text.tag_configure("rank3", font=("Consolas", 13), foreground="#CD7F32")  # Bronze
            

    def refresh_network_info(self) -> None:
        self.net_text.delete("1.0", tk.END)
        self.net_text.insert(tk.END, "[*] Requesting network info...\n")

        if not self._busy_start("netinfo", [getattr(self, "net_refresh_btn", None)]):
            return

        pending = {"n": 2}
        store = {"snap": None, "peers": 0}

        def maybe_done():
            pending["n"] -= 1
            if pending["n"] <= 0:
                try:
                    self._render_network_snapshot(store.get("snap"), int(store.get("peers", 0)))
                except Exception as e:
                    self.net_text.insert(tk.END, f"\n[-] Render error: {e}\n")
                finally:
                    self._busy_end("netinfo")

        def on_info(resp: Optional[Dict[str, Any]]) -> None:
            try:
                if not resp:
                    self.net_text.insert(tk.END, "[-] Failed to fetch network info\n")
                    return
                if resp.get("type") == "NETWORK_INFO" and isinstance(resp.get("data"), dict):
                    store["snap"] = resp["data"]
                else:
                    store["snap"] = {
                        "schema_version": 1,
                        "identity": {},
                        "chain": {"tip_height": resp.get('height'), "total_blocks": resp.get('blocks')},
                        "transactions": {"mempool_txs": resp.get('mempool')},
                        "utxo": {"utxo_set_size": resp.get('utxos')},
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

        # Ask for rich snapshot if node supports it; older nodes return INFO
        self.rpc.send_async({"type": "GET_NETWORK_INFO"}, on_info)
        self.rpc.send_async({"type": "GET_PEERS"}, on_peers)

    # ---------- Network Info Rendering ----------
    def _fmt_num(self, x: int | float | None) -> str:
        try:
            n = int(x or 0)
            return f"{n:,}".replace(",", ".")
        except Exception:
            return str(x)

    def _fmt_tsar(self, sat: int | float | None) -> str:
        try:
            sat = int(sat or 0)
            whole = sat // CFG.TSAR
            frac  = sat % CFG.TSAR
            if frac == 0:
                return f"{self._fmt_num(whole)} TSAR"
            sfrac = str(frac).rjust(8, '0').rstrip('0')
            return f"{self._fmt_num(whole)},{sfrac} TSAR"
        except Exception:
            return str(sat)

    def _fmt_hashrate(self, hps: int | float | None) -> str:
        try:
            v = float(hps or 0)
            if v >= 1e12:
                return f"{v/1e12:.3f} TH/s".replace(",", ".")
            if v >= 1e9:
                return f"{v/1e9:.3f} GH/s".replace(",", ".")
            if v >= 1e6:
                return f"{v/1e6:.3f} MH/s".replace(",", ".")
            if v >= 1e3:
                return f"{v/1e3:.3f} kH/s".replace(",", ".")
            return f"{v:.0f} H/s".replace(",", ".")
        except Exception:
            return str(hps)

    def _fmt_time(self, ts: int | float | None) -> str:
        try:
            import datetime as _dt
            if ts is None:
                return "-"
            dt = _dt.datetime.fromtimestamp(int(ts))
            return dt.strftime("%H:%M:%S")
        except Exception:
            return str(ts)

    def _fmt_last_update(self, last_up: Any) -> str:
        try:
            import datetime as _dt
            if last_up in (None, "", "-"):
                return "-"
            dt: _dt.datetime
            if isinstance(last_up, (int, float)):
                dt = _dt.datetime.fromtimestamp(int(last_up), tz=_dt.timezone.utc)
            else:
                s = str(last_up)
                try:
                    dt = _dt.datetime.fromisoformat(s)
                except Exception:
                    if s.endswith("Z"):
                        try:
                            dt = _dt.datetime.fromisoformat(s[:-1]).replace(tzinfo=_dt.timezone.utc)
                        except Exception:
                            dt = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
                    else:
                        return s

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
        except Exception:
            try:
                return str(last_up)
            except Exception:
                return "-"

    def _render_network_snapshot(self, snap: Optional[Dict[str, Any]], peers_cnt: int) -> None:
        self.net_text.delete("1.0", tk.END)
        if not isinstance(snap, dict):
            self.net_text.insert(tk.END, "[-] Snapshot not available\n")
            return

        ident = snap.get("identity", {}) or {}
        chain = snap.get("chain", {}) or {}
        supply= snap.get("supply", {}) or {}
        txs  = snap.get("transactions", {}) or {}
        utxo = snap.get("utxo", {}) or {}
        miners = ((snap.get("miners_snapshot", {}) or {}).get("top_miners") or [])

        # Header
        self.net_text.insert(tk.END, "🌐 Network Informations 🌐", ("h1","center"))
        self.net_text.insert(tk.END, "\n")
        # Subheader line
        last_up = snap.get("last_updated") or "-"
        schema_v = snap.get("schema_version")
        last_up_fmt = self._fmt_last_update(last_up)
        sub = f"Last Update : {last_up_fmt}  |  Schema Version : {schema_v}  |  Peers : {int(peers_cnt)}\n"
        self.net_text.insert(tk.END, ("="*87) + "\n", ("sep","center"))
        self.net_text.insert(tk.END, sub, ("mut","center"))
        self.net_text.insert(tk.END, ("="*87) + "\n\n\n", ("sep","center"))

        # Network Identity
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "NETWORK IDENTITY\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, f"\nNetwork Id\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{ident.get('network_id','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Network Magic\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{ident.get('network_magic_hex','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Address Prefix\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{ident.get('address_prefix','-')}\n\n\n", ("val","center"))

        # Blockchain Informations
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "BLOCKCHAIN INFORMATIONS\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, f"\nGenesis Message\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('genesis_message','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Genesis Hash\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('genesis_hash','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Network Hashrate\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_hashrate(chain.get('est_network_hashrate_hps_window'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Average Block Time\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('avg_block_time_sec_window','-')} s\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Total Blocks\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(chain.get('total_blocks'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Tip Height\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(chain.get('tip_height'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Tip Hash\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('tip_hash','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Tip Target (hex)\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('tip_target_hex','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Tip Timestamp\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_time(chain.get('tip_timestamp'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Tip Bits\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{chain.get('tip_bits','-')}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Tip Difficulty\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(chain.get('tip_difficulty'))}\n\n\n", ("val","center"))

        # Blockchain Economy
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "BLOCKCHAIN ECONOMY\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, f"\nMax Supply\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_tsar(supply.get('max_supply'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Circulating Supply\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_tsar(supply.get('circulating_estimate'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Coinbase Reward\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_tsar(chain.get('current_block_subsidy') or supply.get('current_block_subsidy'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Maturity Rule\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{supply.get('coinbase_maturity','-')} Block\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Immature Coinbase\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_tsar(supply.get('immature_coinbase'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Emitted Subsidy\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_tsar(supply.get('emitted_subsidy'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Current Epoch\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(supply.get('current_epoch'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Halving\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(supply.get('next_halving_height'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Block To Halving\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(supply.get('blocks_to_halving'))}\n\n\n", ("val","center"))

        # Blockchain Transactions
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, "BLOCKCHAIN TRANSACTIONS\n", ("h2","center"))
        self.net_text.insert(tk.END, ("-"*45) + "\n", ("sep2","center"))
        self.net_text.insert(tk.END, f"\nTransaction On Mempool\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(txs.get('mempool_txs'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Mempool Vbytes Estimate\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(txs.get('mempool_vbytes_estimate'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Total Fee's Paid\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_tsar(txs.get('total_fees_paid'))}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"Total Transactions\n", ("lab","center"))
        total_txs = int(txs.get('total_txs') or 0)
        self.net_text.insert(tk.END, f"{self._fmt_num(total_txs)}\n\n", ("val","center"))

        # Show non-coinbase transactions under 'Transactions'
        try:
            noncb = int(txs.get('total_non_coinbase_txs')) if txs.get('total_non_coinbase_txs') is not None else total_txs
        except Exception:
            noncb = total_txs
        self.net_text.insert(tk.END, f"Transactions\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(noncb)}\n\n", ("val","center"))

        # Coinbase = total - non-coinbase
        cbt = max(total_txs - int(noncb or 0), 0)
        self.net_text.insert(tk.END, f"Coinbase Transactions\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(cbt)}\n\n", ("val","center"))
        self.net_text.insert(tk.END, f"UTXO Set Size\n", ("lab","center"))
        self.net_text.insert(tk.END, f"{self._fmt_num(utxo.get('utxo_set_size'))}\n\n\n\n", ("val","center"))

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
                    f"RANK {i:>2} : ( {addr} ) Has Found : ( {self._fmt_num(found)} ) Block\n",
                    tags,
                )
                if i < len(top):
                    self.net_text.insert(tk.END, ("-"*72) + "\n", ("sep2", "center"))
        else:
            self.net_text.insert(tk.END, "No Miners Data Found\n", ("mut","center"))


    # ---------------- Dev Frame ----------------
    def _build_dev_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["dev"] = f

        top = tk.Frame(f, bg=self.bg)
        top.pack(fill=tk.X, padx=12, pady=8)
        tk.Label(top, text="Built by Tsar Studio | Open Source on GitHub",
                 bg=self.bg, fg=self.accent, font=("Consolas", 8, "bold")).pack(side=tk.RIGHT)
        tk.Label(top, text="Kremlin Wallet v.1", bg=self.bg, fg=self.accent,
                 font=("Consolas", 8, "bold")).pack(side=tk.LEFT)

        info_area = tk.Frame(f, bg=self.bg)
        info_area.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        tk.Label(info_area, text="🌐Tsar Chain🌐", bg=self.bg, fg=self.accent,
                 font=("Segoe UI", 40, "bold")).pack(pady=(0, 0))
        tk.Label(info_area, text="--- Long Live The Voice Sovereignty Monetary System ---\n",
                 bg=self.bg, fg=self.accent, font=("Consolas", 12, "bold")).pack(pady=(0, 0))
        
        tk.Button(f, text="Open Log Viewer", command=self._open_log_viewer).pack(side=tk.RIGHT, padx=4)

        self.dev_text = scrolledtext.ScrolledText(
            info_area, height=10, bg=self.panel_bg, fg=self.fg,
            insertbackground=self.fg, font=("Consolas", 11))
        self.dev_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        self.dev_text.tag_configure("title",  font=("Consolas", 16, "bold"), foreground="#ff5e00")
        self.dev_text.tag_configure("center", justify="center")
        self.dev_text.tag_configure("info",   font=("Consolas", 10), foreground="#858585")
        self.dev_text.tag_configure("alert",  font=("Consolas", 13, "bold"), foreground="#F1633F")
        self.dev_text.tag_configure("status", font=("Consolas", 10, "bold"), foreground="#31C47F")
        self.dev_text.tag_configure("dev",    font=("Consolas", 10, "bold"), foreground="#378EC0")

        self.dev_text.insert(tk.END, "\nWhat is TsarChain?\n", ("title", "center"))
        self.dev_text.insert(tk.END, "----------------------------------\n\n", ("info", "center"))
        self.dev_text.insert(tk.END, "⚠️ This is a Voice Sovereignty chain ⚠️\n\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "A from-scratch, UTXO-based L1 that records **expressive value** graffiti, testimony, evidence—immutably.\n"
            "You pay a small TSAR fee to publish; miners timestamp it; the network verifies it forever.\n"
            "No gatekeepers. No permission. Just math, proof, and a public memory that cannot be silenced.\n",
            ("info", "center"),
        )
        self.dev_text.insert(tk.END, "\nIs \"Graffiti\" an NFT Platform?\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "\nNo. Graffiti is a permanent on-chain record—expression treated as value, not a tradable collectible.\n"
            "Each graffiti is paid with TSAR as a fee for speech; miners timestamp it, and the network verifies it forever.\n"
            "No drops, No royalties, No lamborghini, No mint/burn mechanics\nthis layer is for public memory, not marketplace hype.\n",
            ("info", "center"),
        )
        self.dev_text.insert(tk.END, "\n⚠️ Status ⚠️\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "\n-- Wallet generation (with SegWit Bech32) --\n-- Address prefix 'tsar1' --\n-- Genesis block --\n"
            "-- Proof-of-Work --\n-- Coinbase reward --\n-- UTXO system --\n-- SegWit transactions --\n"
            "-- Fee mechanism --\n-- Mempool --\n-- Multi-node networking --\n-- Transaction & block validation --\n"
            "-- Chain validation --\n-- Security layer --\n",
            ("status", "center"),
        )
        self.dev_text.insert(tk.END, "\n⚠️ Disclaimer ⚠️\n", ("alert", "center"))
        self.dev_text.insert(
            tk.END,
            "\nPublished data becomes part of the chain and cannot be removed.\n"
            "By submitting graffiti or transactions, you accept full responsibility for your content and its legality.\n"
            "This network preserves records. it does not moderate speech.\n",
            ("info", "center"),
        )
        self.dev_text.insert(tk.END, "\nDeveloper Note\n", ("alert", "center"))
        self.dev_text.insert(tk.END, "TsarChain is a lab for Voice Sovereignty.\nan engineering study of how speech can be treated as value and time-stamped as public memory.\n", ("info", "center"))
        self.dev_text.insert(tk.END, "> We don’t sell coins. we mint courage <", ("dev", "center"))
        self.dev_text.config(state="disabled")

    
    # Quick tab switcher (used by GraffitiTab Prefill)
    def switch_tab(self, name: str) -> None:
        m = {
            "wallets": self.show_wallets_frame,
            "send": self.show_send_frame,
            "chat": self.show_chat_frame,
            "history": self.show_history_frame,
            "explorer": self.show_explorer_frame,
            "network": self.show_network_frame,
            "dev": self.show_dev_frame,
            "graffiti": getattr(self, "show_graffiti_frame", self.show_wallets_frame),
        }
        fn = m.get((name or '').lower())
        if fn:
            fn()
            try: self._activate_tab(name.lower())
            except Exception: pass

# ---------------- Helpers: UI control ----------------
    def _hide_all_frames(self) -> None:
        try:
            if hasattr(self, "_chat_poll_job") and self._chat_poll_job:
                self.root.after_cancel(self._chat_poll_job)
                self._chat_poll_job = None
            if hasattr(self, "chat_tab") and getattr(self.chat_tab, "_chat_poll_job", None):
                self.root.after_cancel(self.chat_tab._chat_poll_job)
                self.chat_tab._chat_poll_job = None
        except Exception:
            pass
        for fr in self.frames.values():
            try:
                fr.pack_forget()
            except Exception:
                pass
        try:
            if hasattr(self, "explore_panel"):
                self.explore_panel.on_deactivated()
        except Exception:
            pass

    def show_wallets_frame(self) -> None:
        self._hide_all_frames()
        self.frames["wallets"].pack(fill=tk.BOTH, expand=True)

    def show_send_frame(self) -> None:
        if not self._is_wallet_ready():
            return self._show_locked_screen("Send")
        self._hide_all_frames()
        if "send" not in self.frames:
            self._build_send_frame()
        fr = self.frames["send"]
        try:
            if (not getattr(fr, "winfo_children") or len(fr.winfo_children()) == 0):
                for w in list(fr.winfo_children()):
                    try: w.destroy()
                    except Exception: pass
                self.send_tab.build(fr)
        except Exception as e:
            try:
                for w in list(fr.winfo_children()):
                    w.destroy()
            except Exception:
                pass
            tk.Label(
                fr, text=f"Send tab failed to render: {e}",
                bg=self.bg, fg=self.accent, font=("Consolas", 11, "bold")
           ).pack(anchor="w", padx=12, pady=12)
        fr.pack(fill=tk.BOTH, expand=True)
        self._activate_tab("send")
        try:
            self.reload_addresses()
            self.send_tab.on_wallets_changed(self.wallets)
            self.send_tab.on_activated()
        except Exception:
            pass
        try:
            self.root.after(0, self.refresh_all_wallets)
        except Exception:
            try:
                self.refresh_all_wallets()
            except Exception:
                pass
        
    
    def show_graffiti_frame(self) -> None:
        self._hide_all_frames()
        if "graffiti" not in self.frames:
            self._build_graffiti_frame()
        try:
            self.frames["graffiti"].pack(fill=tk.BOTH, expand=True)
        except Exception:
            pass
        try:
            self._activate_tab("graffiti")
        except Exception:
            pass

    def show_chat_frame(self) -> None:
            if not self._is_wallet_ready():
                return self._show_locked_screen("Chat")

            self._hide_all_frames()

            chat_frame = self.frames.get("chat")
            need_build = (
                chat_frame is None
                or (not hasattr(self.chat_tab, "frame") or self.chat_tab.frame is None)
                or (hasattr(self.chat_tab, "frame") and hasattr(self.chat_tab.frame, "winfo_exists") and not self.chat_tab.frame.winfo_exists()))
            if need_build:
                parent = tk.Frame(self.main, bg=self.bg)
                self.frames["chat"] = parent
                try:
                    self.chat_tab.set_palette({"bg": self.bg, "panel_bg": self.panel_bg, "fg": self.fg, "muted": self.muted, "accent": self.accent})
                    self.chat_tab.build(parent)
                except Exception as e:
                    err = tk.Label(parent, text=f"Chat UI failed: {e}", bg=self.bg, fg="red")
                    err.pack(fill="both", expand=True, padx=20, pady=20)
                chat_frame = parent
            try:
                chat_frame.pack(fill=tk.BOTH, expand=True)
            except Exception:
                pass
            try:
                self._activate_tab("chat")
            except Exception:
                pass
            try:
                self.chat_tab.reload_addresses()
            except Exception:
                pass
    
    def show_history_frame(self) -> None:
        if not self._is_wallet_ready():
            return self._show_locked_screen("History")
        self._hide_all_frames()
        if "history" not in self.frames:
            self._build_history_frame()
        try:
            if (not self.history_addr_var.get()) and self.wallets:
                self.history_addr_var.set(self.wallets[0])
        except Exception:
            pass
        self.frames["history"].pack(fill=tk.BOTH, expand=True)
        try:
            self._hist_render_from_cache()
        except Exception:
            pass

    def show_network_frame(self) -> None:
        self._hide_all_frames()
        self.frames["network"].pack(fill=tk.BOTH, expand=True)

    def show_dev_frame(self) -> None:
        self._hide_all_frames()
        self.frames["dev"].pack(fill=tk.BOTH, expand=True)

    # ---------------- UX: Request Guard / Busy Manager ----------------
    def _busy_setup(self) -> None:
        self._busy_keys: set[str] = set()
        self._busy_widgets: dict[str, list[tk.Widget]] = {}
        self._busy_timers: dict[str, str | int] = {}
        self._toasts = []

    def _set_enabled(self, w: tk.Widget, enabled: bool) -> None:
        try:
            if not hasattr(w, "_prev_state"):
                try:
                    setattr(w, "_prev_state", w.cget("state"))
                except Exception:
                    setattr(w, "_prev_state", None)

            if enabled:
                prev = getattr(w, "_prev_state", None)
                if prev is None:
                    try:
                        w.configure(state="normal")
                    except Exception:
                        pass
                else:
                    try:
                        w.configure(state=prev)
                    except Exception:
                        try:
                            w.configure(state="normal")
                        except Exception:
                            pass
            else:
                try:
                    w.configure(state="disabled")
                except Exception:
                    pass
        except Exception:
            pass

    def _busy_start(self, key: str, widgets: Sequence[tk.Widget] = ()) -> bool:
        if key in self._busy_keys:
            try: self._toast(self._busy_wait_msg(key), ms=1500, kind="info")
            except Exception: pass
            return False

        self._busy_keys.add(key)
        wl = [w for w in (widgets or []) if w]
        self._busy_widgets[key] = wl
        for w in wl:
            self._set_enabled(w, False)
        try: self.root.config(cursor="watch")
        except Exception: pass
        try: self._toast(self._busy_msg_for_key(key), ms=1200, kind="info")
        except Exception: pass
        self.root.update_idletasks()

        # safety timer: auto-unlock after 15s
        try:
            if key in self._busy_timers:
                try: self.root.after_cancel(self._busy_timers[key])
                except Exception: pass
            self._busy_timers[key] = self.root.after(15000, lambda k=key: self._busy_end(k))
        except Exception:
            pass

        return True

    def _busy_end(self, key: str) -> None:
        try:
            tid = self._busy_timers.pop(key, None)
            if tid:
                try: self.root.after_cancel(tid)
                except Exception: pass
        except Exception:
            pass

        if key not in self._busy_keys:
            return
        for w in self._busy_widgets.get(key, []):
            self._set_enabled(w, True)
        self._busy_widgets.pop(key, None)
        self._busy_keys.remove(key)
        if not self._busy_keys:
            try: self.root.config(cursor="")
            except Exception: pass
        self.root.update_idletasks()

    # ---------------- Helper UX ----------------
    def info(self, msg: str):
        self._toast(msg, kind="info")
        
    def warn(self, msg: str):
        self._toast(msg, kind="warn")
        
    def err(self,  msg: str):
        self._toast(msg, kind="error")
        
    def _open_log_viewer(self):
        log_file = str(CFG.LOG_PATH)
        try:
            open_log_toplevel(self.root, log_file=log_file, attach_to_root=False)
        except Exception:
            launch_gui_in_thread(log_file=log_file, attach_to_root=False)

    # --- Treeview hover helper ---
    def _tv_enable_hover(self, tree: "ttk.Treeview", hover_bg: str | None = None) -> None:
        try:
            if hover_bg is None:
                bg = (getattr(self, "bg", "#0f1115") or "").lower()
                hover_bg = "#1e2630" if int(bg.replace("#", "")[:2], 16) < 0x88 else "#e9eef7"

            tree.tag_configure("HOVER", background=hover_bg)

            state = {"last": None}

            def _apply_hover(iid: str | None):
                if state["last"]:
                    old_tags = set(tree.item(state["last"], "tags") or ())
                    if "HOVER" in old_tags:
                        old_tags.remove("HOVER")
                        tree.item(state["last"], tags=tuple(old_tags))
                state["last"] = iid
                if iid:
                    tags = set(tree.item(iid, "tags") or ())
                    tags.add("HOVER")
                    tree.item(iid, tags=tuple(tags))

            def on_motion(e):
                iid = tree.identify_row(e.y)
                if iid != state["last"]:
                    _apply_hover(iid)

            def on_leave(_e):
                _apply_hover(None)

            tree.bind("<Motion>", on_motion, add="+")
            tree.bind("<Leave>", on_leave, add="+")
        except Exception:
            self.log.exception("[hover] enable failed:")

    def _tv_insert_chunked(self, tv: ttk.Treeview, rows: list[tuple[tuple, tuple]], start: int = 0, chunk: int = int(os.getenv("TSAR_TV_CHUNK", "200")),) -> None:
        end = min(start + chunk, len(rows))
        insert = tv.insert
        for vals, tags in rows[start:end]:
            insert("", tk.END, values=vals, tags=tags)
        if end < len(rows):
            self.root.after(0, self._tv_insert_chunked, tv, rows, end, chunk)

    def copy_to_clipboard(self, text: str, label: str = "Copied to clipboard!") -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            messagebox.showinfo("Copied", label)
        except Exception:
            messagebox.showerror("Error", "Failed to copy to clipboard")

# ---------------- Entry point ----------------
if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    os.umask(0o077)

    setup_logging(force=True)
    native.set_py_logger(get_ctx_logger("tsarchain.native"))

    root = tk.Tk()
    try:
        root.withdraw()
        result = show_bootstrap_lockscreen(root)
        globals()["manual_bootstrap"] = result if result else None
        root.deiconify()
        app = KremlinWalletGUI(root)
        root.mainloop()

    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            messagebox.showerror("Fatal error", str(e))
        finally:
            try:
                root.destroy()
            except Exception:
                pass

