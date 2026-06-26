# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

# ---------------- Imports (Module) ----------------
from __future__ import annotations

import os
import re
import sys
import time
import json
import random
import traceback
import tkinter as tk
import multiprocessing
import tkinter.font as tkfont
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------- Local Project (Wallet Only) ----------------
from kremlin.tab_ui.wallet_tab import WalletsMixin, load_registry
from kremlin.tab_ui.graffiti_tab import GraffitiTab
from kremlin.tab_ui.chat_tab import ChatTab
from kremlin.tab_ui.send_tab import SendTab
from kremlin.tab_ui.explore.main_tab import ExplorePanel
from kremlin.tab_ui.network_tab import NetworkTab
from kremlin.tab_ui.history_tab import HistoryTab
from kremlin.tab_ui.dev_tab import DevTab

from kremlin.security.chat.triple_xdh import ChatManager
from kremlin.security.data_security import list_addresses_in_keystore, create_keypair, WALLET_FILE

from kremlin.services.rpc_client import NodeClient
from kremlin.services.contact_management import ContactManager
from kremlin.services.send_service import SendService
from kremlin.services.tx_history import HistoryService
from kremlin.services.graffiti_service import fetch_graffiti_file

from kremlin.theme import get_theme, lighten
from kremlin.ui_utils import center_window

# ---------------- Local Project (With Node) ----------------
import tsarcore_native as native
from tsarchain.storage.kv import kv_enabled, iter_prefix, batch
from tsarchain.utils import config as CFG

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import setup_logging, open_log_toplevel, get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.gui")

# ---------------- Constants & Paths ----------------

manual_bootstrap: Optional[Tuple[str, int]] = None
os.makedirs(os.path.dirname(CFG.USER_KEY_PATH), exist_ok=True)

USER_ID, USER_PUB, USER_PRIV = create_keypair(CFG.USER_KEY_PATH)
USER_CTX = {"net_id": CFG.DEFAULT_NET_ID, "node_id": USER_ID, "pubkey": USER_PUB, "privkey": USER_PRIV}

WALLET_PEER_KEYS_PATH = os.path.join(os.path.dirname(CFG.USER_KEY_PATH), "wallet_peer_keys.json")

if not kv_enabled():
    os.makedirs(os.path.dirname(WALLET_PEER_KEYS_PATH), exist_ok=True)
    
def _load_peer_keys() -> dict:
    if kv_enabled():
        m = {}
        for k, v in iter_prefix('wallet_peer_keys', b'nid:'):
            nid = k.decode('utf-8')[4:]
            m[nid] = v.decode('utf-8')
        return m
    if not os.path.exists(WALLET_PEER_KEYS_PATH):
        _save_peer_keys({})
    try:
        with open(WALLET_PEER_KEYS_PATH, 'r', encoding='utf-8') as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        log.warning("wallet_peer_keys.json corrupted; resetting to empty")
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("failed to load wallet_peer_keys: %s", e)
        
    _save_peer_keys({})
    return {}
    
def _save_peer_keys(d: dict) -> None:
    if kv_enabled():
        with batch('wallet_peer_keys') as b:
            for nid, pk in d.items():
                b.put(f"nid:{nid}".encode('utf-8'), pk.encode('utf-8'))
        return
    os.makedirs(os.path.dirname(WALLET_PEER_KEYS_PATH), exist_ok=True)
    tmp = WALLET_PEER_KEYS_PATH + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, WALLET_PEER_KEYS_PATH)

WALLET_PEER_KEYS = _load_peer_keys()

# ---------------- Utils: Amount formatting ----------------
def sat_to_tsar(amount_satoshi: Optional[int]) -> str:
    if amount_satoshi is None:
        amount_satoshi = 0
    tsar = amount_satoshi / CFG.TSAR
    s = f"{tsar:.8f}".rstrip("0").rstrip(".")
    return f"{s} TSAR"


# ---------------- Password Lock Screen ----------------
class PasswordLockscreen(tk.Toplevel):

    def __init__(self, root: tk.Tk):
        super().__init__(root)
        self.result: Optional[str] = None
        self.configure(bg="#121212")
        self.geometry("1070x700")
        self.title("Unlock Wallet")
        self.resizable(False, False)

        lbl = tk.Label(
            self,
            text="Enter the keystore password to open the wallet.",
            bg="#121212",
            fg="#ff5e00",
            font=("Consolas", 16, "bold"),
        )
        lbl.pack(pady=(40, 12))

        self.entry = tk.Entry(self, font=("Consolas", 14), width=32, bg="#0f0f0f", fg="#ff5e00", show="*")
        self.entry.pack(pady=12)
        self.entry.bind("<Return>", self.on_unlock)

        self.error_var = tk.StringVar(value="")
        tk.Label(
            self,
            textvariable=self.error_var,
            bg="#121212",
            fg="#ff5e00",
            font=("Consolas", 11),
        ).pack(pady=(0, 18))

        btn_frame = tk.Frame(self, bg="#121212")
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame,
            text="Unlock",
            font=("Consolas", 12),
            bg="#ff5e00",
            fg="#fff",
            command=self.on_unlock,
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            btn_frame,
            text="Exit",
            font=("Consolas", 12),
            bg="#444",
            fg="#fff",
            command=self.on_cancel,
        ).pack(side=tk.LEFT, padx=10)

        center_window(self, root)
        self.entry.focus_set()

    def on_unlock(self, _event=None) -> None:
        pwd = self.entry.get().strip()
        if not pwd:
            self.error_var.set("Password is required.")
            return
        _ = list_addresses_in_keystore(pwd)

        self.result = pwd
        self.destroy()

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()
        

def should_show_password_lock() -> bool:
    if load_registry():
        return True
    return os.path.exists(WALLET_FILE) and os.path.getsize(WALLET_FILE) > 0

def show_password_lockscreen(root: tk.Tk) -> Optional[str]:
    lock = PasswordLockscreen(root)
    root.wait_window(lock)
    return lock.result


# ---------------- Main GUI ----------------
class KremlinWalletGUI(WalletsMixin):
    def __init__(self, root: tk.Tk, initial_keystore_password: Optional[str] = None):
        self.root = root

        # 0) Theme & styles
        self.current_theme = getattr(self, "current_theme", "dark")
        self._set_theme(self.current_theme)

        self._install_styles()
        self._bind_shortcuts()
        self._busy_setup()

        root.title("Kremlin")
        root.geometry("1070x700")

        # 1) RPC client - MUST be initialized before services/tabs that use RPC
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
        if initial_keystore_password:
            self._ks_pwd_cache = (initial_keystore_password, time.time() + self._ks_pwd_ttl_sec)

        self._conn_online = False
        self._balance_poll_interval_ms = 30000
        self._balance_poll_job: Optional[str] = None
        self._balance_countdown_job: Optional[str] = None
        self._balance_next_sec: int = 0

        # 4) Tab state
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
            theme=self.theme_set.contacts,
        )
        
        self.chat_tab = ChatTab(
            root=self.root,
            chat_mgr=self.chat_mgr,
            rpc_send=self.rpc.send,
            theme=self.theme_set.chat,
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
            theme=self.theme_set.send,
            on_sent=lambda addr_from: self._handle_balance_refresh_request(addresses=[addr_from], immediate=True),
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
        
    # -------------- Theme palette & styles --------------
    def _set_theme(self, mode: str | None = None) -> None:
        if mode is not None:
            self.current_theme = mode.lower()
        theme_set = get_theme(getattr(self, "current_theme", "dark"))
        self.theme_set = theme_set
        palette = theme_set.palette
        self.bg = palette.bg
        self.panel_bg = palette.panel_bg
        self.fg = palette.fg
        self.muted = palette.muted
        self.accent = palette.accent
        self.inf = palette.info
        self.border_color = palette.border
        self.card_bg = palette.card
        self.sidebar_bg = theme_set.wallet.sidebar_bg
        self.sidebar_active = theme_set.wallet.sidebar_active
        self.root.configure(bg=self.bg)

    def _install_styles(self) -> None:
        bg = getattr(self, "bg", "#0f1115")
        fg = getattr(self, "fg", "#f2f5f7")
        panel = getattr(self, "panel_bg", "#161a1f")
        accent = getattr(self, "accent", "#ff6b00")
        muted = getattr(self, "muted", "#a9b1ba")
        border = getattr(self, "border_color", "#2a2f36")
        style = ttk.Style(self.root)
        style.theme_use("clam")
        
        style.configure("Tsar.TFrame", background=bg)
        style.configure("Tsar.TLabelframe", background=bg, foreground=fg)
        style.configure("Tsar.TLabelframe.Label", background=bg, foreground=fg)
        style.configure("Tsar.TLabel", background=bg, foreground=fg)
        style.configure("Muted.TLabel", background=bg, foreground=muted)
        style.configure("Accent.TLabel", background=bg, foreground=accent)
        style.configure("Tsar.TButton", background=panel, foreground=fg, padding=6, bordercolor=border)
        style.map("Tsar.TButton", background=[("active", lighten(panel, 0.08)), ("pressed", lighten(panel, 0.12))])
        style.configure("Tsar.Vertical.TScrollbar", background=panel, troughcolor=bg)
        
        self._style = style

    def toggle_theme(self) -> None:
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self._set_theme(self.current_theme)
        self._install_styles()
        self.contact_mgr.apply_theme(self.theme_set.contacts)
        self.chat_tab.set_palette(self.theme_set.chat)
        self.send_tab.update_theme(self.theme_set.send)
        if hasattr(self, "graffiti_tab"):
            self.graffiti_tab.apply_theme(self.theme_set.graffiti)
            
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
        title = f"🔒’ {source} is Locked" if source else "🔒 Locked"
        self._lock_title.config(text=title)
        self._lock_sub.config(text="Create or Load Your Wallet First")
        self.frames["locked"].pack(fill=tk.BOTH, expand=True)

    def _maybe_lock_redirect(self) -> None:
        if (not self._is_wallet_ready()) and getattr(self, "_active_tab", "") in ("send", "chat", "history"):
            self._show_locked_screen(self._active_tab.capitalize())


    # --- Sidebar active/hover state ---
    
    def _activate_tab(self, tab: str) -> None:
        self._active_tab = tab
        self._refresh_sidebar_styles()

    def _refresh_sidebar_styles(self) -> None:
        active_fg = self.bg if self.current_theme == "dark" else self.fg
        for tab, btn in getattr(self, "_sidebar_buttons", {}).items():
            if not btn or not btn.winfo_exists():
                continue
            if tab == getattr(self, "_active_tab", ""):
                btn.configure(
                    bg=self.sidebar_active,
                    fg=active_fg,
                    activebackground=self.sidebar_active,
                    activeforeground=active_fg,
                )
            else:
                btn.configure(
                    bg=self.sidebar_bg,
                    fg=self.fg,
                    activebackground=self.sidebar_active,
                    activeforeground=active_fg,
                )

    def _create_sidebar_button(self, text: str, tab: str, on_click) -> tk.Button:
        active_fg = self.bg if self.current_theme == "dark" else self.fg
        btn = tk.Button(
            self.sidebar,
            text=text,
            command=lambda: (on_click(), self._activate_tab(tab)),
            bg=self.sidebar_bg,
            fg=self.fg,
            font=("Segoe UI", 10, "bold"),
            bd=0,
            relief=tk.FLAT,
            padx=8,
            pady=8,
            highlightthickness=0,
            cursor="hand2",
            activebackground=self.sidebar_active,
            activeforeground=active_fg,
        )

        def _hover_in(_e):
            if tab != getattr(self, "_active_tab", ""):
                btn.configure(bg=self.sidebar_active, fg=active_fg)

        def _hover_out(_e):
            if tab != getattr(self, "_active_tab", ""):
                btn.configure(bg=self.sidebar_bg, fg=self.fg)

        btn.bind("<Enter>", _hover_in)
        btn.bind("<Leave>", _hover_out)

        if not hasattr(self, "_sidebar_buttons"):
            self._sidebar_buttons = {}
        self._sidebar_buttons[tab] = btn
        btn.pack(pady=(12, 6))
        return btn

    @staticmethod
    def _widget_exists(widget) -> bool:
        return bool(widget) and widget.winfo_exists()

    def _build_layout(self) -> None:
        self.sidebar = tk.Frame(self.root, bg=self.sidebar_bg, width=100)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.main = tk.Frame(self.root, bg=self.bg)
        self.main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(self.sidebar, text="Kremlin", bg=self.sidebar_bg, fg=self.accent,
                 font=("Segoe UI", 17, "bold")).pack(pady=(12, 6))

        self._sidebar_buttons = {}
        self._create_sidebar_button("Wallets",  "wallets",  self.show_wallets_frame)
        self._create_sidebar_button("Send",     "send",     self.show_send_frame)
        self._create_sidebar_button("History",  "history",  self.show_history_frame)
        self._create_sidebar_button("Chat",     "chat",     self.show_chat_frame)
        self._create_sidebar_button("Graffiti",  "graffiti",  self.show_graffiti_frame)
        self._create_sidebar_button("Explorer", "explorer", self.show_explorer_frame)
        self._create_sidebar_button("Network",  "network",  self.show_network_frame)
        self._create_sidebar_button("Dev",      "dev",      self.show_dev_frame)

        active_fg = self.bg if self.current_theme == "dark" else self.fg
        tk.Button(
            self.sidebar,
            text="Switch Theme",
            command=self.toggle_theme,
            bg=self.sidebar_bg,
            fg=self.fg,
            bd=0,
            relief=tk.FLAT,
            padx=8,
            pady=8,
            highlightthickness=0,
            cursor="hand2",
            activebackground=self.sidebar_active,
            activeforeground=active_fg,
        ).pack(side=tk.BOTTOM, pady=10)

        palette = getattr(self.theme_set, "palette", None)
        offline_color = palette.danger if palette else "#d41c1c"
        self.conn_status = tk.Label(self.sidebar, text="Offline", bg=self.sidebar_bg,
                                    fg=offline_color, font=("Segoe UI", 9, "bold"))
        self.conn_status.pack(side=tk.BOTTOM, pady=(0, 12))

        self.frames: Dict[str, tk.Frame] = {}

        
        # ---------------- UX: Toast (non-blocking) ----------------
    def _toast(self, text: str, ms: int = 1800, kind: str = "info") -> None:
        if isinstance(ms, str):
            kind = ms
            ms = 1800
        ms = int(ms)
        if not hasattr(self, "_toasts"):
            self._toasts = []
        self.root.update_idletasks()
        tw = tk.Toplevel(self.root)
        tw.withdraw()
        tw.overrideredirect(True)
        tw.attributes("-topmost", True)
        tw.attributes("-alpha", 0.96)

        palette = getattr(self, "theme_set", None).palette if hasattr(self, "theme_set") else None
        warn_color = palette.warning if palette else "#f5a524"
        error_color = palette.danger if palette else "#f1633f"
        info_color = self.accent
        border = {"info": info_color, "warn": warn_color, "error": error_color}.get(kind, info_color)
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
            tw.destroy()
            self._toasts.remove(tw)

        tw.after(ms, _close)

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

    # ---------------- Connection status (UI + heartbeat) ----------------
    def _set_conn_status(self, ok: bool) -> None:
        prev = getattr(self, "_conn_online", False)
        self._conn_online = bool(ok)
        palette = getattr(self.theme_set, "palette", None)
        ok_color = palette.success if palette else "#17c964"
        fail_color = palette.danger if palette else "#d41c1c"
        if self._conn_online:
            self.conn_status.config(text="Connected", fg=ok_color)
        else:
            self.conn_status.config(text="Offline", fg=fail_color)

        if self._conn_online and not prev:
            if self._balance_poll_job:
                self.root.after_cancel(self._balance_poll_job)
                self._balance_poll_job = None
            if getattr(self, "wallets", []):
                def _reschedule() -> None:
                    self._schedule_balance_refresh()
                self._request_balance_update(on_complete=_reschedule)
            else:
                self._schedule_balance_refresh()

    def _start_conn_heartbeat(self, interval_ms: int = 10000) -> None:
        self._conn_hb_interval = int(max(1000, interval_ms))
        if hasattr(self, "_conn_hb_job") and self._conn_hb_job:
            self.root.after_cancel(self._conn_hb_job)
            self._conn_hb_job = None

        def _next_delay() -> int:
            jitter = 0.2
            return int(self._conn_hb_interval * (1 + random.uniform(-jitter, jitter)))

        def _tick():
            self._conn_hb_job = None
            def _on(resp: Optional[Dict[str, Any]]) -> None:
                ok = bool(resp and not resp.get("error"))
                self._set_conn_status(ok)

            self.rpc.send_async({"type": "PING"}, _on)
            self._conn_hb_job = self.root.after(_next_delay(), _tick)
        self._conn_hb_job = self.root.after(600, _tick)

    # ---------------- Balance refresh helpers ----------------
    def _set_balance_refresh_label(self, text: str) -> None:
        if getattr(self, "wallet_refresh_label", None):
            self.wallet_refresh_label.config(text=text)

    def _cancel_balance_countdown(self) -> None:
        if self._balance_countdown_job:
            self.root.after_cancel(self._balance_countdown_job)
            self._balance_countdown_job = None

    def _start_balance_countdown(self, seconds: int) -> None:
        self._cancel_balance_countdown()
        self._balance_next_sec = max(int(seconds), 0)

        def _tick():
            if self._balance_next_sec <= 0:
                self._set_balance_refresh_label("Refresh: now")
                self._balance_countdown_job = None
                return
            self._set_balance_refresh_label(f"Refresh: {self._balance_next_sec}s")
            self._balance_next_sec -= 1
            self._balance_countdown_job = self.root.after(1000, _tick)

        _tick()

    def _cancel_balance_poll(self) -> None:
        if self._balance_poll_job:
            self.root.after_cancel(self._balance_poll_job)
            self._balance_poll_job = None
        self._cancel_balance_countdown()
        self._set_balance_refresh_label("Refresh: paused")

    def _schedule_balance_refresh(self, delay_ms: Optional[int] = None) -> None:
        if delay_ms is None:
            delay_ms = self._balance_poll_interval_ms
        delay = int(max(0, delay_ms))
        if self._balance_poll_job:
            self.root.after_cancel(self._balance_poll_job)
        self._balance_poll_job = self.root.after(delay, self._run_balance_poll)
        self._start_balance_countdown(delay // 1000)

    def _run_balance_poll(self) -> None:
        self._balance_poll_job = None
        if not self._conn_online:
            self._schedule_balance_refresh()
            return
        if not getattr(self, "wallets", []):
            self._schedule_balance_refresh()
            return

        def _reschedule() -> None:
            self._schedule_balance_refresh()

        self._request_balance_update(on_complete=_reschedule)

    def _handle_balance_refresh_request(
        self,
        addresses: Optional[Sequence[str]] = None,
        immediate: bool = False,
    ) -> None:
        addrs = [a for a in addresses if a] if addresses else None

        if immediate:
            if self._conn_online:
                self._request_balance_update(addresses=addrs)
                if self._active_tab == "wallets" and self._balance_poll_job is None:
                    self._schedule_balance_refresh()
                else:
                    self._cancel_balance_countdown()
            return

        if self._conn_online:
            if addrs:
                self._request_balance_update(addresses=addrs)
            if self._balance_poll_job is None:
                self._schedule_balance_refresh()

    # ---------------- Send Tab ----------------
    def _build_send_frame(self) -> None:
        fr = ttk.Frame(self.main, style="Tsar.TFrame")
        self.frames["send"] = fr
        self.send_tab.update_theme(self.theme_set.send)
        self.send_tab.build(fr)

    def reload_addresses(self) -> None:
        values = list(self.wallets or [])

        if self._widget_exists(getattr(self, "wallet_count_label", None)):
            self.wallet_count_label.config(text=f"Wallets: {len(values)}")

        history_tab = getattr(self, "history_tab", None)
        if self._widget_exists(history_tab):
            history_tab.reload_addresses(values)

        if hasattr(self, "chat_tab"):
            self.chat_tab.reload_addresses()

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
        a = addr.strip().lower()
        self.chat_mgr.priv_cache.pop(a, None)
        if getattr(self, "_chat_poll_job", None):
            self.root.after_cancel(self._chat_poll_job)
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
        _ = list_addresses_in_keystore(pwd)
        self._ks_pwd_cache = (pwd, time.time() + self._ks_pwd_ttl_sec)
        return pwd

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
        raw = (self.send_to_combo.get() or "").strip()
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
        tab = HistoryTab(self, self.exp_svc, master=self.main)
        self.frames["history"] = tab
        self.history_tab = tab

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
        self.explore_panel = ExplorePanel(f, app=self, theme=self.theme_set.explorer)
        self.explore_panel.pack(fill=tk.BOTH, expand=True)

        # ---------- helper RPC ----------
        def _rpc(payload: dict):
            return self.rpc.send(payload)

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
            s = str(x).strip()
            if re.fullmatch(r"\d+", s):
                h = int(s)
                blk = _rpc({"type": "GET_BLOCK", "height": h})
                if isinstance(blk, dict) and blk and not blk.get("error"):
                    blk.setdefault("height", h)
                return blk

            if re.fullmatch(r"[0-9a-fA-F]{64}", s):
                r = _rpc({"type": "GET_BLOCK", "hash": s})
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

            be = _pick_entry(bals) or {}
            if isinstance(be, dict):
                res["spendable"] = int(be.get("spendable") or be.get("confirmed") or be.get("balance_spendable") or 0)
                res["immature"]  = int(be.get("immature")  or be.get("balance_immature")  or 0)
                res["pending"]   = int(be.get("pending")   or be.get("unconfirmed") or be.get("balance_pending") or 0)

            utxo_list = []
            if isinstance(utx, dict):
                raw = utx.get("utxos") or utx.get("items") or []
                if isinstance(raw, dict):
                    for k, v in raw.items():
                        txid, idx = k.rsplit(":", 1); idx = int(idx)
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
                res["spendable"] = int(sum(int(u.get("amount") or 0) for u in res["utxos"]))
            return res

        def _prov_get_mempool():
            return _rpc({"type": "GET_MEMPOOL"})

        def _prov_get_graffiti(art_id: str):
            return _rpc({"type": "GRAFFITI_GET_ART", "art_id": art_id})

        def _prov_get_graffiti_comments(art_id: str):
            return _rpc({"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id})

        def _prov_fetch_graffiti_file(post: dict | None, art_id: str):
            aid = art_id or (post or {}).get("art_id") or ""
            storer_addr = (post or {}).get("storer") or (post or {}).get("storage")
            return fetch_graffiti_file(_rpc, aid, storer_addr=storer_addr)

        self.explore_panel.set_provider(
            get_info=_prov_get_info,
            get_block=_prov_get_block,
            get_tx=_prov_get_tx,
            get_address=_prov_get_address,
            get_mempool=_prov_get_mempool,
            get_graffiti=_prov_get_graffiti,
            get_graffiti_comments=_prov_get_graffiti_comments,
            fetch_graffiti_file=_prov_fetch_graffiti_file,
        )

    # ---------------- Graffiti Frame ----------------
    
    def _build_graffiti_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["graffiti"] = f
        self.graffiti_tab = GraffitiTab(self, self.theme_set.graffiti, master=f)
        self.graffiti_tab.pack(fill="both", expand=True)
            
    # ---------------- Network Frame ----------------
    def _build_network_frame(self) -> None:
        tab = NetworkTab(self, master=self.main)
        self.frames["network"] = tab
        self.network_tab = tab

    # ---------------- Dev Frame ----------------
    def _build_dev_frame(self) -> None:
        tab = DevTab(self, master=self.main)
        self.frames["dev"] = tab
        self.dev_tab = tab

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
            self._activate_tab(name.lower())

# ---------------- Helpers: UI control ----------------
    def _hide_all_frames(self) -> None:
        if hasattr(self, "_chat_poll_job") and self._chat_poll_job:
            self.root.after_cancel(self._chat_poll_job)
            self._chat_poll_job = None
        if hasattr(self, "chat_tab") and getattr(self.chat_tab, "_chat_poll_job", None):
            self.root.after_cancel(self.chat_tab._chat_poll_job)
            self.chat_tab._chat_poll_job = None
        for fr in self.frames.values():
            fr.pack_forget()
        if hasattr(self, "explore_panel"):
            self.explore_panel.on_deactivated()
        if hasattr(self, "network_tab"):
            self.network_tab.on_hide()

    def show_wallets_frame(self) -> None:
        self._hide_all_frames()
        # mark active tab early so schedulers see the right state
        self._active_tab = "wallets"
        self._refresh_sidebar_styles()
        self.frames["wallets"].pack(fill=tk.BOTH, expand=True)
        if self._conn_online:
            if self._balance_poll_job or self._balance_countdown_job:
                if self._balance_next_sec > 0:
                    self._set_balance_refresh_label(f"Refresh: {self._balance_next_sec}s")
                else:
                    self._set_balance_refresh_label("Refresh: now")
            else:
                self._schedule_balance_refresh()
        else:
            self._set_balance_refresh_label("Refresh: offline")

    def show_send_frame(self) -> None:
        if not self._is_wallet_ready():
            return self._show_locked_screen("Send")
        self._hide_all_frames()
        if "send" not in self.frames:
            self._build_send_frame()
        fr = self.frames["send"]
        if (not getattr(fr, "winfo_children") or len(fr.winfo_children()) == 0):
            for w in list(fr.winfo_children()):
                w.destroy()
            self.send_tab.build(fr)
            for w in list(fr.winfo_children()):
                w.destroy()
            tk.Label(
                fr, text=f"Send tab failed to render: {e}",
                bg=self.bg, fg=self.accent, font=("Consolas", 11, "bold")
           ).pack(anchor="w", padx=12, pady=12)
        fr.pack(fill=tk.BOTH, expand=True)
        self._activate_tab("send")
        self.reload_addresses()
        self.send_tab.on_wallets_changed(self.wallets)
        self.send_tab.on_activated()
    
    def show_graffiti_frame(self) -> None:
        self._hide_all_frames()
        if "graffiti" not in self.frames:
            self._build_graffiti_frame()
        self.frames["graffiti"].pack(fill=tk.BOTH, expand=True)
        self._activate_tab("graffiti")

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
                self.chat_tab.set_palette(self.theme_set.chat)
                self.chat_tab.build(parent)
                chat_frame = parent
            chat_frame.pack(fill=tk.BOTH, expand=True)
            self._activate_tab("chat")
            self.chat_tab.reload_addresses()
            if getattr(self.chat_tab, "_chat_online", False):
                self.chat_tab._chat_schedule_next()
    
    def show_history_frame(self) -> None:
        if not self._is_wallet_ready():
            return self._show_locked_screen("History")

        self._hide_all_frames()
        history_frame = self.frames.get("history")
        if history_frame is None or not self._widget_exists(history_frame):
            self._build_history_frame()
            history_frame = self.frames["history"]

        history_frame.reload_addresses(self.wallets)
        history_frame.on_show()
        history_frame.pack(fill=tk.BOTH, expand=True)
        self._activate_tab("history")

    def show_network_frame(self) -> None:
        self._hide_all_frames()
        self.frames["network"].pack(fill=tk.BOTH, expand=True)
        if hasattr(self, "network_tab"):
            self.network_tab.on_show()

    def show_dev_frame(self) -> None:
        self._hide_all_frames()
        self.frames["dev"].pack(fill=tk.BOTH, expand=True)

    # ---------------- UX: Request Guard / Busy Manager ----------------
    def _busy_setup(self) -> None:
        self._busy_keys: set[str] = set()
        self._busy_widgets: dict[str, list[tk.Widget]] = {}
        self._busy_timers: dict[str, str | int] = {}
        self._toasts = []
        self._balance_countdown_job = None
        self._balance_next_sec = 0

    def _set_enabled(self, w: tk.Widget, enabled: bool) -> None:
        if not hasattr(w, "_prev_state"):
            setattr(w, "_prev_state", w.cget("state"))

        if enabled:
            prev = getattr(w, "_prev_state", None)
            if prev is None:
                w.configure(state="normal")
            else:
                w.configure(state=prev)
        else:
            w.configure(state="disabled")

    def _busy_start(self, key: str, widgets: Sequence[tk.Widget] = ()) -> bool:
        if key in self._busy_keys:
            self._toast(self._busy_wait_msg(key), ms=1500, kind="info")
            return False

        self._busy_keys.add(key)
        wl = [w for w in (widgets or []) if w]
        self._busy_widgets[key] = wl
        for w in wl:
            self._set_enabled(w, False)
        self.root.config(cursor="watch")
        self._toast(self._busy_msg_for_key(key), ms=1200, kind="info")
        self.root.update_idletasks()

        # safety timer: auto-unlock after 15s
        if key in self._busy_timers:
            self.root.after_cancel(self._busy_timers[key])
        self._busy_timers[key] = self.root.after(15000, lambda k=key: self._busy_end(k))

        return True

    def _busy_end(self, key: str) -> None:
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

    # ---------------- Helper UX ----------------
    def info(self, msg: str):
        self._toast(msg, kind="info")
        
    def warn(self, msg: str):
        self._toast(msg, kind="warn")
        
    def err(self,  msg: str):
        self._toast(msg, kind="error")
        
    def _open_log_viewer(self):
        log_file = "logging/wallet.log"
        open_log_toplevel(self.root, log_file=log_file, attach_to_root=False)

    # --- Treeview hover helper ---
    def _tv_enable_hover(self, tree: "ttk.Treeview", hover_bg: str | None = None) -> None:
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

    def _tv_insert_chunked(self, tv: ttk.Treeview, rows: list[tuple[tuple, tuple]], start: int = 0, chunk: int = int(os.getenv("TSAR_TV_CHUNK", "200")),) -> None:
        end = min(start + chunk, len(rows))
        insert = tv.insert
        for vals, tags in rows[start:end]:
            insert("", tk.END, values=vals, tags=tags)
        if end < len(rows):
            self.root.after(0, self._tv_insert_chunked, tv, rows, end, chunk)

    def copy_to_clipboard(self, text: str, label: str = "Copied to clipboard!") -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", label)

# ---------------- Entry point ----------------
if __name__ == "__main__":
    multiprocessing.freeze_support()
    os.umask(0o077)

    setup_logging("logging/wallet.log", force=True)
    native.set_py_logger(get_ctx_logger("tsarchain.native"))

    root = tk.Tk()
    try:
        root.withdraw()
        initial_password: Optional[str] = None
        if should_show_password_lock():
            initial_password = show_password_lockscreen(root)
            if initial_password is None:
                root.destroy()
                sys.exit(0)
        root.deiconify()
        app = KremlinWalletGUI(root, initial_keystore_password=initial_password)
        root.mainloop()

    except Exception as e:
        log.exception("Unhandled exception")
        traceback.print_exc()
        try:
            messagebox.showerror("Fatal error", str(e))
        finally:
            root.destroy()
