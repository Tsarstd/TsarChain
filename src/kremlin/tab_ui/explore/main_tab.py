# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import re
import time
import threading
import tkinter as tk

from datetime import datetime
from tkinter import messagebox, scrolledtext
from typing import Optional, Union, Dict, Any, Callable

from .txid_search import TxSearch
from .block_search import BlockSearch
from .address_search import AddressSearch
from .graffiti_search import GraffitiSearch

# ---------------- Local Project (With Node) ----------------
from tsarchain.utils import config as CFG
from ...theme import ExplorerTheme, get_theme, FONT

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.tab_ui.explorer.main_tab")

MONO     = ("Consolas", 10)
HINT_TEXT = "search with : (block height/txid/hash/address)"

# ---------- small helpers ----------
def _fmt_ts(ts: Optional[Union[int, float]]) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")

def _short(h: str, n: int = 10) -> str:
    if not h:
        return "-"
    h = str(h)
    if len(h) <= 2*n:
        return h
    return f"{h[:n]}…{h[-n:]}"

def _guess_kind(q: str) -> str:
    q = (q or "").strip()
    if not q:
        return "unknown"
    if q.startswith(str(CFG.ART_ID_PREFIX)) and len(q) == (CFG.ART_ID_PREFIX_LEN + CFG.ART_ID_BODY_LEN):
        return "art_id"
    if q.startswith("tsar") and len(q) >= 20:
        return "address"
    if q.isdigit() and 1 <= len(q) <= 7:
        return "block_height"
    if re.fullmatch(r"[0-9a-fA-F]{64}", q):
        return "hash64"
    return "unknown"

def _fmt_tsar_amount(v: Union[int, str, float, None]) -> str:
    if v is None:
        return "0.00000000 TSAR"
    cleaned = str(v).replace("_", "").strip()
    if not re.fullmatch(r"-?\d+", cleaned):
        return str(v)
    sat = int(cleaned)
    neg = sat < 0
    sat = abs(sat)
    whole, frac = divmod(sat, CFG.TSAR)
    s = f"{whole:,}.{frac:08d} TSAR"
    return "-" + s if neg else s


class ExplorePanel(tk.Frame):
    def __init__(self, master, app=None, theme: ExplorerTheme | None = None):
        if theme is None:
            theme = get_theme().explorer
        self.theme = theme
        self.app = app
        self.providers: Dict[str, callable] = {}
        self._active = False
        self._lock = threading.Lock()
        self._search_inflight = False
        self._last_search = ("", 0.0)

        self.bg = theme.bg
        self.card_bg = theme.card_bg
        self.border = theme.border
        self.fg = theme.fg
        self.muted = theme.muted
        self.accent = theme.accent
        self.value_num = theme.value_num
        self.value_id = theme.value_id
        self.confirm_color = theme.confirmed
        self.unconfirm_color = theme.unconfirmed

        super().__init__(master, bg=self.bg)
        self._current_graffiti_post: Optional[Dict[str, Any]] = None
        self._comment_status_var = tk.StringVar(value="")
        self._comment_text_widget: tk.Text | None = None
        self._comment_btn: tk.Button | None = None
        self._center_windows: list[tuple[tk.Widget, int]] = []

        # search/render handlers
        self.block_search = BlockSearch(self, _fmt_ts, _fmt_tsar_amount)
        self.tx_search = TxSearch(self, _fmt_tsar_amount)
        self.address_search = AddressSearch(self, _fmt_tsar_amount)
        self.graffiti_search = GraffitiSearch(self, _fmt_ts, _fmt_tsar_amount)

        # ===== Header (brand + search) =====
        self.header = tk.Frame(self, bg=self.bg)

        self.brand = tk.Label(
            self.header,
            text="♜Kremlin♜",
            bg=self.bg,
            fg=self.accent,
            font=(FONT, 65, "bold"),
        )
        self.brand.pack(side="top", pady=(10, 0))

        self.tagline = tk.Label(
            self.header,
            text="Explore the full Tsarchain ecosystem",
            bg=self.bg,
            fg=self.accent,
            font=("Consolas", 20, "italic"),
        )
        self.tagline.pack(side="top", pady=(0, 35))

        self.search_wrap = tk.Frame(self.header, bg=self.bg)
        self.search_wrap.pack(side="top")
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            self.search_wrap,
            textvariable=self.search_var,
            width=56,
            bg=self.card_bg,
            fg=self.fg,
            insertbackground=self.fg,
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.border,
            highlightcolor=self.border,
        )
        self._search_menu = tk.Menu(
            self,
            tearoff=0,
            bg=self.card_bg,
            fg=self.fg,
            activebackground=self.border,
        )

        def _do_paste():
            clip = self.clipboard_get()
            if not clip:
                return
            e = self.search_entry
            try:
                s, t = e.index("sel.first"), e.index("sel.last")
                e.delete(s, t)
                e.insert(s, clip.strip())
            except tk.TclError:
                e.insert("insert", clip.strip())

        self._search_menu.add_command(label="Paste", command=_do_paste)

        self.infoscreen = tk.Label(
            self.header,
            text=f"© {datetime.now().year} Tsar Studio\nKremlin Wallet (Ver. 0.1.0)",
            bg=self.bg,
            fg=self.muted,
            font=("Consolas", 8),
        )

        def _popup_paste(ev):
            self._search_menu.tk_popup(ev.x_root, ev.y_root)
            self._search_menu.grab_release()

        self.search_entry.bind("<Button-3>", _popup_paste)
        self.search_btn = tk.Button(
            self.search_wrap,
            text="Search",
            command=self._on_search,
            bg=self.bg,
            fg=self.accent,
            activebackground=self.accent,
            activeforeground=self.bg,
        )
        self.exit_btn = tk.Button(
            self.search_wrap,
            text="Exit",
            command=lambda: self._enter_hero(),
            bg=self.bg,
            fg=self.muted,
            activebackground=self.border,
            activeforeground=self.fg,
        )
        self.search_wrap.columnconfigure(0, weight=1)

        self._install_entry_hint(self.search_entry, HINT_TEXT)
        self.bind_all(
            "<Control-l>",
            lambda e: (
                self._enter_compact(),
                self.search_entry.focus_set(),
                self.search_entry.select_range(0, "end"),
                "break",
            ),
        )

        self.bind_all("<Escape>", lambda e: (self._enter_hero(), "break"))
        self.search_entry.bind("<Return>", lambda e: self._on_search())

        # ===== Centered Body (ala Dev) =====
        self.body = tk.Frame(self, bg=self.bg)
        self.body.pack(fill="both", expand=True, padx=0, pady=12)

        grid = tk.Frame(self.body, bg=self.bg)
        grid.pack(fill="both", expand=True)

        grid.grid_columnconfigure(0, weight=1)
        grid.grid_columnconfigure(1, weight=20)
        grid.grid_columnconfigure(2, weight=1)
        grid.grid_rowconfigure(0, weight=1)

        center = tk.Frame(grid, bg=self.bg)
        center.grid(row=0, column=1, sticky="nsew")

        self.card = tk.Frame(
            center,
            bg=self.card_bg,
            bd=1,
            highlightthickness=1,
            highlightbackground=self.border,
            highlightcolor=self.border,
        )
        self.card.pack(fill="both", expand=True, padx=16)

        self.text = scrolledtext.ScrolledText(
            self.card,
            wrap="word",
            bg=self.card_bg,
            fg=self.fg,
            insertbackground=self.fg,
            relief="flat",
            borderwidth=0,
            height=28,
        )
        self.text.pack(fill="both", expand=True, padx=18, pady=16)
        self.text.configure(cursor="arrow")
        self.text.bind("<Configure>", lambda _e=None: self._recenter_windows())

        self.text.tag_configure("title", font=(FONT, 12, "bold"))
        self.text.tag_configure("mono", font=MONO)
        self.text.tag_configure("muted", foreground=self.muted)
        self.text.tag_configure("key", foreground=self.muted)
        self.text.tag_configure("sep", foreground=self.muted)
        self.text.tag_configure("val_hex", foreground=self.value_id)
        self.text.tag_configure("val_num", foreground=self.value_num)
        self.text.tag_configure("val_addr", foreground=self.accent)
        self.text.tag_configure("val_id", foreground=self.value_id)
        self.text.tag_configure("unconfirmed", foreground=self.unconfirm_color)
        self.text.tag_configure("confirmed", foreground=self.confirm_color)
        self.text.tag_configure("center", justify="center")
        self.text.tag_configure("mono_center", font=MONO, justify="center")
        self._img_refs: list = []
        self._media_players: list = []

        self.menu = tk.Menu(
            self,
            tearoff=0,
            bg=self.card_bg,
            fg=self.fg,
            activebackground=self.border,
        )
        self.menu.add_command(label="Copy", command=self._copy_selection)
        self.text.bind("<Button-3>", self._popup_copy)
        self.text.bind("<Control-c>", lambda e: (self._copy_selection(), "break"))

        bottom = tk.Frame(self, bg=self.bg)
        bottom.pack(side="bottom", fill="x", padx=16, pady=(0, 10))
        self.status_var = tk.StringVar(value="Explore ready.")
        tk.Label(bottom, textvariable=self.status_var, bg=self.bg, fg=self.muted).pack(side="right")

        self._hero_top_spacer = tk.Frame(self, bg=self.bg, height=1)
        self._hero_bottom_spacer = tk.Frame(self, bg=self.bg, height=1)
        self.hero_mode = True
        self._enter_hero()
        

    # ---------- public API ----------
    def set_provider(self, **funcs):
        self.providers.update(funcs)

    def on_activated(self):
        self._active = True

    def on_deactivated(self):
        self._active = False

    # ---------- UI behaviors ----------
    def navigate_to_tx(self, txid: str):
        if not txid:
            return
        self._enter_compact()
        self.search_var.set(txid)
        if re.fullmatch(r"[0-9a-fA-F]{64}", txid):
            self._open_tx_or_block(txid)
        else:
            self._on_search()

    def navigate_to_art(self, art_id: str):
        if not art_id:
            return
        self._enter_compact()
        self.search_var.set(art_id)
        self._open_graffiti(art_id)
    
    def _install_entry_hint(self, entry: tk.Entry, hint: str):
        def put_hint():
            if not self.search_var.get().strip():
                entry.insert(0, hint)
                entry.config(fg=self.muted)
        def focus_in(_):
            if entry.get() == hint:
                entry.delete(0, "end")
            entry.config(fg=self.fg)
        def focus_out(_):
            if not entry.get().strip():
                put_hint()
        put_hint()
        entry.bind("<FocusIn>", focus_in)
        entry.bind("<FocusOut>", focus_out)

    def _popup_copy(self, event):
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_selection(self):
        try:
            sel = self.text.get("sel.first", "sel.last")
        except tk.TclError:
            sel = ""
        if not sel:
            return
        self.clipboard_clear()
        self.clipboard_append(sel)

    def _bind_copyable(self, widget: tk.Widget, text_getter: Callable[[], str]):
        if not hasattr(self, "_copy_menu_generic"):
            self._copy_menu_generic = tk.Menu(
                self,
                tearoff=0,
                bg=self.card_bg,
                fg=self.fg,
                activebackground=self.border,
            )
            self._copy_menu_generic.add_command(label="Copy")

        orig_bg = widget.cget("bg")
        orig_fg = widget.cget("fg") if "fg" in widget.keys() else None

        def _flash():
            try:
                widget.config(bg=self.accent, fg=self.bg if orig_fg is not None else None)
                widget.after(280, lambda: widget.config(bg=orig_bg, fg=orig_fg if orig_fg is not None else widget.cget("fg")))
            except Exception:
                return

        def do_copy(_ev=None):
            try:
                txt = text_getter() or ""
            except Exception:
                txt = ""
            if not txt:
                return None
            self.clipboard_clear()
            self.clipboard_append(txt)
            _flash()
            return "break"

        def popup(ev):
            self._copy_menu_generic.entryconfigure(0, command=lambda: do_copy())
            self._copy_menu_generic.tk_popup(ev.x_root, ev.y_root)
            self._copy_menu_generic.grab_release()
            return "break"

        widget.bind("<Button-3>", popup)
        widget.bind("<Control-c>", lambda e: (do_copy(), "break"))
        widget.bind("<Control-C>", lambda e: (do_copy(), "break"))

    # ---------- rendering helpers ----------
    def _cleanup_media_players(self):
        for player in self._media_players:
            player.dispose()
        self._media_players.clear()

    def _clear_text(self):
        self._cleanup_media_players()
        self._img_refs.clear()
        self._center_windows.clear()
        self.text.config(state="normal")
        self.text.delete("1.0", "end")

    def _bind_mousewheel_forward(self, widget):
        def _forward(event):
            delta = getattr(event, "delta", 0)
            if delta != 0:
                self.text.yview_scroll(-int(delta / 120), "units")
            else:
                step = 1 if getattr(event, "num", 0) == 5 else -1
                self.text.yview_scroll(step, "units")
            return "break"

        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            widget.bind(seq, _forward, add="+")
        for child in widget.winfo_children():
            self._bind_mousewheel_forward(child)

    def _calc_center_pad(self, target_width: int) -> int:
        self.text.update_idletasks()
        text_w = self.text.winfo_width()
        if text_w <= 0 and hasattr(self, "card"):
            self.card.update_idletasks()
            text_w = self.card.winfo_width()
        if target_width <= 0:
            target_width = text_w
        return max((text_w - target_width) // 2, 0)

    def _window_create_center(self, widget: tk.Widget, target_width: int = 760, pady: int = 6) -> None:
        pad = self._calc_center_pad(target_width)
        self.text.window_create("end", window=widget, padx=pad, pady=pady)
        self._center_windows.append((widget, target_width))

    def _recenter_windows(self) -> None:
        if not self._center_windows:
            return
        text_w = self.text.winfo_width()
        if text_w <= 0 and hasattr(self, "card"):
            self.card.update_idletasks()
            text_w = self.card.winfo_width()
        for widget, target in self._center_windows:
            if not widget.winfo_exists():
                continue
            try:
                idx = self.text.index(widget)
            except Exception:
                continue
            tgt = widget.winfo_width() or target or text_w
            pad = max((text_w - tgt) // 2, 0)
            try:
                self.text.window_configure(idx, padx=pad)
            except Exception:
                continue
    
    def _ui(self, fn, *args, **kwargs):
        self.after(0, lambda: fn(*args, **kwargs))

    def _writeln(self, s: str = "", *tags):
        self.text.insert("end", s + "\n", tags)

    def _val_tag(self, v: Union[str, int, float]) -> Optional[str]:
        s = str(v or "")
        if s.startswith("tsar"):
            return "val_addr"
        if re.fullmatch(r"[0-9a-fA-F]{64}", s):
            return "val_hex"
        s_num = s.replace("_", "").strip()
        if re.fullmatch(r"-?\d+(?:\.\d+)?", s_num):
            return "val_num"
        return None

    def _kv(self, k: str, v: str, mono=False, vtag: Optional[str]=None):
        self._writeln(f"{k}: ", "key")
        tags = []
        if mono: tags.append("mono")
        t = vtag or self._val_tag(v)
        if t: tags.append(t)
        self._writeln(f"  {v}", *tags)

    def _section(self, title: str):
        self._writeln()
        self._writeln(title, "title")
        self._writeln("—" * max(8, len(title)), "sep")

    def _finish_render(self, status: str = ""):
        self.text.config(state="disabled")
        if status:
            self.status_var.set(status)

    def _finish_search(self, ok: bool):
        # Reset inflight flag and update status
        self._search_inflight = False
        self.search_btn.config(state="normal")
        if ok:
            self.status_var.set("Search done.")
        else:
            self.status_var.set("Search finished (no result).")

    # ---------- default pages ----------
    def _render_welcome(self):
        self._enter_hero()

    def _render_overview_once(self):
        get_info = self.providers.get("get_info")
        if not callable(get_info):
            return
        def worker():
            info = get_info() or {}
            self._ui(self._render_overview, info)
        threading.Thread(target=worker, daemon=True).start()

    def _render_overview(self, info: Dict):
        self._clear_text()
        self._section("Network Overview")
        self._kv("Network", str(info.get("network", "unknown")))
        self._kv("Height", f"#{info.get('height', '-')}", mono=True, vtag="val_num")
        self._kv("Difficulty/Target", str(info.get("difficulty") or info.get("target")), mono=True)
        tip = info.get("tip") or info.get("best_hash") or "-"
        self._kv("Tip", _short(tip, 12), mono=True, vtag="val_hex")
        peers = info.get("peers") or info.get("peer_list") or []
        peers_n = peers if isinstance(peers, int) else len(peers)
        self._kv("Peers", str(peers_n), mono=True, vtag="val_num")
        mem = info.get("mempool_count") or info.get("txpool_size") or info.get("mempool")
        self._kv("Mempool", str(mem), mono=True, vtag="val_num")
        self._finish_render("Overview loaded")

    # ---------- search ----------
    def _on_search(self):
        q = (self.search_var.get() or "").strip()
        if not q or q == HINT_TEXT:
            return
        # simple debounce per query (2s)
        now = time.time()
        if self._search_inflight:
            self.status_var.set("Search in progress, please wait...")
            return
        if q == self._last_search[0] and now - self._last_search[1] < 2.0:
            self.status_var.set("Please wait a moment before searching the same item.")
            return
        
        self._last_search = (q, now)
        self._search_inflight = True
        self.search_btn.config(state="disabled")
        self.status_var.set("Searching...")
        self._enter_compact()
        kind = _guess_kind(q)
        
        if kind == "block_height":
            return self._open_block(q)
        
        if kind == "hash64":
            self._open_tx_or_block(q)
            return
        
        if kind == "address":
            return self._open_address(q)
        if kind == "art_id":
            return self._open_graffiti(q)
        
        self.status_var.set("Input not valid")
        messagebox.showinfo("Search", "Enter: block height, block hash (64 hex), TXID (64 hex), or tsar1 address...")
        
    # ---------- layout mode switchers ----------
    def _layout_search(self, hero: bool):
        for w in (self.search_entry, self.search_btn, self.exit_btn):
            w.grid_forget()
        if hero:
            self.search_entry.grid(row=0, column=0, sticky="ew", pady=(0, 6))
            self.search_btn.grid(row=1, column=0, sticky="ew")
            self.exit_btn.grid_remove()
        else:
            self.search_entry.grid(row=0, column=0, sticky="ew")
            self.search_btn.grid(row=0, column=1, padx=(6, 0))
            self.exit_btn.grid(row=0, column=2, padx=(6, 0))
        self.search_wrap.columnconfigure(0, weight=1)

    def _footer_toggle(self, show: bool):
        self.infoscreen.pack_forget()
        if show:
            self.infoscreen.pack(side="top", pady=(10, 0))

    def _enter_hero(self):
        self.hero_mode = True
        self.body.pack_forget()
        self.header.pack_forget()
        
        self._hero_top_spacer.pack(fill="both", expand=True)
        self.header.pack(padx=16, pady=(0, 0))
        self._hero_bottom_spacer.pack(fill="both", expand=True)
        # besar-kan font + tata search vertikal
        self.brand.config(font=(FONT, 65, "bold"))
        self.tagline.config(font=("Consolas", 14, "italic"))
        self._layout_search(hero=True)
        self._footer_toggle(True)
        self._clear_text()
        self._finish_render("Explore ready.")

    def _enter_compact(self):
        if not getattr(self, "hero_mode", False):
            return
        self.hero_mode = False
        for w in (self._hero_top_spacer, self._hero_bottom_spacer):
            w.pack_forget()
            
        self.header.pack_forget()
        self.header.pack(fill="x", padx=16, pady=(8, 0))
        self.brand.config(font=(FONT, 39, "bold"))
        self.tagline.config(font=("Consolas", 8, "italic"))
        self._layout_search(hero=False)
        self._footer_toggle(False)
        self.body.pack(fill="both", expand=True, padx=0, pady=12)


    # ---------- open helpers ----------
    def _open_block(self, idx: str):
        self.block_search.open_block(idx)

    def _open_tx_or_block(self, hx: str):
        self.tx_search.open_tx_or_block(hx)

    def _open_address(self, addr: str):
        self.address_search.open_address(addr)

    def _open_graffiti(self, art_id: str):
        self.graffiti_search.open_graffiti(art_id)

    # ---------- errors ----------
    def _render_error(self, msg: str):
        self._clear_text()
        self._section("Error")
        self._writeln(str(msg), "muted")
        self._finish_render("Error")
