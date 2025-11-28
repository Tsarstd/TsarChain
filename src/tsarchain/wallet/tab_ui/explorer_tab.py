# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: Merkle
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from typing import Optional, Union, Dict
import re

# ---------------- Local Project (With Node) ----------------
from tsarchain.utils import config as CFG
from ..theme import ExplorerTheme, get_theme


MONO     = ("Consolas", 10)
HINT_TEXT = "search with : (block height/txid/hash/address)"

# ---------- small helpers ----------
def _fmt_ts(ts: Optional[Union[int, float]]) -> str:
    if ts is None:
        return "-"
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

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
    if q.startswith("tsar") and len(q) >= 20:
        return "address"
    if q.isdigit() and 1 <= len(q) <= 7:
        return "block_height"
    if re.fullmatch(r"[0-9a-fA-F]{64}", q):
        # 64 hex starting with "00" treated as block hash (e.g., genesis), otherwise assume TXID
        return "block_hash" if q.startswith("00") else "txid_hash"
    return "unknown"

def _fmt_tsar_amount(v: Union[int, str, float, None]) -> str:
    if v is None:
        return "0.00000000 TSAR"
    try:
        sat = int(str(v).replace("_", "").strip())
    except Exception:
        return str(v)
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

        # ===== Header (brand + search) =====
        self.header = tk.Frame(self, bg=self.bg)

        self.brand = tk.Label(
            self.header,
            text="♜Kremlin♜",
            bg=self.bg,
            fg=self.accent,
            font=("Segoe UI", 65, "bold"),
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
            try:
                clip = self.clipboard_get()
            except Exception:
                clip = ""
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

        self.text = tk.Text(
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

        self._vsb = ttk.Scrollbar(self.card, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=self._vsb.set)
        self._vsb.pack(side="right", fill="y")

        def _wheel(e):
            if getattr(e, "delta", 0) != 0:
                self.text.yview_scroll(-int(e.delta / 120), "units")
            else:
                self.text.yview_scroll(1 if getattr(e, "num", 0) == 5 else -1, "units")
            return "break"

        self.text.bind("<MouseWheel>", _wheel)
        self.text.bind("<Button-4>", _wheel)
        self.text.bind("<Button-5>", _wheel)
        self.text.configure(cursor="arrow")

        self.text.tag_configure("title", font=("Segoe UI", 12, "bold"))
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
            self._open_tx(txid)
        else:
            self._on_search()
    
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

    # ---------- rendering helpers ----------
    def _clear_text(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
    
    def _ui(self, fn, *args, **kwargs):
        self.after(0, lambda: fn(*args, **kwargs))
        
    def _ensure_txid_64(self, s: str) -> bool:
        ok = bool(re.fullmatch(r"[0-9a-fA-F]{64}", s or ""))
        if not ok:
            # render via main thread
            self._ui(self._render_error, f"TxID must be 64 hex. Input length: {len(s or '')} characters")
        return ok

    def _writeln(self, s: str = "", *tags):
        self.text.insert("end", s + "\n", tags)

    def _val_tag(self, v: Union[str, int, float]) -> Optional[str]:
        s = str(v or "")
        if s.startswith("tsar"):
            return "val_addr"
        if re.fullmatch(r"[0-9a-fA-F]{64}", s):
            return "val_hex"
        try:
            float(s.replace("_",""))
            return "val_num"
        except Exception:
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
        try:
            self.search_btn.config(state="normal")
        except Exception:
            pass
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
            try:
                info = get_info() or {}
            except Exception as e:
                return self._ui(self._render_error, f"get_info error: {e}")
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
        import time
        now = time.time()
        if self._search_inflight:
            self.status_var.set("Search in progress, please wait...")
            return
        if q == self._last_search[0] and now - self._last_search[1] < 2.0:
            self.status_var.set("Please wait a moment before searching the same item.")
            return
        self._last_search = (q, now)
        self._search_inflight = True
        try:
            self.search_btn.config(state="disabled")
        except Exception:
            pass
        self.status_var.set("Searching...")
        self._enter_compact()
        kind = _guess_kind(q)
        if kind == "block_height":
            return self._open_block(q)
        if kind == "block_hash":
            return self._open_block(q)
        if kind == "txid_hash":
            q = (self.search_var.get() or "").strip()
            if not self._ensure_txid_64(q):
                self._search_inflight = False
                return
            return self._open_tx(q)
        if kind == "address":
            return self._open_address(q)
        self.status_var.set("Input tidak dikenali, isi block height/hash/txid/alamat.")
        self._search_inflight = False
        messagebox.showinfo("Search", "Enter: block height, block hash (64 hex starting with 0000...), TXID (64 hex), or tsar1 address...")
        
    # ---------- layout mode switchers ----------
    def _layout_search(self, hero: bool):
        for w in (self.search_entry, self.search_btn, self.exit_btn):
            try: w.grid_forget()
            except Exception:
                pass
        if hero:
            self.search_entry.grid(row=0, column=0, sticky="ew", pady=(0, 6))
            self.search_btn.grid(row=1, column=0, sticky="ew")
            try: self.exit_btn.grid_remove()
            except Exception:
                pass
        else:
            self.search_entry.grid(row=0, column=0, sticky="ew")
            self.search_btn.grid(row=0, column=1, padx=(6, 0))
            self.exit_btn.grid(row=0, column=2, padx=(6, 0))
        self.search_wrap.columnconfigure(0, weight=1)

    def _footer_toggle(self, show: bool):
        try:
            self.infoscreen.pack_forget()
        except Exception:
            pass
        if show:
            self.infoscreen.pack(side="top", pady=(10, 0))

    def _enter_hero(self):
        self.hero_mode = True
        try:
            self.body.pack_forget()
        except Exception:
            pass
        try:
            self.header.pack_forget()
        except Exception:
            pass
        self._hero_top_spacer.pack(fill="both", expand=True)
        self.header.pack(padx=16, pady=(0, 0))
        self._hero_bottom_spacer.pack(fill="both", expand=True)
        # besar-kan font + tata search vertikal
        self.brand.config(font=("Segoe UI", 65, "bold"))
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
            try: w.pack_forget()
            except Exception: pass
        try:
            self.header.pack_forget()
        except Exception:
            pass
        self.header.pack(fill="x", padx=16, pady=(8, 0))
        self.brand.config(font=("Segoe UI", 39, "bold"))
        self.tagline.config(font=("Consolas", 8, "italic"))
        self._layout_search(hero=False)
        self._footer_toggle(False)
        try:
            self.body.pack(fill="both", expand=True, padx=0, pady=12)
        except Exception:
            pass


    # ---------- open helpers ----------
    def _open_block(self, idx: str):
        get_block = self.providers.get("get_block")
        if not callable(get_block):
            self._render_error("Provider get_block not available")
            self._finish_search(False)
            return
        def worker():
            done = False
            try:
                b = get_block(idx)
                if not b or (isinstance(b, dict) and b.get("error")):
                    self._ui(self._render_error, "Block not found")
                else:
                    done = True
                    self._ui(self._render_block, b)
            except Exception as e:
                self._ui(self._render_error, f"get_block error: {e}")
            finally:
                self._ui(self._finish_search, done)
        threading.Thread(target=worker, daemon=True).start()

    def _open_tx(self, txid: str):
        get_tx = self.providers.get("get_tx")
        if not callable(get_tx):
            self._render_error("Provider get_tx not available")
            self._finish_search(False)
            return
        def worker():
            done = False
            try:
                t = get_tx(txid)
                if not isinstance(t, dict) or t.get("error"):
                    self._ui(self._render_error, "Tx not found")
                else:
                    if "tx" in t and isinstance(t["tx"], dict): t = t["tx"]
                    if "transaction" in t and isinstance(t["transaction"], dict): t = t["transaction"]
                    if "inputs" not in t and "vin" in t:  t["inputs"]  = t["vin"]
                    if "outputs" not in t and "vout" in t: t["outputs"] = t["vout"]
                    if "txid" not in t: t["txid"] = t.get("id") or t.get("hash") or txid
                    done = True
                    self._ui(self._render_tx, t["txid"], t)
            except Exception as e:
                self._ui(self._render_error, f"get_tx error: {e}")
            finally:
                self._ui(self._finish_search, done)
        threading.Thread(target=worker, daemon=True).start()

    def _open_tx_or_block(self, hx: str):
        get_tx = self.providers.get("get_tx")
        get_block = self.providers.get("get_block")
        if not callable(get_block) and not callable(get_tx):
            self._render_error("Providers not available")
            self._finish_search(False)
            return

        def worker():
            done = False
            b = None
            if callable(get_block):
                try:
                    b = get_block(hx)
                except Exception as e:
                    self._ui(self._render_error, f"get_block error: {e}")
            if isinstance(b, dict) and b and not b.get("error") and (b.get("hash") or b.get("transactions") or b.get("tx")):
                done = True
                self._ui(self._render_block, b)
                self._ui(self._finish_search, True)
                return

            if callable(get_tx):
                try:
                    t = get_tx(hx)
                except Exception as e:
                    self._ui(self._render_error, f"get_tx error: {e}")
                    self._ui(self._finish_search, False)
                    return

                if isinstance(t, dict) and not t.get("error"):
                    if "tx" in t and isinstance(t["tx"], dict):
                        t = t["tx"]
                    elif "transaction" in t and isinstance(t["transaction"], dict):
                        t = t["transaction"]
                    if "inputs" not in t and "vin" in t:
                        t["inputs"] = t.get("vin") or []
                    if "outputs" not in t and "vout" in t:
                        t["outputs"] = t.get("vout") or []

                    txid_disp = t.get("txid") or t.get("id") or t.get("hash") or hx
                    done = True
                    self._ui(self._render_tx, txid_disp, t)
                    self._ui(self._finish_search, True)
                    return
                    
            self._ui(self._render_error, "Not found")
            self._ui(self._finish_search, done)
        threading.Thread(target=worker, daemon=True).start()

    def _open_address(self, addr: str):
        get_address = self.providers.get("get_address")
        if not callable(get_address):
            return self._render_error("Provider get_address not available")
        def worker():
            try:
                a = get_address(addr)
            except Exception as e:
                return self._ui(self._render_error, f"get_address error: {e}")
            if not a:
                return self._ui(self._render_error, "Address not found")
            self._ui(self._render_address, addr, a)
        threading.Thread(target=worker, daemon=True).start()


    # ---------- renderers ----------
    def _render_block(self, b: Dict):
        self._clear_text()
        meta = b.get("_meta") if isinstance(b, dict) else {}

        def _pick(*keys):
            for k in keys:
                v = b.get(k) if isinstance(b, dict) else None
                if v is None and isinstance(meta, dict):
                    v = meta.get(k)
                if v not in (None, ""):
                    return v
            return None

        h     = _pick("height", "index") or "Genesis"
        hh    = _pick("hash")
        blkid = _pick("block_id")
        ts    = _fmt_ts(_pick("timestamp", "time"))
        prev  = _pick("prev_block_hash", "prev_hash", "previous_hash", "previousblockhash")
        nn    = _pick("nonce")
        dif   = _pick("difficulty")
        bits  = _pick("bits")
        ver   = _pick("version")
        mroot = _pick("merkle_root")
        txs   = b.get("transactions") or b.get("tx") or []

        self._section(f"Block #{h}")
        if not blkid:
            try:
                cb = (txs[0] if txs else {}) or {}
                blkid = cb.get("block_id")
            except Exception:
                blkid = None
        self._kv("Block ID", (blkid if blkid else "-"), mono=True, vtag="val_id")
        self._kv("Hash", str(hh), mono=True, vtag="val_hex")
        self._kv("Previous", str(prev), mono=True, vtag="val_hex")
        self._kv("Time", str(ts), mono=True)
        self._kv("Nonce", str(nn), mono=True, vtag="val_num")
        if dif  is not None: self._kv("Difficulty", str(dif), mono=True)
        if bits is not None: self._kv("Bits", str(bits), mono=True, vtag="val_num")
        if ver  is not None: self._kv("Version", str(ver), mono=True, vtag="val_num")
        if mroot is not None: self._kv("Merkle Root", str(mroot), mono=True, vtag="val_hex")

        # Graffiti / comments
        graff = b.get("graffiti") or []
        comments = b.get("comments") or []
        if graff or comments:
            self._section("Graffiti Activity")
            if graff:
                for g in graff:
                    sha = g.get("sha256") or "-"
                    self._kv("SHA256", str(sha), mono=True, vtag="val_hex")
                    self._kv("TxID", str(g.get("txid") or "-"), mono=True, vtag="val_hex")
                    mime = g.get("mime") or "-"
                    sz = g.get("size")
                    size_s = f"{int(sz)} bytes" if isinstance(sz, (int, float)) else "-"
                    self._kv("Meta", f"{mime} | {size_s}", mono=True)
            if comments:
                for c in comments:
                    art = c.get("art_id") or "-"
                    comment_text = c.get("comment_text")
                    if not comment_text:
                        try:
                            ch = c.get("comment_hex") or ""
                            comment_text = bytes.fromhex(ch).decode("utf-8", errors="ignore")
                        except Exception:
                            comment_text = ""
                    self._kv("Art ID", str(art), mono=True, vtag="val_hex")
                    if comment_text:
                        self._kv("Comment", comment_text, mono=False)
                    else:
                        self._kv("Comment", "(unavailable)", mono=False)
                    self._kv("Commenter", str(c.get("commenter") or "-"), mono=True, vtag="val_addr")
                    amt = c.get("amount")
                    if amt is not None:
                        self._kv("Amount", _fmt_tsar_amount(amt), mono=True, vtag="val_num")

        self._section(f"Transactions ({len(txs)})")
        if not txs:
            self._writeln("No transactions.", "muted")
        else:
            for t in txs:
                if isinstance(t, dict):
                    txid = t.get("txid") or t.get("id") or t.get("hash") or "-"
                    vin  = len((t.get("inputs") or t.get("vin") or []) or [])
                    vout = len((t.get("outputs") or t.get("vout") or []) or [])
                else:
                    txid = str(t); vin = vout = 0
                # color the txid segment
                self.text.insert("end", "- ", ("mono",))
                self.text.insert("end", txid, ("mono","val_hex"))
                self.text.insert("end", f"   ({vin} → {vout})\n", ("mono",))
        self._finish_render(f"Block {h}")

    def _render_tx(self, txid: str, t: Dict):
        self._clear_text()
        size = t.get("vsize") or t.get("size") or "-"
        fee  = t.get("fee") or t.get("fees") or "-"
        conf = t.get("confirmations") or t.get("conf") or 0
        height = t.get("height") or t.get("block_height") or "-"
        status = t.get("status") or ("unconfirmed" if int(conf or 0) == 0 else "confirmed")
        coinbase = bool(t.get("is_coinbase"))

        self._section("Transaction")
        self._kv("TxID", txid, mono=True, vtag="val_hex")
        tag = "confirmed" if str(status).lower().startswith("conf") or int(conf or 0) > 0 else "unconfirmed"
        self._kv("Status", str(status), mono=True, vtag=tag)
        self._kv("Conf", str(conf), mono=True, vtag="val_num")
        self._kv("Block", str(height), mono=True, vtag="val_num")
        if size != "-":
            self._kv("Size", str(size), mono=True, vtag="val_num")
        if fee != "-":
            self._kv("Fee", _fmt_tsar_amount(fee), mono=True, vtag="val_num")
        self._kv("Coinbase", str(coinbase))

        vin = t.get("inputs") or t.get("vin") or []
        vout= t.get("outputs") or t.get("vout") or []

        self._section("Inputs")
        if not vin:
            self._writeln("No inputs (coinbase?)", "muted")
        else:
            for vi in vin:
                src  = vi.get("txid") or vi.get("prev_txid") or vi.get("tx") or "-"
                idx  = vi.get("vout") if "vout" in vi else (vi.get("index") or vi.get("n") or 0)
                addr = vi.get("address") or vi.get("addr") or ""
                amt  = vi.get("amount") or vi.get("value")

                self.text.insert("end", "- ", ("mono",))
                self.text.insert("end", f"{src}:{idx}", ("mono", "val_hex"))

                if addr:
                    self.text.insert("end", "  ", ("mono",))
                    self.text.insert("end", addr, ("mono", "val_addr"))

                if amt is not None:
                    self.text.insert("end", "  ", ("mono",))
                    self.text.insert("end", _fmt_tsar_amount(amt), ("mono", "val_num"))

                self.text.insert("end", "\n", ("mono",))

        self._section("Outputs")
        if not vout:
            self._writeln("No outputs", "muted")
        else:
            for i, vo in enumerate(vout):
                val = vo.get("value") or vo.get("amount") or "-"
                addr= vo.get("scriptpubkey_address") or vo.get("address") or ""
                self.text.insert("end", f"- [{i}] ", ("mono",))
                self.text.insert("end", _fmt_tsar_amount(val) + "\n", "val_num")
        self._finish_render("Tx detail")

    def _render_address(self, addr: str, a: Dict):
        self._clear_text()
        spend    = a.get("spendable", a.get("balance_spendable", 0)) or 0
        immature = a.get("immature", a.get("balance_immature", 0)) or 0
        pending  = a.get("pending", a.get("balance_pending", 0)) or 0
        utxos    = a.get("utxos") or []
        hist     = a.get("history") or []

        self._section("Address")
        self._kv("Address", addr, mono=True, vtag="val_addr")
        self._kv("Spendable", _fmt_tsar_amount(spend), mono=True, vtag="val_num")
        self._kv("Immature",  _fmt_tsar_amount(immature), mono=True, vtag="val_num")
        self._kv("Pending",   _fmt_tsar_amount(pending), mono=True, vtag="val_num")
        self._kv("UTXOs",     str(len(utxos)), mono=True, vtag="val_num")

        self._section("Recent Activity")
        if not hist:
            self._writeln("No history", "muted")
        else:
            for h in hist[:300]:
                txid = h.get("txid") or h.get("id")
                amt  = h.get("amount") or h.get("value")
                st   = h.get("status") or "-"
                self.text.insert("end", "- ", ("mono",))
                self.text.insert("end", str(txid), ("mono","val_hex"))
                self.text.insert("end", f"   {_fmt_tsar_amount(amt)}", ("mono","val_num"))

                st_tag = "confirmed" if str(st).lower().startswith("conf") else "unconfirmed"
                self.text.insert("end", "  (", ("mono",))
                self.text.insert("end", str(st), ("mono", st_tag))
                self.text.insert("end", ")\n", ("mono",))
        self._finish_render("Address")

    # ---------- errors ----------
    def _render_error(self, msg: str):
        self._clear_text()
        self._section("Error")
        self._writeln(str(msg), "muted")
        self._finish_render("Error")
