# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP39
import os
import json
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel, filedialog, simpledialog, ttk
from typing import Any, Dict, List, Optional, Sequence
from datetime import datetime

# ---------------- Local Project (Wallet Only) ----------------
from tsarchain.wallet.data_security import Wallet, Security,restore_keystore_bytes, list_addresses_in_keystore,delete_address_from_keystore, get_encrypted_keystore_bytes
from tsarchain.wallet.ui_utils import center_window

# ---------------- Local Project (With Node) ----------------
from ..utils.tsar_logging import get_ctx_logger
from tsarchain.utils import config as CFG

log = get_ctx_logger("tsarchain.wallet.address_management")


# ---------------- Amount formatting (local) ----------------
def sat_to_tsar(amount_satoshi: Optional[int]) -> str:
    if amount_satoshi is None:
        amount_satoshi = 0
    tsar = amount_satoshi / CFG.TSAR
    s = f"{tsar:.8f}".rstrip("0").rstrip(".")
    return f"{s} TSAR"


# ---------------- Registry helpers ----------------
def ensure_registry() -> None:
    if not os.path.exists(CFG.WALLETS_DIR):
        try:
            os.makedirs(CFG.WALLETS_DIR)
        except Exception:
            log.exception("[ensure_registry] cannot create wallets dir")
    if not os.path.exists(CFG.REGISTRY_PATH):
        with open(CFG.REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump({"wallets": []}, f)


def load_registry() -> List[str]:
    ensure_registry()
    try:
        with open(CFG.REGISTRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("wallets", [])
    except Exception:
        log.exception("[load_registry] cannot load registry")
        return []


def save_registry(addrs: Sequence[str]) -> None:
    os.makedirs(os.path.dirname(CFG.REGISTRY_PATH), exist_ok=True)
    with open(CFG.REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump({"wallets": list(addrs)}, f, indent=2)


# --- Create Wallet Dialog ---

class CreateWalletDialog(tk.Toplevel):
    def __init__(self, parent, theme):
        super().__init__(parent)
        self.title("Create New Wallet")
        self.configure(bg=theme["bg"])
        self.geometry("720x420")
        self.resizable(True, False)
        self.minsize(640, 380)
        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Return>", lambda _e: (self.btn_create.invoke() if str(self.btn_create['state']) != 'disabled' else None))
        self.resizable(False, False)
        self.result_password = None
        try:
            self.attributes("-topmost", True)
            self.after(200, lambda: self.attributes("-topmost", False))
        except Exception:
            log.debug("[CreateWalletDialog] cannot set topmost")

        # Header
        hdr = tk.Frame(self, bg=theme["bg"]); hdr.pack(fill=tk.X, padx=20, pady=(18, 8))
        tk.Label(hdr, text="Create a new wallet", bg=theme["bg"], fg=theme["fg"],
                font=("Segoe UI", 16, "bold"), justify="center").pack(anchor="center")
        tk.Label(hdr, text="Choose a strong master password to encrypt your keystore.",
                bg=theme["bg"], fg=theme["muted"], font=("Segoe UI", 10), justify="center").pack(anchor="center", pady=(4,0))

        # Body: single centered card (without the "Password requirements" panel)
        body = tk.Frame(self, bg=theme["bg"]); body.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        center = tk.Frame(body, bg=theme["bg"])
        center.place(relx=0.5, rely=0.5, anchor="center")

        def make_pwd_row(parent, label):
            row = tk.Frame(parent, bg=theme["bg"]); row.pack(fill=tk.X, pady=6)
            tk.Label(row, text=label, bg=theme["bg"], fg=theme["fg"]).pack(side=tk.LEFT)
            box = tk.Frame(row, bg=theme["bg"]); box.pack(side=tk.RIGHT, fill=tk.X, expand=True)
            ent = tk.Entry(box, width=65, show="*", bg=theme["panel_bg"], fg=theme["fg"], insertbackground=theme["fg"])
            ent.pack(side=tk.LEFT, fill=tk.X, expand=True)
            # 👁 Toggle eye
            show = {"v": False}
            def toggle():
                show["v"] = not show["v"]
                ent.config(show=("" if show["v"] else "*"))
                eye_btn.config(text=("🙈" if show["v"] else "👁"))
            eye_btn = tk.Button(box, text="🙈", width=3, command=toggle,
                                bg=theme["panel_bg"], fg=theme["fg"], bd=0, relief=tk.FLAT, cursor="hand2")
            eye_btn.pack(side=tk.LEFT, padx=(6,0))
            return ent

        self.ent_pwd  = make_pwd_row(center,  "Password:")
        self.ent_pwd2 = make_pwd_row(center,  "Confirm:")
        
        # ===== Password strength meter =====
        meter_box = tk.Frame(center, bg=theme["bg"]); meter_box.pack(anchor="w", pady=(2, 8))
        self._bars = []
        for _ in range(5):
            b = tk.Frame(meter_box, width=46, height=7, bg="#3a3a3a")
            b.pack(side=tk.LEFT, padx=3)
            self._bars.append(b)
        self._strength_lbl = tk.Label(
            meter_box, bg=theme["bg"], fg=theme["muted"], font=("Consolas", 9))
        self._strength_lbl.pack(side=tk.LEFT, padx=(10,0))

        # Hint (left aligned, matches entry column)
        tip_box = tk.Frame(center, bg=theme["bg"])
        tip_box.pack(fill=tk.X, pady=(4, 10))
        tk.Label(tip_box, bg=theme["bg"], fg=theme["fg"],
                font=("Segoe UI", 9, "bold"), anchor="w", justify="left").pack(anchor="w")
        tk.Label(
            tip_box,
            text="- at least 8 characters\n- contain at least one uppercase letter\n- contain at least one lowercase letter\n- contain at least one digit\n- at least one special character",
            bg=theme["bg"], fg=theme["muted"], font=("Segoe UI", 9),
            anchor="w", justify="left"
        ).pack(anchor="w", padx=(12, 0))

        # Footer
        footer = tk.Frame(self, bg=theme["bg"]); footer.pack(fill=tk.X, padx=20, pady=16)
        self.btn_create = tk.Button(footer, text="Create", state=tk.DISABLED,
                                    bg=theme["accent"], fg="#000", font=("Segoe UI", 10, "bold"),
                                    command=self._on_create)
        self.btn_create.pack(side=tk.RIGHT)
        tk.Button(footer, text="Cancel", bg=theme["panel_bg"], fg=theme["fg"], command=self.destroy)\
          .pack(side=tk.RIGHT, padx=(0,8))

        # Live validation
        def _paint_strength(score: int, label: str):
            score = max(0, min(5, int(score)))
            for i, b in enumerate(self._bars):
                try:
                    if i < score:
                        col = ("#8d1c1c","#B64839","#caa62f","#dfdc55","#55cf37")[i]
                    else:
                        col = "#3a3a3a"
                    b.configure(bg=col)
                except Exception:
                    log.debug("[CreateWalletDialog] cannot paint strength bar")
            self._strength_lbl.config(text=f"- {label}")
            
        def validate(_e=None):
            s = self.ent_pwd.get()
            match = (s != "") and (s == self.ent_pwd2.get())
            ok_all, details = Security.validate_password_strength(s)
            score, label = 0, "weak"
            try:
                if isinstance(details, dict):
                    score = int(details.get("score", 0))
                    label = str(details.get("label", "weak"))
                elif isinstance(details, (list, tuple)):
                    for x in details:
                        if isinstance(x, int): score = x
                        if isinstance(x, str): label = x
                elif isinstance(details, int):
                    score = details
            except Exception:
                log.debug("[CreateWalletDialog] cannot parse strength details")
            if not isinstance(label, str) or not label:
                label = ("very weak","weak","fair","good","strong","excellent")[max(0,min(5,score))]

            _paint_strength(score, label)
            self.btn_create.config(state=(tk.NORMAL if (ok_all and match) else tk.DISABLED))

        self.ent_pwd.bind("<KeyRelease>", validate)
        self.ent_pwd2.bind("<KeyRelease>", validate)
        validate()
        center_window(self, parent)
        try:
            self.ent_pwd.focus_set()
        except Exception:
            log.debug("[CreateWalletDialog] cannot focus password entry")

    def _on_create(self):
        self.result_password = self.ent_pwd.get()
        self.destroy()


# ---------------- Wallets Mixin ----------------

class WalletsMixin:
    
    def _build_wallets_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["wallets"] = f

        # ====== HERO (empty state) ======
        self._wallets_hero = tk.Frame(f, bg=self.bg)

        wrap = tk.Frame(self._wallets_hero, bg=self.bg)
        wrap.pack(fill="both", expand=True)

        center = tk.Frame(wrap, bg=self.bg)
        center.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            center, text="♜Kremlin♜", bg=self.bg, fg=self.accent,
            font=("Segoe UI", 65, "bold")
        ).pack(pady=(36, 8))

        tk.Label(
            center, text="Zero Censorship. Pure Art. Final Bid.",
            bg=self.bg, fg="#C4A231", font=("Consolas", 14, "italic")
        ).pack(pady=(0, 26))

        cta = tk.Frame(center, bg=self.bg); cta.pack()
        tk.Button(
            cta, text="Create Wallet", command=self.create_wallet,
            bg=self.accent, fg="#ffffff", bd=0, relief="ridge",
            padx=18, pady=10, highlightthickness=0, cursor="hand2"
        ).pack(side="left", padx=6)

        imp_btn = ttk.Menubutton(cta, text="Import Wallet")
        m = tk.Menu(imp_btn, tearoff=False)
        m.add_command(label="Load Wallet File (*.enc)", command=self.load_wallet_file, accelerator="Ctrl+O")
        m.add_command(label="Load with Mnemonic",       command=self.import_by_mnemonic, accelerator="Ctrl+I")
        m.add_command(label="Load with Private Key",    command=self.import_by_privkey)
        imp_btn["menu"] = m
        imp_btn.pack(side="left", padx=6)

        tk.Label(
            center,
            text=f"© {datetime.now().year} Tsar Studio\nKremlin Wallet (Ver. 0.1.0)",
            bg=self.bg, fg=self.muted, font=("Consolas", 8)
        ).pack(pady=(18, 10))

        # ====== COMPACT (list addresses) ======
        self._wallets_compact = tk.Frame(f, bg=self.bg)

        top = tk.Frame(self._wallets_compact, bg=self.bg)
        top.pack(fill=tk.X, padx=12, pady=8)

        left = tk.Frame(top, bg=self.bg);  left.pack(side=tk.LEFT, anchor="w")
        right = tk.Frame(top, bg=self.bg); right.pack(side=tk.RIGHT, anchor="e")

        tk.Button(
            left, text="Create New Address", command=self.create_wallet,
            bg=self.accent, fg="#ffffff", bd=0, relief="ridge",
            padx=12, pady=6, highlightthickness=0, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0,6))

        load_mb = ttk.Menubutton(left, text="Manage Address")
        load_menu = tk.Menu(load_mb, tearoff=False)
        load_menu.add_command(label="Backup Keystore (*.enc)", command=self.backup_keystore, accelerator="Ctrl+B")
        load_menu.add_separator()
        load_menu.add_command(label="Load Wallet File (*.enc)", command=self.load_wallet_file, accelerator="Ctrl+O")
        load_menu.add_command(label="Load with Mnemonic",       command=self.import_by_mnemonic, accelerator="Ctrl+I")
        load_menu.add_command(label="Load with Private Key",    command=self.import_by_privkey)
        load_mb["menu"] = load_menu
        load_mb.pack(side=tk.LEFT, padx=6)

        self.actions_mb = ttk.Menubutton(left, text="Actions")
        act_menu = tk.Menu(self.actions_mb, tearoff=False)
        act_menu.add_command(label="Refresh All",        command=self.refresh_all_wallets, accelerator="Ctrl+R")
        act_menu.add_command(label="Clear balance cache", command=self.clear_balance_cache)
        act_menu.add_command(label="Sync Keystore",      command=self.sync_from_keystore, accelerator="Ctrl+S")
        self.actions_mb["menu"] = act_menu
        self.actions_mb.pack(side=tk.LEFT, padx=6)

        self.wallet_count_label = tk.Label(
            right, text=f"Wallets: {len(getattr(self, 'wallets', []))}",
            bg=self.bg, fg=self.muted, font=("Consolas", 10)
        )
        self.wallet_count_label.pack(side=tk.RIGHT, padx=8)

        container = tk.Frame(self._wallets_compact, bg=self.bg)
        container.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,8))
        canvas = tk.Canvas(container, bg=self.bg, highlightthickness=0)
        sbar   = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.wallet_list_frame = tk.Frame(canvas, bg=self.bg)
        self.wallet_list_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.wallet_list_frame, anchor="nw")
        canvas.configure(yscrollcommand=sbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._render_wallet_list()
        try: self.reload_addresses()
        except Exception:
            log.exception("Failed to load addresses on init")
        self._wallets_update_mode()

    # ====== Address Cards ======
    def _render_wallet_list(self) -> None:
        for c in self.wallet_list_frame.winfo_children():
            c.destroy()

        for addr in getattr(self, "wallets", []):
            card = tk.Frame(self.wallet_list_frame, bg=self.panel_bg, padx=12, pady=10)
            card.pack(fill=tk.X, padx=6, pady=6)

            header = tk.Frame(card, bg=self.panel_bg)
            header.pack(fill=tk.X, pady=(0, 4))
            tk.Label(
                header, text=addr, bg=self.panel_bg, fg=self.fg,
                font=("Consolas", 10)
            ).pack(side=tk.LEFT, anchor="w")
            action_btn = tk.Menubutton(
                header, text="...", bg=self.panel_bg, fg=self.fg,
                activebackground=self.accent, activeforeground="#ffffff",
                relief=tk.FLAT, cursor="hand2", width=3, bd=0,
                highlightthickness=0, padx=4, pady=0
            )
            mm = tk.Menu(action_btn, tearoff=False)
            mm.add_command(label="See Private Key", command=lambda a=addr: self._menu_show_priv(a))
            mm.add_separator()
            mm.add_command(label="Delete Address", command=lambda a=addr: self._menu_delete_addr(a))
            action_btn["menu"] = mm
            action_btn.pack(side=tk.RIGHT)

            bal_labels = self._build_balance_block(card)
            setattr(card, "_bal_labels", bal_labels)
            card._bal_labels["_address"] = addr
            setattr(card, "_address", addr)
            self._preload_cached_balance(addr, card._bal_labels)

            btns = tk.Frame(card, bg=self.panel_bg)
            btns.pack(anchor="e", pady=(6, 0))

            check_btn = tk.Button(
                btns, text="Check Balance",
                command=lambda a=addr, bl=bal_labels: self.refresh_wallet_balance_locked(a, bl, None),
                bg="#d9d9d9", fg="#1a1a1a", bd=0, padx=12, pady=5,
                activebackground="#cfcfcf", activeforeground="#1a1a1a",
                highlightthickness=0, cursor="hand2"
            )
            check_btn.pack(side=tk.LEFT, padx=(0,6))
            setattr(card, "_check_btn", check_btn)

            tk.Button(
                btns, text="Copy", command=lambda a=addr: self.copy_to_clipboard(a),
                bg=self.accent, fg="#ffffff", activebackground=self.accent,
                activeforeground="#ffffff", bd=0, padx=12, pady=5,
                highlightthickness=0, cursor="hand2", relief="ridge"
            ).pack(side=tk.LEFT)

            
    def _menu_show_priv(self, addr: str) -> None:
        pwd = self._ask_password("Unlock Address", f"Input Password For\n{addr}:")
        if not pwd: return
        try:
            w = Wallet.unlock(pwd, addr)
            priv = w.get("private_key") or ""
        except Exception:
            log.exception("Failed to unlock wallet for private key")
        if not priv:
            messagebox.showwarning("Not available", "Private key not found."); return

        d = tk.Toplevel(self.root); d.title("Private Key"); d.configure(bg=self.bg); d.resizable(False, False)
        tk.Label(d, text=addr, bg=self.bg, fg=self.muted, font=("Consolas", 9)).pack(padx=14, pady=(12,0))
        v = tk.StringVar(value="*" * len(priv))
        shown = {"v": False}
        box = tk.Frame(d, bg=self.bg); box.pack(padx=14, pady=10)
        ent = tk.Entry(box, textvariable=v, width=68, bg=self.panel_bg, fg=self.fg, insertbackground=self.fg, relief="flat")
        ent.pack(side=tk.LEFT)
        def toggle():
            shown["v"] = not shown["v"]
            v.set(priv if shown["v"] else ("*" * len(priv)))
            btn.config(text=("🙈" if shown["v"] else "👁"))
        btn = tk.Button(box, text="👁", command=toggle, bg=self.panel_bg, fg=self.fg, bd=0)
        btn.pack(side=tk.LEFT, padx=6)
        def copy():
            self.root.clipboard_clear(); self.root.clipboard_append(priv)
            self._toast("Copied to clipboard", kind="info")
        center_window(d, self.root)
        tk.Button(d, text="Copy", command=copy, bg=self.accent, fg="#fff", bd=0).pack(pady=(0,12))

    def _menu_delete_addr(self, addr: str) -> None:
        if not messagebox.askyesno("Delete Address", f"Delete {addr} from keystore?"):
            return
        pwd = self._ask_password("Delete Address", "Enter the keystore password:")
        if not pwd:
            return
        try:
            delete_address_from_keystore(addr, pwd)
        except Exception:
            log.exception("Failed to delete address from keystore")
            return
        try:
            self.wallets = [a for a in self.wallets if a != addr]
            save_registry(self.wallets)
        except Exception:
            log.exception("Failed to update registry after address deletion")
            pass
        self._wallets_after_change()
        self._toast("Address deleted", kind="info")

    def backup_keystore(self) -> None:
        try:
            pwd = self._ask_password("Backup Keystore", "Input keystore Password:")
            if not pwd:
                return

            data = get_encrypted_keystore_bytes(pwd)
            if not data:
                messagebox.showerror("Backup failed", "Keystore is empty or the password is incorrect.")
                return

            path = filedialog.asksaveasfilename(
                title="Simpan Encrypted Keystore",
                defaultextension=".enc",
                filetypes=[("Encrypted Wallet (*.enc)", "*.enc")],
                initialfile="kremlin_keystore.enc",
            )
            if not path:
                return
            if isinstance(data, str):
                data = data.encode("utf-8")
            with open(path, "wb") as f:
                f.write(data)

            try: self._toast("Keystore backup saved", kind="info")
            except Exception:
                log.debug("Cannot show toast after keystore backup")
                pass
            messagebox.showinfo("Backup OK", f"Saved to:\n{path}")
        except Exception:
            log.exception("Failed to backup keystore")

    # ===================== BALANCE BLOCK =====================

    def _build_balance_block(self, parent: tk.Widget) -> Dict[str, tk.Label]:
        col_total = self.fg
        col_spend = "#17c964"
        col_immat = "#f5a524"
        col_pend  = "#f1633f"

        wrap = tk.Frame(parent, bg=self.panel_bg)
        wrap.pack(anchor="w", pady=(2, 4))

        def row(title: str, color: str, big: bool = False) -> tk.Label:
            r = tk.Frame(wrap, bg=self.panel_bg)
            r.pack(anchor="w")
            tk.Label(r, text=title, bg=self.panel_bg, fg=self.muted,
                     font=("Consolas", 9)).pack(side=tk.LEFT, padx=(0, 8))
            fnt = ("Consolas", 13, "bold") if big else ("Consolas", 10, "bold")
            lbl = tk.Label(r, text="0 TSAR", bg=self.panel_bg, fg=color, font=fnt)
            lbl.pack(side=tk.LEFT)
            return lbl

        spend_lbl = row("Available", col_spend, big=True)
        total_lbl = row("Total",   col_total, big=False)
        immat_lbl = row("Immature",  col_immat, big=False)

        maturity_hint = tk.Label(wrap, text=f"(rule: {CFG.COINBASE_MATURITY} block)", bg=self.panel_bg, fg=self.muted, font=("Consolas", 8))
        maturity_hint.pack(anchor="w", padx=(68, 0))
        pending_row = tk.Frame(wrap, bg=self.panel_bg)
        pending_row.pack(anchor="w")
        tk.Label(pending_row, text="Pending", bg=self.panel_bg, fg=self.muted,
                 font=("Consolas", 9)).pack(side=tk.LEFT, padx=(0, 8))
        pend_lbl = tk.Label(pending_row, text="0 TSAR", bg=self.panel_bg, fg=col_pend,
                            font=("Consolas", 11, "bold"))
        pend_lbl.pack(side=tk.LEFT)
        pending_row.pack_forget()

        return {
            "wrap": wrap,
            "total": total_lbl,
            "spend": spend_lbl,
            "immature": immat_lbl,
            "pending_row": pending_row,
            "pending": pend_lbl,
            "hint": maturity_hint,
        }

    def _normalize_balance_resp(self, resp: Optional[Dict[str, Any]], target_addr: Optional[str] = None):
        if not resp or "error" in resp or not isinstance(resp, dict):
            return None

        typ = str(resp.get("type", "")).upper()

        if typ == "BALANCES" and isinstance(resp.get("items"), dict):
            if target_addr and target_addr in resp["items"]:
                d = resp["items"][target_addr] or {}
                return {
                    "balance": int(d.get("balance", d.get("total", 0)) or 0),
                    "spendable": int(d.get("spendable", d.get("confirmed", d.get("mature", d.get("total", 0)))) or 0),
                    "immature": int(d.get("immature", 0) or 0),
                    "pending_outgoing": int(d.get("pending_outgoing", d.get("pending", d.get("unconfirmed", 0))) or 0),
                    "maturity": int(d.get("maturity", CFG.COINBASE_MATURITY)),
                }
            return None

        return {
            "balance": int(resp.get("balance", resp.get("total", 0)) or 0),
            "spendable": int(resp.get("spendable", resp.get("confirmed", resp.get("mature", resp.get("total", 0)))) or 0),
            "immature": int(resp.get("immature", 0) or 0),
            "pending_outgoing": int(resp.get("pending_outgoing", resp.get("pending", resp.get("unconfirmed", 0))) or 0),
            "maturity": int(resp.get("maturity", CFG.COINBASE_MATURITY)),
        }

    def _update_balance_block(self, bal_labels: Dict[str, tk.Label], resp: Dict[str, Any]) -> None:
        def _sat(v):
            try:
                return int(v or 0)
            except Exception:
                log.debug("[_update_balance_block] cannot parse satoshi value")
                return 0

        tot  = resp.get("balance", resp.get("total"))
        spnd = resp.get("spendable")
        imm  = resp.get("immature")
        
        try:
            s = int(spnd or 0); i = int(imm or 0)
            if tot is None or int(tot) < s or int(tot) < (s + i):
                tot = s + i
        except Exception:
            log.debug("[_update_balance_block] cannot validate total balance")
            tot = int(spnd or 0) + int(imm or 0)
            
        pend = resp.get("pending_outgoing", 0)
        mat  = resp.get("maturity")

        if spnd is None and imm is None:
            spnd, imm = tot, 0

        bal_labels["total"].config(text=sat_to_tsar(_sat(tot)))
        bal_labels["spend"].config(text=sat_to_tsar(_sat(spnd)))
        bal_labels["immature"].config(text=sat_to_tsar(_sat(imm)))
        if mat is not None:
            bal_labels["hint"].config(text=f"(rule: {int(mat)} block)")

        if _sat(pend) > 0:
            bal_labels["pending"].config(text=sat_to_tsar(_sat(pend)))
            try:
                bal_labels["pending_row"].pack_info()
            except Exception:
                log.debug("[_update_balance_block] cannot pack pending row")
                pass
            bal_labels["pending_row"].pack(anchor="w")
        else:
            try:
                bal_labels["pending_row"].pack_forget()
            except Exception:
                log.debug("[_update_balance_block] cannot forget pending row")
                pass

        try:
            addr = None
            if isinstance(bal_labels, dict):
                addr = bal_labels.get("_address")
            if addr:
                cached = {
                    "balance": int(_sat(tot)),
                    "spendable": int(_sat(spnd)),
                    "immature": int(_sat(imm)),
                    "pending_outgoing": int(_sat(pend)),
                    "maturity": int(mat if mat is not None else CFG.COINBASE_MATURITY),
                    "ts": int(time.time()),}
                if not hasattr(self, "_bal_cache"):
                    self._init_balance_cache()
                self._bal_cache[addr] = cached

                if len(self._bal_cache) > 2000:
                    oldest = sorted(self._bal_cache.items(), key=lambda kv: kv[1].get("ts", 0))[:100]
                    for k, _ in oldest:
                        self._bal_cache.pop(k, None)
                self._save_balance_cache()
        except Exception:
            log.debug("[_update_balance_block] cannot update balance cache:", exc_info=True)

    def clear_balance_cache(self):
        self._bal_cache = {}
        try:
            if os.path.exists(self._bal_cache_path):
                os.remove(self._bal_cache_path)
            self._toast("Balance cache cleared", ms=1400, kind="info")
        except Exception:
            log.debug("[clear_balance_cache] cannot clear cache file:", exc_info=True)

    # ===================== WALLET ACTIONS =====================

    def _format_balance_ui(self, resp: Dict[str, Any]) -> str:
        def _sat(v: Optional[int]) -> int:
            return 0 if v is None else int(v)

        total_sat = resp.get("balance", resp.get("total"))
        spend_sat = resp.get("spendable")
        immat_sat = resp.get("immature")
        pend_out  = resp.get("pending_outgoing", 0)
        maturity  = resp.get("maturity")

        if spend_sat is None and immat_sat is None:
            return f"Balance   : {sat_to_tsar(_sat(total_sat))}"

        hint = f" (rule: {int(maturity)} block)" if maturity is not None else ""
        lines = [
            f"Balance   : {sat_to_tsar(_sat(total_sat))}",
            f"Spendable : {sat_to_tsar(_sat(spend_sat))}",
            f"Immature  : {sat_to_tsar(_sat(immat_sat))}{hint}",]

        if int(pend_out or 0) > 0:
            lines.append(f"Pending: {sat_to_tsar(_sat(pend_out))}")
        return "\n".join(lines)

    def _reg(self, addr: str) -> None:
        if not hasattr(self, "wallets"):
            self.wallets = []
        if addr and addr not in self.wallets:
            self.wallets.append(addr)
            save_registry(self.wallets)
        if getattr(self, "wallet_count_label", None):
            self.wallet_count_label.config(text=f"Wallets: {len(self.wallets)}")
        try:
            if hasattr(self, "reload_addresses"):
                self.reload_addresses()
            if hasattr(self, "_render_wallet_list"):
                self._render_wallet_list()
        except Exception:
            log.debug("Cannot reload addresses after registry update:", exc_info=True)

    # ------- Secure Mnemonic Dialog -------
    def _show_mnemonic_dialog(self, addr: str, mnemonic: str) -> None:
        def _safe_cancel_timer():
            tid = getattr(self, "_security_timer_id", None)
            if tid is not None:
                try:
                    self.root.after_cancel(tid)
                except Exception:
                    log.debug("[_show_mnemonic_dialog] cannot cancel timer", exc_info=True)
                    pass
                self._security_timer_id = None

        def _register_and_close(show_info=False, warn=False, timeout=False):
            Security.secure_erase(mnemonic)
            _safe_cancel_timer()
            if dialog.winfo_exists():
                dialog.destroy()
            self._reg(addr)
            self._wallets_after_change()
            if show_info:
                messagebox.showinfo(
                    "Wallet Created",
                    f"Wallet created successfully!\nAddress: {addr}\n\n"
                    f"Store your recovery phrase securely.")
            if warn:
                messagebox.showwarning(
                    "Remember to back up",
                    "Wallet created, but you skipped confirmation.\n"
                    "Export the recovery phrase later and store it securely.")
            if timeout:
                messagebox.showwarning(
                    "Security Timeout",
                    "Mnemonic was auto-cleared.\n"
                    "Wallet has been createdâ€”export your phrase later.")

        dialog = tk.Toplevel(self.root)
        dialog.title("ðŸ”’ Wallet Recovery Phrase - SECURE MODE")
        dialog.geometry("600x700")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        center_window(dialog, self.root)
        DARK_BG  = "#0f1115"
        PANEL_BG = "#161a1f"
        FG       = "#ffffff"
        MUTED    = "#a9b1ba"
        ACCENT   = "#ff5e00"
        style = ttk.Style(dialog)
        try:
            style.theme_use("clam")  # ttk theme that can be styled
        except Exception:
            log.debug("[_show_mnemonic_dialog] cannot set ttk theme", exc_info=True)
            pass

        # Gaya dasar
        style.configure("Dark.TFrame", background=DARK_BG)
        style.configure("Dark.TLabelframe", background=DARK_BG, foreground=FG)
        style.configure("Dark.TLabelframe.Label", background=DARK_BG, foreground=FG)
        style.configure("Dark.TLabel", background=DARK_BG, foreground=FG)
        style.configure("Muted.TLabel", background=DARK_BG, foreground=MUTED)
        style.configure("Accent.TLabel", background=DARK_BG, foreground=ACCENT)

        style.configure("Dark.TButton", background=PANEL_BG, foreground=FG, padding=6)
        style.map("Dark.TButton",
                  background=[("active", "#ff5e00"), ("pressed", "#1b1f24")])

        style.configure("Dark.Vertical.TScrollbar",
                        background=PANEL_BG, troughcolor="#0d1015")
        style.map("Dark.Vertical.TScrollbar",
                  background=[("active", "#222831")])

        # Tk (non-ttk) container
        dialog.configure(bg=DARK_BG)
        try:
            dialog.attributes("-toolwindow", True)
            dialog.attributes("-alpha", 0.98)
        except Exception:
            log.debug("[_show_mnemonic_dialog] cannot set window attributes", exc_info=True)
            pass

        main = ttk.Frame(dialog, padding=20, style="Dark.TFrame")
        main.pack(fill=tk.BOTH, expand=True)
        hdr  = ttk.Frame(main, style="Dark.TFrame")
        hdr.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(hdr, text="SECURITY MODE ACTIVE",
                  font=("Arial", 12, "bold"), style="Accent.TLabel").pack()
        ttk.Label(hdr,
                  text="Auto-clear in 2 minutes, No screenshots, Secure memory",
                  font=("Arial", 8), style="Muted.TLabel").pack()

        # ----- Mnemonic area -----
        mbox = ttk.LabelFrame(main, text="YOUR 12-WORD RECOVERY PHRASE",
                              padding=25, style="Dark.TLabelframe")
        mbox.pack(fill=tk.BOTH, expand=True, pady=10)

        canvas = tk.Canvas(mbox, highlightthickness=0, bg=DARK_BG)
        sbar   = ttk.Scrollbar(mbox, orient="vertical", command=canvas.yview,
                               style="Dark.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=sbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)

        wrap = ttk.Frame(canvas, style="Dark.TFrame")
        wrap_id = canvas.create_window((0, 0), window=wrap, anchor="n")

        def _sync_scrollregion(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            try:
                canvas.itemconfigure(wrap_id, width=canvas.winfo_width())
            except Exception:
                log.debug("[_show_mnemonic_dialog] cannot sync scrollregion", exc_info=True)
                pass
        wrap.bind("<Configure>", _sync_scrollregion)
        canvas.bind("<Configure>", _sync_scrollregion)

        # 3 kolom: kiri & kanan gutter (fleksibel), tengah konten
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_columnconfigure(1, weight=0)
        wrap.grid_columnconfigure(2, weight=1)

        gridf = ttk.Frame(wrap, style="Dark.TFrame")
        gridf.grid(row=0, column=1, pady=5)

        words = mnemonic.split()
        for i, w in enumerate(words):
            r, c = divmod(i, 2)
            cell = ttk.Frame(gridf, padding=(12, 6), style="Dark.TFrame")
            cell.grid(row=r, column=c, padx=12, pady=6, sticky="w")
            ttk.Label(cell, text=f"{i + 1:2d}.", width=4, anchor="e",
                      style="Muted.TLabel").pack(side=tk.LEFT)
            ttk.Label(cell, text=w, font=("Consolas", 12, "bold"),
                      width=12, anchor="w", style="Dark.TLabel").pack(side=tk.LEFT)

        btns = ttk.Frame(main, style="Dark.TFrame")
        btns.pack(pady=15)
        timer_label = ttk.Label(btns, text="Auto-clear: 2:00", font=("Consolas", 9), style="Muted.TLabel")
        timer_label.pack(pady=(0, 10))

        def copy_once():
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(mnemonic)
                self.root.after(10000, lambda: self.root.clipboard_clear())
                messagebox.showinfo(
                    "Copied", "Mnemonic copied.\nPaste to a secure offline place."
                )
                Security.log_security_event("MNEMONIC_COPIED", addr, "Copied to clipboard")
            except Exception:
                log.exception("Failed to copy mnemonic to clipboard")

        ttk.Button(btns, text="Copy", command=copy_once,
                   width=20, style="Dark.TButton").pack(side=tk.LEFT, padx=10)
        ttk.Button(btns, text="I've Secured It",
                   command=lambda: _register_and_close(show_info=True),
                   width=25, style="Dark.TButton").pack(side=tk.LEFT, padx=10)
        ttk.Button(btns, text="Skip for now",
                   command=lambda: _register_and_close(warn=True),
                   width=30, style="Dark.TButton").pack(side=tk.LEFT, padx=10)

        afr = ttk.Frame(main, style="Dark.TFrame"); afr.pack(pady=10)
        ttk.Label(afr, text="Wallet Address:", font=("Arial", 9),
                  style="Muted.TLabel").pack()
        masked = addr if len(addr) <= 16 else (addr[:8] + "..." + addr[-8:])
        lab = ttk.Label(afr, text=masked, font=("Courier", 8),
                        style="Dark.TLabel")
        lab.pack()
        ttk.Button(afr, text="Show/Hide Address",
                   command=lambda: lab.config(
                       text=addr if lab.cget("text") == masked else masked),
                   width=20, style="Dark.TButton").pack(pady=5)

        def start_timer():
            self.security_time_remaining = 120
            self._security_timer_id = None

            def tick():
                try:
                    if not (dialog.winfo_exists() and timer_label.winfo_exists()):
                        _safe_cancel_timer()
                        return
                except Exception:
                    log.debug("[_show_mnemonic_dialog] cannot verify dialog existence", exc_info=True)
                    _safe_cancel_timer()
                    return
                if self.security_time_remaining > 0:
                    m, s = divmod(self.security_time_remaining, 60)
                    try:
                        timer_label.config(text=f"Auto-clear: {m}:{s:02d}")
                    except Exception:
                        log.debug("[_show_mnemonic_dialog] cannot update timer label", exc_info=True)
                        _safe_cancel_timer()
                        return
                    self.security_time_remaining -= 1
                    self._security_timer_id = self.root.after(1000, tick)
                else:
                    _register_and_close(timeout=True)

            tick()

        start_timer()

        def on_close():
            if messagebox.askyesno(
                "Close dialog?",
                "Continue wallet creation without confirming?\n"
                "You can export the recovery phrase later.\n"
                "It's safer to store it now.",
                icon="warning",
            ):
                _register_and_close()

        dialog.protocol("WM_DELETE_WINDOW", on_close)
        try:
            dialog.attributes("-topmost", True)
            dialog.after(1000, lambda: dialog.attributes("-topmost", False))
        except Exception:
            log.debug("[_show_mnemonic_dialog] cannot set topmost attribute", exc_info=True)
            pass

    # ------- Widget locker (collect) -------
    def _wallet_action_widgets(self) -> list[tk.Widget]:
        widgets: list[tk.Widget] = []
        if getattr(self, "actions_mb", None):
            widgets.append(self.actions_mb)
        try:
            for card in getattr(self, "wallet_list_frame", tk.Frame()).winfo_children():
                btn = getattr(card, "_check_btn", None)
                if btn:
                    widgets.append(btn)
        except Exception:
            log.debug("Cannot collect wallet action widgets:", exc_info=True)
            pass
        return widgets

    # ------- Create/Import/Export/Backup/Delete -------
    def create_wallet(self) -> None:
        theme = {"bg": self.bg, "panel_bg": self.panel_bg, "fg": self.fg, "muted": self.muted, "accent": self.accent}
        dlg = CreateWalletDialog(self.root, theme)
        self.root.wait_window(dlg)
        pwd = getattr(dlg, "result_password", None)
        if not pwd:
            return
        try:
            addr, mnemonic = Wallet.create(pwd)
            try:
                Security.secure_erase(pwd)
            except Exception:
                log.exception("Failed to clear password from memory")
            if not addr or not mnemonic:
                messagebox.showerror("Failed", "Wallet creation failed.")
                return

            try:
                self.reload_addresses()
            except Exception:
                log.debug("Cannot reload addresses after wallet creation")
                pass
            self._toast("Wallet created", kind="info")
            try:
                self._show_mnemonic_dialog(addr, mnemonic)
            except Exception:
                log.exception("Failed to show mnemonic dialog")
                messagebox.showinfo("Wallet Created", f"Address: {addr}\n\nSIMPAN recovery phrase dengan aman.")

        except Exception:
            log.exception("Failed to create wallet", exc_info=True)

    def load_wallet_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select encrypted keystore (.enc)",
            filetypes=[("Encrypted keystore", "*.enc"), ("All files", "*.*")]
        )
        if not path:
            return

        pwd = self._ask_password("Keystore Password", "Enter password for this backup:")
        if not pwd:
            return

        try:
            with open(path, "rb") as f:
                data = f.read()
            restore_keystore_bytes(data, pwd)
            self.sync_from_keystore()
            try:
                self._wallets_after_change(password=pwd)
            except Exception:
                try:
                    self.reload_addresses()
                    self._wallets_update_mode()
                except Exception:
                    log.debug("Cannot reload addresses after keystore restore")
                    pass

            messagebox.showinfo("Restore complete", "Keystore restored successfully.")
        except Exception as e:
            log.exception("Failed to restore keystore from file", exc_info=True)


    def import_by_mnemonic(self) -> None:
        theme = {"bg": self.bg, "panel_bg": self.panel_bg, "fg": self.fg, "muted": self.muted, "accent": self.accent}

        dlg = tk.Toplevel(self.root)
        dlg.title("Import Wallet Mnemonic")
        dlg.configure(bg=theme["bg"])
        dlg.resizable(False, False)
        try:
            dlg.attributes("-topmost", True); dlg.after(200, lambda: dlg.attributes("-topmost", False))
        except Exception:
            log.debug("[import_by_mnemonic] cannot set topmost attribute", exc_info=True)
            pass

        wrap = tk.Frame(dlg, bg=theme["bg"]); wrap.pack(fill="both", expand=True, padx=18, pady=16)

        # header
        tk.Label(wrap, text="Mnemonic Words (BIP39)", font=("Segoe UI", 12, "bold"),
                bg=theme["bg"], fg=theme["fg"], justify="center").pack(anchor="center")
        tk.Label(wrap, text="No passphrase", font=("Segoe UI", 9, "italic"),
                bg=theme["bg"], fg=theme["muted"]).pack(anchor="center", pady=(0,10))

        grid = tk.Frame(wrap, bg=theme["bg"]); grid.pack(pady=(6, 10))

        entries = []
        for i in range(12):
            r, c = divmod(i, 4)
            r, c = (i % 4), (i // 4)
            cell = tk.Frame(grid, bg=theme["bg"]); cell.grid(row=r, column=c, padx=8, pady=4, sticky="w")
            tk.Label(cell, text=f"{i+1}.", width=3, anchor="e", bg=theme["bg"], fg=theme["muted"]).pack(side="left")
            e = tk.Entry(cell, width=14, bg=theme["panel_bg"], fg=theme["fg"], insertbackground=theme["fg"])
            e.pack(side="left")
            entries.append(e)

        def _on_paste_first(_e=None):
            try:
                s = entries[0].clipboard_get()
            except Exception:
                log.debug("Cannot get clipboard content on paste", exc_info=True)
                return
            words = " ".join((s or "").replace("\n", " ").split()).strip().split(" ")
            if len(words) >= 12:
                for i in range(12):
                    entries[i].delete(0, tk.END)
                    entries[i].insert(0, words[i])
                try: entries[11].focus_set()
                except Exception:
                    log.debug("Cannot focus last entry after paste", exc_info=True)
                    pass

        entries[0].bind("<<Paste>>", _on_paste_first)
        entries[0].bind("<Control-v>", _on_paste_first)

        # keystore password
        p_row = tk.Frame(wrap, bg=theme["bg"]); p_row.pack(fill="x", pady=(6, 4))
        tk.Label(p_row, text="Password:", bg=theme["bg"], fg=theme["fg"]).pack(side="left")
        pwd_box = tk.Frame(p_row, bg=theme["bg"]); pwd_box.pack(side="right", fill="x", expand=True)
        pwd = tk.Entry(pwd_box, show="*", width=32, bg=theme["panel_bg"], fg=theme["fg"], insertbackground=theme["fg"])
        pwd.pack(side="left", fill="x", expand=True)
        show = {"v": False}
        def _toggle():
            show["v"] = not show["v"]; pwd.config(show="" if show["v"] else "*"); eye.config(text=("🙈" if show["v"] else "👁"))
        eye = tk.Button(pwd_box, text="🙈", width=3, command=_toggle, bg=theme["panel_bg"], fg=theme["fg"], bd=0, relief=tk.FLAT, cursor="hand2")
        eye.pack(side="left", padx=(6,0))

        btns = tk.Frame(wrap, bg=theme["bg"]); btns.pack(fill="x", pady=(10,0))
        def _do_import():
            words = [e.get().strip() for e in entries]
            if any(not w for w in words):
                messagebox.showerror("Error", "Lengkapi 12 kata terlebih dahulu"); return
            phrase = " ".join(words)
            password = pwd.get().strip()
            if not password:
                messagebox.showerror("Error", "Enter the keystore password"); return
            try:
                addr = Wallet.create_from_mnemonic(phrase, password)
                self._reg(addr)
                try:
                    self._wallets_after_change()
                except Exception:
                    log.debug("Cannot reload addresses after wallet import")
                    pass
                messagebox.showinfo("Success", f"Wallet imported!\nAddress: {addr}")
                dlg.destroy()
            except Exception:
                log.exception("Failed to import wallet from mnemonic", exc_info=True)

        tk.Button(btns, text="Import Wallet", command=_do_import, bg=self.accent, fg="#000", font=("Segoe UI", 10, "bold")).pack(side="right")
        tk.Button(btns, text="Cancel", command=dlg.destroy, bg=theme["panel_bg"], fg=theme["fg"]).pack(side="right", padx=(0,8))

        center_window(dlg, self.root)
        try: entries[0].focus_set()
        except Exception:
            log.exception("Cannot focus first entry in import mnemonic dialog", exc_info=True)
            pass


    def import_by_privkey(self) -> None:
        priv = self._ask_text(
            "Import Wallet Private Key",
            "Tempel private key (hex/WIF):",
            multiline=False,
            secret_toggle=True)
        if not priv:
            return
        password = simpledialog.askstring("Password", "Set password to encrypt this imported wallet:", show="*")
        if not password:
            messagebox.showerror("Error", "Password required")
            return
        try:
            addr = Wallet.create_from_privkey_hex(priv.strip(), password)
            self._reg(addr)
            self._wallets_after_change()
            messagebox.showinfo("Wallet Imported", f"Address: {addr}")
        except Exception:
            log.exception("Failed to import wallet from private key", exc_info=True)

    def export_private_key(self) -> None:
        if not getattr(self, "wallets", []):
            messagebox.showerror("Error", "No wallet loaded")
            return

        addr = simpledialog.askstring("Export", "Enter wallet address to export (exact):")
        if not addr:
            return
        if addr not in self.wallets:
            messagebox.showerror("Error", f"Address {addr} not found in registry")
            return

        password = simpledialog.askstring("Password", f"Enter password to unlock {addr}:", show="*")
        if not password:
            return

        try:
            w = Wallet.unlock(password, addr)
        except Exception:
            log.debug("Failed to unlock wallet for private key export", exc_info=True)
            return

        really = messagebox.askyesno(
            "WARNING",
            "You are about to reveal your PRIVATE KEY in plaintext.\n"
            "Anyone who sees this can steal your funds.\n\n"
            "Do you REALLY want to proceed?"
        )
        if not really:
            return

        priv_hex = w.get("private_key")
        win = Toplevel(self.root)
        win.title("Export Private Key (TEMP)")
        win.geometry("720x260")
        tk.Label(win, text=f"Address: {addr}\n\nPRIVATE KEY (hex):", anchor="w")\
            .pack(fill=tk.X, padx=8, pady=(8, 0))
        txt = scrolledtext.ScrolledText(win, wrap="word", font=("Consolas", 11))
        txt.insert("1.0", str(priv_hex))
        txt.configure(state="normal")
        txt.pack(expand=True, fill="both", padx=8, pady=8)

        def save_to_file():
            path = filedialog.asksaveasfilename(
                title="Save private key as...",
                defaultextension=".txt",
                filetypes=[("Text", "*.txt"), ("All", "*.*")]
            )
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(str(priv_hex))
                messagebox.showinfo("Saved", f"Private key saved to {path}. Keep it safe (offline).")

        btn_frame = tk.Frame(win)
        btn_frame.pack(pady=6)
        tk.Button(btn_frame, text="Save to file", command=save_to_file, bg=self.accent, fg="#fff")\
            .pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="Close", command=win.destroy).pack(side=tk.LEFT, padx=8)
        center_window(win, self.root)

    # ===================== BALANCE HELPERS =====================

    def refresh_wallet_balance(self, addr: str, label_widget) -> None:
        def on_bal(resp: Optional[Dict[str, Any]]) -> None:
            try:
                data = self._normalize_balance_resp(resp, target_addr=addr)
                if isinstance(label_widget, dict):
                    self._update_balance_block(label_widget, data)
                else:
                    label_widget.config(text=self._format_balance_ui(data))
            except Exception:
                log.debug("[UI] balance render error:", exc_info=True)
                zero = {"balance": 0, "spendable": 0, "immature": 0,
                        "pending_outgoing": 0, "maturity": CFG.COINBASE_MATURITY}
                if isinstance(label_widget, dict):
                    self._update_balance_block(label_widget, zero)
                else:
                    label_widget.config(text=self._format_balance_ui(zero))

        self.rpc_send({"type": "GET_BALANCES", "addresses": [addr]}, on_bal)

    def refresh_wallet_balance_locked(self, addr: str, label_widget, btn: tk.Widget) -> None:
        def on_bal(resp):
            try:
                data = self._normalize_balance_resp(resp, target_addr=addr)
                if data is None:
                    self._toast("No Connection!!", kind="warn")
                    return
                if isinstance(label_widget, dict):
                    self._update_balance_block(label_widget, data)
                else:
                    label_widget.config(text=self._format_balance_ui(data))
            except Exception:
                log.debug("[UI] balance render error:", exc_info=True)
                zero = {"balance": 0, "spendable": 0, "immature": 0,
                        "pending_outgoing": 0, "maturity": CFG.COINBASE_MATURITY}
                if isinstance(label_widget, dict):
                    self._update_balance_block(label_widget, zero)
                else:
                    label_widget.config(text=self._format_balance_ui(zero))

        if getattr(self, "_request_locked", None):
            self._request_locked(
                "wallet_balances",
                self._wallet_action_widgets(),
                {"type": "GET_BALANCES", "addresses": [addr]},
                on_bal,
            )
        else:
            self.rpc_send({"type": "GET_BALANCES", "addresses": [addr]}, on_bal)

    def refresh_all_wallets(self) -> None:
        if not hasattr(self, "actions_mb"):
            self.actions_mb = None
        widgets = self._wallet_action_widgets()
        if not self._busy_start("wallet_balances", widgets):
            return

        cards = list(self.wallet_list_frame.winfo_children())
        addrs_and_labels: list[tuple[str, object]] = []
        for card in cards:
            try:
                addr = card.winfo_children()[0].cget("text")
                bal_labels = getattr(card, "_bal_labels", None)
                addr = getattr(card, "_address", None)
                if not addr and isinstance(bal_labels, dict):
                    addr = bal_labels.get("_address")
                if addr and bal_labels:
                    addrs_and_labels.append((addr, bal_labels))
            except Exception:
                log.debug("Cannot collect address from wallet card:", exc_info=True)
                continue

        if not addrs_and_labels:
            self._busy_end("wallet_balances")
            return

        addresses = [a for a, _ in addrs_and_labels]

        def _fallback_per_addr():
            CONCURRENCY = 4
            queue = list(addrs_and_labels)
            active = {"n": 0}
            pending = {"n": len(queue)}

            def pump():
                while active["n"] < CONCURRENCY and queue:
                    addr, labels = queue.pop(0)
                    active["n"] += 1

                    def _cb(resp: Optional[Dict[str, Any]], a=addr, lbls=labels):
                        try:
                            data = self._normalize_balance_resp(resp, target_addr=a)
                            self._update_balance_block(lbls, data)
                        finally:
                            active["n"] -= 1
                            pending["n"] -= 1
                            if pending["n"] <= 0:
                                self._busy_end("wallet_balances")
                            else:
                                pump()
                    self.rpc_send({"type": "GET_BALANCES", "addresses": [addr]}, _cb)
            if pending["n"] == 0:
                self._busy_end("wallet_balances")
                return
            pump()


        def _on_bulk(resp: Optional[Dict[str, Any]]) -> None:
            if (not resp) or (resp.get("type") != "BALANCES") or ("items" not in resp):
                _fallback_per_addr()
                return

            try:
                items: Dict[str, Dict[str, Any]] = resp.get("items", {})
                for addr, labels in addrs_and_labels:
                    data = items.get(addr)
                    if isinstance(data, dict):
                        self._update_balance_block(labels, data)
                    else:
                        self._update_balance_block(labels, {"balance":0,"spendable":0,"immature":0,
                                                            "pending_outgoing":0,"maturity":CFG.COINBASE_MATURITY})
            finally:
                self._busy_end("wallet_balances")

        self.rpc_send({"type": "GET_BALANCES", "addresses": addresses}, _on_bulk)
        
        
    # ---------- switch & refresh ----------

    def _wallets_update_mode(self) -> None:
        has = bool(getattr(self, "wallets", []))
        try:
            self._wallets_hero.pack_forget()
            self._wallets_compact.pack_forget()
        except Exception:
            log.debug("Cannot switch wallet mode:", exc_info=True)
            pass
        target = self._wallets_compact if has else self._wallets_hero
        target.pack(fill=tk.BOTH, expand=True)
        if getattr(self, "wallet_count_label", None):
            self.wallet_count_label.config(text=f"Wallets: {len(self.wallets)}")

    def _wallets_after_change(self) -> None:
        try:
            if hasattr(self, "_render_wallet_list"):
                self._render_wallet_list()
            if hasattr(self, "reload_addresses"):
                self.reload_addresses()
        except Exception:
            log.debug("Cannot reload addresses after registry update:", exc_info=True)
            pass
        self._wallets_update_mode()

    def _reg(self, addr: str) -> None:
        if not hasattr(self, "wallets"):
            self.wallets = []
        if addr and addr not in self.wallets:
            self.wallets.append(addr)
            save_registry(self.wallets)
        if getattr(self, "wallet_count_label", None):
            self.wallet_count_label.config(text=f"Wallets: {len(self.wallets)}")
        try:
            if hasattr(self, "reload_addresses"): self.reload_addresses()
            if hasattr(self, "_render_wallet_list"): self._render_wallet_list()
        except Exception:
            log.debug("Cannot reload addresses after registry update:", exc_info=True)
            pass
        try: self._wallets_update_mode()
        except Exception:
            log.debug("Cannot update wallet mode after registry update:", exc_info=True)
            pass


    # ---------- Balance Cache: init, load, save ----------
    def _init_balance_cache(self) -> None:
        try:
            base = getattr(self, "_cache_dir", None)
            if not base:
                base = os.path.join(os.path.abspath(os.getcwd()), ".tsarcache")
                self._cache_dir = base
            os.makedirs(base, exist_ok=True)
            self._bal_cache_path = os.path.join(base, "balances.json")
        except Exception:
            log.debug("Cannot init balance cache dir:", exc_info=True)
            self._bal_cache_path = "balances.json"
        self._bal_cache = self._load_balance_cache()

    def _load_balance_cache(self) -> dict:
        try:
            with open(self._bal_cache_path, "r", encoding="utf-8") as f:
                d = json.load(f)
                return d if isinstance(d, dict) else {}
        except Exception:
            log.debug("Cannot load balance cache:", exc_info=True)
            return {}

    def _save_balance_cache(self) -> None:
        try:
            tmp = self._bal_cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._bal_cache, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self._bal_cache_path)
        except Exception:
            log.debug("Cannot save balance cache:", exc_info=True)
            pass

    def _preload_cached_balance(self, address: str, labels: dict) -> None:
        try:
            d = self._bal_cache.get(address)
            if not isinstance(d, dict):
                return
            data = {
                "balance": int(d.get("balance", 0)),
                "spendable": int(d.get("spendable", 0)),
                "immature": int(d.get("immature", 0)),
                "pending_outgoing": int(d.get("pending_outgoing", 0)),
                "maturity": int(d.get("maturity", d.get("coinbase_maturity", CFG.COINBASE_MATURITY))),
            }
            self._update_balance_block(labels, data)
        except Exception:
            log.debug("Cannot preload cached balance:", exc_info=True)
            pass

    # ------ Password Input ------
    def _ask_password(self, title: str, prompt: str) -> str | None:
        d = tk.Toplevel(self.root)
        d.title(title); d.configure(bg=self.bg); d.resizable(False, False)
        try:
            d.attributes("-topmost", True); d.after(150, lambda: d.attributes("-topmost", False))
        except Exception:
            log.debug("[_ask_password] cannot set topmost attribute", exc_info=True)
            pass

        tk.Label(d, text=prompt, bg=self.bg, fg=self.fg, font=("Segoe UI", 10)).pack(padx=16, pady=(14,6))
        row = tk.Frame(d, bg=self.bg); row.pack(padx=16, pady=(0,12))
        var = tk.StringVar()
        ent = tk.Entry(row, textvariable=var, width=44, show="*", bg=self.panel_bg, fg=self.fg, insertbackground=self.fg, relief="flat")
        ent.pack(side=tk.LEFT)
        show = {"v": False}
        def toggle():
            show["v"] = not show["v"]
            ent.config(show=("" if show["v"] else "*"))
            btn.config(text=("🙈" if show["v"] else "👁"))
        btn = tk.Button(row, text="👁", command=toggle, bg=self.panel_bg, fg=self.fg, bd=0, width=3)
        btn.pack(side=tk.LEFT, padx=6)

        btns = tk.Frame(d, bg=self.bg); btns.pack(padx=16, pady=(0,14))
        out = {"v": None}
        def ok(): out["v"] = var.get() or None; d.destroy()
        tk.Button(btns, text="Cancel", command=d.destroy, bg=self.panel_bg, fg=self.fg).pack(side=tk.RIGHT, padx=(0,8))
        tk.Button(btns, text="OK",     command=ok,       bg=self.accent, fg="#fff").pack(side=tk.RIGHT)
        try:
            ent.focus_set()
        except Exception:
            log.debug("[_ask_password] cannot focus entry", exc_info=True)
            pass
        ent.bind("<Return>", lambda _e: ok())
        d.bind("<Return>", lambda _e: ok())
        center_window(d, self.root)
        d.transient(self.root); d.grab_set(); self.root.wait_window(d)
        return out["v"]

    def _ask_text(self, title: str, prompt: str, *, multiline=False, secret_toggle=False, placeholder:str="") -> str | None:
        d = tk.Toplevel(self.root)
        d.title(title); d.configure(bg=self.bg); d.resizable(False, False)
        tk.Label(d, text=prompt, bg=self.bg, fg=self.fg, font=("Segoe UI", 10)).pack(padx=16, pady=(14,6))

        wrap = tk.Frame(d, bg=self.bg); wrap.pack(padx=16, pady=(0,12))
        if multiline:
            txt = tk.Text(wrap, width=52, height=5, bg=self.panel_bg, fg=self.fg, insertbackground=self.fg, relief="flat", wrap="word")
            if placeholder: txt.insert("1.0", placeholder)
            txt.pack()
            ent = None
        else:
            v = tk.StringVar()
            ent = tk.Entry(wrap, textvariable=v, width=52, bg=self.panel_bg, fg=self.fg, insertbackground=self.fg, relief="flat")
            ent.pack(side=tk.LEFT)
            if secret_toggle:
                show = {"v": False}
                def toggle():
                    show["v"] = not show["v"]
                    ent.config(show=("" if show["v"] else "*"))
                    btn.config(text=("🙈" if show["v"] else "👁"))
                btn = tk.Button(wrap, text="👁", command=toggle, bg=self.panel_bg, fg=self.fg, bd=0, width=3)
                btn.pack(side=tk.LEFT, padx=6)

        btns = tk.Frame(d, bg=self.bg); btns.pack(padx=16, pady=(0,14))
        out = {"v": None}
        def ok():
            if multiline:
                out["v"] = (txt.get("1.0","end").strip() or None)
            else:
                out["v"] = (v.get().strip() or None)
            d.destroy()
        tk.Button(btns, text="Cancel", command=d.destroy, bg=self.panel_bg, fg=self.fg).pack(side=tk.RIGHT, padx=(0,8))
        tk.Button(btns, text="OK",     command=ok,       bg=self.accent, fg="#fff").pack(side=tk.RIGHT)
        try:
            (ent or txt).focus_set()
        except Exception:
            log.debug("[_ask_text] cannot focus input", exc_info=True)
            pass
        if not multiline:
            (ent or txt).bind("<Return>", lambda _e: ok())
            d.bind("<Return>", lambda _e: ok())
        center_window(d, self.root)
        d.transient(self.root); d.grab_set(); self.root.wait_window(d)
        return out["v"]


    # ===================== SYNC / DELETE / BACKUP =====================

    def sync_from_keystore(self) -> None:
        try:
            pwd = None
            if not pwd:
                ask = getattr(self, "_ask_password", None)
                if callable(ask):
                    pwd = ask("Keystore Password", "Enter keystore password to sync addresses:")
                else:
                    pwd = simpledialog.askstring("Keystore Password",
                                                 "Enter keystore password to sync addresses:",
                                                 show="*", parent=self.root)
            if not pwd:
                return
            keystore_addrs = list_addresses_in_keystore(pwd)

            if keystore_addrs is None:
                messagebox.showerror("Sync failed", "Unable to read keystore.")
                return

            old = set(self.wallets or [])
            new = set(keystore_addrs)
            added = list(new - old)
            removed = list(old - new)

            if removed:
                if not messagebox.askyesno(
                    "Remove non-keystore addresses?",
                    "The following addresses are not present in the encrypted keystore:\n\n"
                    + "\n".join(removed[:10]) + ("\nâ€¦" if len(removed) > 10 else "")
                    + "\n\nRemove them from the UI list?",
                    icon="warning",
                ):
                    final = sorted(old | new)
                else:
                    final = sorted(new)
            else:
                final = sorted(new)

            self.wallets = final
            save_registry(self.wallets)

            if getattr(self, "wallet_count_label", None):
                self.wallet_count_label.config(text=f"Wallets: {len(self.wallets)}")
            try:
                self.reload_addresses()
            except Exception:
                log.exception("Cannot reload addresses after sync", exc_info=True)
                pass
            try:
                if hasattr(self, "_maybe_lock_redirect"):
                    self._maybe_lock_redirect()
            except Exception:
                log.exception("Cannot maybe lock redirect after sync", exc_info=True)
                pass
            try:
                self._render_wallet_list()
            except Exception:
                log.exception("Cannot render wallet list after sync", exc_info=True)
                pass

            messagebox.showinfo(
                "Sync complete",
                f"Added: {len(added)}\nRemoved: {len(removed)}\nTotal: {len(self.wallets)}"
            )
        except Exception:
            log.exception("Failed to sync from keystore", exc_info=True)

    def delete_wallet_dialog(self) -> None:
        if not self.wallets:
            messagebox.showinfo("Delete Wallet", "No wallets in the list.")
            return

        addr = simpledialog.askstring("Delete Wallet", "Type the EXACT address to delete:", parent=self.root)
        if not addr:
            return
        if addr not in (self.wallets or []):
            messagebox.showerror("Not found", "Address not in the current list.")
            return

        if not messagebox.askyesno(
            "Confirm delete",
            f"Delete wallet:\n\n{addr}\n\n"
            "This removes the private key from the encrypted keystore.\n"
            "Make sure you have a backup!",
            icon="warning",
        ):
            return

        pwd = simpledialog.askstring("Keystore Password", "Enter keystore password:", show="*", parent=self.root)
        if not pwd:
            return

        try:
            ok = delete_address_from_keystore(addr, pwd)
            if not ok:
                messagebox.showerror("Delete failed", "Address not found in keystore.")
                return

            self.wallets = [a for a in (self.wallets or []) if a != addr]
            save_registry(self.wallets)

            if getattr(self, "wallet_count_label", None):
                self.wallet_count_label.config(text=f"Wallets: {len(self.wallets)}")
            try:
                self.reload_addresses()
            except Exception:
                log.debug("Cannot reload addresses after wallet deletion", exc_info=True)
                pass
            try:
                self._render_wallet_list()
            except Exception:
                log.debug("Cannot render wallet list after wallet deletion", exc_info=True)
                pass
            try:
                if hasattr(self, "_maybe_lock_redirect"):
                    self._maybe_lock_redirect()
            except Exception:
                log.debug("Cannot maybe lock redirect after wallet deletion", exc_info=True)
                pass
            messagebox.showinfo("Deleted", "Wallet removed from keystore and UI.")
        except Exception:
            log.exception("Failed to delete wallet", exc_info=True)

    def backup_keystore(self) -> None:
        try:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            default_name = f"TsarWallet_backup_{ts}.enc"
            path = filedialog.asksaveasfilename(
                title="Save encrypted keystore backup",
                defaultextension=".enc",
                initialfile=default_name,
                filetypes=[("Encrypted backup", ".enc"), ("All files", "*.*")]
            )
            if not path:
                return

            data = get_encrypted_keystore_bytes()
            with open(path, "wb") as f:
                f.write(data)
            messagebox.showinfo("Backup complete", f"Encrypted keystore saved:\n{path}")
        except FileNotFoundError:
            messagebox.showerror("Backup failed", "Keystore file not found.")
        except Exception:
            log.exception("Failed to backup keystore", exc_info=True)

