# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from __future__ import annotations
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Optional, Dict, Tuple, List

# ---------------- Local Project (Wallet Only) ----------------
from .data_security import list_contacts_in_keystore, upsert_contact_in_keystore, delete_contact_from_keystore
from .ui_utils import center_window

Mask = Tuple[str, str]


def _mask_addr(addr: str) -> str:
    a = (addr or "").strip()
    return f"{a[:10]}-{a[-6:]}" if len(a) >= 20 else a



class _ContactForm(tk.Toplevel):
    def __init__(self, parent, colors, title="Contact", alias="", address=""):
        super().__init__(parent)
        self.configure(bg=colors["bg"])
        self.title(title)
        self.resizable(False, False)
        try:
            self.transient(parent); self.grab_set()
        except Exception:
            pass

        body = tk.Frame(self, bg=colors["bg"]); body.pack(fill=tk.BOTH, expand=True, padx=16, pady=14)

        tk.Label(body, text="Alias", bg=colors["bg"], fg=colors["fg"]).pack(anchor="w")
        self.ent_alias = tk.Entry(
            body, bg=colors["card"], fg=colors["fg"], insertbackground=colors["fg"],
            relief="flat", highlightthickness=1, highlightbackground=colors["border"], width=44)
        self.ent_alias.pack(fill=tk.X, pady=(2,10))
        self.ent_alias.insert(0, alias)

        tk.Label(body, text="Address (tsar1…)", bg=colors["bg"], fg=colors["fg"]).pack(anchor="w")
        self.ent_addr = tk.Entry(
            body, bg=colors["card"], fg=colors["fg"], insertbackground=colors["fg"],
            relief="flat", highlightthickness=1, highlightbackground=colors["border"], width=44)
        self.ent_addr.pack(fill=tk.X, pady=(2,6))
        self.ent_addr.insert(0, address)

        # footer
        foot = tk.Frame(self, bg=colors["bg"]); foot.pack(fill=tk.X, padx=16, pady=(6,14))
        tk.Button(foot, text="Cancel", bg=colors["panel_bg"], fg=colors["fg"],
                  bd=0, relief=tk.FLAT, command=self._cancel).pack(side=tk.RIGHT, padx=(0,8))
        self.btn_ok = tk.Button(foot, text="Save", bg=colors["accent"], fg="white",
                                bd=0, relief=tk.FLAT, command=self._ok)
        self.btn_ok.pack(side=tk.RIGHT)

        self.result = None
        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        try:
            center_window(self, parent)
            self.ent_alias.focus_set()
        except Exception:
            pass

    def _ok(self):
        self.result = ((self.ent_addr.get() or "").strip(), (self.ent_alias.get() or "").strip())
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


class ContactManager:
    def __init__(
        self,
        root: tk.Misc,
        get_password_cb: Callable[[], Optional[str]],
        toast_cb: Optional[Callable[[str], None]] = None,
        palette: Optional[Dict[str, str]] = None,
    ) -> None:
        self.root = root
        self.get_pwd = get_password_cb
        self.toast = toast_cb or (lambda m: None)
        self.colors = {
            "bg": "#0f1115",
            "panel_bg": "#161a1f",
            "fg": "#f2f5f7",
            "muted": "#a9b1ba",
            "accent": "#e06214",
            "card": "#1e1e1e",
            "border": "#2a2f36",
            "on": "#5ade3b",
            "off":  "#e05555",
        }
        if palette:
            self.colors.update(palette)
        self.colors.setdefault("card", "#1e1e1e")
        self.colors.setdefault("border", "#2a2f36")
        self.colors.setdefault("on", "#5ade3b")
        self.colors.setdefault("off",  "#e05555")

        self._contacts: Dict[str, str] = {}  # address -> alias

    # ---------- Data ----------
    def load(self) -> Dict[str, str]:
        pwd = self.get_pwd()
        if not pwd:
            return self._contacts
        try:
            self._contacts = list_contacts_in_keystore(pwd) or {}
        except Exception as e:
            self.toast(f"Load contacts failed: {e}")
        return self._contacts

    def pairs(self) -> List[Mask]:
        items: List[Mask] = []
        for addr, alias in sorted(self._contacts.items(), key=lambda kv: kv[1].lower()):
            items.append((f"{alias} - {_mask_addr(addr)}", addr))
        return items

    def upsert(self, address: str, alias: str) -> bool:
        address = (address or "").strip().lower()
        alias = (alias or "").strip()
        if not address.startswith("tsar1"):
            messagebox.showwarning("Invalid", "Address must start with tsar1")
            return False
        if not alias:
            messagebox.showwarning("Invalid", "Alias cannot be empty")
            return False
        pwd = self.get_pwd()
        if not pwd:
            return False
        try:
            upsert_contact_in_keystore(address, alias, pwd)
            self._contacts[address] = alias
            return True
        except Exception as e:
            messagebox.showerror("Failed", f"Save contact failed: {e}")
            return False

    def delete(self, address: str) -> bool:
        address = (address or "").strip().lower()
        pwd = self.get_pwd()
        if not pwd:
            return False
        try:
            delete_contact_from_keystore(address, pwd)
            self._contacts.pop(address, None)
            return True
        except Exception as e:
            messagebox.showerror("Failed", f"Delete contact failed: {e}")
            return False

    # ---------- UI helpers ----------
    def _styled_entry(self, parent) -> tk.Entry:
        c = self.colors
        ent = tk.Entry(
            parent, bg=c["card"], fg=c["fg"], insertbackground=c["fg"],
            relief="flat", highlightthickness=1,
            highlightbackground=c["border"], highlightcolor=c["border"],
            width=56
        )
        return ent

    # ---------- UI: Contact Picker (grid/tile canvas) ----------
    def _ask_contact(self, parent, title="Contact", alias="", address=""):
        d = _ContactForm(parent, self.colors, title=title, alias=alias, address=address)
        parent.wait_window(d)
        return d.result
    
    def pick_contact(
        self,
        title: str = "Contacts",
        on_pick: Optional[Callable[[str, str], None]] = None,  # (address, alias)
        presence_provider: Optional[Callable[[str, Callable[[Optional[str]], None]], None]] = None,
        prompt_password: bool = True,
    ) -> None:
        
        if prompt_password:
            self.load()
        c = self.colors

        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=c["bg"])
        dlg.geometry("740x560")
        dlg.resizable(True, True)
        try:
            dlg.transient(self.root)
            dlg.grab_set()
        except Exception:
            pass
        # ⬇️ center window
        try:
            center_window(dlg, self.root)
        except Exception:
            pass

        # ---- search (tema gelap) ----
        hdr = tk.Frame(dlg, bg=c["bg"]); hdr.pack(fill=tk.X, padx=18, pady=(14, 8))
        tk.Label(hdr, text="Search:", bg=c["bg"], fg=c["fg"]).pack(side=tk.LEFT, padx=(0, 8))
        qvar = tk.StringVar(value="")
        qentry = self._styled_entry(hdr)
        qentry.configure(textvariable=qvar)
        qentry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        qentry.bind("<KeyRelease>", lambda _e: _rebuild())
        try:
            qvar.trace_add("write", lambda *_: _rebuild())
        except Exception:
            pass

        # ---- area scrollable (grid 2 kolom) ----
        outer = tk.Frame(dlg, bg=c["bg"]); outer.pack(fill=tk.BOTH, expand=True, padx=18, pady=(2, 8))
        frame_border = tk.Frame(outer, bg=c["border"]); frame_border.pack(fill=tk.BOTH, expand=True)
        container = tk.Frame(frame_border, bg=c["bg"]); container.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        canvas = tk.Canvas(container, bg=c["bg"], bd=0, highlightthickness=0)
        vs = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vs.set)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        grid = tk.Frame(canvas, bg=c["bg"])
        canvas.create_window((0, 0), window=grid, anchor="nw")

        # --- state & helpers ---
        state = {"sel_addr": None, "cards": {}}
        use_btn: Optional[tk.Button] = None  # akan di-set setelah tombol dibuat

        def _set_sel(addr: Optional[str]):
            nonlocal use_btn
            state["sel_addr"] = addr
            for a, box in state["cards"].items():
                try:
                    box.config(highlightthickness=2 if a == addr else 0,
                            highlightbackground=c["accent"], highlightcolor=c["accent"])
                except Exception:
                    pass
            # toggle Use Contact
            if use_btn is not None:
                if addr:
                    use_btn.config(bg=c["accent"], fg="white", state="normal")
                else:
                    use_btn.config(bg="white", fg="black", state="disabled")

        def _mk_card(parent, addr: str, alias: str):
            card = tk.Frame(parent, bg=c["card"], padx=14, pady=10, highlightthickness=0)

            top = tk.Frame(card, bg=c["card"]); top.pack(fill=tk.X)
            tk.Label(top, text=f"({alias})", bg=c["card"], fg=c["accent"],
                    font=("Consolas", 16, "bold")).pack(side=tk.LEFT)

            pres = tk.Label(card, text="•  Checking", bg=c["card"], fg=c["muted"],
                            font=("Consolas", 10, "bold"))
            pres.pack(side=tk.BOTTOM, anchor="e", pady=(6, 0))

            tk.Label(card, text=f"({_mask_addr(addr)})", bg=c["card"], fg=c["muted"],
                    font=("Consolas", 11)).pack(side=tk.TOP, anchor="w", pady=(5, 2))

            def _sel(_e=None): _set_sel(addr)
            card.bind("<Button-1>", _sel)
            for child in card.winfo_children():
                child.bind("<Button-1>", _sel)
            state["cards"][addr] = card

            # presence lookup (optional)
            def _apply_presence(ok: Optional[bool]):
                try:
                    if ok is True:
                        pres.config(text="•  Online", fg=c["on"])
                    elif ok is False:
                        pres.config(text="•  Offline", fg=c["off"])
                    else:
                        pres.config(text="•  Unknown", fg=c["muted"])
                except Exception:
                    pass
            if presence_provider:
                try:
                    presence_provider(addr, lambda pub: self.root.after(0, lambda: _apply_presence(bool(pub))))
                except Exception:
                    _apply_presence(None)
            else:
                _apply_presence(None)

            return card
        
        def _rank(alias: str, addr: str, key: str):
            if not key:
                return (0, alias.lower())
            al = alias.lower(); ad = addr.lower()
            if al.startswith(key): return (0, al)
            if ad.startswith(key): return (1, al)
            if key in al or key in ad: return (2, al)
            return None

        def _rebuild():
            for w in grid.winfo_children():
                w.destroy()
            _set_sel(None)
            key = (qvar.get() or "").strip().lower()

            ranked: List[tuple[tuple[int, str], str, str]] = []
            for addr, alias in self._contacts.items():
                r = _rank(alias, addr, key)
                if r is not None:
                    ranked.append((r, addr, alias))
            ranked.sort(key=lambda t: t[0])

            col = row = 0
            for _r, addr, alias in ranked:
                wrap = tk.Frame(grid, bg=c["bg"])
                wrap.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)
                _mk_card(wrap, addr, alias).pack(fill=tk.BOTH, expand=True)
                col = 1 - col
                if col == 0: row += 1

            grid.update_idletasks()
            grid.grid_columnconfigure(0, weight=1, minsize=320)
            grid.grid_columnconfigure(1, weight=1, minsize=320)
            canvas.configure(scrollregion=canvas.bbox("all") or (0, 0, 0, 0))

        # scroll & resize events
        def _on_scroll(ev):
            if not canvas.winfo_exists():
                return
            canvas.yview_scroll(-1 if ev.delta > 0 else 1, "units")

        canvas.bind_all("<MouseWheel>", _on_scroll)
        dlg.bind("<Destroy>", lambda _e: canvas.unbind_all("<MouseWheel>"), add="+")
        grid.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all") or (0, 0, 0, 0)))

        # ---- action bar (tombol) ----
        bar = tk.Frame(dlg, bg=c["bg"])
        bar.pack(fill=tk.X, padx=18, pady=(0, 14))

        def add_contact():
            res = self._ask_contact(dlg, title="Add Contact")
            if not res: return
            addr, alias = res
            if self.upsert(addr, alias):
                self.toast("Contact saved."); _rebuild()

        def edit_contact():
            a = state["sel_addr"]
            if not a:
                messagebox.showinfo("Edit Contact", "Select a contact first."); return
            alias0 = self._contacts.get(a, "")
            res = self._ask_contact(dlg, title="Edit Contact", alias=alias0, address=a)
            if not res: return
            new_addr, new_alias = res
            if new_addr != a:
                if not self.delete(a):
                    return
            if self.upsert(new_addr, new_alias):
                self.toast("Contact updated."); _rebuild()
                _set_sel(new_addr)

        def del_contact():
            a = state["sel_addr"]
            if not a:
                messagebox.showinfo("Delete Contact", "Select a contact first."); return
            if not messagebox.askyesno("Delete Contact", "Are you sure you want to delete this contact?"):
                return
            if self.delete(a):
                self.toast("Contact deleted."); _rebuild()

        def use_selected():
            a = state["sel_addr"]
            if not a:
                return
            alias = self._contacts.get(a, "")
            try:
                if on_pick: on_pick(a, alias)
            finally:
                dlg.destroy()

        # Tombol: Add (orange), Edit, Delete, Use (putih -> orange saat dipilih)
        add_btn = tk.Button(bar, text="Add", command=add_contact,
                            bg=c["accent"], fg="white", bd=0, padx=14, pady=6, cursor="hand2", relief=tk.FLAT)
        edit_btn = tk.Button(bar, text="Edit", command=edit_contact,
                            bg=c["panel_bg"], fg=c["fg"], bd=0, padx=14, pady=6, cursor="hand2", relief=tk.FLAT)
        del_btn = tk.Button(bar, text="Delete", command=del_contact,
                            bg=c["panel_bg"], fg=c["fg"], bd=0, padx=14, pady=6, cursor="hand2", relief=tk.FLAT)
        use_local = tk.Button(bar, text="Use Contact", command=use_selected,
                            bg="white", fg="black", state="disabled", bd=0, padx=14, pady=6, cursor="hand2", relief=tk.FLAT)

        # keep a ref for _set_sel
        use_btn = use_local

        add_btn.pack(side=tk.LEFT, padx=(0, 6))
        edit_btn.pack(side=tk.LEFT, padx=6)
        del_btn.pack(side=tk.LEFT, padx=6)
        use_local.pack(side=tk.RIGHT)

        # terakhir: render grid
        _rebuild()

        # live filter
        qentry.bind("<KeyRelease>", lambda _e: _rebuild())


        try:
            qentry.focus_set()
        except Exception:
            pass
        try:
            center_window(dlg, self.root)
        except Exception:
            pass

    # ---------- UX helper: context menu for Entry/Combobox ----------
    def attach_to_entry(self, widget: tk.Widget, on_pick: Callable[[str, str], None]) -> None:
        menu = tk.Menu(widget, tearoff=0, bg="#1b1d20", fg="#e8e8e8",
                       activebackground="#2a2f36", activeforeground="#ffffff")
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Pick Contact…", command=lambda: self.pick_contact(on_pick=on_pick))

        def show_menu(e):
            try:
                menu.tk_popup(e.x_root, e.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)
