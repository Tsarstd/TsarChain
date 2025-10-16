﻿# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading, time, re
import multiprocessing as mp

# ---------------- Local Project ----------------
import tsarcore_native as native
from tsarchain.consensus.blockchain import Blockchain
from tsarchain.network.node import Network
from tsarchain.core.block import Block
from tsarchain.utils import config as CFG

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import launch_gui_in_thread, setup_logging, open_log_toplevel, get_ctx_logger
native.set_py_logger(get_ctx_logger("tsarchain.native"))

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    psutil = None
    HAVE_PSUTIL = False

ADDR_HINT = "tsar1..."
IPPORT_RE = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})$")


class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _e=None):
        if self.tip: return
        x, y, cx, cy = self.widget.bbox("insert") if self.widget.winfo_exists() else (0,0,0,0)
        x += self.widget.winfo_rootx() + 20
        y += self.widget.winfo_rooty() + 20
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify="left",
                         background="#2a2a2a", foreground="#ddd",
                         relief="solid", borderwidth=1, font=("Consolas", 9))
        label.pack(ipadx=6, ipady=4, padx=1, pady=1)
        
    def _hide(self, _e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class BlockchainGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TsarChain Miner")
        root.geometry("820x720")
        self.node_alive = threading.Event()
        self.mining_alive = threading.Event()
        self.cancel_mining = None
        self.gui_log = get_ctx_logger("apps.[miner_gui]")
        self._last_chain_height = -1

        # theme
        self.bg = "#121212"
        self.panel_bg = "#1e1e1e"
        self.accent = "#ff5e00"
        self.fg = "#C8C8C8"
        self.good = "#4EBD40"
        self.bad  = "#F1633F"
        self.warn = "#E7B923"
        self.root.configure(bg=self.bg)

        # state
        self.blockchain: Blockchain | None = None
        self.network: Network | None = None
        self.mining_thread: threading.Thread | None = None
        self.progress_queue: mp.Queue | None = None
        self.peer_list: list[tuple[str,int]] = []
        self.bootstrap_manual: tuple[str, int] | None = None
        self.progress_polling = False

        # layout
        self.sidebar = tk.Frame(root, bg=self.panel_bg, width=160)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.main = tk.Frame(root, bg=self.bg)
        self.main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._make_sidebar_button("Mining", self.show_mining_frame)
        self._make_sidebar_button("Print Chain", self.show_print_frame)
        self._make_sidebar_button("Dev", self.show_dev_frame)

        self.frames = {}
        self._build_mining_frame()
        self._build_print_frame()
        self._build_dev_frame()
        self._build_corner_status()

        self.show_mining_frame()
        self._heartbeat()

    # ---------- UI builders ----------
    def _make_sidebar_button(self, text, cmd):
        b = tk.Button(self.sidebar, text=text, bd=0, relief=tk.FLAT,
                      bg=self.panel_bg, fg=self.fg, activebackground=self.panel_bg, command=cmd)
        b.pack(pady=10, padx=10, fill=tk.X)

    def _section(self, parent, title):
        frame = tk.LabelFrame(parent, text=title, bg=self.bg, fg=self.accent, padx=10, pady=8,
                              labelanchor="nw", bd=1, highlightbackground=self.panel_bg, highlightcolor=self.panel_bg,
                              font=("Consolas", 10, "bold"))
        return frame

    # ---------------- Mining Tab ----------------
    def _build_mining_frame(self):
        f = tk.Frame(self.main, bg=self.bg)
        self.frames['mining'] = f

        # Wizard hint
        hint = tk.Label(f, text="Address -> 1) Performance -> 2) Start Node -> 3) Happy Mining!",
                        bg=self.bg, fg=self.fg, font=("Consolas", 10))
        hint.pack(anchor="w", padx=12, pady=(10, 2))

        # Section 1: Miner Address (with validation)
        sec_addr = self._section(f, "1) Miner Address")
        sec_addr.pack(fill=tk.X, padx=12, pady=8)
        r = tk.Frame(sec_addr, bg=self.bg); r.pack(fill=tk.X)
        tk.Label(r, text="Address (tsar1…):", bg=self.bg, fg=self.fg).pack(side=tk.LEFT)
        self.miner_address_entry = tk.Entry(r, width=44, bg="#1e1e1e", fg=self.fg, insertbackground=self.fg)
        self.miner_address_entry.pack(side=tk.LEFT, padx=6)
        self.addr_status = tk.Label(sec_addr, text="Waiting input…", bg=self.bg, fg=self.warn)
        self.addr_status.pack(anchor="w", pady=2)
        self.miner_address_entry.bind("<KeyRelease>", lambda _e: (self._validate_address(False), self._set_buttons_state()))
        Tooltip(self.miner_address_entry, "Only Support 'tsar1' Prefix Address")

        # Section 2: Performance
        sec_perf = self._section(f, "2) Performance")
        sec_perf.pack(fill=tk.X, padx=12, pady=8)
        rr = tk.Frame(sec_perf, bg=self.bg); rr.pack(fill=tk.X)
        tk.Label(rr, text="CPU cores:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT)
        self.cpu_entry = tk.Entry(rr, width=6, bg="#1e1e1e", fg=self.fg, insertbackground=self.fg)
        self.cpu_entry.pack(side=tk.LEFT, padx=6)
        self.cpu_entry.insert(0, "1")
        tk.Button(rr, text="MAX", command=self._auto_cores).pack(side=tk.LEFT, padx=(4,0))
        self.numba_var = tk.BooleanVar(value=True)
        Tooltip(self.cpu_entry, "More Cores More Fast!!!!")

        # Section 3: Controls
        sec_ctrl = self._section(f, "3) Controls")
        sec_ctrl.pack(fill=tk.X, padx=12, pady=8)
        ctrl = tk.Frame(sec_ctrl, bg=self.bg); ctrl.pack()
        self.btn_start_node = tk.Button(ctrl, text="Start Node", bg=self.accent, fg="#fff", command=self.start_node)
        self.btn_start_node.grid(row=0, column=0, padx=5, pady=2)
        self.btn_bench = tk.Button(ctrl, text="Benchmark 5s", command=self.run_benchmark, state="disabled")
        self.btn_bench.grid(row=0, column=1, padx=5, pady=2)
        self.btn_start_mining = tk.Button(ctrl, text="Start Mining", bg=self.accent, fg="#fff", command=self.start_mining, state="disabled")
        self.btn_start_mining.grid(row=0, column=2, padx=5, pady=2)
        self.btn_stop = tk.Button(ctrl, text="Stop Node & Mining", bg="#d9534f", fg="#fff", command=self.stop_all, state="disabled")
        self.btn_stop.grid(row=0, column=3, padx=5, pady=2)

        # Hashrate row + log controls
        hr = tk.Frame(f, bg=self.bg); hr.pack(fill=tk.X, padx=12, pady=(6,0))
        tk.Label(hr, text="Total Hashrate:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT)
        self.hashrate_var = tk.StringVar(value="0 H/s")
        self.hashrate_label = tk.Label(hr, textvariable=self.hashrate_var, bg=self.bg, fg=self.accent, font=("Consolas", 12, "bold"))
        self.hashrate_label.pack(side=tk.LEFT, padx=8)
        
        tk.Button(hr, text="Open Log Viewer", command=self._open_log_viewer).pack(side=tk.RIGHT, padx=4)
        tk.Button(hr, text="Clear Logs", command=self._clear_logs).pack(side=tk.RIGHT, padx=4)

        # Log area
        self.log = scrolledtext.ScrolledText(f, width=96, height=18, state="disabled", bg="#1e1e1e", fg="#52aa41")
        self.log.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

    # ---------------- Print Chain Tab ----------------
    def _build_print_frame(self):
        f = tk.Frame(self.main, bg=self.bg)
        self.frames['print'] = f
        btn_frame = tk.Frame(f, bg=self.bg)
        btn_frame.pack(pady=(10, 6))
        tk.Button(btn_frame, text="Print Chain", bg=self.accent, fg="#fff", command=self.print_chain).pack(pady=5)
        meta_frame = tk.Frame(f, bg=self.bg)
        meta_frame.pack(fill=tk.X, padx=12, pady=(0, 6))
        self.meta_label = tk.Label(meta_frame, text="Height: -   |   Supply: - TSAR", bg=self.bg, fg=self.accent)
        
        try:
            self.meta_label.configure(font=("Consolas", 12, "bold"))
        except Exception:
            self.meta_label.configure(font=("Courier New", 12, "bold"))
            
        self.meta_label.pack(anchor="center")
        self.print_output = scrolledtext.ScrolledText(f, width=90, height=25, state="disabled", bg="#1e1e1e", fg=self.fg, wrap="none", undo=False, autoseparators=False)
        
        try:
            self.print_output.configure(font=("Consolas", 10))
        except Exception:
            self.print_output.configure(font=("Courier New", 10))

        self.print_output.tag_configure("hdr", foreground=self.accent)
        self.print_output.tag_configure("meta", foreground="#9aa0a6")
        self.print_output.tag_configure("hash", foreground="#9cdcfe")
        self.print_output.tag_configure("prev", foreground="#6fb3ce")
        self.print_output.tag_configure("id",   foreground="#c3e88d")
        self.print_output.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

    # ---------------- Dev Tab ----------------
    def _build_dev_frame(self):
            f = tk.Frame(self.main, bg=self.bg)
            self.frames['dev'] = f
            
            top = tk.Frame(f, bg=self.bg)
            top.pack(fill=tk.X, padx=12, pady=8)
            tk.Label(top, text="Built by Tsar Studio | Open Source on GitHub", bg=self.bg, fg=self.accent, font=("Consolas", 8, 'bold')).pack(side=tk.RIGHT)
            tk.Label(top, text="Miner Gui v.1", bg=self.bg, fg=self.accent, font=("Consolas", 8, "bold")).pack(side=tk.LEFT)

            info_area = tk.Frame(f, bg=self.bg)
            info_area.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
            lbl_title = tk.Label(info_area, text="🌐Tsar Chain🌐", bg=self.bg, fg=self.accent, font=("Segoe UI", 65, 'bold'))
            lbl_title.pack(pady=(0, 0)) 
            lbl_sub = tk.Label(info_area, text="--- Long Live The Voice Sovereignty Monetary System ---\n", bg=self.bg, fg=self.accent, font=("Consolas", 12, 'bold'))
            lbl_sub.pack(pady=(0, 0))
            self.dev_text = scrolledtext.ScrolledText(info_area, height=5, bg="#1e1e1e", fg=self.fg, insertbackground=self.fg, font=("Consolas", 11))
            self.dev_text.pack(fill=tk.BOTH, expand=True)
            
            self.dev_text.tag_configure("title", font=("Consolas", 16, "bold"), foreground="#ff5e00")
            self.dev_text.tag_configure("center", justify="center")
            self.dev_text.tag_configure("info", font=("Consolas", 10), foreground="#858585")
            self.dev_text.tag_configure("alert", font=("Consolas", 13, "bold"), foreground="#F1633F")
            self.dev_text.tag_configure("status", font=("Consolas", 10, "bold"), foreground="#31C47F")
            self.dev_text.tag_configure("on_develop", font=("Consolas", 10, "bold"), foreground="#BDAA3F")
            self.dev_text.tag_configure("dev", font=("Consolas", 10, "bold"), foreground="#378EC0")
            
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
                "-- Proof-of-Work --\n-- Chat Feature (3XDH & Double Rachet) --\n-- Coinbase reward --\n-- UTXO system --\n-- SegWit transactions --\n"
                "-- Fee mechanism --\n-- Mempool --\n-- Multi-node networking --\n-- Transaction & block validation --\n"
                "-- Chain validation --\n",
                ("status", "center"),
            )
            self.dev_text.insert(tk.END, "\n⚠️ On Development ⚠️\n", ("alert", "center"))
            self.dev_text.insert(
                tk.END,
                "\n-- Storage Node --\n-- Graffiti --\n-- Some Security --\n-- Some UI/UX Wallet --\n"
                "-- etc. --\n",
                ("on_develop", "center"),
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
            
    def _build_corner_status(self):
        self.corner = tk.Frame(self.main, bg="#4D4D4D")
        self.corner.place(relx=0.0, rely=1.0, anchor="sw", x=8, y=-8)

        self.dot_node = tk.Label(self.corner, text="•", fg=self.bad, bg="#4D4D4D", font=("Consolas", 10, "bold"))
        self.dot_node.pack(side=tk.LEFT, padx=(8, 4), pady=4)
        
        self.status_node = tk.Label(self.corner, text="Offline", fg=self.fg, bg="#4D4D4D", font=("Consolas", 9))
        self.status_node.pack(side=tk.LEFT, padx=(0, 8))

        self.status_peers = tk.Label(self.corner, text="Peers: 0", fg=self.fg, bg="#4D4D4D", font=("Consolas", 9))
        self.status_peers.pack(side=tk.LEFT, padx=(0, 8))

        self.dot_mine = tk.Label(self.corner, text="•", fg=self.bad, bg="#4D4D4D", font=("Consolas", 10, "bold"))
        self.dot_mine.pack(side=tk.LEFT, padx=(8, 4))
        
        self.status_mine = tk.Label(self.corner, text="Mining: stopped", fg=self.fg, bg="#4D4D4D", font=("Consolas", 9))
        self.status_mine.pack(side=tk.LEFT, padx=(0, 8))

    # ---------- Helpers ----------
    def log_print(self, msg: str):
        try:
            (getattr(self, "gui_log", None) or get_ctx_logger("apps.[miner_gui]")).info(msg)
        except Exception:
            pass
        self.root.after(0, self._log_print_main, msg)

    def _log_print_main(self, msg: str):
        self.log.config(state="normal")
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.config(state="disabled")

    def _set_buttons_state(self):
        node_on   = self.blockchain is not None and self.network is not None
        mining_on = self.mining_alive.is_set()
        addr_ok   = self._address_ok()
        if mining_on:
            self.btn_start_node.config(state="disabled")
            self.btn_start_mining.config(state="disabled")
            self.btn_bench.config(state="disabled")
            self.btn_stop.config(state="normal")
        else:
            self.btn_start_node.config(state="disabled" if node_on else "normal")
            can_mine = node_on and addr_ok and (getattr(self.blockchain, "height", -1) >= 0)
            self.btn_start_mining.config(state="normal" if can_mine else "disabled")
            self.btn_bench.config(state="normal" if node_on else "disabled")
            self.btn_stop.config(state="normal" if node_on else "disabled")
        
    def _address_ok(self) -> bool:
        addr = (self.miner_address_entry.get() or "").strip()
        return bool(addr) and addr.lower().startswith("tsar1")

    def _validate_address(self, notify=True) -> bool:
        ok = self._address_ok()
        if ok:
            self.addr_status.config(text="Looks good...", fg=self.good)
        else:
            self.addr_status.config(text=f"Address should start with '{ADDR_HINT}'", fg=self.warn)
            if notify:
                messagebox.showwarning("Address", f"Isi miner address yang valid, contoh: {ADDR_HINT}")
        return ok

    def _auto_cores(self):
        try:
            cores = psutil.cpu_count(logical=True) if HAVE_PSUTIL else mp.cpu_count()
            self.cpu_entry.delete(0, tk.END)
            self.cpu_entry.insert(0, str(max(1, int(cores) - 1)))
        except Exception:
            self.cpu_entry.delete(0, tk.END)
            self.cpu_entry.insert(0, "1")

    def _clear_logs(self):
        self.log.config(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.config(state="disabled")
        
    def _open_log_viewer(self):
        log_file = str(CFG.LOG_PATH)
        try:
            open_log_toplevel(self.root, log_file=log_file, attach_to_root=False)
        except Exception:
            launch_gui_in_thread(log_file=log_file, attach_to_root=False)
        self.log_print("[Log] Opened Tsar Logging viewer")

    # ---------- Node / Mining control ----------
    def start_node(self):
        if self.blockchain:
            messagebox.showinfo("Info", "Node is already running.")
            return

        try:
            use_cores = int(self.cpu_entry.get() or "1")
            self.blockchain = Blockchain(
                db_path=CFG.BLOCK_FILE, in_memory=False,
                use_cores=use_cores, miner_address=self.miner_address_entry.get().strip()
            )
            self.network = Network(blockchain=self.blockchain)
            try:
                self._last_chain_height = int(getattr(self.blockchain, "height", -1))
            except Exception:
                self._last_chain_height = -1

            # Fallback ? BOOTSTRAP from config.py
            fallback_nodes = tuple(getattr(CFG, "BOOTSTRAP_NODES", ()) or (CFG.BOOTSTRAP_NODE,))
            try:
                for peer in fallback_nodes:
                    self.network.persistent_peers.add(peer)
                    self.network.peers.add(peer)
                if fallback_nodes:
                    host, port = fallback_nodes[0]
                    extra = f" (+{len(fallback_nodes)-1} alt)" if len(fallback_nodes) > 1 else ""
                    self.log_print(f"[Network] Using config bootstrap: {host}:{port}{extra}")
            except Exception:
                pass
        except Exception as e:
            self.blockchain = None
            self.network = None
            self._last_chain_height = -1
            messagebox.showerror("Start Node", f"Failed to Starting Node: {e}")
            return

        if self.network:
            threading.Thread(target=self._sync_daemon, daemon=True).start()
            self.log_print("[Sync] Background sync started..")

            def _early_sync():
                for _ in range(5):
                    try:
                        self.network.request_sync(fast=True)
                    except Exception:
                        pass
                    time.sleep(1.0)
            threading.Thread(target=_early_sync, daemon=True).start()

    def _sync_daemon(self):
        while self.blockchain and self.network:
            try:
                if self.network.peers:
                    self.network.request_sync(fast=True)
                    try:
                        height_raw = getattr(self.blockchain, "height", -1)
                        height = int(height_raw)
                    except Exception:
                        height = -1
                    if height != self._last_chain_height:
                        if height >= 0 and not self.mining_alive.is_set():
                            self.log_print(f"[Sync] Chain height now {height}")
                        self._last_chain_height = height
            except Exception:
                pass
            time.sleep(20)

    def start_mining(self):
        if not self.blockchain or not self.network:
            messagebox.showwarning("Warning", "Start the node first before mining.")
            return
        if not self._validate_address():
            return
        if self.mining_alive.is_set():
            return

        if getattr(self.blockchain, "height", -1) < 0:
            created = self.blockchain.ensure_genesis(
                (self.miner_address_entry.get()).strip(),
                use_cores=int(self.cpu_entry.get() or "1")
                )
            
            if created:
                self.log_print("[+] Genesis block created")
            else:
                self.log_print("[Genesis] Auto-genesis disabled; trying initial sync…")
                try:
                    if self.network:
                        self.network.request_sync(fast=True)
                        time.sleep(1.0)
                except Exception:
                    pass
                messagebox.showwarning("Warning", "No chain available. Wait for sync from a peer.")
                return

        use_cores = int(self.cpu_entry.get() or "1")
        pow_backend = "numba"

        self.log_print(f"[*] Mining with addr={self.miner_address_entry.get().strip()}  backend={pow_backend}  cores={use_cores}")

        self.mining_alive.set()
        self.status_mine.config(text="Mining: running"); self.dot_mine.config(fg=self.good)
        self.cancel_mining = mp.Event()
        self.progress_queue = mp.Queue()
        self.progress_polling = True
        self._poll_progress()
        self._set_buttons_state()

        def mining_loop():
            while self.mining_alive.is_set():
                try:
                    if self.network.peers:
                        self.network.request_sync(fast=True)
                        time.sleep(1)

                    block = self.blockchain.mine_block(
                        miner_address=self.miner_address_entry.get().strip(),
                        use_cores=use_cores,
                        cancel_event=self.cancel_mining,
                        pow_backend=pow_backend,
                        progress_queue=self.progress_queue
                    )
                    if not self.mining_alive.is_set():
                        break
                    if block:
                        self.log_print(f"[+] Block mined: {block.hash().hex()[:16]}…")
                        try:
                            msg = {"type": "NEW_BLOCK", "data": block.to_dict(), "port": self.network.port}
                            for peer in list(self.network.peers):
                                self.network.broadcast._send(peer, msg)
                        except Exception:
                            pass
                        try:
                            for tx in (getattr(block, "transactions", []) or [])[1:]:
                                try:
                                    self.network.broadcast.mempool.remove_tx(tx.txid.hex())
                                except Exception:
                                    pass
                            try:
                                self.network.broadcast.mempool.save_pool(self.network.broadcast.mempool.load_pool())
                            except Exception:
                                pass
                        except Exception as _e:
                            try:
                                self.log_print(f"[Mempool] prune error: {_e}")
                            except Exception:
                                pass
                except Exception as e:
                    self.log_print(f"[-] Mining : {e}")
                    time.sleep(1)

        self.mining_thread = threading.Thread(target=mining_loop, daemon=True)
        self.mining_thread.start()


    def _poll_progress(self):
        if not (self.progress_polling and self.progress_queue):
            return
        updated = False
        try:
            while True:
                tag, val = self.progress_queue.get_nowait()
                if tag == "TOTAL_HPS":
                    self.hashrate_var.set(f"{float(val):,.0f} H/s")
                    updated = True
        except Exception:
            pass
        finally:
            self.root.after(500, self._poll_progress)

    def stop_mining(self):
        self.status_mine.config(text="Mining: stopped"); self.dot_mine.config(fg=self.bad)
        self.mining_alive.clear()
        if self.cancel_mining:
            self.cancel_mining.set()
        if self.mining_thread and self.mining_thread.is_alive():
            self.mining_thread.join(timeout=3)
        self.progress_polling = False
        self.hashrate_var.set(" 0 H/s")
        self.progress_queue = None
        self.log_print("[!] Mining stopped")
        self._set_buttons_state()

    def stop_all(self):
        self.stop_mining()
        if self.network:
            try:
                self.network.shutdown()
            except:
                pass
        self.blockchain = None
        self.network = None
        self._last_chain_height = -1
        self.log_print("[!] Node stopped")
        self._set_buttons_state()

    # ---------- Benchmark ----------
    def run_benchmark(self):
        if self.mining_alive.is_set():
            messagebox.showinfo("Benchmark", "Stop mining first before running the benchmark.")
            return
        if not self.blockchain:
            messagebox.showwarning("Benchmark", "Start the node first to obtain network parameters.")
            return
        use_cores = int(self.cpu_entry.get() or "1")
        pow_backend = "numba"

        try:
            last = self.blockchain.chain[-1] if self.blockchain.chain else None
            prev_hash = last.hash() if last else bytes.fromhex("00"*32)
            nxt_height = (getattr(self.blockchain, "height", -1) or -1) + 1
            bits = getattr(last, "bits", None)
            if hasattr(self.blockchain, "_expected_bits_on_prefix"):
                bits = self.blockchain._expected_bits_on_prefix(self.blockchain.chain, nxt_height)
            if not isinstance(bits, int):
                bits = getattr(self.blockchain, "MAX_BITS", 0x1D75FFFF)

            dummy_txs = ["benchmark"]
            dummy = Block(height=nxt_height, prev_block_hash=prev_hash, transactions=dummy_txs, bits=bits)
        except Exception as e:
            messagebox.showerror("Benchmark", f"Failed to make dummy block: {e}")
            return

        q = mp.Queue()
        stop_event = mp.Event()
        hps_values: list[float] = []
        self.log_print("[*] Benchmark started (5 seconds)…")

        def worker():
            try:
                dummy.mine(use_cores=use_cores, stop_event=stop_event, pow_backend=pow_backend, progress_queue=q)
            except Exception:
                pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()

        t0 = time.time()
        def poll_bench():
            nonlocal t0
            now = time.time()
            try:
                while True:
                    tag, val = q.get_nowait()
                    if tag == "TOTAL_HPS":
                        hps_values.append(float(val))
                        self.hashrate_var.set(f"{float(val):,.0f} H/s (bench)")
            except Exception:
                pass
            if now - t0 >= 5.0:
                stop_event.set()
                self.root.after(200, finish_bench)
            else:
                self.root.after(200, poll_bench)

        def finish_bench():
            try:
                t.join(timeout=1.5)
            except Exception:
                pass
            avg = sum(hps_values[-10:]) / max(1, len(hps_values[-10:])) if hps_values else 0.0
            self.log_print(f"Benchmark done ~{avg:,.0f} H/s (avg of last samples)")
            messagebox.showinfo("Benchmark Result", f"Average hashrate: ~{avg:,.0f} H/s\nBackend: {pow_backend}, Cores: {use_cores}")

        poll_bench()

    # ---------- Print chain ----------
    def print_chain(self):
        if not getattr(self, "blockchain", None):
            messagebox.showwarning("Warning", "Start Node First, Broo!!")
            return
        
        try:
            chain_str = self.blockchain.print_chain(max_blocks=100, columns=("height","time","txs","prev","hash","block_id"), widths={"prev":12, "hash":12, "block_id":35}, hash_len=12)
            h_raw = getattr(self.blockchain, "height", "")
            try:
                height_str = str(int(h_raw))
            except Exception:
                height_str = str(h_raw)
            s_raw = getattr(self.blockchain, "total_supply", 0)
            supply_num = 0.0
            if isinstance(s_raw, (int, float)):
                supply_num = float(s_raw)
            elif isinstance(s_raw, (list, tuple)):
                try:
                    supply_num = float(sum(x for x in s_raw if isinstance(x, (int, float))))
                except Exception:
                    supply_num = 0.0
            elif isinstance(s_raw, str):
                try:
                    supply_num = float(s_raw)
                except Exception:
                    supply_num = 0.0

            supply_str = f"{supply_num/1e8:.8f} TSAR"
            self.meta_label.config(text=f"Height: {height_str}   |   Supply: {supply_str}")
            self.print_output.config(state="normal")
            self.print_output.delete(1.0, tk.END)
            self.print_output.insert(tk.END, chain_str)
            first_nl = self.print_output.search("\n", "1.0", tk.END) or "1.end"
            self.print_output.tag_add("hdr", "1.0", first_nl)
            text_all = self.print_output.get("1.0", tk.END)
            lines = text_all.splitlines()
            
            for i, line in enumerate(lines[1:], start=2):
                parts = [p.strip() for p in line.split("|")]
                
                if len(parts) < 6:
                    continue

                c0 = line.find("|")
                c1 = line.find("|", c0 + 1)
                c2 = line.find("|", c1 + 1)
                c3 = line.find("|", c2 + 1)
                c4 = line.find("|", c3 + 1)

                if c2 != -1 and c3 != -1:
                    self.print_output.tag_add("prev", f"{i}.{c2+1}", f"{i}.{c3}")
                if c3 != -1 and c4 != -1:
                    self.print_output.tag_add("hash", f"{i}.{c3+1}", f"{i}.{c4}")
                if c4 != -1:
                    self.print_output.tag_add("id", f"{i}.{c4+1}", f"{i}.end")
                    
            self.print_output.see(tk.END)
            self.print_output.config(state="disabled")
            
        except Exception as e:
            self.print_output.config(state="normal")
            self.print_output.insert(tk.END, f"\n[-] Print error: {e}")
            self.print_output.config(state="disabled")

    # ---------- Frame routing ----------
    def _hide_all_frames(self):
        for fr in self.frames.values():
            fr.pack_forget()

    def show_mining_frame(self):
        self._hide_all_frames()
        self.frames['mining'].pack(fill=tk.BOTH, expand=True)

    def show_print_frame(self):
        self._hide_all_frames()
        self.frames['print'].pack(fill=tk.BOTH, expand=True)

    def show_dev_frame(self):
        self._hide_all_frames()
        self.frames['dev'].pack(fill=tk.BOTH, expand=True)

    # ---------- Heartbeat ----------
    def _heartbeat(self):
        node_on = (self.blockchain is not None and self.network is not None)
        self.status_node.config(text="Online" if node_on else "Offline")
        self.dot_node.config(fg=self.good if node_on else self.bad)
        peers = 0
        if node_on:
            try:
                peers = len(self.network.peers)
            except Exception:
                peers = 0
        self.status_peers.config(text=f"Peers: {peers}")
        self._set_buttons_state()
        self.root.after(1000, self._heartbeat)


if __name__ == "__main__":
    mp.freeze_support()
    
    setup_logging(force=True)
    
    root = tk.Tk()
    app = BlockchainGUI(root)
    root.mainloop()
