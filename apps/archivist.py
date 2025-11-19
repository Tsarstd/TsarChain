# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

import os, threading, sys
import tkinter as tk
import multiprocessing as mp
from tkinter import ttk, messagebox, simpledialog
from typing import Optional, Dict, Any

# ---------------- Local Project ----------------
from tsarchain.contracts.storage_node.server import StorageServer
from tsarchain.contracts.storage_node.rpc import RPC, NodeDirectory

from tsarchain.utils import config as CFG

from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
log = get_ctx_logger("apps.archivist")

APP_TITLE = "TsarChain • Archivist"
HEARTBEAT_SEC = 10
RETENTION_GC_SEC = 800
STORAGE_PORT_OFFSET = 100

class TsarStorageGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("980x680")
        self.rpc = RPC()
        global SCAN_KP
        
        SCAN_KP = {"net_id": CFG.DEFAULT_NET_ID, "node_id": self.rpc.ctx["node_id"],
           "privkey": self.rpc.ctx["privkey"], "pubkey": self.rpc.pub}
        
        self.connected = False
        self.last_info: Dict[str, Any] | None = None
        self._retention_stop = threading.Event()
        self._retention_thread: Optional[threading.Thread] = None
        self._pending_paid: set[str] = set()
        self._pool_data: dict[str, Dict[str, Any]] = {}
        self._storage_port: Optional[int] = None
        self._server: Optional[StorageServer] = None
        self.addr_var = tk.StringVar(value=self.rpc.address or "")
        self._target_node: Optional[tuple[str,int]] = None
        self._build_ui()
        self._heartbeat()


    # ---------------- UI -----------------
    def _build_ui(self):
        self.style = ttk.Style()
        self.style.theme_use("default")

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        self.status_lbl = ttk.Label(top, text="● Offline", foreground="#d33", font=("Consolas", 10, "bold"))
        self.status_lbl.pack(side=tk.LEFT)

        ttk.Label(top, text="  Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(top, textvariable=self.host_var, width=14).pack(side=tk.LEFT)

        ttk.Label(top, text="  Port:").pack(side=tk.LEFT)
        self.port_var = tk.IntVar(value=CFG.PORT_START)
        ttk.Entry(top, textvariable=self.port_var, width=6).pack(side=tk.LEFT)

        ttk.Label(top, text="  Payout addr:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.addr_var, width=46).pack(side=tk.LEFT, padx=(4, 0))

        self.btn_connect = ttk.Button(top, text="Connect", command=self.on_connect)
        self.btn_connect.pack(side=tk.LEFT, padx=8)
        self.btn_disconnect = ttk.Button(top, text="Disconnect", command=self.on_disconnect, state=tk.DISABLED)
        self.btn_disconnect.pack(side=tk.LEFT)

        self.btn_open_dir = ttk.Button(top, text="Open Storage Folder", command=self.on_open_dir)
        self.btn_open_dir.pack(side=tk.RIGHT)

        # Info panel
        info = ttk.Frame(self.root, padding=(10, 4))
        info.pack(fill=tk.X)
        self.info_vars = {
            "role": tk.StringVar(value="NODE_STORAGE"),
            "tip": tk.StringVar(value="-"),
            "peers": tk.StringVar(value="0"),
            "bytes": tk.StringVar(value="0 B"),
            "files": tk.StringVar(value="0"),
            "saddr": tk.StringVar(value=""),
        }
        for key, label in [
            ("role", "Role"),("tip", "Tip Height"),("peers","Peers"),
            ("bytes","Bytes Used"),("files","Files")
        ]:
            f = ttk.Frame(info)
            f.pack(side=tk.LEFT, padx=12)
            ttk.Label(f, text=f"{label}", font=("Consolas",9)).pack(anchor="w")
            ttk.Label(f, textvariable=self.info_vars[key], font=("Consolas", 11, "bold")).pack(anchor="w")

        row = ttk.Frame(info)  # or your custom info panel
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Storage Address:", width=18).pack(side=tk.LEFT)
        addr_entry = ttk.Entry(row, textvariable=self.info_vars["saddr"])
        addr_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Copy", command=self._copy_addr).pack(side=tk.LEFT, padx=4)
        
        # Actions
        ttk.Frame(self.root, height=4).pack(fill=tk.X)

        # Table
        table = ttk.Frame(self.root, padding=(10, 0))
        table.pack(fill=tk.BOTH, expand=True)
        cols = ("graffiti_id","size","paid","expire","state","path")
        self.tree = ttk.Treeview(table, columns=cols, show="headings", height=16)
        for c, w in [("graffiti_id",220),("size",100),("paid",60),("expire",90),("state",90),("path",360)]:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, stretch=(c=="path"))
        self.tree.pack(fill=tk.BOTH, expand=True)
        action_row = ttk.Frame(table, padding=(0, 4))
        action_row.pack(fill=tk.X)
        ttk.Button(action_row, text="Mark Selected Paid", command=self._mark_selected_paid).pack(side=tk.LEFT, padx=6)

        pool_fr = ttk.LabelFrame(self.root, text="Storage Pool Balances", padding=(10, 6))
        pool_fr.pack(fill=tk.BOTH, expand=False, padx=10, pady=(4, 4))
        pool_cols = ("graffiti_id","pool","size","creator","comments")
        self.pool_tree = ttk.Treeview(pool_fr, columns=pool_cols, show="headings", height=6)
        for c, w in [("graffiti_id",220),("pool",120),("size",100),("creator",120),("comments",80)]:
            self.pool_tree.heading(c, text=c)
            self.pool_tree.column(c, width=w, stretch=(c=="graffiti_id"))
        self.pool_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0,4))
        pool_btn = ttk.Frame(pool_fr)
        pool_btn.pack(fill=tk.X, pady=(0,4))
        ttk.Button(pool_btn, text="Claim Pool Payout", command=self._claim_pool_payout).pack(side=tk.LEFT, padx=4)
        self.pool_status_var = tk.StringVar(value="Pool status pending.")
        ttk.Label(pool_fr, textvariable=self.pool_status_var).pack(anchor="w", padx=4)

        # Log
        logf = ttk.Frame(self.root, padding=10)
        logf.pack(fill=tk.BOTH, expand=False)
        ttk.Label(logf, text="Log").pack(anchor="w")
        self.log = tk.Text(logf, height=6)
        self.log.pack(fill=tk.BOTH, expand=True)

    def logln(self, text: str):
        try:
            self.log.insert(tk.END, text + "\n")
            self.log.see(tk.END)
        except Exception:
            pass
    
    def _copy_addr(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.info_vars["saddr"].get())

    def _launch_storage_server(self, fallback_start: Optional[int] = None) -> int:
        cand_ports: list[int] = []
        cfg_start = CFG.STORAGE_PORT_START
        cfg_end = CFG.STORAGE_PORT_END
        if cfg_start > 0 and cfg_end >= cfg_start:
            cand_ports.extend(range(cfg_start, cfg_end + 1))
        if fallback_start:
            base = max(1024, fallback_start)
            cand_ports.extend(range(base, base + 64))
        if not cand_ports:
            cand_ports.extend(range(39000, 39064))
        tried = set()
        for port in cand_ports:
            if port <= 0 or port in tried:
                continue
            tried.add(port)
            try:
                self._server = StorageServer("0.0.0.0", port, CFG.STORAGE_DIR)
                self.logln(f"[Storage] server listening on 0.0.0.0:{port}")
                log.info("Storage server listening on 0.0.0.0:%s", port)
                return port
            except OSError:
                continue
        raise RuntimeError("No free port for storage server")
    

    # ------------- Events --------------
    def on_connect(self):
        host = self.host_var.get().strip()
        miner_port = int(self.port_var.get())
        self._target_node = (host, miner_port)

        try:
            override = (self.addr_var.get() or "").strip()
            self.rpc.set_address_override(override)
        except ValueError as e:
            messagebox.showerror("Storage address", str(e))
            return
        self.rpc.set_trusted(True)

        storage_port = self._storage_port
        if self._server is None or storage_port is None:
            try:
                fallback = miner_port + STORAGE_PORT_OFFSET
                storage_port = self._launch_storage_server(fallback)
                self._storage_port = storage_port
            except Exception as e:
                log.exception("[connect] failed to start storage server near %s", miner_port)
                messagebox.showerror("Connect", f"Gagal start storage server: {e}")
                return

        ok = self.rpc.connect(host, miner_port, my_listen_port=storage_port)
        if not ok:
            peers = NodeDirectory.get_nodes() or []
            for ip, p in peers:
                if self.rpc.connect(ip, p, my_listen_port=storage_port):
                    NodeDirectory.mark_good((ip, p))
                    ok = True
                    break

        if ok:
            NodeDirectory.mark_good((host, miner_port))
            self.connected = True
            self.status_lbl.configure(text="● Connected", foreground="#1a8")
            self.btn_connect.config(state=tk.DISABLED)
            self.btn_disconnect.config(state=tk.NORMAL)
            self.refresh_all()
            self._start_retention_loop()
            log.info("Connected to node %s:%s", host, miner_port)
        else:
            log.warning("Failed to connect to any node (primary %s:%s)", host, miner_port)
            messagebox.showerror("Connect", "Gagal connect ke node mana pun")


    def on_disconnect(self):
        self.connected = False
        self.rpc.node = None
        self._retention_stop.set()
        self._pending_paid.clear()
        self._target_node = None
        self.btn_connect.configure(state=tk.NORMAL)
        self.btn_disconnect.configure(state=tk.DISABLED)
        self.status_lbl.configure(text="● Offline", foreground="#d33")
        self.tree.delete(*self.tree.get_children())
        for k in self.info_vars:
            if k != "role":
                self.info_vars[k].set("-")
        self.logln("Disconnected")
        log.info("Storage GUI disconnected from node")

    def on_open_dir(self):
        path = os.path.abspath(CFG.STORAGE_DIR)
        try:
            os.makedirs(path, exist_ok=True)
            if os.name == "nt":
                os.startfile(path)  # type: ignore
            elif sys.platform == "darwin":  # noqa: F821
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
        except Exception as e:
            messagebox.showerror("Open folder", str(e))

    # ------------- Refresh -------------
    def refresh_all(self):
        if not self.connected:
            return
        try:
            info = self.rpc.call({"type":"GET_INFO"}, timeout=4.0) or {}
            if not isinstance(info, dict):
                raise RuntimeError("rpc_failure")
            self.last_info = info
            self.info_vars["tip"].set(str(info.get("height","-")))
            self.info_vars["peers"].set(str(info.get("peers","0")))
            self.info_vars["saddr"].set(str(info.get("storage_address","-")))
        except Exception:
            self._handle_rpc_drop("refresh")
            return
        try:
            idx = self.rpc.call({"type":"STOR_INDEX"}, timeout=6.0)
            if not isinstance(idx, dict):
                raise RuntimeError("rpc_failure")
            self._render_index(idx)
        except Exception:
            self._handle_rpc_drop("refresh")

    def _render_index(self, idx: Dict[str,Any] | None):
        self.tree.delete(*self.tree.get_children())
        if not isinstance(idx, dict) or idx.get("status") != "ok":
            self.info_vars["files"].set("0")
            self.info_vars["bytes"].set("0 B")
            return
        files = idx.get("files", {})
        used  = int(idx.get("bytes_used", 0))
        self.info_vars["files"].set(str(len(files)))
        self.info_vars["bytes"].set(f"{used} bytes")
        for aid, meta in files.items():
            self.tree.insert("", tk.END, values=(
                aid,
                int(meta.get("size_bytes",0)),
                "yes" if meta.get("paid") else "no",
                meta.get("expire_at_height"),
                meta.get("state"),
                meta.get("path")
            ))
        self._refresh_pool_listing(files)

    def _refresh_pool_listing(self, files: Dict[str, Any]) -> None:
        if not getattr(self, "pool_tree", None):
            return
        rpc = getattr(self, "rpc", None)
        if not rpc:
            self.pool_status_var.set("RPC unavailable.")
            return
        try:
            resp = rpc.call({"type":"GRAFFITI_GET_POSTS","limit":500}, timeout=6.0) or {}
        except Exception:
            self.pool_status_var.set("Pool fetch failed.")
            return
        posts = resp.get("posts") or []
        self.pool_tree.delete(*self.pool_tree.get_children())
        self._pool_data = {}
        files_by_sha = {}
        for aid, meta in (files or {}).items():
            sha = str(meta.get("sha256") or "").lower()
            if sha:
                files_by_sha[sha] = {"id": aid, "meta": meta}

        for art in posts:
            aid = art.get("art_id")
            sha = str(art.get("sha256") or "").lower()
            file_meta = files_by_sha.get(sha)
            if not (aid and file_meta):
                continue
            stats = art.get("stats") or {}
            pool_balance = stats.get("pool_balance", 0)
            creator = (art.get("creator") or "")[:18]
            comments = stats.get("comments", 0)
            size_bytes = int(file_meta["meta"].get("size_bytes", 0))
            self._pool_data[aid] = {"post": art, "stats": stats, "file": file_meta["meta"]}
            self.pool_tree.insert("", tk.END, values=(
                aid[:16] + ("..." if len(aid) > 16 else ""),
                f"{pool_balance / CFG.TSAR:.8f}",
                f"{size_bytes:,}",
                creator,
                comments,
            ))
        if self._pool_data:
            self.pool_status_var.set(f"{len(self._pool_data)} karya dengan saldo pool.")
        else:
            self.pool_status_var.set("Belum ada saldo pool untuk karya tersimpan.")

    def _mark_selected_paid(self) -> None:
        if not self.connected:
            messagebox.showwarning("Payout", "Hubungkan ke node terlebih dahulu.")
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Payout", "Pilih entri pada tabel.")
            return
        gid = self.tree.item(sel[0], "values")[0]
        txid = simpledialog.askstring("Payout TXID", "Masukkan TXID payout (opsional):", parent=self.root)
        if txid is None:
            return
        try:
            resp = self.rpc.call({"type":"STOR_PAID", "graffiti_id": gid, "txid": (txid or "").strip()}, timeout=6.0)
        except Exception as exc:
            messagebox.showerror("Payout", f"RPC error: {exc}")
            return
        if isinstance(resp, dict) and resp.get("status") in ("ok", None):
            self.logln(f"[Payout] {gid} ditandai paid.")
            self.refresh_all()
        else:
            messagebox.showerror("Payout", f"Gagal menandai paid: {resp}")

    def _start_retention_loop(self) -> None:
        if self._retention_thread and self._retention_thread.is_alive():
            return
        self._retention_stop.clear()
        t = threading.Thread(target=self._retention_worker, daemon=True)
        self._retention_thread = t
        t.start()
        log.info("Started retention worker thread")
        
    def _attempt_reconnect(self) -> bool:
        target = getattr(self, "_target_node", None)
        storage_port = self._storage_port
        if not target or storage_port is None:
            return False
        host, miner_port = target
        try:
            override = (self.addr_var.get() or "").strip()
            self.rpc.set_address_override(override)
        except ValueError:
            pass
        self.rpc.set_trusted(True)
        ok = self.rpc.connect(host, miner_port, my_listen_port=storage_port)
        if ok:
            self.connected = True
            self.status_lbl.configure(text="● Connected", foreground="#1a8")
            self.btn_connect.config(state=tk.DISABLED)
            self.btn_disconnect.config(state=tk.NORMAL)
            self.refresh_all()
            log.info("Reconnected to node %s:%s", host, miner_port)
            return True
        return False

    def _handle_rpc_drop(self, reason: str = "") -> None:
        if not self.connected:
            return
        note = "[RPC] connection lost"
        if reason:
            note += f" ({reason})"
        self.logln(note + ".")
        self.connected = False
        self.btn_connect.config(state=tk.NORMAL)
        self.btn_disconnect.config(state=tk.DISABLED)
        self.status_lbl.configure(text="⚠ Offline (RPC)", foreground="#db3")
        if self._attempt_reconnect():
            self.logln("[RPC] reconnected automatically.")
        else:
            self.logln("Reconnection failed. Click Connect to retry.")

    def _retention_worker(self) -> None:
        while not self._retention_stop.is_set():
            if not self.connected:
                self._retention_stop.wait(RETENTION_GC_SEC)
                continue
            tip = int((self.last_info or {}).get("height") or 0)
            try:
                gc_resp = self.rpc.call({"type":"STOR_GC","tip_height": tip}, timeout=6.0)
                idx = self.rpc.call({"type":"STOR_INDEX"}, timeout=6.0)
                if not isinstance(gc_resp, dict) or not isinstance(idx, dict):
                    raise RuntimeError("rpc_failure")
                self.root.after(0, lambda r=gc_resp, i=idx: self._on_retention_cycle(r, i))
            except Exception as exc:
                log.warning("[Retention] rpc error at height %s: %s", tip, exc)
                self.root.after(0, self._handle_rpc_drop, "retention")
            self._retention_stop.wait(max(30, RETENTION_GC_SEC))

    def _on_retention_cycle(self, gc_resp: Optional[Dict[str, Any]], idx: Optional[Dict[str, Any]]) -> None:
        if isinstance(gc_resp, dict) and gc_resp.get("status") == "ok":
            expired = int(gc_resp.get("expired", 0))
            if expired:
                self.logln(f"[Retention] GC removed {expired} expired item(s)")
                log.info("[Retention] removed %s expired files", expired)
        if isinstance(idx, dict):
            self._render_index(idx)
            self._mark_pending_payouts(idx)

    def _mark_pending_payouts(self, idx: Dict[str, Any]) -> None:
        files = idx.get("files", {}) if isinstance(idx, dict) else {}
        current: set[str] = set()
        for aid, meta in (files.items() if isinstance(files, dict) else []):
            if not isinstance(meta, dict):
                continue
            if meta.get("state") == "stored" and not meta.get("paid"):
                current.add(aid)
                if aid not in self._pending_paid:
                    size = int(meta.get("size_bytes", 0))
                    self.logln(f"[Payout] Pending for {aid} ({size} bytes)")
                    log.info("[Payout] pending - %s (%s bytes)", aid, size)
            elif aid in self._pending_paid:
                self.logln(f"[Payout] Cleared for {aid}")
                log.info("[Payout] cleared - %s", aid)
        self._pending_paid = current

    def _claim_pool_payout(self) -> None:
        if not self.connected or not getattr(self, "pool_tree", None):
            messagebox.showwarning("Pool", "Hubungkan node terlebih dahulu.")
            return
        sel = self.pool_tree.selection()
        if not sel:
            messagebox.showinfo("Pool", "Pilih karya dari daftar pool.")
            return
        art_id = self.pool_tree.item(sel[0], "values")[0]
        entry = self._pool_data.get(art_id)
        if not entry:
            messagebox.showerror("Pool", "Data pool tidak ditemukan.")
            return
        stats = entry.get("stats") or {}
        pool_balance = int(stats.get("pool_balance", 0))
        if pool_balance <= 0:
            messagebox.showinfo("Pool", "Saldo pool nol.")
            return
        amount_str = simpledialog.askstring("Claim Pool",
                                            f"Saldo tersedia {pool_balance / CFG.TSAR:.8f} TSAR.\nMasukkan jumlah TSAR yang ingin diklaim:",
                                            parent=self.root,
                                            initialvalue=f"{pool_balance / CFG.TSAR:.8f}")
        if amount_str is None:
            return
        try:
            amount = float(amount_str.replace(",", "."))
            amount_sats = int(amount * CFG.TSAR)
        except Exception:
            messagebox.showerror("Pool", "Jumlah tidak valid.")
            return
        if amount_sats <= 0 or amount_sats > pool_balance:
            messagebox.showerror("Pool", "Jumlah melebihi saldo.")
            return
        txid = simpledialog.askstring("Claim Pool", "Masukkan TXID payout (opsional):", parent=self.root) or ""
        recipient = (self.addr_var.get() or self.rpc.address or "").strip().lower()
        try:
            resp = self.rpc.call({
                "type":"GRAFFITI_POOL_PAYOUT",
                "art_id": art_id,
                "amount": amount_sats,
                "recipient": recipient,
                "txid": txid.strip(),
            }, timeout=6.0)
        except Exception as exc:
            messagebox.showerror("Pool", f"RPC error: {exc}")
            return
        if isinstance(resp, dict) and resp.get("status") in (None, "ok"):
            self.logln(f"[Pool] Claimed {amount:.8f} TSAR for {art_id[:10]}...")
            self.pool_status_var.set("Payout recorded.")
            self.refresh_all()
        else:
            messagebox.showerror("Pool", f"Gagal klaim: {resp}")

    # ---------- Heartbeat ------------
    def _heartbeat(self):
        def run():
            if self.connected:
                try:
                    pong = self.rpc.call({"type":"PING"}, timeout=2.0)
                    if isinstance(pong, dict) and pong.get("type") == "PONG":
                        self.status_lbl.configure(text="● Connected", foreground="#1a8")
                        self.refresh_all()
                    else:
                        self._handle_rpc_drop("heartbeat")
                except Exception:
                    self._handle_rpc_drop("heartbeat")
            self.root.after(HEARTBEAT_SEC * 1000, run)
        self.root.after(HEARTBEAT_SEC * 1000, run)



if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    log.info("Launching Tsar Storage GUI")
    root = tk.Tk()
    app  = TsarStorageGUI(root)
    root.mainloop()
