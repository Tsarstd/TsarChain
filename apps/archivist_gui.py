# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

import os, threading, sys, json, socket, time, secrets
import tkinter as tk
import multiprocessing as mp
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any

# ---------------- Local Project ----------------
from tsarchain.contracts.storage_node.server import StorageServer
from tsarchain.contracts.storage_node.connect import RPC, NodeDirectory
from tsarchain.network.protocol import send_message, recv_message
from tsarchain.storage.db import AtomicJSONFile

from tsarchain.utils import config as CFG
from tsarchain.contracts import graffiti as GRAFFITI

from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger, open_log_toplevel
log = get_ctx_logger("apps.archivist")

APP_TITLE = "TsarChain • Archivist"
HEARTBEAT_SEC = 30
STORAGE_PORT_OFFSET = 100

class TsarStorageGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("980x680")
        self.rpc = RPC()
        self.directory = NodeDirectory()
        global SCAN_KP
        
        SCAN_KP = {"net_id": CFG.DEFAULT_NET_ID, "node_id": self.rpc.ctx["node_id"],
           "privkey": self.rpc.ctx["privkey"], "pubkey": self.rpc.pub}
        
        self.connected = False
        self.last_info: Dict[str, Any] | None = None
        self._retention_stop = threading.Event()
        self._retention_thread: Optional[threading.Thread] = None
        self._pending_paid: set[str] = set()
        self._pool_data: dict[str, Dict[str, Any]] = {}
        self._auto_payout_guard: dict[str, Dict[str, Any]] = {}
        self._auto_payout_store: Optional[AtomicJSONFile] = None
        self._auto_payout_guard_path: str = ""
        self._storage_port: Optional[int] = None
        self._server: Optional[StorageServer] = None
        self.addr_var = tk.StringVar(value="")
        self._target_node: Optional[tuple[str,int]] = None
        self._refresh_inflight = False
        self._log_max_lines = 500
        self._load_auto_payout_guard()
        self._build_ui()
        self._heartbeat()


    # ---------------- UI -----------------
    def _call_storage_local(self, payload: Dict[str, Any], timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        port = self._storage_port
        if port is None:
            return None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(("127.0.0.1", int(port)))
            send_message(s, json.dumps(payload).encode("utf-8"))
            raw = recv_message(s, timeout)
            if not raw:
                return None
            obj = json.loads(raw.decode("utf-8"))
            return obj if isinstance(obj, dict) else None

    def _normalize_network_info(self, info_obj: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(info_obj, dict) or info_obj.get("error"):
            return None
        data = info_obj.get("data") if info_obj.get("type") == "NETWORK_INFO" else info_obj
        chain = data.get("chain") if isinstance(data, dict) else {}
        peers = data.get("peers") if isinstance(data, dict) else {}

        def _as_int(val: Any) -> Optional[int]:
            try:
                return int(val)
            except (TypeError, ValueError):
                return None

        height = _as_int(chain.get("tip_height") if isinstance(chain, dict) else None)
        if isinstance(data, dict) and height is None:
            height = _as_int(data.get("height"))
        peers_cnt = _as_int(peers.get("count") if isinstance(peers, dict) else None)
        if isinstance(data, dict) and peers_cnt is None:
            peers_cnt = _as_int(data.get("peers"))

        if height is None and peers_cnt is None:
            return None
        normalized = dict(info_obj)
        normalized["height"] = height
        normalized["peers"] = peers_cnt
        return normalized

    def _build_ui(self):
        self.style = ttk.Style()
        self.style.theme_use("default")

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        self.status_lbl = ttk.Label(top, text="● Offline", foreground="#d33", font=("Consolas", 10, "bold"))
        self.status_lbl.pack(side=tk.LEFT)

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
        }
        for key, label in [
            ("role", "Role"),("tip", "Tip Height"),("peers","Peers"),
            ("bytes","Bytes Used"),("files","Files")
        ]:
            f = ttk.Frame(info)
            f.pack(side=tk.LEFT, padx=12)
            ttk.Label(f, text=f"{label}", font=("Consolas",9)).pack(anchor="w")
            ttk.Label(f, textvariable=self.info_vars[key], font=("Consolas", 11, "bold")).pack(anchor="w")

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
        
        tk.Button(pool_btn, text="Open Log Viewer", command=self._open_log_viewer).pack(side=tk.RIGHT, padx=4)
        
        self.pool_status_var = tk.StringVar(value="Pool status pending.")
        ttk.Label(pool_fr, textvariable=self.pool_status_var).pack(anchor="w", padx=4)

        # Log
        logf = ttk.Frame(self.root, padding=10)
        logf.pack(fill=tk.BOTH, expand=False)
        ttk.Label(logf, text="Log").pack(anchor="w")
        self.log = tk.Text(logf, height=6)
        self.log.pack(fill=tk.BOTH, expand=True)

    def logln(self, text: str):
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        lines = int(self.log.index("end-1c").split(".")[0])
        if lines > self._log_max_lines:
            self.log.delete("1.0", f"{lines - self._log_max_lines}.0")

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
            self._server = StorageServer("0.0.0.0", port, CFG.STORAGE_DIR)
            self.logln(f"[Storage] server listening on 0.0.0.0:{port}")
            return port
        raise RuntimeError("No free port for storage server")
    

    # ------------- Events --------------
    def on_connect(self):
        host, miner_port = CFG.BOOTSTRAP_NODE
        self._target_node = (host, miner_port)

        override = (self.addr_var.get() or "").strip()
        if not override:
            messagebox.showerror("Storage address", "Isi payout address terlebih dahulu.")
            return
        try:
            self.rpc.set_address_override(override)
        except Exception as exc:
            messagebox.showerror("Payout address", f"Alamat payout tidak valid: {exc}")
            return
        self.rpc.set_trusted(True)

        storage_port = self._storage_port
        if self._server is None or storage_port is None:
            fallback = miner_port + STORAGE_PORT_OFFSET
            storage_port = self._launch_storage_server(fallback)
            self._storage_port = storage_port

        ok = self.rpc.connect(host, miner_port, my_listen_port=storage_port)
        if not ok:
            peers = self.directory.get_nodes() or []
            for ip, p in peers:
                if self.rpc.connect(ip, p, my_listen_port=storage_port):
                    self.directory.mark_good((ip, p))
                    ok = True
                    break

        if ok:
            self.directory.mark_good((host, miner_port))
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

    def on_open_dir(self):
        path = os.path.abspath(CFG.STORAGE_DIR)
        os.makedirs(path, exist_ok=True)
        if os.name == "nt":
            os.startfile(path)  # type: ignore
        elif sys.platform == "darwin":  # noqa: F821
            os.system(f"open '{path}'")
        else:
            os.system(f"xdg-open '{path}'")
    
    def _open_log_viewer(self):
        log_file = str(CFG.LOG_PATH)
        open_log_toplevel(self.root, log_file=log_file, attach_to_root=False)

    # ------------- Refresh -------------
    def refresh_all(self):
        if not self.connected or self._refresh_inflight:
            return
        self._refresh_inflight = True

        def worker():
            info = None
            idx = None
            info_ok = idx_ok = False
            try:
                raw_info = self.rpc.call({"type":"GET_NETWORK_INFO"}, timeout=4.0) or {}
                info = self._normalize_network_info(raw_info)
                info_ok = isinstance(info, dict)
            except Exception as exc:
                log.warning("[refresh_all] GET_NETWORK_INFO error: %s", exc)
            try:
                idx = self._call_storage_local({"type":"STOR_INDEX"}, timeout=6.0)
                idx_ok = isinstance(idx, dict)
            except Exception as exc:
                log.warning("[refresh_all] STOR_INDEX error: %s", exc)

            def apply():
                if info_ok:
                    self.last_info = info
                    height = info.get("height") if isinstance(info, dict) else None
                    peers = info.get("peers") if isinstance(info, dict) else None
                    self.info_vars["tip"].set("-" if height is None else str(height))
                    self.info_vars["peers"].set("-" if peers is None else str(peers))
                else:
                    self.info_vars["tip"].set("-")
                    self.info_vars["peers"].set("-")
                    self._handle_rpc_drop("refresh_info")
                if idx_ok:
                    self._render_index(idx)
                else:
                    self._handle_rpc_drop("refresh_index")
                self._refresh_inflight = False

            self.root.after(0, apply)

        threading.Thread(target=worker, daemon=True).start()

    def _render_index(self, idx: Dict[str,Any] | None):
        self.tree.delete(*self.tree.get_children())
        if not isinstance(idx, dict) or idx.get("status") != "ok":
            self.info_vars["files"].set("0")
            self.info_vars["bytes"].set("0 B")
            return
        files = idx.get("files", {})
        used  = int(idx.get("bytes_used", 0))
        self.info_vars["files"].set(str(len(files)))
        self.info_vars["bytes"].set(self._fmt_bytes(used))
        for aid, meta in files.items():
            display_id = meta.get("art_id") or aid
            self.tree.insert("", tk.END, values=(
                display_id,
                int(meta.get("size_bytes",0)),
                "yes" if meta.get("paid") else "no",
                meta.get("expire_at_height"),
                meta.get("state"),
                meta.get("path")
            ))
        self._refresh_pool_listing(files, idx.get("art_map"))

    def _refresh_pool_listing(self, files: Dict[str, Any], art_map_idx: Optional[Dict[str, Any]] = None) -> None:
        if not getattr(self, "pool_tree", None):
            return
        rpc = getattr(self, "rpc", None)
        if not rpc:
            self.pool_status_var.set("RPC unavailable.")
            return
        resp = rpc.call({"type":"GRAFFITI_GET_POSTS","limit":500}, timeout=6.0) or {}
        posts = resp.get("posts") or []
        self.pool_tree.delete(*self.pool_tree.get_children())
        self._pool_data = {}
        files_by_sha: dict[str, dict] = {}
        files_by_art: dict[str, dict] = {}
        art_map = art_map_idx or {}
        for gid, meta in (files or {}).items():
            sha = str(meta.get("sha256") or "").lower()
            if sha:
                files_by_sha[sha] = {"id": gid, "meta": meta}
            art_id = str(meta.get("art_id") or "").lower()
            if art_id:
                files_by_art[art_id] = {"id": gid, "meta": meta}
        if isinstance(art_map, dict):
            for art_id, gid in art_map.items():
                if art_id in files_by_art:
                    continue
                meta = files.get(gid) if isinstance(files, dict) else None
                if isinstance(meta, dict):
                    files_by_art[str(art_id).lower()] = {"id": gid, "meta": meta}

        for art in posts:
            aid = art.get("art_id")
            sha = str(art.get("sha256") or "").lower()
            file_meta = files_by_art.get(str(aid).lower()) or files_by_sha.get(sha)
            if not (aid and file_meta):
                continue
            stats = art.get("stats") or {}
            pool_balance = stats.get("pool_balance", 0)
            creator = (art.get("creator") or "")[:18]
            comments = stats.get("comments", 0)
            size_bytes = int(file_meta["meta"].get("size_bytes", 0))
            self._pool_data[aid] = {"post": art, "stats": stats, "file": file_meta["meta"]}
            display_id = aid[:16] + ("..." if len(aid) > 16 else "")
            self.pool_tree.insert("", tk.END, iid=aid, values=(
                display_id,
                f"{pool_balance / CFG.TSAR:.8f}",
                f"{size_bytes:,}",
                creator,
                comments,
            ))
        if self._pool_data:
            self.pool_status_var.set(f"{len(self._pool_data)} karya dengan saldo pool.")
        else:
            self.pool_status_var.set("Belum ada saldo pool untuk karya tersimpan.")
        self._auto_mark_paid(posts, files_by_art)
        self._auto_payout()

    def _fmt_bytes(self, n: Any) -> str:
        size = float(n)
        units = ["B", "KB", "MB", "GB", "TB"]
        for u in units:
            if size < 1024.0 or u == units[-1]:
                return f"{size:.2f} {u}" if u != "B" else f"{int(size)} {u}"
            size /= 1024.0

    def _start_retention_loop(self) -> None:
        if self._retention_thread and self._retention_thread.is_alive():
            return
        self._retention_stop.clear()
        t = threading.Thread(target=self._retention_worker, daemon=True)
        self._retention_thread = t
        t.start()

    def _auto_mark_paid(self, posts: list[dict], files_by_art: dict[str, dict]) -> None:
        """
        Tandai otomatis file lokal sebagai paid ketika blok POST sudah diketahui.
        """
        if not posts or not files_by_art:
            return
        marked = False
        for art in posts:
            aid = str(art.get("art_id") or "").lower()
            if not aid:
                continue
            file_entry = files_by_art.get(aid)
            if not file_entry:
                continue
            meta = file_entry.get("meta") or {}
            if meta.get("paid"):
                continue
            bh = int(art.get("block_height", 0) or 0)
            if bh <= 0:
                continue
            gid = file_entry.get("id") or aid
            txid = (art.get("txid") or "").strip()
            resp = self._call_storage_local({"type":"STOR_PAID", "graffiti_id": gid, "txid": txid, "block_height": bh}, timeout=4.0)
            if isinstance(resp, dict) and resp.get("status") in ("ok", None):
                marked = True
                self.logln(f"[Auto-Paid] {gid} (h={bh})")
        if marked:
            self.refresh_all()

    def _load_auto_payout_guard(self) -> None:
        path = str(CFG.ARCHIVIST_AUTO_PAYOUT_GUARD_FILE)
        self._auto_payout_guard_path = path
        self._auto_payout_store = AtomicJSONFile(path, keep_backups=2, checksum=True)
        try:
            raw = self._auto_payout_store.load(default={}) or {}
        except Exception as exc:
            log.warning("[auto-payout] guard load failed: %s", exc)
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
        cleaned: dict[str, Dict[str, Any]] = {}
        for art_id, entry in raw.items():
            if not isinstance(entry, dict):
                continue
            try:
                epoch = int(entry.get("epoch", -1))
                ts = int(entry.get("ts", 0))
            except Exception:
                continue
            status = str(entry.get("status") or "error").lower()
            cleaned[str(art_id)] = {"epoch": epoch, "ts": ts, "status": status}
        self._auto_payout_guard = cleaned

    def _save_auto_payout_guard(self) -> None:
        if not self._auto_payout_store:
            return
        try:
            self._auto_payout_store.save(self._auto_payout_guard)
        except Exception as exc:
            log.warning("[auto-payout] guard save failed: %s", exc)

    def _auto_payout(self) -> None:
        if not self.connected or not self._pool_data:
            return
        tip_height = int((self.last_info or {}).get("height") or 0)
        tip_epoch = GRAFFITI.compute_proof_epoch(tip_height)
        drift = int(CFG.GRAFFITI_PROOF_EPOCH_DRIFT)
        if drift <= 0:
            return
        threshold = max(0, drift - 1)
        cooldown = int(CFG.ARCHIVIST_AUTO_PAYOUT_COOLDOWN_SEC)
        recipient = (self.addr_var.get() or self.rpc.address or "").strip().lower()
        if not recipient:
            return
        for art_id, entry in self._pool_data.items():
            stats = entry.get("stats") or {}
            last_paid_epoch = int(stats.get("last_paid_epoch", -1))
            pool_balance = int(stats.get("pool_balance", 0))
            if pool_balance <= 0:
                continue
            file_meta = entry.get("file") or {}
            if not file_meta.get("paid") or str(file_meta.get("state") or "") != "stored":
                continue
            last_proof_epoch = int(file_meta.get("last_proof_epoch", -1))
            if last_proof_epoch < 0:
                continue
            if last_paid_epoch >= last_proof_epoch:
                continue
            gap = tip_epoch - last_proof_epoch
            if gap < threshold or gap > drift:
                continue
            guard_entry = self._auto_payout_guard.get(art_id, {})
            guard_epoch = int(guard_entry.get("epoch", -1)) if isinstance(guard_entry, dict) else -1
            guard_ts = int(guard_entry.get("ts", 0)) if isinstance(guard_entry, dict) else 0
            guard_status = str(guard_entry.get("status") or "").lower() if isinstance(guard_entry, dict) else ""
            if guard_epoch > last_proof_epoch:
                continue
            if guard_epoch == last_proof_epoch:
                if guard_status == "ok":
                    continue
                if cooldown > 0 and int(time.time()) - guard_ts < cooldown:
                    continue
            attempt_ts = int(time.time())
            self._auto_payout_guard[art_id] = {"epoch": last_proof_epoch, "ts": attempt_ts, "status": "attempt"}
            self._save_auto_payout_guard()
            self.logln(
                f"[Auto-Payout] art={art_id[:16]} epoch={last_proof_epoch} gap={gap} pool={pool_balance}"
            )
            payload = {
                "type": "GRAFFITI_BUILD_PAYOUT",
                "art_id": art_id,
                "recipients": [{"addr": recipient, "amount": pool_balance}],
                "epoch": last_proof_epoch,
                "broadcast": True,
                "ts": int(time.time()),
                "nonce": secrets.token_hex(16),
            }
            resp = self.rpc.call(payload, timeout=8.0)
            ok = isinstance(resp, dict) and resp.get("status") == "ok"
            self._auto_payout_guard[art_id] = {
                "epoch": last_proof_epoch,
                "ts": int(time.time()),
                "status": "ok" if ok else "error",
            }
            self._save_auto_payout_guard()
            if ok:
                txid = (resp.get("tx") or {}).get("txid") or "?"
                self.logln(f"[Auto-Payout] broadcast tx {txid[:16]}... art={art_id[:12]}...")
                self.refresh_all()
            else:
                self.logln(f"[Auto-Payout] failed art={art_id[:12]} resp={resp}")
        
    def _attempt_reconnect(self) -> bool:
        target = getattr(self, "_target_node", None)
        storage_port = self._storage_port
        if not target or storage_port is None:
            return False
        host, miner_port = target
        override = (self.addr_var.get() or "").strip()
        self.rpc.set_address_override(override)
        self.rpc.set_trusted(True)
        ok = self.rpc.connect(host, miner_port, my_listen_port=storage_port)
        if ok:
            self.connected = True
            self.status_lbl.configure(text="● Connected", foreground="#1a8")
            self.btn_connect.config(state=tk.DISABLED)
            self.btn_disconnect.config(state=tk.NORMAL)
            self.refresh_all()
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
                self._retention_stop.wait(CFG.RETENTION_GC_SEC)
                continue
            tip = int((self.last_info or {}).get("height") or 0)
            gc_resp = self._call_storage_local({"type":"STOR_GC","tip_height": tip}, timeout=6.0)
            idx = self._call_storage_local({"type":"STOR_INDEX"}, timeout=6.0)
            if not isinstance(gc_resp, dict) or not isinstance(idx, dict):
                raise RuntimeError("rpc_failure")
            self._run_retention_proofs(idx, tip)
            self.root.after(0, lambda r=gc_resp, i=idx: self._on_retention_cycle(r, i))
            self._retention_stop.wait(max(30, CFG.RETENTION_GC_SEC))

    def _on_retention_cycle(self, gc_resp: Optional[Dict[str, Any]], idx: Optional[Dict[str, Any]]) -> None:
        if isinstance(gc_resp, dict) and gc_resp.get("status") == "ok":
            expired = int(gc_resp.get("expired", 0))
            if expired:
                self.logln(f"[Retention] GC removed {expired} expired item(s)")
        if isinstance(idx, dict):
            self._render_index(idx)
            self._mark_pending_payouts(idx)

    def _run_retention_proofs(self, idx: Dict[str, Any], tip_height: int) -> None:
        files = idx.get("files", {}) if isinstance(idx, dict) else {}
        if not files:
            return
        epoch_target = GRAFFITI.compute_proof_epoch(tip_height)
        for gid, meta in files.items():
            if not isinstance(meta, dict):
                continue
            if not meta.get("paid") or meta.get("state") != "stored":
                continue
            last_epoch = int(meta.get("last_proof_epoch", -1))
            if last_epoch >= epoch_target:
                continue
            art_id = str(meta.get("art_id") or "").strip().lower()
            if not art_id:
                self.logln(f"[Proof] skip {gid[:10]} (missing art_id)")
                continue
            payload = {
                "type": "STOR_PROOF_RUN",
                "graffiti_id": gid,
                "art_id": art_id,
                "tip_height": tip_height,
            }
            resp = self._call_storage_local(payload, timeout=10.0)
            if resp is None:
                resp = self.rpc.call(payload, timeout=10.0)
            if not isinstance(resp, dict) or resp.get("status") != "ok":
                reason = (resp or {}).get("reason") if isinstance(resp, dict) else "rpc_error"
                self.logln(f"[Proof] {gid[:10]} failed ({reason})")
                continue
            proof_epoch = int(resp.get("epoch", epoch_target))
            offset = int(resp.get("offset", 0))
            length = int(resp.get("length", 0))
            phash = str(resp.get("hash") or "")
            seed = str(resp.get("seed") or "")
            chunk = resp.get("chunk")
            mpath = resp.get("path")
            self.logln(f"[Proof] {gid[:10]} epoch {proof_epoch} offset {offset} len {length}")
            if not self.connected:
                continue
            
            submit = {
                "type": "GRAFFITI_PROOF_SUBMIT",
                "art_id": art_id,
                "epoch": proof_epoch,
                "offset": offset,
                "length": length,
                "hash": phash,
                "height": tip_height,
                "seed": seed,
                "storer": (self.addr_var.get() or self.rpc.address or "").strip().lower(),
                "ts": int(time.time()),
                "nonce": secrets.token_hex(16),
            }
            if chunk:
                submit["chunk"] = chunk
            if mpath:
                submit["path"] = mpath
            ack = self.rpc.call(submit, timeout=8.0)
            if isinstance(ack, dict) and ack.get("status") == "ok":
                self.logln(f"[Proof] submitted epoch {proof_epoch} for {art_id[:12]}...")
            else:
                self.logln(f"[Proof] submit failed: {ack}")

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
            elif aid in self._pending_paid:
                self.logln(f"[Payout] Cleared for {aid}")
        self._pending_paid = current

    # ---------- Heartbeat ------------
    def _heartbeat(self):
        def run():
            if self.connected:
                threading.Thread(target=self._heartbeat_worker, daemon=True).start()
            self.root.after(HEARTBEAT_SEC * 1000, run)
        self.root.after(HEARTBEAT_SEC * 1000, run)

    def _heartbeat_worker(self):
        ok = False
        pong = self.rpc.call({"type":"PING"}, timeout=2.0)
        ok = isinstance(pong, dict) and pong.get("type") == "PONG"
        if ok:
            self.root.after(0, lambda: self.status_lbl.configure(text="• Connected", foreground="#1a8"))
            self.refresh_all()
        else:
            self.root.after(0, self._handle_rpc_drop, "heartbeat")

if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    log.info("Launching Tsar Storage GUI")
    root = tk.Tk()
    app  = TsarStorageGUI(root)
    root.mainloop()
