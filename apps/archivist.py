# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

import os, json, socket, threading, sys, time, tkinter as tk
import base64, hashlib
import multiprocessing as mp
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any, List, Sequence, Tuple
from bech32 import bech32_encode, convertbits
from tsarchain.utils.helpers import hash160

# ---------------- Local Project ----------------
from tsarchain.network.protocol import (
    send_message, recv_message, build_envelope, verify_and_unwrap,
    is_envelope, load_or_create_keypair_at, SecureChannel,)
from tsarchain.storage.kv import kv_enabled, iter_prefix, batch

from tsarchain.utils import config as CFG
from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger

APP_TITLE = "TsarChain • Storage Node"
HEARTBEAT_SEC = 10

manual_bootstrap: Optional[Tuple[str, int]] = None
SCAN_KP = None
RETENTION_GC_SEC = 800
STORAGE_PORT_OFFSET = 100
log = get_ctx_logger("apps.archivist")

# --- Pinned peer keys store for SecureChannel (TOFU) ---
_STOR_PEER_KEYS_PATH = os.path.join("data_user", "storage_peer_keys.json")
if not kv_enabled():
    try:
        os.makedirs(os.path.dirname(_STOR_PEER_KEYS_PATH), exist_ok=True)
    except Exception:
        pass
    
def _load_stor_peer_keys() -> dict:
    if kv_enabled():
        m = {}
        try:
            for k, v in iter_prefix('stor_peer_keys', b'nid:'):
                nid = k.decode('utf-8')[4:]
                m[nid] = v.decode('utf-8')
        except Exception:
            pass
        return m
    try:
        with open(_STOR_PEER_KEYS_PATH, 'r', encoding='utf-8') as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}
    
def _save_stor_peer_keys() -> None:
    if kv_enabled():
        try:
            with batch('stor_peer_keys') as b:
                for nid, pk in _STOR_PEER_KEYS.items():
                    b.put(f"nid:{nid}".encode('utf-8'), pk.encode('utf-8'))
        except Exception:
            pass
        return
    try:
        tmp = _STOR_PEER_KEYS_PATH + ".tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(_STOR_PEER_KEYS, f, indent=2)
        os.replace(tmp, _STOR_PEER_KEYS_PATH)
    except Exception:
        pass
    
_STOR_PEER_KEYS = _load_stor_peer_keys()



class StorageServer:
    def __init__(self, host: str, port: int, storage_dir: str):
        self.host = host
        self.port = int(port)
        self.storage_dir = storage_dir
        self.idx_path = os.path.join(storage_dir, "index.json")
        self._load_index()
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _load_index(self):
        os.makedirs(self.storage_dir, exist_ok=True)
        try:
            with open(self.idx_path, "r", encoding="utf-8") as f:
                self.index = json.load(f)
        except Exception:
            self.index = {"files": {}, "bytes_used": 0}

    def _save_index(self):
        tmp = self.idx_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.index, f, indent=2)
        os.replace(tmp, self.idx_path)

    def _respond(self, conn, obj):
        send_message(conn, json.dumps(obj).encode("utf-8"))

    def _handle(self, msg):
        t = str(msg.get("type","")).upper()

        if t == "PING":
            return {"type":"PONG"}

        if t == "GET_INFO":
            return {
                "type":"INFO",
                "height": 0,
                "peers": 0,
                "storage_address": None,
                "storage_files": len(self.index.get("files",{})),
                "storage_bytes_used": int(self.index.get("bytes_used",0))
            }

        if t == "STOR_INDEX":
            return {"type":"STOR_INDEX", "status":"ok", **self.index}

        if t == "STOR_INIT":
            aid   = str(msg.get("graffiti_id","")).strip()
            size  = int(msg.get("size_bytes",0))
            sha   = str(msg.get("sha256","")).lower()
            fname = str(msg.get("filename","")).strip() or "blob.bin"
            chunk = int(CFG.STORAGE_UPLOAD_CHUNK)
            if not aid or size <= 0 or len(sha) != 64:
                return {"type":"STOR_ACK","status":"rejected","reason":"bad_fields"}
            
            inc_dir = os.path.join(self.storage_dir, "incoming"); os.makedirs(inc_dir, exist_ok=True)
            path    = os.path.join(inc_dir, f"{aid}.part")
            meta = {
                "size_bytes": size,
                "sha256": sha,
                "filename": fname,
                "paid": False,
                "expire_at_height": 0,
                "state": "receiving",
                "path": path,
                "received_bytes": 0,
                "chunk_size": chunk,
                "created_ts": int(time.time()),
            }
            self.index["files"][aid] = meta
            self._save_index()
            # buat file kosong
            with open(path, "wb"):
                pass
            return {
                "type": "STOR_ACK",
                "status": "ok",
                "upload_id": aid,
                "graffiti_id": aid,
                "chunk_size": chunk,
            }

        if t == "STOR_PUT":
            aid  = str(msg.get("graffiti_id","")).strip()
            b64  = str(msg.get("data",""))
            if not aid or not b64:
                return {"type":"STOR_ACK","status":"rejected","reason":"bad_fields"}
            meta = self.index.get("files",{}).get(aid)
            if not meta or meta.get("state") not in ("receiving","appending"):
                return {"type":"STOR_ACK","status":"rejected","reason":"no_init"}
            try:
                chunk_bytes = base64.b64decode(b64)
                max_chunk = int(meta.get("chunk_size") or CFG.STORAGE_UPLOAD_CHUNK)
                if len(chunk_bytes) > max_chunk:
                    return {"type":"STOR_ACK","status":"rejected","reason":"chunk_too_big"}
                with open(meta["path"], "ab") as f:
                    f.write(chunk_bytes)
                meta["state"] = "appending"
                meta["received_bytes"] = int(meta.get("received_bytes", 0)) + len(chunk_bytes)
                meta["updated_ts"] = int(time.time())
                self.index["files"][aid] = meta
                self._save_index()
                return {
                    "type":"STOR_ACK",
                    "status":"ok",
                    "received": int(meta["received_bytes"]),
                    "of": int(meta.get("size_bytes", 0))
                }
            except Exception as e:
                return {"type":"STOR_ACK","status":"rejected","reason":str(e)}

        if t == "STOR_COMMIT":
            aid = str(msg.get("graffiti_id","")).strip()
            meta = self.index.get("files",{}).get(aid)
            if not meta:
                return {"type":"STOR_ACK","status":"rejected","reason":"no_such"}
            try:
                expected_size = int(meta.get("size_bytes", 0))
                tmp_path = meta.get("path")
                if not tmp_path or not os.path.isfile(tmp_path):
                    return {"type":"STOR_ACK","status":"rejected","reason":"missing_file"}
                digest = hashlib.sha256()
                actual_size = 0
                with open(tmp_path, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        if not chunk:
                            break
                        digest.update(chunk)
                        actual_size += len(chunk)
                if actual_size != expected_size:
                    return {"type":"STOR_ACK","status":"rejected","reason":"size_mismatch"}
                if digest.hexdigest().lower() != meta.get("sha256"):
                    return {"type":"STOR_ACK","status":"rejected","reason":"hash_mismatch"}
                fin_dir = os.path.join(self.storage_dir, "final"); os.makedirs(fin_dir, exist_ok=True)
                fin = os.path.join(fin_dir, f"{aid}.bin")
                os.replace(tmp_path, fin)
                now_ts = int(time.time())
                receipt_id = meta.get("receipt_id") or f"rcpt_{aid}_{now_ts}"
                receipt = {
                    "id": receipt_id,
                    "graffiti_id": aid,
                    "sha256": meta.get("sha256"),
                    "size_bytes": expected_size,
                    "filename": meta.get("filename"),
                    "ts": now_ts,
                }
                meta.update({
                    "path": fin,
                    "state": "stored",
                    "receipt_id": receipt_id,
                    "receipt": receipt,
                    "stored_ts": now_ts,
                })
                self.index["files"][aid] = meta
                self.index["bytes_used"] = sum(int(v.get("size_bytes",0)) for v in self.index["files"].values())
                self._save_index()
                return {"type":"STOR_ACK","status":"ok","receipt": receipt}
            except Exception as e:
                return {"type":"STOR_ACK","status":"rejected","reason":str(e)}

        if t == "STOR_STATUS":
            aid = str(msg.get("graffiti_id","")).strip()
            meta = self.index.get("files",{}).get(aid)
            return {"type":"STOR_STATUS","found": bool(meta), "meta": meta}

        return {"error":"unknown type"}

    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(8)
            while not self._stop:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()
                except Exception:
                    time.sleep(0.1)

    def _handle_conn(self, conn):
        try:
            raw = recv_message(conn, timeout=5.0)
            if not raw:
                return
            outer = json.loads(raw.decode("utf-8"))
            if is_envelope(outer):
                msg = verify_and_unwrap(outer, lambda nid: None)
            else:
                msg = outer if isinstance(outer, dict) else {}
            resp = self._handle(msg)
            self._respond(conn, resp)
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass



class RPC:
    def __init__(self, key_dir: str | None = None):
        node_id, pub, priv = load_or_create_keypair_at(key_dir or os.path.join(os.getcwd(), "data", ".keys_storage"))
        self.ctx = {"net_id": CFG.DEFAULT_NET_ID, "node_id": node_id, "privkey": priv}
        self.pub = pub
        self.priv = priv
        self.node: Optional[tuple[str,int]] = None
        self.sock = None
        self.lock = threading.RLock()

        # derive storage address from pubkey (bech32 p2wpkh)
        try:
            pkh = hash160(bytes.fromhex(self.pub))
            data = [0] + list(convertbits(pkh, 8, 5, True))
            self._default_address = bech32_encode(CFG.ADDRESS_PREFIX, data)
            self.address = self._default_address
        except Exception:
            self._default_address = ""
            self.address = ""
        self.trusted = False

    def set_address_override(self, addr: Optional[str]) -> None:
        if not addr:
            self.address = self._default_address
            return
        cand = addr.strip().lower()
        if not cand.startswith(CFG.ADDRESS_PREFIX):
            raise ValueError("Invalid storage payout address")
        self.address = cand

    def set_trusted(self, flag: bool) -> None:
        self.trusted = bool(flag)

    def _send(self, inner: Dict[str, Any]) -> None:
        if not self.sock:
            raise RuntimeError("no socket")
        outer = build_envelope(inner, self.ctx, extra={"pubkey": self.pub})
        send_message(self.sock, json.dumps(outer).encode("utf-8"))

    def _recv(self, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        if not self.sock:
            return None
        raw = recv_message(self.sock, timeout)
        if not raw:
            return None
        outer = json.loads(raw.decode("utf-8"))
        if is_envelope(outer):
            return verify_and_unwrap(outer, lambda nid: None)
        return outer if isinstance(outer, dict) else None

    def connect(self, ip: str, port: int, my_listen_port: int = 0) -> bool:
        with self.lock:
            self.node = (ip, port)
        try:
            hello = {
                "type": "HELLO",
                "role": "NODE_STORAGE",
                "pubkey": self.pub,
                "address": self.address,
                "url": "",
                "port": int(my_listen_port) if my_listen_port else 0,
                "trusted": bool(self.trusted),
            }
            _ = self.call(hello, timeout=3.0)
            pong = self.call({"type":"PING"}, timeout=3.0)
            return isinstance(pong, dict) and (pong.get("type") == "PONG")
        except Exception:
            log.exception("[RPC.connect] handshake failed to %s:%s", ip, port)
            return False

    def call(self, inner: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any] | None:
        with self.lock:
            if not self.node:
                raise RuntimeError("Not connected")
            ip, port = self.node
        payload = build_envelope(inner, self.ctx, extra={"pubkey": self.pub})
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            raw = None
            try:
                chan = SecureChannel(
                    s, role="client",
                    node_id=self.ctx.get("node_id"), node_pub=self.pub, node_priv=self.priv,
                    get_pinned=lambda nid: _STOR_PEER_KEYS.get(nid),
                    set_pinned=lambda nid, pk: (_STOR_PEER_KEYS.__setitem__(nid, pk), _save_stor_peer_keys())[-1]
                )
                chan.handshake()
                chan.send(json.dumps(payload).encode("utf-8"))
                raw = chan.recv(timeout)
            except Exception:
                if CFG.P2P_ENC_REQUIRED:
                    log.exception("[RPC.call] secure channel failed %s:%s type=%s", ip, port, inner.get("type"))
                    return None
                send_message(s, json.dumps(payload).encode("utf-8"))
                raw = recv_message(s, timeout)
            if not raw:
                return None
            outer = json.loads(raw.decode("utf-8"))
            if not isinstance(outer, dict):
                return None
            if is_envelope(outer):
                try:
                    return verify_and_unwrap(outer, lambda nid: None)
                except Exception:
                    return None
            return outer


# ---------------- Discovery ----------------
class _NodeDirectory:
    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self.cache: list[tuple[str,int]] = []
        self.ts = 0.0
        self.last_good: Optional[tuple[str,int]] = None
        self.lock = threading.Lock()

    def get_nodes(self) -> list[tuple[str,int]]:
        with self.lock:
            if self.cache and (time.time() - self.ts) < self.ttl:
                nodes = list(self.cache)
                if self.last_good and self.last_good in nodes:
                    nodes.remove(self.last_good)
                    nodes.insert(0, self.last_good)
                return nodes
        nodes = _scan_nodes()
        with self.lock:
            self.cache = nodes
            self.ts = time.time()
        return nodes

    def mark_good(self, peer: tuple[str,int]) -> None:
        with self.lock:
            self.last_good = peer
            if peer not in self.cache:
                self.cache.insert(0, peer)
                self.ts = time.time()

NODE_DIR = _NodeDirectory(ttl=30)

def _scan_nodes(start: int = CFG.PORT_START, end: int = CFG.PORT_END, manual_nodes: Optional[Sequence[Tuple[str,int]]] = None) -> List[Tuple[str,int]]:
    candidates: List[Tuple[str,int]] = []
    if manual_bootstrap:
        candidates.append(manual_bootstrap)
    if manual_nodes:
        candidates.extend(list(manual_nodes))
    for port in range(start, end + 1):
        candidates.append(("127.0.0.1", port))
    if CFG.BOOTSTRAP_NODE not in candidates:
        candidates.append(CFG.BOOTSTRAP_NODE)

    seen: set[Tuple[str,int]] = set()
    uniq: List[Tuple[str,int]] = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            uniq.append(item)

    found: List[Tuple[str,int]] = []
    for ip, port in uniq:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(CFG.CONNECT_TIMEOUT_SCAN)
                s.connect((ip, port))
                try:
                    kp = SCAN_KP
                    if kp:
                        ping_env = build_envelope({"type": "PING"}, kp, extra={"pubkey": kp["pubkey"]})
                        resp = None
                        try:
                            chan = SecureChannel(
                                s, role="client",
                                node_id=kp.get("node_id"), node_pub=kp.get("pubkey"), node_priv=kp.get("privkey"),
                                get_pinned=lambda nid: _STOR_PEER_KEYS.get(nid),
                                set_pinned=lambda nid, pk: (_STOR_PEER_KEYS.__setitem__(nid, pk), _save_stor_peer_keys())[-1]
                            )
                            chan.handshake()
                            chan.send(json.dumps(ping_env).encode("utf-8"))
                            resp = chan.recv(CFG.CONNECT_TIMEOUT_SCAN)
                        except Exception:
                            if CFG.P2P_ENC_REQUIRED:
                                raise
                            send_message(s, json.dumps(ping_env).encode("utf-8"))
                            resp = recv_message(s, timeout=CFG.CONNECT_TIMEOUT_SCAN)
                        if not resp:
                            raise RuntimeError("no framed response")
                        outer = json.loads(resp.decode("utf-8"))
                        if is_envelope(outer):
                            inner = verify_and_unwrap(outer, lambda nid: None)
                            if isinstance(inner, dict) and inner.get("type") == "PONG":
                                found.append((ip, port)); continue
                    else:
                        raise RuntimeError("no keypair for scan")
                    if (not CFG.ENVELOPE_REQUIRED) and isinstance(outer, dict) and outer.get("type") == "PONG":
                        found.append((ip, port)); continue
                except Exception:
                    if not CFG.ENVELOPE_REQUIRED:
                        try:
                            s.sendall(json.dumps({"type":"PING"}).encode("utf-8"))
                            s.shutdown(socket.SHUT_WR)
                            raw = s.recv(65536)
                            if not raw: continue
                            obj = json.loads(raw.decode("utf-8"))
                            if isinstance(obj, dict) and obj.get("type") == "PONG":
                                found.append((ip, port)); continue
                        except Exception:
                            continue
        except Exception:
            continue
    return found

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
            peers = NODE_DIR.get_nodes() or []
            for ip, p in peers:
                if self.rpc.connect(ip, p, my_listen_port=storage_port):
                    NODE_DIR.mark_good((ip, p))
                    ok = True
                    break

        if ok:
            NODE_DIR.mark_good((host, miner_port))
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
