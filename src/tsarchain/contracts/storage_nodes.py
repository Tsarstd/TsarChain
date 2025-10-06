# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173
from __future__ import annotations
import json, os, base64, time, threading, hashlib
from typing import Any, Dict, Optional
from dataclasses import dataclass, asdict
from bech32 import bech32_decode, convertbits

# ---------------- Local Project ----------------
from ..storage.db import AtomicJSONFile
from ..storage.kv import kv_enabled, iter_prefix, batch, clear_db
from ..utils.helpers import Script, OP_RETURN, OP_PUSHDATA1, OP_PUSHDATA2
from ..utils import config as CFG


def _address_to_pkhash(addr: str) -> Optional[bytes]:
    hrp, data = bech32_decode(addr)
    if hrp is None or hrp != CFG.ADDRESS_PREFIX:
        return None
    prog = bytes(convertbits(data[1:], 5, 8, False))
    return prog if len(prog) == 20 else None

def _build_opreturn(data: bytes) -> Script:
    if len(data) > CFG.MAX_STORAGE_OPRET:
        raise ValueError("storage OP_RETURN too large")
    return Script([OP_RETURN, data])

def _parse_opreturn(script: Script) -> Optional[bytes]:
    try:
        raw = script.serialize()
        if not raw or raw[0] != OP_RETURN:
            return None
        if len(raw) < 2:
            return None
        i = 1
        first = raw[i]
        i += 1
        if 1 <= first <= 75:
            n = first
            end = i + n
            if end > len(raw):
                return None
            data = raw[i:end]
        elif first == OP_PUSHDATA1:
            if i + 1 > len(raw):
                return None
            n = raw[i]
            i += 1
            end = i + n
            if end > len(raw):
                return None
            data = raw[i:end]
        elif first == OP_PUSHDATA2:
            if i + 2 > len(raw):
                return None
            n = int.from_bytes(raw[i:i+2], 'little')
            i += 2
            end = i + n
            if end > len(raw):
                return None
            data = raw[i:end]
        else:
            return None
        if len(data) > CFG.MAX_STORAGE_OPRET:
            return None
        return data
    except Exception:
        return None

@dataclass
class StorageNode:
    address: str
    url: str            # e.g. https://stor1.tsar:4545  (any format is acceptable for the off-chain API)
    pubkey: str         # hex string (optionally used to verify signatures in the off-chain layer)
    capacity_bytes: int # declarative, informational only
    updated_at: int

class StorageNodeRegistry:
    def __init__(self, path: Optional[str] = None):
        self.path = path or CFG.STORAGE_NODES_FILE
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if kv_enabled():
            # Load from LMDB subdb 'stor_nodes'
            data = {"schema":1, "net": CFG.DEFAULT_NET_ID, "nodes":{}}
            try:
                nodes = {}
                for k, v in iter_prefix('stor_nodes', b'addr:'):
                    addr = k.decode('utf-8')[5:]
                    try:
                        obj = json.loads(v.decode('utf-8'))
                        nodes[addr] = obj
                    except Exception:
                        continue
                data["nodes"] = nodes
            except Exception:
                pass
            self.store = None
            self._data = data
        else:
            self.store = AtomicJSONFile(self.path, keep_backups=2, checksum=True)
            self._data = self.store.load(default={"schema":1, "net": CFG.DEFAULT_NET_ID, "nodes":{}})

    def save(self):
        if kv_enabled():
            try:
                clear_db('stor_nodes')
            except Exception:
                pass
            try:
                with batch('stor_nodes') as b:
                    for addr, meta in (self._data.get("nodes", {}) or {}).items():
                        b.put(f"addr:{addr}".encode('utf-8'), json.dumps(meta, separators=(",", ":")).encode('utf-8'))
            except Exception:
                pass
        else:
            self.store.save(self._data)

    def is_registered(self, addr: str) -> bool:
        return addr.lower() in self._data.get("nodes", {})

    def get(self, addr: str) -> Optional[Dict[str, Any]]:
        return self._data.get("nodes", {}).get(addr.lower())

    def parse_action(self, tx) -> Optional[Dict[str, Any]]:
        for o in getattr(tx, "outputs", []) or []:
            data = _parse_opreturn(o.script_pubkey)
            if not data or not data.startswith(CFG.STORAGE_MAGIC):
                continue
            payload = data[len(CFG.STORAGE_MAGIC):]
            parts = payload.split(b'|', 1)
            if len(parts) != 2:
                continue
            action = parts[0].decode("utf-8").strip().upper()
            if action != "REG":
                continue
            try:
                obj = json.loads(base64.b64decode(parts[1], validate=True).decode("utf-8"))
            except Exception:
                continue
            if isinstance(obj, dict):
                obj["_action"] = "REG"
                return obj
        return None

    def validate_tx(self, tx) -> bool:
        act = self.parse_action(tx)
        if not act:
            return True
        if act.get("_action") != "REG":
            return False

        if act.get("net") != CFG.DEFAULT_NET_ID:
            return False

        addr = str(act.get("address","")).strip().lower()
        url  = str(act.get("url","")).strip()
        cap  = int(act.get("capacity_bytes", 0))
        ts   = int(act.get("ts", 0))

        pubk_hex = str(act.get("pubkey","")).strip()
        sig_hex  = str(act.get("sig","")).strip()
        _msg  = f"TSAR_STOR_REG|{addr}|{url}|{cap}|{ts}".encode()

        if not addr or _address_to_pkhash(addr) is None:
            return False
        if cap < 100_000:  # minimal deklaratif 100KB
            return False
        if not url:
            return False
        return True

    def apply_tx(self, tx) -> None:
        act = self.parse_action(tx)
        if not act or act.get("net") != CFG.DEFAULT_NET_ID:
            return
        addr = str(act["address"]).strip().lower()
        node = StorageNode(
            address=addr,
            url=str(act.get("url","")).strip(),
            pubkey=str(act.get("pubkey","")).strip(),
            capacity_bytes=int(act.get("capacity_bytes",0)),
            updated_at=int(time.time())
        )
        self._data.setdefault("nodes", {})[addr] = asdict(node)
        self.save()

# ========================= Storage Engine (NODE_STORAGE) =====================

@dataclass
class UploadSession:
    upload_id: str
    graffiti_id: str
    seller: str
    sha256_hex: str
    size_bytes: int
    expire_at_height: int
    created_ts: int
    received_bytes: int = 0
    tmp_path: str = ""
    closed: bool = False

@dataclass
class StoredFile:
    graffiti_id: str
    sha256_hex: str
    size_bytes: int
    seller: str
    storage_addr: str
    path: str
    created_ts: int
    expire_at_height: int
    paid: bool = False
    paid_txid: Optional[str] = None
    state: str = "stored"
    receipt: Optional[Dict[str, Any]] = None

class StorageService:
    def __init__(self, storage_addr: str, node_id: str):
        os.makedirs(CFG.STORAGE_DIR, exist_ok=True)
        self.storage_addr = storage_addr
        self.node_id = node_id
        self.meta = AtomicJSONFile(os.path.join(CFG.STORAGE_DIR, "index.json"))
        self.sessions: Dict[str, UploadSession] = {}
        self.lock = threading.RLock()
        idx = self.meta.load(default={"files": {}, "bytes_used": 0})
        if "files" not in idx: idx["files"] = {}
        if "bytes_used" not in idx: idx["bytes_used"] = 0
        self.meta.save(idx)

    def _idx(self) -> Dict[str, Any]:
        return self.meta.load() or {"files": {}, "bytes_used": 0}

    def _flush(self, idx: Dict[str, Any]) -> None:
        self.meta.save(idx)

    def _reserve(self, n: int) -> bool:
        with self.lock:
            idx = self._idx()
            used = int(idx.get("bytes_used", 0))
            if used + n > CFG.STORAGE_MAX_BYTES:
                return False
            idx["bytes_used"] = used + n
            self._flush(idx)
            return True

    def _release(self, n: int) -> None:
        with self.lock:
            idx = self._idx()
            used = max(0, int(idx.get("bytes_used", 0)) - n)
            idx["bytes_used"] = used
            self._flush(idx)

    # ------------ API ------------
    def init_upload(self, graffiti_id: str, seller: str, sha256_hex: str,
                    size_bytes: int, end_height: int,
                    download_window_blocks: int = CFG.DOWNLOAD_WINDOW_BLOCKS,
                    allow_unregistered: bool = CFG.ALLOW_UNREGISTERED_STORAGE_UPLOADS) -> Dict[str, Any]:
        if size_bytes < CFG.STORAGE_MIN_SIZE:
            size_bytes = CFG.STORAGE_MIN_SIZE
        if not self._reserve(size_bytes):
            return {"status":"rejected","reason":"no_space"}
        upid = f"up_{int(time.time())}_{hashlib.sha1(os.urandom(8)).hexdigest()[:8]}"
        tmp = os.path.join(CFG.STORAGE_DIR, f"{upid}.part")
        sess = UploadSession(
            upload_id=upid, graffiti_id=graffiti_id, seller=seller,
            sha256_hex=sha256_hex.lower(), size_bytes=int(size_bytes),
            expire_at_height=int(end_height) + int(download_window_blocks),
            created_ts=int(time.time()), tmp_path=tmp,
        )
        self.sessions[upid] = sess
        open(tmp, "wb").close()
        return {"status":"ok","upload_id":upid,"chunk_size":int(CFG.STORAGE_UPLOAD_CHUNK),
                "expire_at_height": sess.expire_at_height}

    def put_chunk(self, upload_id: str, chunk_index: int, b64: str) -> Dict[str, Any]:
        sess = self.sessions.get(upload_id)
        if not sess or sess.closed:
            return {"status":"rejected","reason":"bad_upload_id"}
        try:
            raw = base64.b64decode(b64)
        except Exception:
            return {"status":"rejected","reason":"bad_b64"}
        if len(raw) > CFG.STORAGE_UPLOAD_CHUNK:
            return {"status":"rejected","reason":"chunk_too_big"}
        with open(sess.tmp_path, "ab") as f:
            f.write(raw)
        sess.received_bytes += len(raw)
        return {"status":"ok","received":sess.received_bytes,"of":sess.size_bytes}

    def commit_upload(self, upload_id: str) -> Dict[str, Any]:
        sess = self.sessions.get(upload_id)
        if not sess or sess.closed:
            return {"status":"rejected","reason":"bad_upload_id"}
        if sess.received_bytes != sess.size_bytes:
            return {"status":"rejected","reason":"size_mismatch"}
        h = hashlib.sha256()
        with open(sess.tmp_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                h.update(chunk)
        if h.hexdigest().lower() != sess.sha256_hex:
            try: os.remove(sess.tmp_path)
            except: pass
            self._release(sess.size_bytes)
            self.sessions.pop(upload_id, None)
            return {"status":"rejected","reason":"sha256_mismatch"}
        final_name = f"{sess.graffiti_id}_{sess.sha256_hex}.bin"
        final_path = os.path.join(CFG.STORAGE_DIR, final_name)
        os.replace(sess.tmp_path, final_path)
        sess.closed = True
        idx = self._idx()
        idx["files"][sess.graffiti_id] = asdict(StoredFile(
            graffiti_id=sess.graffiti_id, sha256_hex=sess.sha256_hex, size_bytes=sess.size_bytes,
            seller=sess.seller, storage_addr=self.storage_addr, path=final_path,
            created_ts=int(time.time()), expire_at_height=sess.expire_at_height,
            paid=False, state="stored",
            receipt={
                "net": CFG.DEFAULT_NET_ID,
                "graffiti_id": sess.graffiti_id,
                "sha256": sess.sha256_hex,
                "size_bytes": sess.size_bytes,
                "expire_at_height": sess.expire_at_height,
                "storage_addr": self.storage_addr,
                "node_id": self.node_id,
                "ts": int(time.time()),
            },
        ))
        self._flush(idx)
        self.sessions.pop(upload_id, None)
        return {"status":"ok","receipt": idx["files"][sess.graffiti_id]["receipt"]}

    def status(self, graffiti_id: str) -> Dict[str, Any]:
        meta = self._idx().get("files",{}).get(graffiti_id)
        if not meta:
            return {"status":"not_found"}
        return {"status":"ok","file": meta}

    def index(self) -> Dict[str, Any]:
        idx = self._idx()
        return {"status":"ok","files": idx.get("files",{}), "bytes_used": idx.get("bytes_used",0)}

    def mark_paid(self, graffiti_id: str, txid: str) -> Dict[str, Any]:
        idx = self._idx()
        meta = idx.get("files",{}).get(graffiti_id)
        if not meta:
            return {"status":"not_found"}
        meta["paid"] = True
        meta["paid_txid"] = txid
        idx["files"][graffiti_id] = meta
        self._flush(idx)
        return {"status":"ok"}

    def gc(self, current_height: int) -> Dict[str, Any]:
        idx = self._idx()
        changed = 0
        for aid, meta in list(idx.get("files",{}).items()):
            if meta.get("state") != "stored":
                continue
            if int(current_height) > int(meta.get("expire_at_height", 0)):
                try:
                    os.remove(meta["path"])
                except Exception:
                    pass
                self._release(int(meta.get("size_bytes", 0)))
                meta["state"] = "expired"
                idx["files"][aid] = meta
                changed += 1
        if changed:
            self._flush(idx)
        return {"status":"ok","expired": changed}
    
    def encode_register(address: str, url: str, pubkey_hex: str, capacity_bytes: int) -> Script:
        payload = {
            "net": CFG.DEFAULT_NET_ID,
            "address": address,
            "url": url,
            "pubkey": pubkey_hex,
            "capacity_bytes": int(capacity_bytes),
            "ts": int(time.time()),
        }
        # (optional) add "sig" at the application layer if you want off-chain verification
        blob = json.dumps(payload, separators=(",",":")).encode("utf-8")
        data = CFG.STORAGE_MAGIC + b"REG|" + base64.b64encode(blob)
        return _build_opreturn(data)

