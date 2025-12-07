# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os, json, socket, threading, time

# ---------------- Local Project ----------------
from tsarchain.network.protocol import send_message, recv_message, verify_and_unwrap, is_envelope
from tsarchain.utils import config as CFG
from .database import ArchivistDatabase
from . import wallet_route, node_route

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.server")

class StorageServer:
    def __init__(self, host: str, port: int, storage_dir: str):
        self.host = host
        self.port = int(port)
        self.storage_dir = storage_dir
        self.db = ArchivistDatabase(storage_dir)
        self.use_kv = bool(getattr(self.db, "use_kv", False))
        self.idx_path = os.path.join(storage_dir, "index.json")
        self._load_index()
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _normalize_file_meta(self, aid: str, meta: dict) -> dict:
        if not isinstance(meta, dict):
            return {}
        meta.setdefault("paid", False)
        meta.setdefault("expire_at_height", 0)
        meta.setdefault("confirmed_at_height", 0)
        meta.setdefault("state", meta.get("state") or "stored")
        meta.setdefault("received_bytes", int(meta.get("received_bytes", 0)))
        meta.setdefault("chunk_size", int(meta.get("chunk_size", CFG.STORAGE_UPLOAD_CHUNK)))
        meta.setdefault("last_proof_epoch", -1)
        meta.setdefault("last_proof_ts", 0)
        meta.setdefault("last_proof_offset", 0)
        meta.setdefault("last_proof_length", 0)
        meta.setdefault("last_proof_hash", "")
        meta.setdefault("last_proof_height", 0)
        meta.setdefault("missed_proofs", 0)
        meta.setdefault("proof_fail_reason", "")
        meta.setdefault("proof_status", "")
        if "path" not in meta:
            meta["path"] = ""
        # Keep art_map in sync when art_id is present
        art_id = str(meta.get("art_id", "")).strip().lower()
        if art_id:
            self.index.setdefault("art_map", {})[art_id] = aid
        return meta

    def _load_index(self):
        os.makedirs(self.storage_dir, exist_ok=True)
        try:
            self.index = self.db.load_index()
        except Exception:
            log.exception("Failed to load index from database, falling back to JSON file")
            self.index = {"files": {}, "bytes_used": 0, "art_map": {}}

        self.index.setdefault("files", {})
        self.index.setdefault("bytes_used", 0)
        self.index.setdefault("art_map", {})
        files = dict(self.index.get("files") or {})
        for aid, meta in list(files.items()):
            files[aid] = self._normalize_file_meta(aid, meta)
        self.index["files"] = files
        try:
            self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        except Exception:
            log.exception("Failed to compute bytes_used in index")
            self.index["bytes_used"] = 0
        try:
            self._save_index()
        except Exception:
            log.exception("Failed to save index after loading")
            pass

    def _save_index(self):
        try:
            self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (self.index.get("files") or {}).values())
        except Exception:
            log.exception("Failed to compute bytes_used in _save_index")
            self.index["bytes_used"] = 0
        try:
            self.db.save_index(self.index)
        except Exception:
            log.exception("Failed to save index to database, falling back to JSON file")
            # Fallback hard-save JSON if LMDB gagal
            tmp = self.idx_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.index, f, indent=2)
            os.replace(tmp, self.idx_path)

    def _respond(self, conn, obj):
        cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
        try:
            raw = json.dumps(obj).encode("utf-8")
        except Exception:
            log.exception("Failed to serialize response object to JSON")
            raw = b"{}"
        if len(raw) + len(CFG.NETWORK_MAGIC) > cap:
            try:
                t = obj.get("type") if isinstance(obj, dict) else "unknown"
            except Exception:
                log.exception("Failed to get type from response object")
                t = "unknown"
            obj = {"type": t, "status": "error", "reason": "msg_too_large"}
            raw = json.dumps(obj).encode("utf-8")
        send_message(conn, raw, max_len=cap)

    def _handle(self, msg):
        resp = wallet_route.handle_wallet_rpc(self, msg)
        if resp is not None:
            return resp
        resp = node_route.handle_node_rpc(self, msg)
        if resp is not None:
            return resp
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
                    log.exception("Error accepting connection")
                    time.sleep(0.1)

    def _handle_conn(self, conn):
        try:
            raw = recv_message(conn, timeout=float(CFG.HANDSHAKE_TIMEOUT))
            if not raw:
                return
            outer = json.loads(raw.decode("utf-8"))
            if is_envelope(outer):
                msg = verify_and_unwrap(outer, lambda nid: None)
            else:
                msg = outer if isinstance(outer, dict) else {}
            resp = self._handle(msg)
            self._respond(conn, resp)
        except Exception as exc:
            log.exception("[conn] error handling request: %s", exc)
        finally:
            try: conn.close()
            except: pass
