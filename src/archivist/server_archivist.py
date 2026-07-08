# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os
import json
import socket
import threading

# ---------------- Local Project ----------------
from . import wallet_route, node_route
from .storage_guard import StorageGuard
from tsarchain.utils import config as CFG
from .database_archivist import ArchivistDatabase
from tsarchain.network.protocol import (
    is_envelope,
    send_message,
    recv_message,
    verify_and_unwrap
)

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
        self.guard = StorageGuard()
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
        self.index = self.db.load_index()
        self.index.setdefault("files", {})
        self.index.setdefault("bytes_used", 0)
        self.index.setdefault("art_map", {})
        files = dict(self.index.get("files") or {})
        for aid, meta in list(files.items()):
            files[aid] = self._normalize_file_meta(aid, meta)
        self.index["files"] = files
        self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        self._save_index()

    def _save_index(self):
        self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (self.index.get("files") or {}).values())
        self.db.save_index(self.index)

    def _respond(self, conn, obj):
        cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
        raw = json.dumps(obj).encode("utf-8")
        if len(raw) + len(CFG.NETWORK_MAGIC) > cap:
            t = obj.get("type") if isinstance(obj, dict) else "unknown"
            obj = {"type": t, "status": "error", "reason": "msg_too_large"}
            raw = json.dumps(obj).encode("utf-8")
        send_message(conn, raw, max_len=cap)

    def _client_ip(self, addr) -> str:
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return "0.0.0.0"

    def _handle(self, msg, *, client_ip: str):
        resp = wallet_route.handle_wallet_rpc(self, msg, client_ip=client_ip)
        if resp is not None:
            return resp
        resp = node_route.handle_node_rpc(self, msg, client_ip=client_ip)
        if resp is not None:
            return resp
        return {"error":"unknown type"}

    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(8)
            while not self._stop:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn, addr):
        ip = self._client_ip(addr)
        try:
            if self.guard.is_banned(ip):
                log.warning("[stor_guard] blocked banned ip=%s", ip)
                self._respond(conn, {"status": "error", "reason": "banned"})
                return

            raw = recv_message(conn, timeout=float(CFG.HANDSHAKE_TIMEOUT), max_len=CFG.GRAFFITI_MAX_MSG_BYTES)
            if not raw:
                return
            outer = json.loads(raw.decode("utf-8"))
            identity = None
            if is_envelope(outer):
                msg = verify_and_unwrap(outer, lambda nid: None)
                identity = str(outer.get("from") or "").strip().lower() or None
            else:
                msg = outer if isinstance(outer, dict) else {}
            wallet_ident = str(msg.get("wallet_addr") or msg.get("creator_addr") or "").strip().lower()
            node_ident = str(msg.get("node_id") or "").strip().lower()
            identity = wallet_ident or identity or node_ident or None
            mtype = str(msg.get("type", "")).strip().upper() if isinstance(msg, dict) else ""
            pow_obj = msg.get("pow") if isinstance(msg, dict) else None
            decision = self.guard.allow(ip, mtype, identity=identity, pow_obj=pow_obj)
            if not decision.get("ok"):
                reason = str(decision.get("error", "forbidden"))
                drop = bool(decision.get("drop"))
                log.warning("[stor_guard] deny ip=%s type=%s reason=%s drop=%s", ip, mtype or "-", reason, drop)
                if drop:
                    return
                resp_obj = {
                    "type": mtype or "UNKNOWN",
                    "status": "error",
                    "reason": reason,
                }
                if "retry_after" in decision:
                    resp_obj["retry_after"] = decision.get("retry_after")
                if decision.get("pow_challenge"):
                    resp_obj["pow_challenge"] = decision["pow_challenge"]
                self._respond(conn, resp_obj)
                return

            resp = self._handle(msg, client_ip=ip)
            self._respond(conn, resp)
        finally:
            conn.close()
