# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os, json, socket, threading, time
import base64, hashlib

# ---------------- Local Project ----------------
from tsarchain.network.protocol import send_message, recv_message, verify_and_unwrap, is_envelope
from tsarchain.utils import config as CFG

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.server")

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
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass
