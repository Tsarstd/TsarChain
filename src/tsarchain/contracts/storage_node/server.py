# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os, json, socket, threading, time
import base64, hashlib

# ---------------- Local Project ----------------
from tsarchain.network.protocol import send_message, recv_message, verify_and_unwrap, is_envelope
from tsarchain.utils import config as CFG
from tsarchain.contracts import graffiti as GRAFFITI

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
            with open(self.idx_path, "r", encoding="utf-8") as f:
                self.index = json.load(f)
        except Exception:
            self.index = {"files": {}, "bytes_used": 0, "art_map": {}}

        self.index.setdefault("files", {})
        self.index.setdefault("bytes_used", 0)
        self.index.setdefault("art_map", {})
        try:
            files = dict(self.index.get("files") or {})
            for aid, meta in list(files.items()):
                files[aid] = self._normalize_file_meta(aid, meta)
            self.index["files"] = files
            self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        except Exception:
            pass
        # persist normalization for older indexes
        try:
            self._save_index()
        except Exception:
            pass

    def _save_index(self):
        tmp = self.idx_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.index, f, indent=2)
        os.replace(tmp, self.idx_path)

    def _respond(self, conn, obj):
        cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
        try:
            raw = json.dumps(obj).encode("utf-8")
        except Exception:
            raw = b"{}"
        if len(raw) + len(CFG.NETWORK_MAGIC) > cap:
            try:
                t = obj.get("type") if isinstance(obj, dict) else "unknown"
            except Exception:
                t = "unknown"
            obj = {"type": t, "status": "error", "reason": "msg_too_large"}
            raw = json.dumps(obj).encode("utf-8")
        send_message(conn, raw, max_len=cap)

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
            try:
                self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (self.index.get("files") or {}).values())
            except Exception:
                pass
            return {"type":"STOR_INDEX", "status":"ok", **self.index}

        if t == "STOR_INIT":
            aid   = str(msg.get("graffiti_id","")).strip()
            size  = int(msg.get("size_bytes",0))
            sha   = str(msg.get("sha256","")).lower()
            fname = str(msg.get("filename","")).strip() or "blob.bin"
            mime  = str(msg.get("mime","")).strip().lower()
            art_id = str(msg.get("art_id","")).strip().lower()
            chunk = int(CFG.STORAGE_UPLOAD_CHUNK)
            if not aid or size <= 0 or len(sha) != 64:
                return {"type":"STOR_ACK","status":"rejected","reason":"bad_fields"}
            try:
                mime = GRAFFITI.validate_graffiti_file(size, mime, fname)
            except Exception as exc:
                return {"type":"STOR_ACK","status":"rejected","reason": str(exc)}
            if int(CFG.MAX_GRAFFITI_ON_MEMPOOL) > 0:
                try:
                    active = 0
                    for meta in (self.index.get("files") or {}).values():
                        if not isinstance(meta, dict):
                            continue
                        if meta.get("paid"):
                            continue
                        state = str(meta.get("state") or "").lower()
                        if state in ("receiving", "appending", "pending_confirm") or not meta.get("paid"):
                            active += 1
                    if active >= int(CFG.MAX_GRAFFITI_ON_MEMPOOL):
                        return {"type":"STOR_ACK","status":"rejected","reason":"mempool_graffiti_full"}
                except Exception:
                    pass
            
            inc_dir = os.path.join(self.storage_dir, "incoming"); os.makedirs(inc_dir, exist_ok=True)
            path    = os.path.join(inc_dir, f"{aid}.part")
            meta = {
                "size_bytes": size,
                "sha256": sha,
            "filename": fname,
            "mime": mime,
            "paid": False,
            "expire_at_height": 0,
            "confirmed_at_height": 0,
            "state": "receiving",
            "path": path,
            "received_bytes": 0,
            "chunk_size": chunk,
            "created_ts": int(time.time()),
            }
            if art_id:
                meta["art_id"] = art_id
                self.index.setdefault("art_map", {})[art_id] = aid
            self.index["files"][aid] = meta
            self._save_index()
            # buat file kosong
            with open(path, "wb"):
                pass
            log.info("[STOR_INIT] aid=%s size=%s art_id=%s state=receiving", aid[:16], size, (art_id[:16] if art_id else "-"))
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
                try:
                    GRAFFITI.validate_graffiti_file(actual_size, meta.get("mime"), meta.get("filename"))
                except Exception as exc:
                    return {"type":"STOR_ACK","status":"rejected","reason": str(exc)}
                if actual_size != expected_size:
                    return {"type":"STOR_ACK","status":"rejected","reason":"size_mismatch"}
                if digest.hexdigest().lower() != meta.get("sha256"):
                    return {"type":"STOR_ACK","status":"rejected","reason":"hash_mismatch"}
                # Tahan di folder incoming sampai ada konfirmasi STOR_PAID
                inc_dir = os.path.join(self.storage_dir, "incoming"); os.makedirs(inc_dir, exist_ok=True)
                fin = os.path.join(inc_dir, f"{aid}.bin")
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
                    "state": "pending_confirm",
                    "receipt_id": receipt_id,
                    "receipt": receipt,
                    "stored_ts": now_ts,
                })
                art_id = str(meta.get("art_id","")).strip().lower()
                if art_id:
                    self.index.setdefault("art_map", {})[art_id] = aid
                self.index["files"][aid] = meta
                self.index["bytes_used"] = sum(int(v.get("size_bytes",0)) for v in self.index["files"].values())
                self._save_index()
                log.info("[STOR_COMMIT] aid=%s size=%s -> pending_confirm", aid[:16], expected_size)
                return {"type":"STOR_ACK","status":"ok","receipt": receipt}
            except Exception as e:
                return {"type":"STOR_ACK","status":"rejected","reason":str(e)}

        if t == "STOR_STATUS":
            aid = str(msg.get("graffiti_id","")).strip()
            meta = self.index.get("files",{}).get(aid)
            return {"type":"STOR_STATUS","found": bool(meta), "meta": meta}

        if t == "STOR_PAID":
            aid = str(msg.get("graffiti_id","")).strip()
            txid = str(msg.get("txid","")).strip()
            try:
                block_h = int(msg.get("block_height", 0) or 0)
            except Exception:
                block_h = 0
            meta = self.index.get("files", {}).get(aid)
            if not aid or not meta:
                return {"type": "STOR_PAID", "status": "error", "reason": "no_such"}
            # jika file masih di incoming, pastikan dipindah ke final
            try:
                path = meta.get("path")
                if path and os.path.isfile(path) and ("incoming" in path):
                    fin_dir = os.path.join(self.storage_dir, "final"); os.makedirs(fin_dir, exist_ok=True)
                    fin = os.path.join(fin_dir, os.path.basename(path).replace(".part", ".bin"))
                    os.replace(path, fin)
                    meta["path"] = fin
                    meta["state"] = "stored"
            except Exception as e:
                return {"type": "STOR_PAID", "status": "error", "reason": str(e)}

            meta["paid"] = True
            if txid:
                meta["txid_paid"] = txid
            if block_h > 0:
                meta["confirmed_at_height"] = block_h
                # disable automatic expiry for paid files (keep persisted)
                meta["expire_at_height"] = 0
            self.index["files"][aid] = self._normalize_file_meta(aid, meta)
            try:
                self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in self.index["files"].values())
            except Exception:
                pass
            self._save_index()
            log.info("[STOR_PAID] aid=%s h=%s expire=%s", aid[:16], meta.get("confirmed_at_height"), meta.get("expire_at_height"))
            return {
                "type": "STOR_PAID",
                "status": "ok",
                "graffiti_id": aid,
                "expire_at_height": meta.get("expire_at_height", 0),
                "confirmed_at_height": meta.get("confirmed_at_height", 0),
            }

        if t == "STOR_GC":
            try:
                tip_h = int(msg.get("tip_height", 0) or 0)
            except Exception:
                tip_h = 0
            files = self.index.get("files", {}) or {}
            expired = 0
            remove_keys: list[str] = []
            for gid, meta in files.items():
                try:
                    expire_h = int(meta.get("expire_at_height", 0) or 0)
                except Exception:
                    expire_h = 0
                if expire_h and tip_h and expire_h <= tip_h and not meta.get("paid"):
                    remove_keys.append(gid)
            for gid in remove_keys:
                meta = files.pop(gid, None) or {}
                expired += 1
                try:
                    path = meta.get("path")
                    if path and os.path.isfile(path):
                        os.remove(path)
                except Exception:
                    pass
                art_id = str(meta.get("art_id", "")).strip().lower()
                if art_id and self.index.get("art_map", {}).get(art_id) == gid:
                    try:
                        self.index["art_map"].pop(art_id, None)
                    except Exception:
                        pass
            self.index["files"] = files
            try:
                self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
            except Exception:
                self.index["bytes_used"] = 0
            self._save_index()
            if expired:
                log.info("[STOR_GC] expired=%s tip=%s", expired, tip_h)
            return {"type":"STOR_GC","status":"ok","expired": expired}

        if t == "STOR_TAG_ART":
            aid = str(msg.get("graffiti_id","")).strip()
            art_id = str(msg.get("art_id","")).strip().lower()
            if not aid or not art_id:
                return {"type":"STOR_ACK","status":"rejected","reason":"missing_art_id"}
            meta = self.index.get("files",{}).get(aid)
            if not meta:
                return {"type":"STOR_ACK","status":"rejected","reason":"no_such"}
            meta["art_id"] = art_id
            for fld in ("block_height","block_hash","creator","pool_address","paid"):
                if fld in msg:
                    meta[fld] = msg.get(fld)
            self.index.setdefault("art_map", {})[art_id] = aid
            self.index["files"][aid] = meta
            self._save_index()
            return {"type":"STOR_ACK","status":"ok","graffiti_id": aid, "art_id": art_id}

        if t == "STOR_PROOF_RUN":
            aid = str(msg.get("graffiti_id","")).strip()
            art_id = str(msg.get("art_id","")).strip().lower()
            try:
                tip_h = int(msg.get("tip_height", 0) or 0)
            except Exception:
                tip_h = 0
            files = self.index.get("files", {}) or {}
            if art_id and not aid:
                aid = (self.index.get("art_map") or {}).get(art_id, "")
            meta = files.get(aid) if aid else None
            if not meta:
                return {"type": "STOR_PROOF_RUN", "status": "error", "reason": "no_such"}
            path = meta.get("path")
            size = int(meta.get("size_bytes", 0) or 0)
            art_norm = str(meta.get("art_id") or art_id or "").strip().lower()
            if not art_norm:
                meta["missed_proofs"] = int(meta.get("missed_proofs", 0)) + 1
                meta["proof_fail_reason"] = "missing_art_id"
                self.index["files"][aid] = self._normalize_file_meta(aid, meta)
                self._save_index()
                return {"type": "STOR_PROOF_RUN", "status": "error", "reason": "missing_art_id"}
            try:
                challenge = GRAFFITI.calc_proof_challenge(art_norm, size, tip_h)
            except Exception as exc:
                meta["missed_proofs"] = int(meta.get("missed_proofs", 0)) + 1
                meta["proof_fail_reason"] = str(exc)
                self.index["files"][aid] = self._normalize_file_meta(aid, meta)
                self._save_index()
                return {"type": "STOR_PROOF_RUN", "status": "error", "reason": "bad_challenge"}
            if not path or not os.path.isfile(path):
                meta["missed_proofs"] = int(meta.get("missed_proofs", 0)) + 1
                meta["proof_fail_reason"] = "file_missing"
                self.index["files"][aid] = self._normalize_file_meta(aid, meta)
                self._save_index()
                return {"type": "STOR_PROOF_RUN", "status": "error", "reason": "file_missing"}
            offset = int(challenge.get("offset", 0))
            length = int(challenge.get("length", 0))
            try:
                with open(path, "rb") as fh:
                    fh.seek(offset)
                    chunk = fh.read(length)
                proof_hash = GRAFFITI.hash_proof_chunk(chunk)
            except Exception as exc:
                meta["missed_proofs"] = int(meta.get("missed_proofs", 0)) + 1
                meta["proof_fail_reason"] = str(exc)
                self.index["files"][aid] = self._normalize_file_meta(aid, meta)
                self._save_index()
                return {"type": "STOR_PROOF_RUN", "status": "error", "reason": "read_fail"}

            now_ts = int(time.time())
            meta.update({
                "last_proof_epoch": int(challenge.get("epoch", 0)),
                "last_proof_ts": now_ts,
                "last_proof_offset": offset,
                "last_proof_length": length,
                "last_proof_hash": proof_hash,
                "proof_fail_reason": "",
                "proof_status": "ok",
                "missed_proofs": max(0, int(meta.get("missed_proofs", 0))),
                "last_proof_height": tip_h,
            })
            if art_norm:
                self.index.setdefault("art_map", {})[art_norm] = aid
                meta["art_id"] = art_norm
            self.index["files"][aid] = self._normalize_file_meta(aid, meta)
            self._save_index()
            log.info("[STOR_PROOF_RUN] aid=%s epoch=%s offset=%s len=%s", aid[:16], meta.get("last_proof_epoch"), offset, length)
            return {
                "type": "STOR_PROOF_RUN",
                "status": "ok",
                "graffiti_id": aid,
                "art_id": art_norm,
                "epoch": int(challenge.get("epoch", 0)),
                "offset": offset,
                "length": length,
                "hash": proof_hash,
                "seed": challenge.get("seed"),
                "height": tip_h,
            }

        if t == "STOR_GET_BY_ART" or t == "GRAFFITI_GET_FILE":
            art_id = str(msg.get("art_id","")).strip().lower()
            if not art_id:
                return {"type":t,"found": False}
            gid = (self.index.get("art_map") or {}).get(art_id)
            meta = None
            if gid:
                meta = (self.index.get("files") or {}).get(gid)
            found = bool(meta)
            log.debug("[STOR_GET_BY_ART] art=%s gid=%s include_data=%s", art_id[:16], (gid or "")[:12], bool(msg.get("include_data")))
            msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
            data_cap = int(msg_cap * 3 // 4)
            resp = {"type": t, "found": found, "graffiti_id": gid, "meta": meta}
            include_data = bool(msg.get("include_data"))
            if include_data and meta:
                path = meta.get("path")
                try:
                    max_bytes = int(msg.get("max_bytes", 0) or 0)
                except Exception:
                    max_bytes = 0
                if max_bytes <= 0:
                    max_bytes = int(CFG.GRAFFITI_MAX_SIZE_BYTES)
                max_bytes = max(32 * 1024, min(max_bytes, int(CFG.GRAFFITI_MAX_SIZE_BYTES), data_cap))
                if path and os.path.isfile(path):
                    try:
                        size = os.path.getsize(path)
                    except Exception:
                        size = 0
                    if size > max_bytes:
                        resp["status"] = "error"
                        resp["reason"] = "file_too_large"
                        log.warning("[STOR_GET_BY_ART] file_too_large aid=%s size=%s limit=%s", art_id[:16], size, max_bytes)
                    else:
                        with open(path, "rb") as fh:
                            data_b64 = base64.b64encode(fh.read()).decode("ascii")
                        resp["data_b64"] = data_b64
                        resp["status"] = "ok"
                else:
                    resp["status"] = "error"
                    resp["reason"] = "file_missing"
                    log.warning("[STOR_GET_BY_ART] file_missing aid=%s gid=%s path=%s", art_id[:16], gid, path)
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
