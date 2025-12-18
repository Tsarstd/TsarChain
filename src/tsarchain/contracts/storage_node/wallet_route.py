# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import os, base64, hashlib, time
from typing import Any, Dict, Optional

from tsarchain.utils import config as CFG
from tsarchain.contracts import graffiti as GRAFFITI


from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.wallet_route")


def handle_wallet_rpc(server, msg: Dict[str, Any], client_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    RPC handle sent from wallet to storage node.
    """
    t = str(msg.get("type", "")).upper()

    if t == "STOR_INIT":
        aid = str(msg.get("graffiti_id", "")).strip()
        size = int(msg.get("size_bytes", 0))
        sha = str(msg.get("sha256", "")).lower()
        fname = str(msg.get("filename", "")).strip() or "blob.bin"
        mime = str(msg.get("mime", "")).strip().lower()
        art_id = str(msg.get("art_id", "")).strip().lower()
        chunk = int(CFG.STORAGE_UPLOAD_CHUNK)
        if not aid or size <= 0 or len(sha) != 64:
            return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_fields"}
        
        mime = GRAFFITI.validate_graffiti_file(size, mime, fname)
        projected = int(server.index.get("bytes_used", 0)) + size
        if projected > int(CFG.STORAGE_MAX_BYTES):
            return {"type": "STOR_ACK", "status": "rejected", "reason": "storage_full"}
        
        if int(CFG.MAX_GRAFFITI_ON_MEMPOOL) > 0:
            active = 0
            for meta in (server.index.get("files") or {}).values():
                if not isinstance(meta, dict):
                    continue
                if meta.get("paid"):
                    continue
                state = str(meta.get("state") or "").lower()
                if state in ("receiving", "appending", "pending_confirm") or not meta.get("paid"):
                    active += 1
            if active >= int(CFG.MAX_GRAFFITI_ON_MEMPOOL):
                return {"type": "STOR_ACK", "status": "rejected", "reason": "mempool_graffiti_full"}
            
        if server.use_kv:
            path = f"lmdb://incoming/{aid}"
        else:
            inc_dir = os.path.join(server.storage_dir, "incoming")
            os.makedirs(inc_dir, exist_ok=True)
            path = os.path.join(inc_dir, f"{aid}.part")
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
            server.index.setdefault("art_map", {})[art_id] = aid
        server.index["files"][aid] = meta
        server._save_index()
        if not server.use_kv:
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
        aid = str(msg.get("graffiti_id", "")).strip()
        b64 = str(msg.get("data", ""))
        if not aid or not b64:
            return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_fields"}
        meta = server.index.get("files", {}).get(aid)
        if not meta or meta.get("state") not in ("receiving", "appending"):
            return {"type": "STOR_ACK", "status": "rejected", "reason": "no_init"}
        
        chunk_bytes = base64.b64decode(b64)
        max_chunk = int(meta.get("chunk_size") or CFG.STORAGE_UPLOAD_CHUNK)
        received_total = int(meta.get("received_bytes", 0))
        if server.use_kv:
            received_total = server.db.append_incoming(aid, chunk_bytes, max_chunk)
        else:
            if len(chunk_bytes) > max_chunk:
                return {"type": "STOR_ACK", "status": "rejected", "reason": "chunk_too_big"}
            with open(meta["path"], "ab") as f:
                f.write(chunk_bytes)
            received_total += len(chunk_bytes)
            log.debug("received: %s", received_total)
        meta["state"] = "appending"
        meta["received_bytes"] = int(received_total)
        meta["updated_ts"] = int(time.time())
        server.index["files"][aid] = meta
        server._save_index()
        return {
            "type": "STOR_ACK",
            "status": "ok",
            "received": int(meta["received_bytes"]),
            "of": int(meta.get("size_bytes", 0)),
        }

    if t == "STOR_COMMIT":
        log.debug("Received STOR_COMMIT")
        aid = str(msg.get("graffiti_id", "")).strip()
        req_receipt = str(msg.get("receipt_id", "")).strip()
        meta = server.index.get("files", {}).get(aid)
        if not meta:
            return {"type": "STOR_ACK", "status": "rejected", "reason": "no_such"}
        try:
            expected_size = int(meta.get("size_bytes", 0))
            actual_size = 0
            digest_hex = ""
            blob_bytes: bytes | None = None
            if server.use_kv:
                blob_bytes = server.db.get_incoming_bytes(aid)
                if blob_bytes is None:
                    return {"type": "STOR_ACK", "status": "rejected", "reason": "missing_file"}
                actual_size = len(blob_bytes)
                digest_hex = hashlib.sha256(blob_bytes).hexdigest().lower()
            else:
                tmp_path = meta.get("path")
                if not tmp_path or not os.path.isfile(tmp_path):
                    return {"type": "STOR_ACK", "status": "rejected", "reason": "missing_file"}
                digest = hashlib.sha256()
                with open(tmp_path, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        if not chunk:
                            break
                        digest.update(chunk)
                        actual_size += len(chunk)
                digest_hex = digest.hexdigest().lower()
            
            GRAFFITI.validate_graffiti_file(actual_size, meta.get("mime"), meta.get("filename"))
            if actual_size != expected_size:
                return {"type": "STOR_ACK", "status": "rejected", "reason": "size_mismatch"}
            if digest_hex != meta.get("sha256"):
                return {"type": "STOR_ACK", "status": "rejected", "reason": "hash_mismatch"}
            now_ts = int(time.time())
            receipt_id = meta.get("receipt_id") or req_receipt or f"rcpt_{aid}_{now_ts}"
            receipt = {
                "id": receipt_id,
                "graffiti_id": aid,
                "sha256": meta.get("sha256"),
                "size_bytes": expected_size,
                "filename": meta.get("filename"),
                "ts": now_ts,
            }
            if server.use_kv:
                meta.update(
                    {
                        "path": f"lmdb://incoming/{aid}",
                        "state": "pending_confirm",
                        "receipt_id": receipt_id,
                        "receipt": receipt,
                        "stored_ts": now_ts,
                        "received_bytes": actual_size,
                    }
                )
            else:
                inc_dir = os.path.join(server.storage_dir, "incoming")
                os.makedirs(inc_dir, exist_ok=True)
                fin = os.path.join(inc_dir, f"{aid}.bin")
                os.replace(tmp_path, fin)
                meta.update(
                    {
                        "path": fin,
                        "state": "pending_confirm",
                        "receipt_id": receipt_id,
                        "receipt": receipt,
                        "stored_ts": now_ts,
                    }
                )
            # set payment deadline height for unpaid blobs when caller supplies current tip height
            tip_h = int(msg.get("tip_height", 0) or msg.get("block_height", 0) or 0)
            expire_after = max(0, int(CFG.GRAFFITI_EXPIRE_AFTER_BLOCKS))
            if (not meta.get("paid")) and expire_after > 0 and tip_h > 0:
                try:
                    expire_h = int(meta.get("expire_at_height", 0) or 0)
                except Exception:
                    log.exception("Failed to parse existing expire_at_height from metadata")
                    expire_h = 0
                if expire_h <= 0:
                    meta["expire_at_height"] = tip_h + expire_after
            art_id = str(meta.get("art_id", "")).strip().lower()
            if art_id:
                server.index.setdefault("art_map", {})[art_id] = aid
            server.index["files"][aid] = meta
            server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in server.index["files"].values())
            server._save_index()
            log.info("[STOR_COMMIT] aid=%s size=%s -> pending_confirm", aid[:16], expected_size)
            return {"type": "STOR_ACK", "status": "ok", "receipt": receipt}
        except Exception as e:
            return {"type": "STOR_ACK", "status": "rejected", "reason": str(e)}

    if t == "STOR_GET_BY_ART":
        art_id = str(msg.get("art_id", "")).strip().lower()
        if not art_id:
            return {"type": t, "found": False}
        gid = (server.index.get("art_map") or {}).get(art_id)
        meta = None
        if gid:
            meta = (server.index.get("files") or {}).get(gid)
        found = bool(meta)
        msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
        data_cap = int(msg_cap * 3 // 4)
        resp = {"type": t, "found": found, "graffiti_id": gid, "meta": meta}
        include_data = bool(msg.get("include_data"))
        if include_data and meta:
            max_bytes = int(msg.get("max_bytes", 0) or 0)
            if max_bytes <= 0:
                max_bytes = int(CFG.GRAFFITI_MAX_SIZE_BYTES)
            max_bytes = max(32 * 1024, min(max_bytes, int(CFG.GRAFFITI_MAX_SIZE_BYTES), data_cap))
            log.debug("size_art: %s", max_bytes)
            if server.use_kv:
                data_bytes = server.db.get_final_bytes(gid) if gid else None
                size = len(data_bytes) if data_bytes is not None else 0
                if data_bytes is None:
                    resp["status"] = "error"
                    resp["reason"] = "file_missing"
                    log.warning("[STOR_GET_BY_ART] file_missing aid=%s gid=%s", art_id[:16], gid)
                elif size > max_bytes:
                    resp["status"] = "error"
                    resp["reason"] = "file_too_large"
                    log.warning("[STOR_GET_BY_ART] file_too_large aid=%s size=%s limit=%s", art_id[:16], size, max_bytes)
                else:
                    resp["data_b64"] = base64.b64encode(data_bytes).decode("ascii")
                    resp["status"] = "ok"
            else:
                path = meta.get("path")
                if path and os.path.isfile(path):
                    size = os.path.getsize(path)
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
                    log.warning("[STOR_GET_BY_ART] file_missing aid=%s gid=%s path=%s", art_id[:16], gid, path if "path" in locals() else None)
        return resp

    return None


__all__ = ["handle_wallet_rpc"]
