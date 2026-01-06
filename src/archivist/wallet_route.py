# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import os, base64, hashlib, time, math
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
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
    
        aid = str(msg.get("graffiti_id", "")).strip()
        size = int(msg.get("size_bytes", 0))
        sha = str(msg.get("sha256", "")).lower()
        fname = str(msg.get("filename", "")).strip() or "blob.bin"
        mime = str(msg.get("mime", "")).strip().lower()
        art_id = str(msg.get("art_id", "")).strip().lower()
        mroot = msg.get("mroot") or msg.get("merkle_root")
        mchunk = msg.get("mchunk") or msg.get("merkle_chunk")
        mcount = msg.get("mcount") or msg.get("merkle_count")
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
        if mroot or mchunk or mcount:
            if not (mroot and mchunk and mcount):
                return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_merkle_meta"}
            mroot = str(mroot).strip().lower()
            if not GRAFFITI._is_valid_sha256_hex(mroot):
                return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_merkle_root"}
            try:
                mchunk = int(mchunk)
                mcount = int(mcount)
            except Exception:
                return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_merkle_meta"}
            if mchunk <= 0 or mcount <= 0:
                return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_merkle_meta"}
            expected = int(math.ceil(int(size) / float(mchunk)))
            if expected != mcount:
                return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_merkle_meta"}
            meta["mroot"] = mroot
            meta["mchunk"] = mchunk
            meta["mcount"] = mcount
        if art_id:
            meta["art_id"] = art_id
            server.index.setdefault("art_map", {})[art_id] = aid
        server.index["files"][aid] = meta
        server._save_index()
        with open(path, "wb"):
            pass
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 15.0:
                log.warning("[STOR_INIT] Benchmark : %.3f ms", result)
        
        return {
            "type": "STOR_ACK",
            "status": "ok",
            "upload_id": aid,
            "graffiti_id": aid,
            "chunk_size": chunk,
        }

    if t == "STOR_PUT":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        
        aid = str(msg.get("graffiti_id", "")).strip()
        b64 = str(msg.get("data", ""))
        if not aid or not b64:
            return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_fields"}
        meta = server.index.get("files", {}).get(aid)
        if not meta or meta.get("state") not in ("receiving", "appending"):
            return {"type": "STOR_ACK", "status": "rejected", "reason": "no_init"}
        
        chunk_bytes = base64.b64decode(b64)
        max_chunk = int(meta.get("chunk_size") or CFG.STORAGE_UPLOAD_CHUNK)
        if len(chunk_bytes) > max_chunk:
            return {"type": "STOR_ACK", "status": "rejected", "reason": "chunk_too_big"}
        try:
            received_total = server.db.append_incoming(aid, chunk_bytes, max_chunk)
        except ValueError as exc:
            return {"type": "STOR_ACK", "status": "rejected", "reason": str(exc)}
        meta["state"] = "appending"
        meta["received_bytes"] = int(received_total)
        meta["updated_ts"] = int(time.time())
        server.index["files"][aid] = meta
        server._save_index()
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 100.0:
                log.warning("[STOR_PUT] Benchmark : %.3f ms", result)
        
        return {
            "type": "STOR_ACK",
            "status": "ok",
            "received": int(meta["received_bytes"]),
            "of": int(meta.get("size_bytes", 0)),
        }

    if t == "STOR_COMMIT":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        
        aid = str(msg.get("graffiti_id", "")).strip()
        req_receipt = str(msg.get("receipt_id", "")).strip()
        meta = server.index.get("files", {}).get(aid)
        if not meta:
            return {"type": "STOR_ACK", "status": "rejected", "reason": "no_such"}
        try:
            expected_size = int(meta.get("size_bytes", 0))
            actual_size = 0
            digest_hex = ""
            tmp_path = meta.get("path")
            if not tmp_path or not os.path.isfile(tmp_path):
                inc_dir = os.path.join(server.storage_dir, "incoming")
                part_path = os.path.join(inc_dir, f"{aid}.part")
                bin_path = os.path.join(inc_dir, f"{aid}.bin")
                if os.path.isfile(bin_path):
                    tmp_path = bin_path
                elif os.path.isfile(part_path):
                    tmp_path = part_path
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
            inc_dir = os.path.join(server.storage_dir, "incoming")
            os.makedirs(inc_dir, exist_ok=True)
            fin = os.path.join(inc_dir, f"{aid}.bin")
            if os.path.abspath(tmp_path) != os.path.abspath(fin):
                os.replace(tmp_path, fin)
            meta.update(
                {
                    "path": fin,
                    "state": "pending_confirm",
                    "receipt_id": receipt_id,
                    "receipt": receipt,
                    "stored_ts": now_ts,
                    "received_bytes": actual_size,
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

            if CFG.DEBUG_BENCHMARKS:
                end = time.perf_counter()
                result = round((end - start) * 1000.0, 3)
                if result > 250.0:
                    log.warning("[STOR_COMMIT] Benchmark : %.3f ms", result)
            
            return {"type": "STOR_ACK", "status": "ok", "receipt": receipt}
        except Exception as e:
            return {"type": "STOR_ACK", "status": "rejected", "reason": str(e)}

    if t == "STOR_GET_BY_ART":    
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
            
        # Public fetch by art_id (or direct graffiti_id). Supports optional chunked reads via offset/length.
        art_id = str(msg.get("art_id", "")).strip().lower()
        gid = str(msg.get("graffiti_id", "")).strip()

        if not art_id and not gid:
            return {"type": t, "found": False}

        if not gid and art_id:
            gid = (server.index.get("art_map") or {}).get(art_id) or ""

        meta = None
        if gid:
            meta = (server.index.get("files") or {}).get(gid)

        found = bool(meta)
        msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
        data_cap = int(msg_cap * 3 // 4)
        resp = {"type": t, "found": found, "graffiti_id": gid, "meta": meta}
        include_data = bool(msg.get("include_data"))
        if include_data and meta:
            # max_bytes here is a *per-response* cap (raw bytes), not total file size.
            max_bytes = int(msg.get("max_bytes", 0) or 0)
            if max_bytes <= 0:
                max_bytes = int(CFG.GRAFFITI_MAX_SIZE_BYTES)
            max_bytes = max(32 * 1024, min(max_bytes, int(CFG.GRAFFITI_MAX_SIZE_BYTES), data_cap))

            # Optional chunk controls. If not provided, we keep the old behavior (full blob or error if too large).
            chunk_mode = ("offset" in msg) or ("length" in msg)
            try:
                offset = int(msg.get("offset", 0) or 0)
            except Exception:
                offset = 0
            try:
                req_len = int(msg.get("length", 0) or 0)
            except Exception:
                req_len = 0

            if offset < 0:
                offset = 0

            total_size = int(meta.get("size_bytes", 0) or 0)

            # When not in chunk_mode, enforce that the whole file fits in one response (legacy behavior).
            if (not chunk_mode) and total_size > 0 and total_size > max_bytes:
                resp["status"] = "error"
                resp["reason"] = "file_too_large"
                log.warning(
                    "[STOR_GET_BY_ART] file_too_large art=%s size=%s limit=%s",
                    (art_id[:16] if art_id else "-"),
                    total_size,
                    max_bytes,
                )
                return resp

            if total_size > 0 and offset >= total_size:
                resp.update(
                    {
                        "status": "ok",
                        "offset": int(offset),
                        "length": 0,
                        "total_size": int(total_size),
                        "eof": True,
                        "data_b64": "",
                    }
                )
                return resp

            # Decide how many bytes to read this response.
            # - In chunk_mode, prefer explicit length; fallback to max_bytes.
            # - Always clamp by max_bytes & remaining bytes.
            if req_len <= 0:
                req_len = int(max_bytes)
            read_len = int(max(0, min(int(req_len), int(max_bytes))))
            if total_size > 0:
                read_len = int(min(read_len, int(total_size) - int(offset)))

            data_bytes = None
            if server.use_kv:
                # Prefer a true range read if the DB supports it, otherwise fallback to full read + slice.
                get_range = getattr(server.db, "get_final_range", None) or getattr(server.db, "get_final_bytes_range", None)
                try:
                    if callable(get_range):
                        data_bytes = get_range(gid, int(offset), int(read_len))
                    else:
                        blob = server.db.get_final_bytes(gid) if gid else None
                        if blob is not None:
                            data_bytes = blob[int(offset) : int(offset) + int(read_len)]
                except Exception:
                    data_bytes = None

                if data_bytes is None:
                    resp["status"] = "error"
                    resp["reason"] = "file_missing"
                    log.warning("[STOR_GET_BY_ART] file_missing art=%s gid=%s", (art_id[:16] if art_id else "-"), gid)
                    return resp

                out_len = len(data_bytes)
                eof = bool(total_size > 0 and (int(offset) + out_len) >= int(total_size))
                resp.update(
                    {
                        "data_b64": base64.b64encode(data_bytes).decode("ascii"),
                        "status": "ok",
                        "offset": int(offset),
                        "length": int(out_len),
                        "total_size": int(total_size),
                        "eof": eof,
                    }
                )
                #log.info("[STOR_GET_BY_ART] data_bytes: offset=%s length=%s total_size=%s eof=%s", offset, out_len, total_size, eof)
                return resp

            # filesystem mode
            path = meta.get("path")
            if path and os.path.isfile(path):
                try:
                    if total_size <= 0:
                        total_size = os.path.getsize(path)
                    with open(path, "rb") as fh:
                        fh.seek(int(offset))
                        chunk = fh.read(int(read_len))
                    out_len = len(chunk)
                    eof = bool(total_size > 0 and (int(offset) + out_len) >= int(total_size))
                    resp.update(
                        {
                            "data_b64": base64.b64encode(chunk).decode("ascii"),
                            "status": "ok",
                            "offset": int(offset),
                            "length": int(out_len),
                            "total_size": int(total_size),
                            "eof": eof,
                        }
                    )
                    return resp
                except Exception:
                    resp["status"] = "error"
                    resp["reason"] = "file_missing"
                    log.warning(
                        "[STOR_GET_BY_ART] file_missing art=%s gid=%s path=%s",
                        (art_id[:16] if art_id else "-"),
                        gid,
                        path,
                    )
                    return resp

            resp["status"] = "error"
            resp["reason"] = "file_missing"
            log.warning(
                "[STOR_GET_BY_ART] file_missing art=%s gid=%s path=%s",
                (art_id[:16] if art_id else "-"),
                gid,
                path if "path" in locals() else None,
            )
            return resp
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 15.0:
                log.warning("[STOR_GET_BY_ART] Benchmark : %.3f ms", result)
            
        return resp

    return None


__all__ = ["handle_wallet_rpc"]
