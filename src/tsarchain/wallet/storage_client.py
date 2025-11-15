# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

from __future__ import annotations

import base64, json, os, socket, time
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from tsarchain.network.protocol import send_message, recv_message
from tsarchain.utils import config as CFG


DEFAULT_CHUNK = int(CFG.STORAGE_UPLOAD_CHUNK)


def _pick_endpoint(meta: Dict[str, Any]) -> Optional[Tuple[str, int]]:
    host = str(meta.get("ip") or "").strip()
    port = int(meta.get("port") or 0)
    if host and port > 0:
        return host, port

    url = str(meta.get("url") or "").strip()
    if url:
        parsed = urlparse(url if "://" in url else f"tcp://{url}")
        netloc = parsed.netloc or parsed.path
        if netloc:
            if ":" in netloc:
                host_part, port_part = netloc.split(":", 1)
                try:
                    port = int(port_part)
                except Exception:
                    port = 0
            else:
                host_part = netloc
            host_part = host_part.strip()
            if host_part:
                if port <= 0:
                    port = CFG.STORAGE_PORT_START or CFG.PORT_START
                if port <= 0:
                    return None
                return host_part, port
    return None


def _send_storage_request(host: str, port: int, payload: Dict[str, Any], timeout: float | None = None) -> Dict[str, Any]:
    timeout = timeout or getattr(CFG, "RPC_TIMEOUT", 5.0)
    resp: Dict[str, Any] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))
            raw = json.dumps(payload).encode("utf-8")
            send_message(s, raw)
            data = recv_message(s, timeout)
            if not data:
                return {"status": "error", "reason": "no_response"}
            obj = json.loads(data.decode("utf-8"))
            if isinstance(obj, dict):
                resp = obj
            else:
                resp = {"status": "error", "reason": "bad_response"}
    except Exception as e:
        resp = {"status": "error", "reason": str(e)}
    return resp


def fetch_storers(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]], limit: Optional[int] = None) -> list[Dict[str, Any]]:
    resp = rpc_call({"type": "STOR_LIST"}) or {}
    storers = resp.get("storers") or resp.get("items") or []
    valid: list[Dict[str, Any]] = []
    for meta in storers:
        try:
            port = int(meta.get("port") or 0)
        except Exception:
            port = 0
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        if not addr or port <= 0:
            continue
        valid.append(meta)
    valid.sort(key=lambda m: int(m.get("last_seen", 0)), reverse=True)
    if limit is not None and limit > 0:
        return valid[:limit]
    return valid


def _sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(chunk), b""):
            if not part:
                break
            h.update(part)
    return h.hexdigest()


def upload_graffiti(
    storer_meta: Dict[str, Any],
    file_path: str,
    *,
    graffiti_id: Optional[str] = None,
    sha256_hex: Optional[str] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """
    Upload a file to a storage node discovered from the TsarChain node RPC.

    rpc_call    : callable yang menerima dict dan mengembalikan response RPC node (sinkron).
    storer_addr : bech32 address storage target.
    file_path   : path file yang akan diunggah.
    graffiti_id : optional id unik (default = sha256_hex).
    sha256_hex  : optional file hash (akan dihitung jika None).
    progress_cb : optional callback(sent_bytes, total_bytes).
    """
    if not os.path.isfile(file_path):
        return {"status": "error", "reason": "file_not_found"}

    total_size = os.path.getsize(file_path)
    sha_hex = (sha256_hex or _sha256_file(file_path)).lower()
    gid = graffiti_id or sha_hex
    meta = dict(storer_meta or {})
    endpoint = _pick_endpoint(meta)
    if not endpoint:
        return {"status": "error", "reason": "storer_no_endpoint"}
    host, port = endpoint

    init_payload = {
        "type": "STOR_INIT",
        "graffiti_id": gid,
        "size_bytes": int(total_size),
        "sha256": sha_hex,
        "filename": os.path.basename(file_path) or "blob.bin",
    }
    init_resp = _send_storage_request(host, port, init_payload)
    if init_resp.get("status") not in ("ok", "accepted"):
        return {"status": "error", "stage": "init", "resp": init_resp}

    chunk_size = int(init_resp.get("chunk_size") or DEFAULT_CHUNK)
    sent = 0
    with open(file_path, "rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            put_payload = {
                "type": "STOR_PUT",
                "graffiti_id": gid,
                "data": base64.b64encode(buf).decode("ascii"),
            }
            put_resp = _send_storage_request(host, port, put_payload)
            if put_resp.get("status") not in ("ok", "accepted"):
                return {"status": "error", "stage": "put", "resp": put_resp}
            sent += len(buf)
            if progress_cb:
                try:
                    progress_cb(sent, total_size)
                except Exception:
                    pass

    commit_payload = {"type": "STOR_COMMIT", "graffiti_id": gid}
    commit_resp = _send_storage_request(host, port, commit_payload)
    if commit_resp.get("status") not in ("ok", "accepted"):
        return {"status": "error", "stage": "commit", "resp": commit_resp}

    receipt = commit_resp.get("receipt") or {"graffiti_id": gid, "sha256": sha_hex, "size_bytes": total_size}
    receipt.setdefault("id", receipt.get("receipt_id") or f"rcpt_{gid}_{int(time.time())}")
    return {
        "status": "ok",
        "graffiti_id": gid,
        "receipt": receipt,
        "storer": meta,
        "size_bytes": total_size,
        "sha256": sha_hex,
    }


__all__ = ["fetch_storers", "upload_graffiti"]
