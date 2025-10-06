# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from __future__ import annotations

import os, hashlib
from typing import Any, Callable, Dict, Optional


def resolve_storer(rpc_send, desired_addr: str, on_done: Callable[[Optional[Dict[str, Any]]], None]) -> None:
    desired = (desired_addr or "").strip().lower()
    def _on(resp: Optional[Dict[str, Any]]):
        storers = (resp or {}).get("storers") or (resp or {}).get("items") or []
        target = None
        for s in storers:
            try:
                addr = (s.get("addr") or s.get("address") or "").strip().lower()
                if addr == desired:
                    target = s; break
            except Exception:
                continue
        if not target:
            on_done({"error": "storer_not_found"}); return
        if not target.get("port"):
            on_done({"error": "storer_no_port"}); return
        on_done({"status": "ok", "storer": target})
    rpc_send({"type": "STOR_LIST"}, _on)


def upload_graffiti(
    rpc_send,
    rpc_send_to: Callable[[str, int, Dict[str, Any], Callable[[Dict[str, Any]], None]], None],
    graffiti_id: str,
    seller_addr: str,
    storer_addr: str,
    file_path: str,
    download_window_blocks: int,
    on_progress: Callable[[str], None],
    on_done: Callable[[Optional[Dict[str, Any]]], None],
) -> None:
    aid = (graffiti_id or "").strip()
    seller = (seller_addr or "").strip().lower()
    if not (aid and seller and storer_addr and os.path.isfile(file_path)):
        on_done({"error": "bad_fields"}); return

    def _after_resolve(res: Optional[Dict[str, Any]]):
        if not res or res.get("status") != "ok":
            on_done(res); return
        s = res.get("storer") or {}
        host, port = s.get("ip") or "127.0.0.1", int(s.get("port") or 0)
        size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        init_msg = {
            "type": "STOR_INIT",
            "graffiti_id": aid,
            "seller": seller,
            "file_id": file_hash,
            "size_bytes": int(size),
            "download_window_blocks": int(download_window_blocks),
        }

        def _after_init(resp):
            if not resp or resp.get("status") not in (None, "ok", "accepted"):
                on_done({"error": "init_failed", "resp": resp}); return
            upid  = resp.get("upload_id")
            chunk = int(resp.get("chunk_size") or 65536)
            sent = 0
            with open(file_path, "rb") as f:
                while True:
                    buf = f.read(chunk)
                    if not buf:
                        break
                    put_msg = {
                        "type": "STOR_PUT",
                        "upload_id": upid,
                        "offset": sent,
                        "data": buf.hex(),
                    }
                    rpc_send_to(host, port, put_msg, lambda _r: None)
                    sent += len(buf)
                    on_progress(f"Uploaded {sent}/{size} bytes")

            def _after_commit(r2):
                if not r2 or r2.get("status") not in (None, "ok", "accepted"):
                    on_done({"error": "commit_failed", "resp": r2}); return
                on_done({"status": "ok", "receipt": r2.get("receipt")})

            rpc_send_to(host, port, {"type": "STOR_COMMIT", "upload_id": upid}, _after_commit)

        rpc_send_to(host, port, init_msg, _after_init)

    resolve_storer(rpc_send, storer_addr, _after_resolve)

