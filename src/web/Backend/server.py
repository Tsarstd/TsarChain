# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import argparse
import json
import mimetypes
import os

from pathlib import Path
from glob import glob
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .rpc_gateway import ExplorerGateway

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
log = get_ctx_logger("web.Backend.server")

BASE_DIR = Path(__file__).resolve().parents[3]


def _safe_int(val: Any) -> Optional[int]:
    """
    Parse int query param; tolerate None/empty and bad inputs without raising.
    """
    log.debug("value: %s", val)
    if val in (None, "", [], ()):
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        log.warning("invalid int value: %r", val)
        return None

def _guess_mime(path: str, fallback: str = "application/octet-stream") -> str:
    log.debug("guessing mime for path: %s", path)
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jpg", ".jpeg", ".jepg"):
        return "image/jpeg"
    if ext == ".mp4":
        return "video/mp4"
    guess = mimetypes.guess_type(path)[0]
    log.debug("guess: %s", guess)
    if not guess:
        log.warning("mime guess failed for path: %s, using fallback: %s", path, fallback)
    return guess or fallback

def _find_cached_graffiti(art_id: str) -> Optional[str]:
    log.debug("find cached graffiti art_id=%s", art_id)
    roots = [
        os.path.join(str(BASE_DIR), "data_user", "graffiti_cache"),
        os.path.join(str(BASE_DIR), "data_web", "data_user", "graffiti_cache"),
    ]
    for cache_root in roots:
        if not os.path.isdir(cache_root):
            continue
        for ext in (".jpg", ".jpeg", ".jepg", ".mp4", ".bin"):
            path = os.path.join(cache_root, f"{art_id}{ext}")
            if os.path.isfile(path):
                return path
        for path in glob(os.path.join(cache_root, f"{art_id}.*")):
            if os.path.isfile(path):
                return path
    return None

class ExplorerHandler(BaseHTTPRequestHandler):
    gateway: ExplorerGateway | None = None
    enable_cors: bool = True

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        log.debug("send_json status=%s keys=%s", status, list(payload.keys()))
        if status >= 400 or payload.get("error"):
            log.warning("json error response status=%s error=%s", status, payload.get("error"))
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.enable_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status: int, data: bytes, content_type: str) -> None:
        log.debug("send_bytes status=%s size=%s content_type=%s", status, len(data), content_type)
        if status >= 400 or not data:
            log.warning("send_bytes status=%s size=%s content_type=%s", status, len(data), content_type)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        if self.enable_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def _bad_gateway(self, msg: str = "gateway_not_ready") -> None:
        log.debug("bad_gateway msg=%s", msg)
        log.warning("gateway error: %s", msg)
        self._send_json(500, {"error": msg})

    def do_OPTIONS(self) -> None:
        log.debug("OPTIONS %s", self.path)
        if not self.enable_cors:
            log.warning("CORS disabled for OPTIONS %s", self.path)
        self.send_response(204)
        if self.enable_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        log.debug("GET %s", self.path)
        if not self.gateway:
            log.warning("gateway not ready for %s", self.path)
            return self._bad_gateway()

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        parts = [unquote(p) for p in path.split("/") if p]
        params = parse_qs(parsed.query)

        if not parts:
            return self._send_json(200, {"status": "ok", "service": "tsarchain-explorer-api"})

        if parts[0] != "api":
            return self._send_json(404, {"error": "not_found"})

        if parts == ["api", "health"]:
            return self._send_json(200, {"status": "ok"})

        if parts == ["api", "info"]:
            info = self.gateway.get_info()
            status = 200 if not info.get("error") else 502
            return self._send_json(status, info)

        if parts in (["api", "info", "snapshot"], ["api", "info_full"], ["api", "info", "full"]):
            snap = self.gateway.get_info_snapshot()
            status = 200 if not snap.get("error") else 502
            return self._send_json(status, snap)

        if len(parts) == 3 and parts[1] == "block":
            blk = self.gateway.get_block(parts[2])
            status = 200 if not blk.get("error") else 404
            return self._send_json(status, blk)

        if len(parts) == 3 and parts[1] == "tx":
            tx = self.gateway.get_tx(parts[2])
            status = 200 if not tx.get("error") else 404
            return self._send_json(status, tx)

        if len(parts) == 3 and parts[1] == "address":
            limit = _safe_int((params.get("limit") or [None])[0])
            offset = _safe_int((params.get("offset") or [None])[0])
            direction = (params.get("direction") or [None])[0]
            status_q = (params.get("status") or [None])[0]
            addr = self.gateway.get_address(
                parts[2],
                limit=limit,
                offset=offset,
                direction=str(direction) if direction else None,
                status=str(status_q) if status_q else None,
            )
            status = 200 if not addr.get("error") else 404
            return self._send_json(status, addr)

        if len(parts) >= 3 and parts[1] == "graffiti":
            art_id = parts[2].lower()
            if len(parts) == 3:
                post = self.gateway.get_graffiti(art_id)
                status = 200 if not post.get("error") else 404
                return self._send_json(status, post)

            if len(parts) == 4 and parts[3] == "comments":
                limit = _safe_int((params.get("limit") or [None])[0])
                comments = self.gateway.get_graffiti_comments(art_id, limit=limit)
                status = 200 if not comments.get("error") else 404
                return self._send_json(status, comments)

            if len(parts) == 4 and parts[3] == "file":
                post_resp = self.gateway.get_graffiti(art_id)
                post = None
                if isinstance(post_resp, dict):
                    post = post_resp.get("post") if isinstance(post_resp.get("post"), dict) else post_resp

                result = self.gateway.fetch_graffiti_file(art_id, post=post)
                if isinstance(result, dict) and result.get("status") == "ok":
                    raw = result.get("bytes")
                    meta = result.get("meta") or {}
                    fname = meta.get("filename") or meta.get("name")
                    mime = meta.get("mime") or meta.get("mime_type")
                    if not mime:
                        if fname:
                            mime = _guess_mime(fname)
                        else:
                            mime = "image/jpeg"
                    if isinstance(raw, (bytes, bytearray)):
                        return self._send_bytes(200, bytes(raw), str(mime))

                cached = _find_cached_graffiti(art_id)
                if cached and os.path.isfile(cached):
                    with open(cached, "rb") as fh:
                        data = fh.read()
                    return self._send_bytes(200, data, _guess_mime(cached))

                reason = result.get("reason") if isinstance(result, dict) else "not_found"
                return self._send_json(404, {"error": reason or "not_found"})
        return self._send_json(404, {"error": "not_found"})


def _parse_bootstrap(raw: str) -> Optional[tuple[str, int]]:
    log.debug("parse bootstrap: %s", raw)
    if not raw:
        return None
    if ":" not in raw:
        log.warning("bootstrap must be host:port, got %s", raw)
        raise ValueError("bootstrap must be host:port")
    host, port_s = raw.split(":", 1)
    return host.strip(), int(port_s)


def main() -> None:
    parser = argparse.ArgumentParser(description="TsarChain Explorer API")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="bind port (default: 8787)")
    parser.add_argument("--no-cors", action="store_true", help="disable CORS headers")
    parser.add_argument("--bootstrap", default="", help="manual bootstrap peer host:port")
    args = parser.parse_args()

    log.debug(
        "server start host=%s port=%s no_cors=%s bootstrap=%s",
        args.host,
        args.port,
        args.no_cors,
        args.bootstrap,
    )
    if args.no_cors:
        log.warning("CORS disabled; browser clients may fail")
    bootstrap = _parse_bootstrap(args.bootstrap) if args.bootstrap else None
    gateway = ExplorerGateway(manual_bootstrap=bootstrap)

    ExplorerHandler.gateway = gateway
    ExplorerHandler.enable_cors = not args.no_cors

    server = ThreadingHTTPServer((args.host, args.port), ExplorerHandler)
    print(f"Explorer API running on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    setup_logging(force=True)
    main()
