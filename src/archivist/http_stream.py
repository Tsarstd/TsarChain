# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import json
import re
import threading

from urllib.parse import urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler

from tsarchain.utils.tsar_logging import get_ctx_logger

log = get_ctx_logger("tsarchain.contracts.storage_node.http_stream")

RANGE_RE = re.compile(r"bytes=(\d+)-(\d+)?")


class ArchivistHTTPHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler untuk streaming media dan Partial Content (206) pada Archivist Node.
    """
    server_archivist = None  # Reference to StorageServer instance

    def log_message(self, format, *args):
        pass  # Suppress default stderr logging

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        
        # Route: /media/{art_id} or /media/{art_id}/meta
        parts = path.split("/")
        if len(parts) >= 2 and parts[0] == "media":
            art_id = parts[1].strip().lower()
            is_meta_req = (len(parts) >= 3 and parts[2] == "meta")
            self._handle_media(art_id, is_meta_req)
        elif path == "health":
            self._send_json(200, {"status": "ok", "service": "archivist_http"})
        else:
            self._send_json(404, {"error": "not_found"})

    def _send_json(self, code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _handle_media(self, art_id: str, is_meta_req: bool):
        storage_server = getattr(self, "server_archivist", None)
        if not storage_server:
            self._send_json(500, {"error": "server_not_configured"})
            return

        index = storage_server.index
        art_map = index.get("art_map") or {}
        gid = art_map.get(art_id) or art_id

        files = index.get("files") or {}
        meta = files.get(gid)
        if not meta:
            self._send_json(404, {"error": "art_not_found", "art_id": art_id})
            return

        if is_meta_req:
            self._send_json(200, {"status": "ok", "art_id": art_id, "graffiti_id": gid, "meta": meta})
            return

        # Resolve binary file on disk
        db = storage_server.db
        blob_path = db._final_blob_path(gid)
        if not os.path.isfile(blob_path):
            blob_path = db._incoming_bin_path(gid)
        if not os.path.isfile(blob_path):
            blob_path = db._incoming_part_path(gid)

        if not os.path.isfile(blob_path):
            self._send_json(404, {"error": "file_missing", "art_id": art_id})
            return

        try:
            total_size = os.path.getsize(blob_path)
        except OSError:
            self._send_json(500, {"error": "io_error"})
            return

        mime = str(meta.get("mime") or "application/octet-stream")
        range_header = self.headers.get("Range")

        if range_header:
            match = RANGE_RE.match(range_header.strip())
            if match:
                start = int(match.group(1))
                end = int(match.group(2)) if match.group(2) else total_size - 1
                if start >= total_size or start > end:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{total_size}")
                    self._send_cors_headers()
                    self.end_headers()
                    return

                end = min(end, total_size - 1)
                length = end - start + 1

                self.send_response(206)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(length))
                self.send_header("Content-Range", f"bytes {start}-{end}/{total_size}")
                self.send_header("Accept-Ranges", "bytes")
                self._send_cors_headers()
                self.end_headers()

                self._stream_file_range(blob_path, start, length)
                return

        # Full file response (200 OK)
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(total_size))
        self.send_header("Accept-Ranges", "bytes")
        self._send_cors_headers()
        self.end_headers()
        self._stream_file_range(blob_path, 0, total_size)

    def _stream_file_range(self, path: str, offset: int, length: int):
        chunk_size = 64 * 1024
        remaining = length
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                while remaining > 0:
                    read_len = min(chunk_size, remaining)
                    data = f.read(read_len)
                    if not data:
                        break
                    self.wfile.write(data)
                    remaining -= len(data)
        except (OSError):
            pass


class ArchivistHTTPServer:
    """
    Server HTTP pembantu untuk Archivist Node yang berjalan di background thread.
    """
    def __init__(self, storage_server, host: str = "0.0.0.0", http_port: int = 0):
        self.storage_server = storage_server
        self.host = host
        self.http_port = http_port or (storage_server.port + 100 if storage_server.port > 0 else 39300)
        
        class CustomHandler(ArchivistHTTPHandler):
            pass
        CustomHandler.server_archivist = storage_server

        self.server = HTTPServer((self.host, self.http_port), CustomHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        log.info(f"Archivist HTTP Streaming Server listening on http://{self.host}:{self.http_port}/media/")

    def stop(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


__all__ = ["ArchivistHTTPHandler", "ArchivistHTTPServer"]
