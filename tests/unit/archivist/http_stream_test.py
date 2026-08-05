# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import json
import urllib.request
import pytest
from unittest.mock import MagicMock

from archivist.server_archivist import StorageServer
from archivist.http_stream import ArchivistHTTPServer, ArchivistHTTPHandler


@pytest.fixture
def storage_server(tmp_path):
    storage_dir = str(tmp_path / "storage")
    # Start StorageServer on ephemeral ports
    server = StorageServer(host="127.0.0.1", port=0, storage_dir=storage_dir, enable_http=True, http_port=0)
    
    # Register mock file index
    aid = "graf_testart123"
    blob_path = server.db._final_blob_path(aid)
    os.makedirs(os.path.dirname(blob_path), exist_ok=True)
    with open(blob_path, "wb") as f:
        f.write(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    server.index["files"][aid] = {
        "size_bytes": 36,
        "mime": "video/mp4",
        "filename": "sample.mp4",
        "art_id": aid,
    }
    server.index["art_map"][aid] = aid
    
    yield server
    if server.http_server:
        server.http_server.stop()
    server._stop = True


def test_http_stream_health(storage_server):
    port = storage_server.http_server.http_port
    url = f"http://127.0.0.1:{port}/health"
    req = urllib.request.urlopen(url)
    assert req.status == 200
    data = json.loads(req.read().decode("utf-8"))
    assert data["status"] == "ok"


def test_http_stream_meta(storage_server):
    port = storage_server.http_server.http_port
    url = f"http://127.0.0.1:{port}/media/graf_testart123/meta"
    req = urllib.request.urlopen(url)
    assert req.status == 200
    data = json.loads(req.read().decode("utf-8"))
    assert data["status"] == "ok"
    assert data["meta"]["mime"] == "video/mp4"


def test_http_stream_full_file(storage_server):
    port = storage_server.http_server.http_port
    url = f"http://127.0.0.1:{port}/media/graf_testart123"
    req = urllib.request.urlopen(url)
    assert req.status == 200
    content = req.read()
    assert content == b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert req.headers.get("Content-Type") == "video/mp4"


def test_http_stream_range_partial_content(storage_server):
    port = storage_server.http_server.http_port
    url = f"http://127.0.0.1:{port}/media/graf_testart123"
    req = urllib.request.Request(url, headers={"Range": "bytes=0-9"})
    res = urllib.request.urlopen(req)
    assert res.status == 206
    assert res.headers.get("Content-Range") == "bytes 0-9/36"
    assert res.headers.get("Content-Length") == "10"
    content = res.read()
    assert content == b"0123456789"
