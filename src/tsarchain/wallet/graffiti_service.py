# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from __future__ import annotations
import os, time, hashlib, mimetypes, random, string
from typing import Optional, Tuple, Dict

from ..wallet import graffiti as G

# Toggle: kalau True dan storage_client tersedia, akan coba upload untuk dapat receipt_id asli.
USE_STORAGE_UPLOAD = False

def _gen_receipt_id() -> str:
    t = int(time.time())
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"rcp_{t}_{rnd}"

def _sha256_file(fp: str) -> str:
    h = hashlib.sha256()
    with open(fp, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def prepare_graffiti(file_path: str, storer_addr: str, *, receipt_id: Optional[str] = None, mime_hint: Optional[str] = None, extra_meta: Optional[Dict] = None,) -> Tuple[str, Dict]:
    if not os.path.isfile(file_path):
        raise ValueError("file_not_found")

    size = os.path.getsize(file_path)
    sha256_hex = _sha256_file(file_path)

    mime = mime_hint or (mimetypes.guess_type(file_path)[0] or "image/jpeg")

    rid = receipt_id
    if USE_STORAGE_UPLOAD:
        try:
            from ..wallet.storage_client import upload_graffiti
            # upload_graffiti diharapkan mengembalikan dict { "graffiti_id": "...", "receipt": "..." }
            up_res = upload_graffiti(file_path=file_path, storer_addr=storer_addr)
            rid = up_res.get("receipt") or up_res.get("graffiti_id")
        except Exception:
            # fallback ke local receipt id
            rid = rid or _gen_receipt_id()
    else:
        rid = rid or _gen_receipt_id()

    meta = G.build_metadata(
        sha256_hex=sha256_hex,
        size_bytes=size,
        mime=mime,
        storer_addr=storer_addr,
        receipt_id=rid,
        extra=extra_meta or {},
    )
    opret_hex = G.build_opret_hex(meta)
    return opret_hex, meta
