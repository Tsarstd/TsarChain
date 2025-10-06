# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173
from __future__ import annotations
import json, re, time
from typing import Any, Dict, Optional
from bech32 import bech32_decode, convertbits

from ..utils.helpers import Script, OP_RETURN
from ..utils import config as CFG


# -----------------------------
# Internal helpers / validation
# -----------------------------

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MIME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+/_-]{0,63}$")  # konservatif

def _is_valid_sha256_hex(x: str) -> bool:
    try:
        return bool(HEX64_RE.fullmatch(x.strip().lower()))
    except Exception:
        return False

def _is_valid_mime(x: str) -> bool:
    if not isinstance(x, str):
        return False
    x = x.strip()
    if not x:
        return False
    if len(x) > 64:
        return False
    return bool(MIME_RE.fullmatch(x))

def _is_valid_tsar_address(addr: str) -> bool:
    try:
        hrp, data = bech32_decode(addr)
        if hrp is None or hrp != CFG.ADDRESS_PREFIX:
            return False
        prog = bytes(convertbits(data[1:], 5, 8, False))
        return len(prog) == 20
    except Exception:
        return False

def _compact_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def _max_graffiti_limit() -> int:
    if hasattr(CFG, "MAX_GRAFFITI_OPRET"):
        return int(getattr(CFG, "MAX_GRAFFITI_OPRET"))
    if hasattr(CFG, "OPRET_MAX_BYTES"):
        return int(getattr(CFG, "OPRET_MAX_BYTES"))
    return 80

def _guard_payload_size(data: bytes) -> None:
    limit = _max_graffiti_limit()
    if len(data) > limit:
        raise ValueError(f"graffiti_opreturn_too_large: {len(data)} > {limit}")


# -----------------------------
# Public API
# -----------------------------

def build_metadata(sha256_hex: str, size_bytes: int, mime: str,
                   storer_addr: str, receipt_id: str,
                   ts: Optional[int] = None, height: Optional[int] = None,
                   extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    
    if not _is_valid_sha256_hex(sha256_hex):
        raise ValueError("bad_sha256_hex")
    if not isinstance(size_bytes, int) or size_bytes < 0:
        raise ValueError("bad_size_bytes")
    if not _is_valid_mime(mime):
        raise ValueError("bad_mime")
    if not _is_valid_tsar_address(storer_addr):
        raise ValueError("bad_storer_addr")
    if not isinstance(receipt_id, str) or not receipt_id.strip():
        raise ValueError("bad_receipt_id")

    meta: Dict[str, Any] = {
        "sha256": sha256_hex.strip().lower(),
        "size": int(size_bytes),
        "mime": mime.strip(),
        "storer": storer_addr.strip().lower(),
        "receipt": receipt_id.strip(),
    }
    # Anchor opsional
    if ts is None:
        ts = int(time.time())
    meta["ts"] = int(ts)
    if height is not None:
        meta["height"] = int(height)

    # Extra kecil (dibatasi agar payload tetap kecil)
    if extra:
        for k, v in extra.items():
            if k in meta:
                continue
            if isinstance(v, (str, bytes)) and len(str(v)) > 128:
                continue
            meta[k] = v
    return meta


def encode_payload(meta: Dict[str, Any]) -> bytes:
    if not isinstance(meta, dict):
        raise ValueError("meta_must_be_dict")
    payload = CFG.GRAFFITI_MAGIC + _compact_json(meta)
    _guard_payload_size(payload)
    return payload


def build_script(meta: Dict[str, Any]) -> Script:
    payload = encode_payload(meta)
    return Script([OP_RETURN, payload])


def build_opret_hex(meta: Dict[str, Any]) -> str:
    return encode_payload(meta).hex()


def parse_payload(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        if not isinstance(data, (bytes, bytearray)):
            return None
        data = bytes(data)
        if not data.startswith(CFG.GRAFFITI_MAGIC):
            return None
        blob = data[len(CFG.GRAFFITI_MAGIC):]
        if not blob:
            return None
        obj = json.loads(blob.decode('ascii'))
        if not isinstance(obj, dict):
            return None
        # Sanity re-check
        if not _is_valid_sha256_hex(obj.get("sha256", "")):
            return None
        if not isinstance(obj.get("size"), int) or obj["size"] < 0:
            return None
        if not _is_valid_mime(obj.get("mime", "")):
            return None
        if not _is_valid_tsar_address(obj.get("storer", "")):
            return None
        if not isinstance(obj.get("receipt", ""), str) or not obj["receipt"].strip():
            return None
        return obj
    except Exception:
        return None


def parse_from_script(script: Script) -> Optional[Dict[str, Any]]:
    try:
        raw = script.serialize()
        if not raw or raw[0] != OP_RETURN:
            return None
        # Ambil push pertama setelah OP_RETURN
        i = 1
        if i >= len(raw):
            return None
        first = raw[i]; i += 1
        if 1 <= first <= 75:
            n = first
            end = i + n
            if end > len(raw): return None
            data = raw[i:end]
        elif first == 0x4c:  # OP_PUSHDATA1
            if i >= len(raw): return None
            n = raw[i]; i += 1
            end = i + n
            if end > len(raw): return None
            data = raw[i:end]
        elif first == 0x4d:  # OP_PUSHDATA2
            if i + 1 >= len(raw): return None
            n = int.from_bytes(raw[i:i+2], 'little'); i += 2
            end = i + n
            if end > len(raw): return None
            data = raw[i:end]
        else:
            return None
        return parse_payload(data)
    except Exception:
        return None


__all__ = [
    "build_metadata",
    "encode_payload",
    "build_script",
    "build_opret_hex",
    "parse_payload",
    "parse_from_script",
]
