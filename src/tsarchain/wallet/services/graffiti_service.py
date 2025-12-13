# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173

from __future__ import annotations

import base64, json, os, socket, time, hashlib, mimetypes
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from tsarchain.network.protocol import send_message, recv_message
from tsarchain.utils import config as CFG
from tsarchain.contracts.graffiti import (
    build_comment_metadata,
    build_metadata,
    build_opret_hex,
    calc_comment_split,
    calc_upload_fee_sats,
    compute_art_id,
    derive_pool_address,
    validate_graffiti_file,
)

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.graffiti_service")


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
                port = int(port_part)
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

def _send_storage_request(host: str, port: int, payload: Dict[str, Any], timeout: float | None = None, max_len: int | None = None) -> Dict[str, Any]:
    timeout = timeout or CFG.RPC_TIMEOUT
    if max_len is None:
        max_len = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    resp: Dict[str, Any] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, int(port)))
        raw = json.dumps(payload).encode("utf-8")
        send_message(s, raw, max_len=max_len)
        data = recv_message(s, timeout, max_len=max_len)
        if not data:
            return {"status": "error", "reason": "no_response"}
        obj = json.loads(data.decode("utf-8"))
        if isinstance(obj, dict):
            resp = obj
        else:
            resp = {"status": "error", "reason": "bad_response"}
    return resp

def fetch_storers(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]], limit: Optional[int] = None) -> list[Dict[str, Any]]:
    resp = rpc_call({"type": "STOR_LIST"}) or {}
    storers = resp.get("storers") or resp.get("items") or []
    valid: list[Dict[str, Any]] = []
    for meta in storers:
        port = int(meta.get("port") or 0)
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        if not addr or port <= 0:
            continue
        valid.append(meta)
    valid.sort(key=lambda m: int(m.get("last_seen", 0)), reverse=True)
    if limit is not None and limit > 0:
        return valid[:limit]
    return valid

def _sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(chunk), b""):
            if not part:
                break
            h.update(part)
    return h.hexdigest()

def read_graffiti_file_info(path: str) -> Dict[str, Any]:
    """
    Read local file and return basic info (size, mime, sha256) while validating graffiti boundaries.
    """
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(path)
    size = os.path.getsize(path)
    mime_raw, _ = mimetypes.guess_type(path)
    mime = validate_graffiti_file(size, mime_raw, os.path.basename(path))
    sha = _sha256_file(path)
    return {"size": size, "mime": mime, "sha": sha}

def select_upload_storers(resp: Optional[Dict[str, Any]], *, replication_r: Optional[int] = None) -> list[Dict[str, Any]]:
    """
    Select candidate storage nodes based on metadata and sort by most trusted/recently seen.
    """
    storers = (resp or {}).get("storers") or (resp or {}).get("items") or []
    usable: list[Dict[str, Any]] = []
    for meta in storers:
        port = int(meta.get("port") or 0)
        if port <= 0:
            continue
        usable.append(meta)
    usable.sort(key=lambda m: int(m.get("trusted") or 0) * 1_000_000 + int(m.get("last_seen", 0)), reverse=True)
    limit = max(1, int(replication_r if replication_r is not None else CFG.GRAFFITI_REPLICATION_R))
    return usable[:limit]

def filter_online_storers(storers: list[Dict[str, Any]], timeout: float = 2.0) -> list[Dict[str, Any]]:
    """
    Perform a quick TCP health check to ensure the storage node is reachable.
    """
    online: list[Dict[str, Any]] = []
    for meta in storers:
        host = str(meta.get("ip") or meta.get("host") or "").strip() or "127.0.0.1"
        port = int(meta.get("port") or 0)
        if port <= 0:
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout):
                online.append(meta)
        except OSError:
            continue
    return online

def build_upload_context(sha256_hex: str, creator_addr: str, *, now_ts: Optional[int] = None) -> Dict[str, str]:
    """
    Create art_id + upload identity (graffiti_id and receipt_id) for one file.
    """
    creator = (creator_addr or "").strip().lower()
    if not creator:
        raise ValueError("creator wallet belum dipilih")
    art_id = compute_art_id(sha256_hex, creator)
    ts = int(now_ts or time.time())
    gid = f"{sha256_hex}_{ts}"
    receipt_id = f"rcpt_{gid}"
    return {"art_id": art_id, "graffiti_id": gid, "receipt_id": receipt_id}

def build_post_plan(
    *,
    sha256_hex: str,
    size_bytes: int,
    mime: str,
    creator_addr: str,
    storer_meta: Dict[str, Any],
    receipt_id: str,
    art_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Arrange metadata and POST fees before and after upload.
    """
    if size_bytes is None:
        raise ValueError("upload metadata incomplete")
    creator = (creator_addr or "").strip().lower()
    if not creator:
        raise ValueError("creator wallet belum dipilih")
    storer_addr = str(storer_meta.get("addr") or storer_meta.get("address") or "").strip().lower()
    art = art_id or compute_art_id(sha256_hex, creator)
    meta = build_metadata(
        sha256_hex=sha256_hex,
        size_bytes=int(size_bytes),
        mime=mime,
        storer_addr=storer_addr or "unknown",
        receipt_id=receipt_id,
        creator_addr=creator,
    )
    opret_hex = build_opret_hex(meta)
    pool_addr = derive_pool_address(art)
    fee_sats = calc_upload_fee_sats(int(size_bytes))
    tsar_fee = fee_sats / CFG.TSAR
    return {
        "pool_addr": pool_addr,
        "fee_sats": fee_sats,
        "opret_hex": opret_hex,
        "art_id": art,
        "tsar_fee": tsar_fee,
    }

def parse_amount_str(raw: str, default: int) -> int:
    txt = (raw or "").strip()
    if not txt:
        return int(default)
    txt = txt.replace(" ", "").replace(",", ".")
    if txt.startswith("."):
        txt = "0" + txt
    try:
        dec = Decimal(txt)
    except InvalidOperation:
        raise ValueError("Format jumlah tidak valid")
    if dec <= 0:
        if dec == 0 and int(default) == 0:
            return 0
        raise ValueError("Jumlah harus > 0")

    quant = Decimal("1").scaleb(-CFG.MAX_DECIMALS)
    dec_q = dec.quantize(quant, rounding=ROUND_DOWN)
    sats = int(dec_q * Decimal(CFG.TSAR))
    if sats <= 0:
        raise ValueError("Jumlah terlalu kecil")

    return sats

def build_comment_plan(
    *,
    art: Dict[str, Any],
    commenter_addr: str,
    base_amount_raw: str,
    tip_amount_raw: str,
    comment_text: str,
) -> Dict[str, Any]:
    """
    Validate comment input and arrange opret + payment output.
    """
    if not art:
        raise ValueError("Pilih karya terlebih dahulu.")
    art_id = str(art.get("art_id") or "").strip()
    if not art_id:
        raise ValueError("Art ID tidak tersedia.")

    commenter = (commenter_addr or "").strip().lower()
    if not commenter:
        raise ValueError("Pilih wallet untuk komentar.")

    text = (comment_text or "").strip()
    if not text:
        raise ValueError("Teks komentar belum diisi.")

    base_sats = parse_amount_str(base_amount_raw, int(CFG.GRAFFITI_COMMENT_MIN_FEE))
    if base_sats < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
        base_sats = int(CFG.GRAFFITI_COMMENT_MIN_FEE)
    tip_sats = parse_amount_str(tip_amount_raw, 0) if (tip_amount_raw or "").strip() else 0

    creator_addr = str(art.get("creator") or "").strip().lower()
    if not creator_addr:
        raise ValueError("Creator address is not available for this graffiti.")

    pool_addr = str(art.get("pool_address") or derive_pool_address(art_id)).strip().lower()
    try:
        meta = build_comment_metadata(
            art_id=art_id,
            comment_text=text,
            amount_sats=base_sats,
            creator_addr=creator_addr,
            commenter_addr=commenter,
            tip_sats=tip_sats,
        )
    except ValueError as exc:
        raise ValueError(f"Metadata komentar invalid: {exc}") from exc
    opret_hex = build_opret_hex(meta)
    split = calc_comment_split(base_sats, tip_sats)

    outputs = []
    if split["creator_total"] > 0:
        outputs.append({"address": creator_addr, "amount": split["creator_total"]})
    if split["storage"] > 0:
        outputs.append({"address": pool_addr, "amount": split["storage"]})
    if not outputs:
        raise ValueError("Tidak ada output pembayaran yang valid.")

    return {
        "opret_hex": opret_hex,
        "outputs": outputs,
        "base_sats": base_sats,
        "tip_sats": tip_sats,
        "split": split,
    }

def upload_graffiti(
    storer_meta: Dict[str, Any],
    file_path: str,
    *,
    graffiti_id: Optional[str] = None,
    sha256_hex: Optional[str] = None,
    art_id: Optional[str] = None,
    receipt_id: Optional[str] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """
    Upload a file to a storage node discovered from the TsarChain node RPC.

    rpc_call    : callable that accepts a dict and returns a node RPC response (synchronous).
    storer_addr : bech32 address storage target.
    file_path   : path of the file to be uploaded.
    graffiti_id : unique id (default = sha256_hex).
    sha256_hex  : hash file (will be counted if None).
    """
    if not os.path.isfile(file_path):
        return {"status": "error", "reason": "file_not_found"}

    total_size = os.path.getsize(file_path)
    mime_guess, _ = mimetypes.guess_type(file_path)
    mime_norm = validate_graffiti_file(total_size, mime_guess, os.path.basename(file_path))
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
        "mime": mime_norm,
    }
    if art_id:
        init_payload["art_id"] = str(art_id).strip().lower()
    init_resp = _send_storage_request(host, port, init_payload)
    if init_resp.get("status") not in ("ok", "accepted"):
        return {"status": "error", "stage": "init", "resp": init_resp}

    chunk_size = int(init_resp.get("chunk_size") or CFG.STORAGE_UPLOAD_CHUNK)
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
                progress_cb(sent, total_size)

    commit_payload = {"type": "STOR_COMMIT", "graffiti_id": gid}
    if receipt_id:
        commit_payload["receipt_id"] = receipt_id
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

def fetch_graffiti_file(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    art_id: str,
    *,
    storer_addr: Optional[str] = None,
    cache_dir: Optional[str] = None,
    max_bytes: int = CFG.GRAFFITI_MAX_SIZE_BYTES,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Retrieve graffiti files from the storage node based on art_id.
    - rpc_call: Synchronous function to the node (e.g., NodeClient.send)
    - storer_addr: Preferred storage address (bech32) if available
    - cache_dir: Local cache location (default: data_user/graffiti_cache)
    Return: {"status": "ok", "bytes": b"...", "meta": {...}, "cache_path": "..."} atau {"status": "error", "reason": "..."}
    """
    art_norm = (art_id or "").strip().lower()
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

    max_bytes = int(max_bytes)
    # Clamp by graffiti msg limit to avoid hitting generic MAX_MSG
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = int(msg_cap * 3 // 4)  # guard for base64/json overhead
    max_bytes = max(32 * 1024, min(max_bytes, int(CFG.GRAFFITI_MAX_SIZE_BYTES), data_cap))
    storers = fetch_storers(rpc_call)  # type: ignore[arg-type]

    if not storers:
        log.warning("[fetch] no_storers art=%s", art_norm[:16])
        return {"status": "error", "reason": "no_storers"}

    preferred, others = [], []
    storer_target = (storer_addr or "").strip().lower()
    for meta in storers:
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        (preferred if storer_target and addr == storer_target else others).append(meta)
    candidates = preferred + others

    cache_root = cache_dir or os.path.join("data_user", "graffiti_cache")
    os.makedirs(cache_root, exist_ok=True)

    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = int(msg_cap * 3 // 4)  # approximate base64 overhead guard

    last_error = None
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint
        payload = {"type": "STOR_GET_BY_ART", "art_id": art_norm, "include_data": True, "max_bytes": min(max_bytes, data_cap)}
        resp = _send_storage_request(host, port, payload, timeout=timeout, max_len=msg_cap)
        if not isinstance(resp, dict):
            last_error = "bad_response"
            log.warning("[fetch] bad_response art=%s host=%s port=%s meta=%s", art_norm[:16], host, port, meta)
            continue
        if not resp.get("found"):
            last_error = resp.get("reason") or "not_found"
            log.info("[fetch] not_found art=%s host=%s port=%s reason=%s meta=%s", art_norm[:16], host, port, last_error, meta)
            continue
        if resp.get("status") == "error":
            last_error = resp.get("reason") or "error"
            log.warning("[fetch] storage_error art=%s host=%s port=%s reason=%s meta=%s", art_norm[:16], host, port, last_error, meta)
            continue
        data_b64 = resp.get("data_b64")
        meta_resp = resp.get("meta") or {}
        if not data_b64:
            last_error = "no_data"
            log.warning("[fetch] no_data art=%s host=%s port=%s", art_norm[:16], host, port)
            continue
        
        raw = base64.b64decode(data_b64)
        fname = meta_resp.get("filename") or f"{art_norm}.bin"
        ext = ".jpg" if str(meta_resp.get("mime") or "").startswith("image/") else os.path.splitext(fname)[1] or ".bin"
        cache_path = os.path.join(cache_root, f"{art_norm}{ext}")
        with open(cache_path, "wb") as fh:
            fh.write(raw)
        log.info("[fetch] ok art=%s host=%s size=%s cache=%s", art_norm[:16], host, len(raw), bool(cache_path))
        return {"status": "ok", "bytes": raw, "meta": meta_resp, "cache_path": cache_path}

    return {"status": "error", "reason": last_error or "unavailable"}


__all__ = [
    "build_comment_plan",
    "build_post_plan",
    "build_upload_context",
    "fetch_graffiti_file",
    "fetch_storers",
    "filter_online_storers",
    "parse_amount_str",
    "read_graffiti_file_info",
    "select_upload_storers",
    "upload_graffiti",
]
