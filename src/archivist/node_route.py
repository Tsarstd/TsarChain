# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import time
import base64

from typing import Any, Dict, Optional

from tsarchain.utils import config as CFG
from tsarchain.utils.benchmarks import benchmark
from tsarchain.contracts import graffiti as GRAFFITI

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.node_route")


def handle_node_rpc(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    RPC handle sent from node/archivist to storage node.
    """
    t = str(msg.get("type", "")).upper()

    handlers = {
        "PING": _handle_ping,
        "STOR_INDEX": _handle_stor_index,
        "STOR_PAID": _handle_stor_paid,
        "STOR_GC": _handle_stor_gc,
        "STOR_PROOF_RUN": _handle_stor_proof_run,
    }

    if t in handlers:
        return handlers[t](server, msg)

    return None

# =============================================================================
# RPC
# =============================================================================

def _handle_ping(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return {"type": "PONG"}

@benchmark(label="STOR_INDEX", threshold_ms=15.0)
def _handle_stor_index(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (server.index.get("files") or {}).values())
    return {"type": "STOR_INDEX", "status": "ok", **server.index}

def _finalize_storage(server, aid: str, meta: dict) -> tuple[bool, Optional[str]]:
    already_final = server.db.has_final(aid) if hasattr(server.db, "has_final") else (server.db.get_final_bytes_range(aid, 0, 1) is not None)
    if already_final is not True:
        data = server.db.pop_incoming(aid)
        if data is None:
            p = meta.get("path")
            if p and os.path.isfile(p):
                try:
                    with open(p, "rb") as f:
                        data = f.read()
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                except OSError:
                    pass
        if data is None:
            return False, "missing_file"
        server.db.put_final(aid, data)
    server.db.delete_blob(aid, incoming=True)
    meta["path"] = f"lmdb://final/{aid}"
    meta["state"] = "stored"
    return True, None

@benchmark(label="STOR_PAID", threshold_ms=500.0)
def _handle_stor_paid(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    aid = str(msg.get("graffiti_id", "")).strip()
    art_id = str(msg.get("art_id", "")).strip().lower()
    txid = str(msg.get("txid", "")).strip()
    block_h = int(msg.get("block_height", 0) or 0)
    meta = server.index.get("files", {}).get(aid)
    if not meta and art_id:
        real_gid = server.index.get("art_map", {}).get(art_id)
        if real_gid:
            meta = server.index.get("files", {}).get(real_gid)
            aid = real_gid
    if not meta:
        for gid_k, m in server.index.get("files", {}).items():
            if m.get("sha256", "").lower() == aid.lower() or m.get("art_id", "").lower() == aid.lower():
                meta = m
                aid = gid_k
                break
    if not aid or not meta:
        return {"type": "STOR_PAID", "status": "error", "reason": "no_such"}
        
    if art_id:
        meta["art_id"] = art_id
        server.index.setdefault("art_map", {})[art_id] = aid

    success, err_reason = _finalize_storage(server, aid, meta)
    if not success:
        return {"type": "STOR_PAID", "status": "error", "reason": err_reason}

    meta["paid"] = True
    if txid:
        meta["txid_paid"] = txid
    if block_h > 0:
        meta["confirmed_at_height"] = block_h
        meta["expire_at_height"] = 0
    server.index["files"][aid] = server._normalize_file_meta(aid, meta)
    server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in server.index["files"].values())
    server._save_index()
    
    return {
        "type": "STOR_PAID",
        "status": "ok",
        "graffiti_id": aid,
        "expire_at_height": meta.get("expire_at_height", 0),
        "confirmed_at_height": meta.get("confirmed_at_height", 0),
    }

@benchmark(label="STOR_GC", threshold_ms=15.0)
def _handle_stor_gc(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    tip_h = int(msg.get("tip_height", 0) or 0)
    expire_after = max(0, int(CFG.GRAFFITI_EXPIRE_AFTER_BLOCKS))
    files = server.index.get("files", {}) or {}
    
    remove_keys = _find_expired_keys(files, tip_h, expire_after)
    expired = _remove_expired_files(server, files, remove_keys)
            
    server.index["files"] = files
    server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
    server._save_index()
    if expired:
        log.info("[STOR_GC] expired=%s tip=%s", expired, tip_h)
        
    return {"type": "STOR_GC", "status": "ok", "expired": expired}

@benchmark(label="STOR_PROOF_RUN", threshold_ms=75.0)
def _handle_stor_proof_run(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    aid = str(msg.get("graffiti_id", "")).strip()
    art_id = str(msg.get("art_id", "")).strip().lower()
    tip_h = int(msg.get("tip_height", 0) or 0)
    files = server.index.get("files", {}) or {}
    if art_id and not aid:
        aid = (server.index.get("art_map") or {}).get(art_id, "")

    meta = files.get(aid) if aid else None
    if not meta:
        return {"type": "STOR_PROOF_RUN", "status": "error", "reason": "no_such"}

    size = int(meta.get("size_bytes", 0) or 0)
    art_norm = str(meta.get("art_id") or art_id or "").strip().lower()
    if not art_norm:
        meta["missed_proofs"] = int(meta.get("missed_proofs", 0)) + 1
        meta["proof_fail_reason"] = "missing_art_id"
        server.index["files"][aid] = server._normalize_file_meta(aid, meta)
        server._save_index()
        return {"type": "STOR_PROOF_RUN", "status": "error", "reason": "missing_art_id"}

    merkle_chunk = int(CFG.GRAFFITI_PROOF_CHUNK_BYTES)
    challenge = GRAFFITI.calc_proof_challenge(art_norm, size, tip_h, chunk_bytes=merkle_chunk)
    offset = int(challenge.get("offset", 0))
    length = int(challenge.get("length", 0))
    
    chunk_index = offset // merkle_chunk if merkle_chunk > 0 else 0
    chunk, merkle_path = _get_chunk_and_merkle(server, aid, meta, offset, length, merkle_chunk, chunk_index)
            
    proof_hash = GRAFFITI.hash_proof_chunk(chunk)
    chunk_b64 = base64.b64encode(chunk).decode("ascii")
    now_ts = int(time.time())
    meta.update(
        {
            "last_proof_epoch": int(challenge.get("epoch", 0)),
            "last_proof_ts": now_ts,
            "last_proof_offset": offset,
            "last_proof_length": length,
            "last_proof_hash": proof_hash,
            "proof_fail_reason": "",
            "proof_status": "ok",
            "missed_proofs": max(0, int(meta.get("missed_proofs", 0))),
            "last_proof_height": tip_h,
        }
    )
    if art_norm:
        server.index.setdefault("art_map", {})[art_norm] = aid
        meta["art_id"] = art_norm
    server.index["files"][aid] = server._normalize_file_meta(aid, meta)
    server._save_index()
        
    return {
        "type": "STOR_PROOF_RUN",
        "status": "ok",
        "graffiti_id": aid,
        "art_id": art_norm,
        "epoch": int(challenge.get("epoch", 0)),
        "offset": offset,
        "length": length,
        "hash": proof_hash,
        "seed": challenge.get("seed"),
        "height": tip_h,
        "chunk": chunk_b64,
        "path": merkle_path,
    }

# =============================================================================
# HELPERS
# =============================================================================

def _find_expired_keys(files: dict, tip_h: int, expire_after: int) -> list[str]:
    remove_keys = []
    for gid, meta in files.items():
        if not isinstance(meta, dict):
            continue
        if (not meta.get("paid")) and expire_after > 0 and tip_h > 0:
            expire_h = int(meta.get("expire_at_height", 0) or 0)
            if expire_h <= 0:
                expire_h = tip_h + expire_after
                meta["expire_at_height"] = expire_h
        expire_h = int(meta.get("expire_at_height", 0) or 0)
        if expire_h and tip_h and expire_h <= tip_h and not meta.get("paid"):
            remove_keys.append(gid)
    return remove_keys

def _remove_expired_files(server, files: dict, remove_keys: list[str]) -> int:
    expired = 0
    for gid in remove_keys:
        meta = files.pop(gid, None) or {}
        expired += 1
        server.db.delete_blob(gid, incoming=True, final=True)
        art_id = str(meta.get("art_id", "")).strip().lower()
        if art_id and server.index.get("art_map", {}).get(art_id) == gid:
            server.index["art_map"].pop(art_id, None)
    return expired

def _get_chunk_and_merkle(server, aid: str, meta: dict, offset: int, length: int, merkle_chunk: int, chunk_index: int):
    chunk = server.db.get_final_bytes_range(aid, offset, length)
    if chunk is None:
        raise FileNotFoundError("file_missing")
    merkle_path = server.db.get_final_merkle_path(aid, merkle_chunk, chunk_index)
    if merkle_path is None:
        raise FileNotFoundError("file_missing")
    log.debug("use merkle_path_for_lmdb")
    return chunk, merkle_path


__all__ = ["handle_node_rpc"]
