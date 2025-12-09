# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import os, time
from typing import Any, Dict, Optional

from tsarchain.contracts import graffiti as GRAFFITI
from tsarchain.utils import config as CFG

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.node_route")


def handle_node_rpc(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    RPC handle sent from node/archivist to storage node.
    """
    t = str(msg.get("type", "")).upper()

    if t == "PING":
        return {"type": "PONG"}

    if t == "STOR_INDEX":
        server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (server.index.get("files") or {}).values())
        return {"type": "STOR_INDEX", "status": "ok", **server.index}

    if t == "STOR_PAID":
        aid = str(msg.get("graffiti_id", "")).strip()
        txid = str(msg.get("txid", "")).strip()
        block_h = int(msg.get("block_height", 0) or 0)
        meta = server.index.get("files", {}).get(aid)
        if not aid or not meta:
            return {"type": "STOR_PAID", "status": "error", "reason": "no_such"}
        if server.use_kv:
            already_final = server.db.get_final_bytes(aid) is not None
            if not already_final:
                data = server.db.pop_incoming(aid)
                if data is None:
                    return {"type": "STOR_PAID", "status": "error", "reason": "missing_file"}
                server.db.put_final(aid, data)
            meta["path"] = f"lmdb://final/{aid}"
            meta["state"] = "stored"
        else:
            path = meta.get("path")
            if path and os.path.isfile(path) and ("incoming" in path):
                fin_dir = os.path.join(server.storage_dir, "final")
                os.makedirs(fin_dir, exist_ok=True)
                fin = os.path.join(fin_dir, os.path.basename(path).replace(".part", ".bin"))
                os.replace(path, fin)
                meta["path"] = fin
                meta["state"] = "stored"

        meta["paid"] = True
        if txid:
            meta["txid_paid"] = txid
        if block_h > 0:
            meta["confirmed_at_height"] = block_h
            meta["expire_at_height"] = 0
        server.index["files"][aid] = server._normalize_file_meta(aid, meta)
        server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in server.index["files"].values())
        server._save_index()
        log.info("[STOR_PAID] aid=%s h=%s expire=%s", aid[:16], meta.get("confirmed_at_height"), meta.get("expire_at_height"))
        return {
            "type": "STOR_PAID",
            "status": "ok",
            "graffiti_id": aid,
            "expire_at_height": meta.get("expire_at_height", 0),
            "confirmed_at_height": meta.get("confirmed_at_height", 0),
        }

    if t == "STOR_GC":
        tip_h = int(msg.get("tip_height", 0) or 0)
        expire_after = max(0, int(CFG.GRAFFITI_EXPIRE_AFTER_BLOCKS))
        files = server.index.get("files", {}) or {}
        expired = 0
        remove_keys: list[str] = []
        for gid, meta in files.items():
            if not isinstance(meta, dict):
                continue
            if (not meta.get("paid")) and expire_after > 0 and tip_h > 0:
                expire_h = int(meta.get("expire_at_height", 0) or 0)
                if expire_h <= 0:
                    expire_h = tip_h + expire_after
                    meta["expire_at_height"] = expire_h
                    files[gid] = meta
            expire_h = int(meta.get("expire_at_height", 0) or 0)
            if expire_h and tip_h and expire_h <= tip_h and not meta.get("paid"):
                remove_keys.append(gid)
        for gid in remove_keys:
            meta = files.pop(gid, None) or {}
            expired += 1
            if server.use_kv:
                server.db.delete_blob(gid, incoming=True, final=True)
            else:
                path = meta.get("path")
                if path and os.path.isfile(path):
                    os.remove(path)
            art_id = str(meta.get("art_id", "")).strip().lower()
            if art_id and server.index.get("art_map", {}).get(art_id) == gid:
                server.index["art_map"].pop(art_id, None)
                
        server.index["files"] = files
        server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        server._save_index()
        if expired:
            log.info("[STOR_GC] expired=%s tip=%s", expired, tip_h)
        return {"type": "STOR_GC", "status": "ok", "expired": expired}

    if t == "STOR_PROOF_RUN":
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
        challenge = GRAFFITI.calc_proof_challenge(art_norm, size, tip_h)
        offset = int(challenge.get("offset", 0))
        length = int(challenge.get("length", 0))
        
        if server.use_kv:
            data_bytes = server.db.get_final_bytes(aid)
            if data_bytes is None:
                raise FileNotFoundError("file_missing")
            chunk = data_bytes[offset : offset + length]
        else:
            path = meta.get("path")
            if not path or not os.path.isfile(path):
                raise FileNotFoundError("file_missing")
            with open(path, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(length)
                
        proof_hash = GRAFFITI.hash_proof_chunk(chunk)
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
        log.info("[STOR_PROOF_RUN] aid=%s epoch=%s offset=%s len=%s", aid[:16], meta.get("last_proof_epoch"), offset, length)
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
        }

    return None


__all__ = ["handle_node_rpc"]
