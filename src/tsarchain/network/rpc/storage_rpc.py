# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os, json
from typing import TYPE_CHECKING, Any, Optional

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc(storage_rpc)")
from ...utils import config as CFG

if TYPE_CHECKING:
    from ..node import Network


__all__ = ["handle_storage_rpc"]


def _storage_index_path() -> str:
    return os.path.join(CFG.STORAGE_DIR, "index.json")

def _load_storage_index() -> dict[str, Any]:
    default = {"files": {}, "bytes_used": 0, "art_map": {}}
    try:
        with open(_storage_index_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("files", {})
    data.setdefault("bytes_used", 0)
    data.setdefault("art_map", {})
    return data

def _save_storage_index(data: dict[str, Any]) -> None:
    path = _storage_index_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def handle_storage_rpc(self: "Network", message: dict[str, Any], addr: Optional[tuple], mtype: str) -> dict | None:

    if mtype == "STOR_INDEX":
        idx = _load_storage_index()
        # Recompute bytes_used to avoid stale values
        try:
            idx["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (idx.get("files") or {}).values())
        except Exception:
            pass
        return {"type": "STOR_INDEX", "status": "ok", **idx}

    if mtype == "STOR_STATUS":
        aid = str(message.get("graffiti_id") or "").strip()
        idx = _load_storage_index()
        meta = (idx.get("files") or {}).get(aid)
        return {"type": "STOR_STATUS", "found": bool(meta), "meta": meta}

    if mtype == "STOR_PAID":
        aid = str(message.get("graffiti_id") or "").strip()
        txid = str(message.get("txid") or "").strip()
        idx = _load_storage_index()
        files = idx.setdefault("files", {})
        meta = files.get(aid)
        if not aid or not isinstance(meta, dict):
            return {"status": "error", "reason": "no_such"}
        meta["paid"] = True
        if txid:
            meta["txid_paid"] = txid
        files[aid] = meta
        try:
            idx["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        except Exception:
            pass
        _save_storage_index(idx)
        return {"status": "ok", "graffiti_id": aid}

    if mtype == "STOR_GC":
        try:
            tip_h = int(message.get("tip_height", 0) or 0)
        except Exception:
            tip_h = 0
        idx = _load_storage_index()
        files = idx.get("files") or {}
        expired = 0
        remove_keys: list[str] = []
        for gid, meta in files.items():
            try:
                expire_h = int(meta.get("expire_at_height", 0) or 0)
            except Exception:
                expire_h = 0
            if expire_h and tip_h and expire_h <= tip_h:
                remove_keys.append(gid)
        for gid in remove_keys:
            meta = files.pop(gid, None) or {}
            expired += 1
            try:
                path = meta.get("path")
                if path and os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass
        idx["files"] = files
        try:
            idx["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        except Exception:
            idx["bytes_used"] = 0
        _save_storage_index(idx)
        return {"type": "STOR_GC", "status": "ok", "expired": expired}

    if mtype == "GRAFFITI_GET_PAYOUTS":
        art_id = str(message.get("art_id") or "").strip().lower()
        if not art_id:
            return {"type": "GRAFFITI_GET_PAYOUTS", "payouts": []}
        limit = int(message.get("limit", 100) or 100)
        limit = max(1, min(limit, 500))
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        payouts = reg.list_payouts(art_id, limit) if reg else []
        return {"type": "GRAFFITI_GET_PAYOUTS", "art_id": art_id, "payouts": payouts}

    elif mtype == "GRAFFITI_POOL_PAYOUT":
        art_id = str(message.get("art_id") or "").strip().lower()
        try:
            amount = int(message.get("amount", 0))
        except Exception:
            amount = 0
        recipient = str(message.get("recipient") or "").strip().lower() or "storage"
        txid = str(message.get("txid") or "").strip() or "offchain"
        if not art_id or amount <= 0:
            return {"error": "bad_request"}
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        if not reg:
            return {"error": "registry_unavailable"}
        post = reg.get_post(art_id)
        if not post:
            return {"error": "unknown_art_id"}
        stats = post.setdefault("stats", {})
        pool_balance = int(stats.get("pool_balance", 0))
        if pool_balance < amount:
            return {"error": "insufficient_pool_balance", "pool_balance": pool_balance}
        height = getattr(getattr(self.broadcast, "blockchain", None), "height", 0)
        reg.record_payout(art_id, {recipient: amount}, txid, height)
        return {"status": "ok", "art_id": art_id, "pool_balance": int(stats.get("pool_balance", 0))}

    return None

