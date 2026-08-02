# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import os
import time
import json
from typing import Any, Dict

from ..utils import config as CFG
from ..storage.kv import kv_enabled, iter_prefix, batch

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.contracts.graffiti_registry')


class GraffitiRegistry:
    def __init__(self) -> None:
        self._kv = kv_enabled()
        self._kv_prefix = "graffiti:"
        self.store = None
        self._data_cache = None
        default = {"posts": {}, "comments": {}, "payouts": {}, "proofs": {}}
        self.data = self._load(default)
        self.data.setdefault("proofs", {})


    def record_post(self, art_id: str, meta: Dict[str, Any], txid: str, block_height: int, pool_addr: str, amount_paid: int, *, block_hash: str | None = None) -> None:
        posts = self.data.setdefault("posts", {})
        existing = posts.get(art_id)
        if existing and existing.get("txid") == txid:
            return
        entry = dict(meta)
        entry.update({
            "art_id": art_id,
            "txid": txid,
            "block_height": int(block_height),
            "pool_address": pool_addr,
            "amount_paid": int(amount_paid),
            "block_hash": block_hash,
        })
        stats = entry.setdefault("stats", {})
        stats["pool_balance"] = int(stats.get("pool_balance", 0)) + int(amount_paid)
        stats.setdefault("creator_paid", 0)
        stats.setdefault("storage_paid", 0)
        stats.setdefault("comments", 0)
        posts[art_id] = entry
        self._flush()


    def get_post(self, art_id: str) -> Dict[str, Any] | None:
        return (self.data.get("posts") or {}).get(art_id)


    def record_comment(self, art_id: str, meta: Dict[str, Any], txid: str,
                       block_height: int, creator_paid: int, storage_paid: int) -> None:
        comments = self.data.setdefault("comments", {})
        thread = comments.setdefault(art_id, [])
        entry = {
            "txid": txid,
            "block_height": int(block_height),
            "comment": meta.get("comment"),
            "commenter": meta.get("commenter"),
            "amount": int(meta.get("amount") or 0),
            "tip": int(meta.get("tip") or 0),
            "creator_paid": int(creator_paid),
            "storage_paid": int(storage_paid),
            "ts": int(meta.get("ts") or time.time()),
        }
        existing_txids = {item.get("txid") for item in thread}
        if txid in existing_txids:
            return
        thread.append(entry)
        post = self.get_post(art_id)
        if post:
            stats = post.setdefault("stats", {})
            stats["creator_paid"] = int(stats.get("creator_paid", 0)) + int(creator_paid)
            stats["storage_paid"] = int(stats.get("storage_paid", 0)) + int(storage_paid)
            stats["pool_balance"] = int(stats.get("pool_balance", 0)) + int(storage_paid)
            stats["comments"] = int(stats.get("comments", 0)) + 1
        self._flush()


    def record_payout(self, art_id: str, recipients: Dict[str, int], txid: str, block_height: int, epoch: int | None = None, pool_balance: int | None = None) -> None:
        posts = self.data.setdefault("posts", {})
        post = posts.get(art_id)
        if not post:
            return
        stats = post.setdefault("stats", {})
        total = sum(int(v) for v in recipients.values())
        payouts = self.data.setdefault("payouts", {})
        art_payouts = payouts.setdefault(art_id, [])
        # Idempotent replay: skip if already recorded
        for existing in art_payouts:
            if existing.get("txid") == txid:
                if pool_balance is not None:
                    stats["pool_balance"] = max(0, int(pool_balance))
                return
        if pool_balance is not None:
            stats["pool_balance"] = max(0, int(pool_balance))
        else:
            stats["pool_balance"] = max(0, int(stats.get("pool_balance", 0)) - total)
        if epoch is not None:
            stats["last_paid_epoch"] = max(int(stats.get("last_paid_epoch", -1)), int(epoch))
        art_payouts.append({
            "txid": txid,
            "block_height": int(block_height),
            "recipients": {addr: int(val) for addr, val in recipients.items()},
            "amount": int(total),
            "epoch": None if epoch is None else int(epoch),
        })
        self._flush()


    def set_pool_balance(self, art_id: str, pool_balance: int) -> None:
        posts = self.data.setdefault("posts", {})
        post = posts.get(art_id)
        if not post:
            return
        stats = post.setdefault("stats", {})
        stats["pool_balance"] = max(0, int(pool_balance))
        self._flush()


    def record_proof(self, art_id: str, storer: str, epoch: int, offset: int, length: int,
                     proof_hash: str, height: int = 0, seed: str = "") -> None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower()
        if not art_id or not storer:
            return
        proofs = self.data.setdefault("proofs", {})
        art_proofs = proofs.setdefault(art_id, [])
        entry = {
            "storer": storer,
            "epoch": int(epoch),
            "offset": int(offset),
            "length": int(length),
            "hash": proof_hash,
            "height": int(height),
            "seed": seed,
            "ts": int(time.time()),
        }
        # Replace existing entry for same storer+epoch
        replaced = False
        for idx, item in enumerate(art_proofs):
            if item.get("storer") == storer and int(item.get("epoch", -1)) == int(epoch):
                art_proofs[idx] = entry
                replaced = True
                break
        if not replaced:
            art_proofs.append(entry)
        self.data["proofs"][art_id] = art_proofs
        self._flush()


    def get_proof(self, art_id: str, storer: str, epoch: int) -> Dict[str, Any] | None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower()
        if not art_id or not storer:
            return None
        proofs = (self.data.get("proofs") or {}).get(art_id, [])
        for item in proofs:
            if item.get("storer") == storer and int(item.get("epoch", -1)) == int(epoch):
                return dict(item)
        return None


    def get_latest_proof(self, art_id: str, storer: str | None = None) -> Dict[str, Any] | None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower() if storer else None
        proofs = (self.data.get("proofs") or {}).get(art_id, [])
        if not proofs:
            return None
        filtered = [dict(p) for p in proofs if (not storer or p.get("storer") == storer)]
        if not filtered:
            return None
        filtered.sort(key=lambda r: (int(r.get("epoch", -1)), int(r.get("ts", 0))), reverse=True)
        return filtered[0]


    def get_latest_proof_epoch(self, art_id: str, storer: str | None = None) -> int:
        proof = self.get_latest_proof(art_id, storer)
        if not proof:
            return -1
        return int(proof.get("epoch", -1))


    def list_payouts(self, art_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        art_id = (art_id or "").strip().lower()
        payouts = (self.data.get("payouts") or {}).get(art_id, [])
        items = [dict(entry) for entry in payouts]
        items.sort(key=lambda r: int(r.get("block_height") or 0), reverse=True)
        if isinstance(limit, int) and limit > 0:
            return items[:limit]
        return items


    def list_posts(self, limit: int = 50, offset: int = 0) -> list[Dict[str, Any]]:
        posts = self.data.get("posts") or {}
        items: list[Dict[str, Any]] = []
        for art_id, entry in posts.items():
            rec = dict(entry)
            rec["art_id"] = art_id
            stats = rec.get("stats") or {}
            rec["stats"] = stats
            items.append(rec)
        items.sort(key=lambda r: (int(r.get("block_height") or 0), int(r.get("ts") or 0)), reverse=True)
        off = max(0, int(offset or 0))
        if isinstance(limit, int) and limit > 0:
            return items[off:off + limit]
        return items[off:]


    def list_comments(self, art_id: str, limit: int = 50) -> list[Dict[str, Any]]:
        art_id = (art_id or "").strip().lower()
        if not art_id:
            return []
        comments = (self.data.get("comments") or {}).get(art_id, [])
        items = [dict(entry) for entry in comments]
        items.sort(key=lambda r: (int(r.get("block_height") or 0), int(r.get("ts") or 0)), reverse=True)
        if isinstance(limit, int) and limit > 0:
            return items[:limit]
        return items


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _load(self, default: dict) -> dict:
        if self._kv:
            data = {"posts": {}, "comments": {}, "payouts": {}, "proofs": {}}
            for k, v in iter_prefix("graffiti", b"data:"):
                if k.decode("utf-8") == "data:data":
                    data = json.loads(v.decode("utf-8"))
                    break
            return data or dict(default)
        return dict(default)


    def _flush(self) -> None:
        if self._kv:
            with batch("graffiti") as b:
                b.put(b"data:data", json.dumps(self.data, separators=CFG.CANONICAL_SEP).encode("utf-8"))


__all__ = ["GraffitiRegistry"]
