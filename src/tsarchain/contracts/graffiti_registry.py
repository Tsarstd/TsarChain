# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os
import time
import json
from typing import Any, Dict

from ..storage.db import AtomicJSONFile
from ..storage.kv import kv_enabled, iter_prefix, batch
from ..utils import config as CFG


class GraffitiRegistry:
    def __init__(self) -> None:
        self._kv = kv_enabled()
        self._kv_prefix = "graffiti:"
        if self._kv:
            self.store = None
            self._data_cache = None
        else:
            os.makedirs(os.path.dirname(CFG.GRAFFITI_FILE), exist_ok=True)
            self.store = AtomicJSONFile(CFG.GRAFFITI_FILE, keep_backups=2, checksum=True)
        default = {"posts": {}, "comments": {}, "payouts": {}}
        self.data = self._load(default)

    def _load(self, default: dict) -> dict:
        if self._kv:
            data = {"posts": {}, "comments": {}, "payouts": {}}
            try:
                for k, v in iter_prefix("graffiti", b"data:"):
                    if k.decode("utf-8") == "data:data":
                        data = json.loads(v.decode("utf-8"))
                        break
            except Exception:
                data = dict(default)
            return data or dict(default)
        try:
            return self.store.load(default=default)
        except FileNotFoundError:
            self.store.save(default)
            return dict(default)

    def _flush(self) -> None:
        if self._kv:
            try:
                with batch("graffiti") as b:
                    b.put(b"data:data", json.dumps(self.data, separators=CFG.CANONICAL_SEP).encode("utf-8"))
            except Exception:
                pass
        else:
            self.store.save(self.data)

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

    def record_payout(self, art_id: str, recipients: Dict[str, int], txid: str, block_height: int) -> None:
        posts = self.data.setdefault("posts", {})
        post = posts.get(art_id)
        if not post:
            return
        stats = post.setdefault("stats", {})
        total = sum(int(v) for v in recipients.values())
        stats["pool_balance"] = max(0, int(stats.get("pool_balance", 0)) - total)
        payouts = self.data.setdefault("payouts", {})
        art_payouts = payouts.setdefault(art_id, [])
        art_payouts.append({
            "txid": txid,
            "block_height": int(block_height),
            "recipients": {addr: int(val) for addr, val in recipients.items()},
            "amount": int(total),
        })
        self._flush()

    def list_payouts(self, art_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        art_id = (art_id or "").strip().lower()
        payouts = (self.data.get("payouts") or {}).get(art_id, [])
        items = [dict(entry) for entry in payouts]
        items.sort(key=lambda r: int(r.get("block_height") or 0), reverse=True)
        if isinstance(limit, int) and limit > 0:
            return items[:limit]
        return items

    def list_posts(self, limit: int = 50) -> list[Dict[str, Any]]:
        posts = self.data.get("posts") or {}
        items: list[Dict[str, Any]] = []
        for art_id, entry in posts.items():
            try:
                rec = dict(entry)
                rec["art_id"] = art_id
                stats = rec.get("stats") or {}
                rec["stats"] = stats
                items.append(rec)
            except Exception:
                continue
        items.sort(key=lambda r: (int(r.get("block_height") or 0), int(r.get("ts") or 0)), reverse=True)
        if isinstance(limit, int) and limit > 0:
            return items[:limit]
        return items

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


__all__ = ["GraffitiRegistry"]
