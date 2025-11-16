import os
import time
from typing import Any, Dict

from ..storage.db import AtomicJSONFile
from ..utils import config as CFG


class GraffitiRegistry:
    def __init__(self) -> None:
        os.makedirs(os.path.dirname(CFG.GRAFFITI_FILE), exist_ok=True)
        self.store = AtomicJSONFile(CFG.GRAFFITI_FILE, keep_backups=2, checksum=True)
        self.data = self.store.load(default={"posts": {}, "comments": {}, "payouts": {}})

    def _flush(self) -> None:
        self.store.save(self.data)

    def record_post(self, art_id: str, meta: Dict[str, Any], txid: str, block_height: int, pool_addr: str, amount_paid: int) -> None:
        posts = self.data.setdefault("posts", {})
        entry = dict(meta)
        entry.update({
            "txid": txid,
            "block_height": int(block_height),
            "pool_address": pool_addr,
            "amount_paid": int(amount_paid),
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


__all__ = ["GraffitiRegistry"]
