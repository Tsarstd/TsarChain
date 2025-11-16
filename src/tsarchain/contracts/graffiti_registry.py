import os
from typing import Any, Dict

from ..storage.db import AtomicJSONFile
from ..utils import config as CFG


class GraffitiRegistry:
    def __init__(self) -> None:
        os.makedirs(os.path.dirname(CFG.GRAFFITI_FILE), exist_ok=True)
        self.store = AtomicJSONFile(CFG.GRAFFITI_FILE, keep_backups=2, checksum=True)
        self.data = self.store.load(default={"posts": {}})

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
        posts[art_id] = entry
        self._flush()

    def get_post(self, art_id: str) -> Dict[str, Any] | None:
        return (self.data.get("posts") or {}).get(art_id)


__all__ = ["GraffitiRegistry"]
