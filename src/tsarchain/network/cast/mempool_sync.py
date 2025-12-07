# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import json
import time
from typing import Tuple

from ...utils import config as CFG
from ...utils.tsar_logging import get_ctx_logger

log = get_ctx_logger("tsarchain.network.cast.fullsync")


class MempoolSyncMixin:
    def _mempool_chunks(self, max_bytes: int) -> list[list[dict]]:
        try:
            txs = self.mempool.get_all_txs() or []
        except Exception:
            txs = []
        chunks, cur = [], []
        base = {"type": "MEMPOOL", "data": []}
        for tx in txs:
            try:
                d = tx.to_dict() if hasattr(tx, "to_dict") else tx
            except Exception:
                log.exception("txc_dict_err")
                continue

            test = dict(base)
            test["data"] = cur + [d]
            try:
                enc = json.dumps(self._encode(test), separators=CFG.CANONICAL_SEP).encode("utf-8")
            except Exception:
                log.exception("enc_err")
                continue

            hard_cap = max(1024, CFG.MAX_MSG) - len(CFG.NETWORK_MAGIC)
            if len(enc) > hard_cap and cur:
                chunks.append(cur)
                cur = [d]
            else:
                cur.append(d)
        if cur:
            chunks.append(cur)
        return chunks

    def send_mempool_to_peer(
        self,
        peer: Tuple[str, int],
        *,
        min_interval_s: float | None = None,
        force: bool = False,
    ) -> int:
        
        if not hasattr(self, "_last_mempool_push"):
            self._last_mempool_push = {}
        ttl = float(CFG.MEMPOOL_SYNC_MIN_INTERVAL) if min_interval_s is None else max(0.0, float(min_interval_s))
        now = time.time()
        last = float(self._last_mempool_push.get(peer, 0.0))
        if not force and now - last < ttl:
            return 0

        current_seq = getattr(self.mempool, "change_seq", None)
        if not force and current_seq is not None:
            last_seq = self._last_mempool_seq.get(peer)
            if last_seq is not None and last_seq == current_seq:
                return 0

        sent = 0
        hard_cap = max(1024, CFG.MAX_MSG) - len(CFG.NETWORK_MAGIC)
        for chunk in self._mempool_chunks(hard_cap):
            if not chunk:
                continue
            ok = self._send(
                peer,
                {
                    "type": "MEMPOOL",
                    "data": chunk,
                    "port": getattr(self, "port", 0),
                },
            )
            if ok:
                sent += len(chunk)
        self._last_mempool_push[peer] = now
        if current_seq is not None and sent >= 0:
            self._last_mempool_seq[peer] = current_seq
        return sent


__all__ = ["MempoolSyncMixin"]
