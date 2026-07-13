# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

"""
Minimal Dandelion++ helper: manages stem forwarding, delayed fluffing, and
deduplication so integration can stay contained inside Broadcast/Gossip.
"""

from __future__ import annotations

import secrets
import threading
from typing import Dict, Optional, Set, Tuple

from ..utils import config as CFG

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.dandelion_pp")

_secure_random = secrets.SystemRandom()

class DandelionPP:
    def __init__(self, host) -> None:
        # host is Broadcast; relies on host._send and host.broadcast_tx_fluff
        self.host = host
        self.lock = threading.RLock()
        self._stem_seen: Set[str] = set()
        self._fluffed: Set[str] = set()
        self._timers: Dict[str, threading.Timer] = {}


    def enabled(self, peers_count: int) -> bool:
        min_peers = int(CFG.MIN_PEERS_FOR_DANDELION)
        return bool(CFG.ENABLE_DANDELION_PP) and peers_count >= max(0, min_peers)


    def handle_outbound(self, tx, tx_id: str, peers: Set[Tuple[str, int]], exclude=None) -> bool:
        """
        Handle locally-originated tx in stem phase.
        Returns True if Dandelion++ handled the send (so caller should skip normal broadcast).
        """
        if not self.enabled(len(peers)):
            return False

        peer = self._pick_peer(peers, exclude)
        if peer is None:
            return False

        if not self._mark_stem(tx_id):
            return False

        payload = tx.to_dict()
        sent = self._send_stem(peer, payload, tx_id)
        if not sent:
            # fallback to diffusion when first stem hop fails
            self.fluff(tx, tx_id, peers)
            return True
        self._schedule_fluff(tx, tx_id, peers)
        return True


    def handle_inbound_stem(
        self,
        tx,
        tx_id: str,
        peers: Set[Tuple[str, int]],
        origin: Optional[Tuple[str, int]] = None,
    ) -> bool:
        """
        Process inbound stem. Returns True when handled (caller should not run normal broadcast).
        """
        if not self.enabled(len(peers)):
            return False

        if not self._mark_stem(tx_id):
            return True  # already stemmed or fluffed; drop quietly

        payload = tx.to_dict()
        peer = self._pick_peer(peers, origin)
        if peer:
            if not self._send_stem(peer, payload, tx_id):
                self.fluff(tx, tx_id, peers)
        else:
            # no candidate -> fluff immediately
            self.fluff(tx, tx_id, peers)

        self._schedule_fluff(tx, tx_id, peers)
        log.debug("[handle_inbound_stem] inbound stem processed for %s", tx_id[:16])
        return True


    def fluff(self, tx, tx_id: str, peers: Set[Tuple[str, int]]):
        with self.lock:
            if tx_id in self._fluffed:
                return 0
            self._fluffed.add(tx_id)
            timer = self._timers.pop(tx_id, None)
            if timer:
                timer.cancel()
        return self.host.broadcast_tx_fluff(tx, tx_id, peers)


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _mark_stem(self, tx_id: str) -> bool:
        with self.lock:
            if tx_id in self._fluffed or tx_id in self._stem_seen:
                return False
            self._stem_seen.add(tx_id)
            log.debug("[_mark_stem] marked stem for %s", tx_id[:16])
            return True


    def _pick_peer(self, peers: Set[Tuple[str, int]], exclude: Optional[Tuple[str, int]]) -> Optional[Tuple[str, int]]:
        candidates = [p for p in peers if p and p != exclude]
        if not candidates:
            return None
        return _secure_random.choice(candidates)


    def _send_stem(self, peer: Tuple[str, int], payload: dict, tx_id: str) -> bool:
        msg = {"type": "NEW_TX", "data": payload, "phase": "stem"}
        ok = self.host._send(peer, msg)
        log.debug("[_send_stem] stem send to %s for %s returned %s", peer, tx_id[:16], ok)
        return bool(ok)


    def _schedule_fluff(self, tx, tx_id: str, peers: Set[Tuple[str, int]]) -> None:
        # Avoid multiple timers per tx
        with self.lock:
            if tx_id in self._timers or tx_id in self._fluffed:
                return

        delay = self._compute_fluff_delay()

        def _do_fluff():
            self.fluff(tx, tx_id, peers)

        timer = threading.Timer(delay, _do_fluff)
        timer.daemon = True
        with self.lock:
            # double-check before starting
            if tx_id in self._fluffed:
                return
            self._timers[tx_id] = timer
        log.debug("[_schedule_fluff] scheduled fluff in %.2f seconds for %s", delay, tx_id[:16])
        timer.start()


    def _compute_fluff_delay(self) -> float:
        # Keep deterministic-ish but jittered delay to reduce timing leaks
        base = max(CFG.MIN_FLUFF_DELAY_S, min(CFG.MAX_FLUFF_DELAY_S, float(CFG.SYNC_TIMEOUT or 2)))
        jitter = _secure_random.uniform(0.25, 0.75) * base
        log.debug("[_compute_fluff_delay] computed fluff delay: %.2f seconds", base + jitter)
        return max(0.5, min(CFG.MAX_FLUFF_DELAY_S, base + jitter))


__all__ = ["DandelionPP"]
