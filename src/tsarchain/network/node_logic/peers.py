# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

from ...utils import config as CFG
from typing import Any, Optional, Set, Tuple, TYPE_CHECKING

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node_logic.peers")

if TYPE_CHECKING:
    from ...core.block import Block


def normalize_peer(_, peer: Any) -> Optional[Tuple[str, int]]:
    if not peer:
        return None
    if isinstance(peer, tuple) and len(peer) == 2:
        return (str(peer[0]), int(peer[1]))
    if isinstance(peer, list) and len(peer) == 2:
        return (str(peer[0]), int(peer[1]))
    return None


def penalize_peer(self, peer: Any, amount: int) -> None:
    norm = self.normalize_peer(peer)
    if norm is None:
        return
    delta = max(1, int(amount))
    with self.lock:
        score = self.peer_scores.get(norm, CFG.PEER_SCORE_START) - delta
        self.peer_scores[norm] = score
        if score <= CFG.PEER_SCORE_MIN:
            self.peers.discard(norm)
            self.outbound_peers.discard(norm)
            self._peer_best_height.pop(norm, None)
            self._peer_last_sync.pop(norm, None)
            self._peer_last_mempool_sync.pop(norm, None)


def reward_peer(self, peer: Any, amount: int = CFG.PEER_SCORE_REWARD) -> None:
    norm = self.normalize_peer(peer)
    if norm is None:
        return
    delta = max(0, int(amount))
    with self.lock:
        score = self.peer_scores.get(norm, CFG.PEER_SCORE_START) + delta
        self.peer_scores[norm] = min(score, CFG.PEER_SCORE_START * 5)
        self.peers.add(norm)
        if len(self.outbound_peers) < CFG.MAX_OUTBOUND_PEERS or norm in self.outbound_peers:
            self.outbound_peers.add(norm)


def publish_block(self, block: "Block", exclude: Optional[Tuple[str, int]] = None, force: bool = True) -> int:
    peers = _collect_broadcast_peers(self)
    if not peers:
        return 0
    return self.broadcast.broadcast_block(block, peers, exclude=exclude, force=force)


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _collect_broadcast_peers(self) -> Set[Tuple[str, int]]:
    with self.lock:
        targets: Set[Tuple[str, int]] = set(self.outbound_peers)
        targets.update(self.inbound_peers)
        if not targets:
            targets.update(self.peers)
    return targets
