# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional, Tuple

from ...utils import config as CFG
from ...utils.tsar_logging import get_ctx_logger

log = get_ctx_logger("tsarchain.network.node_logic.sync")


def sync_loop(self):
    while not self._stop.is_set():
        try:
            window = CFG.FAST_SYNC_INTERVAL if time.time() < self._sync_fast_until else CFG.SYNC_INTERVAL
            self._sync_event.wait(timeout=max(1.0, float(window)))
            self._sync_event.clear()
            self.sync_with_peers()
        except Exception:
            log.exception("[sync_loop] Error during sync")


def request_sync(self, fast: bool = False) -> None:
    if fast:
        self._sync_fast_until = max(self._sync_fast_until, time.time() + CFG.FAST_SYNC_INTERVAL)
    self._sync_event.set()


def sync_with_peers(self):
    """
    Run a single round of sync: select outbound peers (plus high-ranking candidates),
    call _sync_peer for headers/blocks, then pull an inline/snapshot or full sync mempool if needed.
    """
    with self.lock:
        selected = [p for p in self.outbound_peers if p in self.peers]
        if len(selected) < CFG.MAX_OUTBOUND_PEERS:
            extras = sorted(
                (p for p in self.peers if p not in selected),
                key=lambda p: self.peer_scores.get(p, 0),
                reverse=True,
            )
            for peer in extras:
                if len(selected) >= CFG.MAX_OUTBOUND_PEERS:
                    break
                selected.append(peer)
    if not selected:
        try:
            log.info("[sync_with_peers] No peers available for sync round")
        except Exception:
            pass
        return

    now = time.time()
    if (len(selected) != getattr(self, "_last_sync_count", -1)) or (
        now - self._last_sync_log > float(CFG.SYNC_INFO_MIN_INTERVAL)
    ):
        try:
            log.info("[sync_with_peers] syncing %s peers", len(selected))
        except Exception:
            pass
        self._last_sync_count = len(selected)
        self._last_sync_log = now

    random.shuffle(selected)
    for peer in selected:
        norm = self._normalize_peer(peer)
        if not norm:
            continue
        try:
            synced = self._sync_peer(norm)

            allow_mempool = False
            try:
                allow_mempool = self.is_caught_up(freshness=20.0, height_slack=0)
            except Exception:
                allow_mempool = False

            pending_mempool_pull = bool(getattr(self, "_pending_mempool_pull", False))
            inline_status: Optional[bool] = None
            if allow_mempool:
                if pending_mempool_pull:
                    pulled = self._request_mempool_inline(norm, force=True)
                    if pulled is False or pulled is None:
                        pulled = self._request_mempool_snapshot(norm, force=True)
                    if pulled:
                        try:
                            self._pending_mempool_pull = False
                        except Exception:
                            pass
                inline_status = self._request_mempool_inline(norm)
                if inline_status is False:
                    retry_inline = self._request_mempool_inline(norm, force=True)
                    if retry_inline is True:
                        inline_status = True
                    elif retry_inline is not None:
                        inline_status = retry_inline

            if not synced:
                if CFG.ENABLE_FULL_SYNC:
                    self._request_full_sync(norm)
                elif allow_mempool and inline_status is False:
                    if norm not in self._snapshot_unreachable:
                        self._request_mempool_snapshot(norm)
                        
            elif allow_mempool and inline_status is False:
                if norm not in self._snapshot_unreachable:
                    self._request_mempool_snapshot(norm)
        except Exception:
            log.exception("[sync_with_peers] Error syncing with peer %s", norm)
            self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY * 2)


def _sync_peer(self, peer: Tuple[str, int]) -> bool:
    """
    Single-peer sync: respect intervals, request headers, calculate lost/reorg blocks,
    download and apply blocks, set backoff on rejection, and reward/penalty for peers.
    Returns True if up-to-date or a new block is applied.
    """
    now = time.time()
    min_iv = 0.0 if now < getattr(self, "_sync_fast_until", 0.0) else float(CFG.HEADERS_SYNC_MIN_INTERVAL)
    if now - self._peer_last_sync.get(peer, 0.0) < min_iv:
        return False

    locator = self._build_locator()
    headers_resp = self._request_headers(peer, locator)
    if not headers_resp:
        self._penalize_peer(peer, CFG.PEER_SCORE_FAILURE_PENALTY)
        return False

    if headers_resp.get("type") == "SYNC_REJECT":
        retry = float(headers_resp.get("retry_after", CFG.FULL_SYNC_BACKOFF_INITIAL))
        self._full_sync_backoff[peer] = now + min(retry, CFG.FULL_SYNC_BACKOFF_MAX)
        try:
            log.info("[_sync_peer] %s rejected header request (retry in %.1fs)", peer, min(retry, CFG.FULL_SYNC_BACKOFF_MAX))
        except Exception:
            pass
        return False

    headers = headers_resp.get("headers") or []
    if not headers:
        self._peer_last_sync[peer] = now
        self._reward_peer(peer)
        return True

    missing = self._determine_missing_blocks(headers)
    if not missing:
        self._peer_last_sync[peer] = now
        self._reward_peer(peer)
        return True

    downloaded_count, download_elapsed = self._download_blocks(peer, missing)
    if downloaded_count > 0:
        self._peer_last_sync[peer] = time.time()
        self._reward_peer(peer, CFG.PEER_SCORE_REWARD * 2)
        try:
            log.info("[_sync_peer] Applied %d blocks from %s in %.2fs", downloaded_count, peer, download_elapsed)
        except Exception:
            pass
        if headers_resp.get("more"):
            self.request_sync(fast=True)
        return True
    try:
        log.info("[_sync_peer] Failed to apply blocks from %s (elapsed=%.2fs)", peer, download_elapsed)
    except Exception:
        pass

    return False


def _build_locator(self) -> List[str]:
    """
    Build a block locator for request headers: take the block hash from the end of the chain in exponential steps (up to the depth),
    then ensure ZERO_HASH is also listed as the lowest anchor.
    """
    locator: List[str] = []
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
    if not chain:
        locator.append(CFG.ZERO_HASH.hex())
        return locator
    idx = len(chain) - 1
    step = 1
    while idx >= 0 and len(locator) < CFG.HEADERS_LOCATOR_DEPTH:
        try:
            locator.append(chain[idx].hash().hex())
        except Exception:
            break
        if len(locator) >= 10:
            step *= 2
        idx -= step
    zero_hex = CFG.ZERO_HASH.hex()
    if zero_hex not in locator:
        locator.append(zero_hex)
    return locator


def _request_headers(self, peer: Tuple[str, int], locator: List[str]) -> Optional[dict]:
    payload = {
        "type": "GET_HEADERS",
        "locator": locator[: CFG.HEADERS_LOCATOR_DEPTH],
        "limit": int(CFG.HEADERS_BATCH_MAX),
        "port": self.port,
    }
    return self._rpc_request(peer, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))


def _determine_missing_blocks(self, headers: List[dict]) -> List[int]:
    """
    Calculate the height of missing blocks or reorgs: compare the remote header
    with the local chain, record mismatches as reorg points,
    and return a unique list of heights to be downloaded (sorted).
    """
    missing: List[int] = []
    reorg_point: Optional[int] = None
    max_remote_height = -1
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
    for header in headers:
        try:
            height = int(header.get("height", -1))
        except Exception:
            continue
        blk_hash = header.get("hash")
        if height < 0 or not isinstance(blk_hash, str):
            continue
        max_remote_height = max(max_remote_height, height)
        if height < len(chain):
            try:
                local_hash = chain[height].hash().hex()
            except Exception:
                local_hash = ""
            if local_hash != blk_hash:
                reorg_point = height if reorg_point is None else min(reorg_point, height)
        else:
            missing.append(height)
    if reorg_point is not None:
        start = max(0, reorg_point)
        end = max(max_remote_height, len(chain) - 1)
        missing.extend(range(start, end + 1))
    return sorted(set(missing))


def _download_blocks(self, peer: Tuple[str, int], heights: List[int]) -> Tuple[int, float]:
    start_time = time.time()
    if not heights:
        return 0, 0.0

    unique_heights = sorted({int(h) for h in heights if isinstance(h, int)})
    if not unique_heights:
        return 0, 0.0

    batch_size = max(1, int(CFG.BLOCK_DOWNLOAD_BATCH_MAX))
    total_applied = 0
    total_attempted = len(unique_heights)
    total_chunks = (total_attempted + batch_size - 1) // batch_size
    for idx in range(0, len(unique_heights), batch_size):
        chunk = unique_heights[idx : idx + batch_size]
        chunk_start = time.time()
        try:
            log.info(
                "[_download_blocks.chunk] requesting %d blocks (%s-%s) from %s",
                len(chunk),
                chunk[0],
                chunk[-1],
                peer,
            )
        except Exception:
            pass
        payload = {"type": "GET_BLOCKS", "heights": chunk, "port": self.port}
        resp = self._rpc_request(peer, payload, timeout=max(15.0, CFG.SYNC_TIMEOUT))
        if not resp:
            try:
                log.info(
                    "[_download_blocks] %s no response for chunk %d/%d (heights %s-%s)",
                    peer,
                    (idx // batch_size) + 1,
                    total_chunks,
                    chunk[0],
                    chunk[-1],
                )
            except Exception:
                pass
            break

        if resp.get("type") == "BLOCKS":
            blocks = resp.get("blocks") or []
            try:
                log.info(
                    "[_download_blocks.chunk] received %d blocks from %s in %.2fs",
                    len(blocks),
                    peer,
                    time.time() - chunk_start,
                )
            except Exception:
                pass
            applied_in_chunk = 0
            for block_obj in blocks:
                try:
                    applied = self._apply_block_from_sync(block_obj, peer)
                except Exception:
                    log.exception("[_download_blocks] Failed applying block from %s", peer)
                    return total_applied, time.time() - start_time
                if applied:
                    total_applied += 1
                    applied_in_chunk += 1
                else:
                    blk_hash = None
                    try:
                        blk_hash = block_obj.get("hash")
                    except Exception:
                        blk_hash = None
                    try:
                        label = str(blk_hash or "unknown")
                        log.warning("[_download_blocks] Block %s rejected during sync from %s", label[:12], peer)
                    except Exception:
                        pass
                    return total_applied, time.time() - start_time
            try:
                log.info(
                    "[_download_blocks] %s chunk %d/%d applied %d/%d blocks in %.2fs (heights %s-%s)",
                    peer,
                    (idx // batch_size) + 1,
                    total_chunks,
                    applied_in_chunk,
                    len(blocks),
                    time.time() - chunk_start,
                    chunk[0],
                    chunk[-1],
                )
            except Exception:
                pass

        elif resp.get("type") == "SYNC_REJECT":
            retry = float(resp.get("retry_after", CFG.FULL_SYNC_BACKOFF_INITIAL))
            self._full_sync_backoff[peer] = time.time() + min(retry, CFG.FULL_SYNC_BACKOFF_MAX)
            try:
                log.info(
                    "[_download_blocks] %s asked to retry later (retry %.1fs)",
                    peer,
                    min(retry, CFG.FULL_SYNC_BACKOFF_MAX),
                )
            except Exception:
                pass
            break
        else:
            try:
                log.info("[_download_blocks] %s returned unexpected type=%s", peer, resp.get("type"))
            except Exception:
                pass
            break

    elapsed = time.time() - start_time
    try:
        log.info("[_download_blocks] %s total applied %d/%d blocks in %.2fs", peer, total_applied, total_attempted, elapsed)
    except Exception:
        pass
    return total_applied, elapsed


def _apply_block_from_sync(self, block_obj: Dict[str, Any], peer: Tuple[str, int]) -> bool:
    message = {
        "type": "NEW_BLOCK",
        "data": block_obj,
        "port": peer[1],
    }
    return bool(self.broadcast.receive_block(message, peer, self.peers))


def handle_block_gap(self, block, origin: Optional[Tuple[str, int]]) -> None:
    peer = self._normalize_peer(origin)
    self.request_sync(fast=True)
    if not peer:
        return

    now = time.time()
    last = self._recent_gap_requests.get(peer, 0.0)
    if now - last < float(CFG.HEADERS_SYNC_MIN_INTERVAL):
        return

    self._recent_gap_requests[peer] = now
    try:
        height = int(getattr(block, "height", 0))
    except Exception:
        height = 0

    span = max(1, int(CFG.HEADERS_FANOUT) // 2)
    missing = list(range(max(0, height - span), height + 1))
    self._download_blocks(peer, missing)


def is_caught_up(self, freshness: float = 10.0, height_slack: int = 0) -> bool:
    """
    Check if the node is sufficiently synchronized: it needs a recent peer sync (freshness)
    and the local block height difference to the best peer <= slack.
    """
    now = time.time()
    freshness = max(0.0, float(freshness))
    slack = max(0, int(height_slack))
    with self.lock:
        if not self._peer_last_sync:
            return False
        recent = any(now - ts <= freshness for ts in self._peer_last_sync.values())
        if not recent:
            return False
        candidates = [h for h in self._peer_best_height.values() if isinstance(h, int) and h >= 0]
        if not candidates:
            return False
        best_remote = max(candidates)
    local_height = int(self.broadcast.blockchain.height)
    return (best_remote - local_height) <= slack


def get_best_peer_height(self) -> int:
    with self.lock:
        candidates = [h for h in self._peer_best_height.values() if isinstance(h, int) and h >= 0]
    return max(candidates) if candidates else -1


__all__ = (
    "sync_loop",
    "request_sync",
    "sync_with_peers",
    "_sync_peer",
    "_build_locator",
    "_request_headers",
    "_determine_missing_blocks",
    "_download_blocks",
    "_apply_block_from_sync",
    "handle_block_gap",
    "is_caught_up",
    "get_best_peer_height",
)
