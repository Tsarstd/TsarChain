# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import json
import time
from typing import List

from bech32 import convertbits, bech32_encode
from ...utils import config as CFG
from ...utils.helpers import decode_address
from ...utils.tsar_logging import get_ctx_logger
from .storage_registry import register_storage_peer

log = get_ctx_logger("tsarchain.network.node_logic.handlers")


def _handle_hello(self, message, addr, *, src_node_id: str | None = None, src_pubkey: str | None = None):
    peer_ip = addr[0] if isinstance(addr, tuple) and len(addr) > 0 else str(message.get("ip", "")).strip()
    peer_port = int(message.get("port", 0))
    peer_tuple = (peer_ip, peer_port) if peer_ip and isinstance(peer_port, int) and peer_port > 0 else None

    role = str(message.get("role", "")).strip().upper()
    now = time.time()
    advertised_height = int(message.get("height", -1))

    is_storage = role == "NODE_STORAGE"
    if is_storage:
        if not (src_node_id and src_pubkey):
            return {"error": "storage_auth_required"}
        
        payout_addr = (message.get("address") or "").strip().lower()
        if not payout_addr:
            return {"error": "storage_address_required"}
        
        try:
            decode_address(payout_addr)
        except Exception:
            return {"error": "storage_address_invalid"}
        
        # enforce pin consistency
        with self.lock:
            for _peer, meta in (getattr(self, "storage_peers", {}) or {}).items():
                if (meta or {}).get("node_id") == src_node_id:
                    pinned_pk = (meta or {}).get("pubkey")
                    if pinned_pk and pinned_pk != src_pubkey:
                        log.warning("[hello] storage pubkey change rejected nid=%s", src_node_id[:12])
                        return {"error": "storage_pubkey_pinned"}
        meta = {
            "addr": (message.get("address") or "").strip().lower(),
            "url": (message.get("url") or "").strip(),
            "ip": peer_ip,
            "port": int(peer_port or 0),
            "last_seen": int(now),
            "alive": True,
            "trusted": bool(message.get("trusted", False)),
            "node_id": src_node_id,
            "pubkey": src_pubkey,
        }
        register_storage_peer(self, peer_ip, meta)

    incoming_peers = message.get("peers") or []
    normalized_incoming = []
    for entry in incoming_peers:
        if isinstance(entry, dict):
            ip = str(entry.get("ip") or entry.get("host") or "").strip()
            port = int(entry.get("port", 0))
            if not ip or port <= 0:
                continue
            if self._is_local_address(ip) and port == self.port:
                continue
            normalized_incoming.append((ip, port))

    with self.lock:
        if (not is_storage) and peer_tuple and not (self._is_local_address(peer_tuple[0]) and peer_tuple[1] == self.port):
            self.peers.add(peer_tuple)
            self.peer_scores.setdefault(peer_tuple, CFG.PEER_SCORE_START)
            if advertised_height >= 0:
                self._peer_best_height[peer_tuple] = advertised_height

        if not is_storage:
            for cand in normalized_incoming:
                if cand == peer_tuple:
                    continue
                self.peers.add(cand)
                self.peer_scores.setdefault(cand, CFG.PEER_SCORE_START // 2)

        sane_peers = [{"ip": ip, "port": port} for ip, port in self.peers if isinstance(port, int) and port > 0]
        height = int(self.broadcast.blockchain.height)
        peer_port = int(message.get("port", -1))
        if (not is_storage) and isinstance(addr, tuple) and peer_port > 0:
            dst = (addr[0], peer_port)
            self.broadcast.send_mempool_to_peer(dst)

    if (not is_storage) and peer_tuple:
        self._reward_peer(peer_tuple)

    return {
        "type": "HELLO_RESPONSE",
        "port": self.port,
        "height": height,
        "peers": sane_peers,
    }


def _handle_get_headers(self, message, addr):
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()
    
    locator = message.get("locator") or []
    limit = int(message.get("limit", CFG.HEADERS_BATCH_MAX))
    limit = max(1, min(limit, CFG.HEADERS_BATCH_MAX))
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
    start_idx = 0
    if locator:
        known = {}
        for idx, blk in enumerate(chain):
            known[blk.hash().hex()] = idx

        for cand in locator:
            idx = known.get(str(cand))
            if idx is not None:
                start_idx = idx + 1
                break

    headers = []
    for blk in chain[start_idx : start_idx + limit]:
        prev_hash = (
            blk.prev_block_hash.hex()
            if isinstance(blk.prev_block_hash, (bytes, bytearray))
            else str(blk.prev_block_hash)
        )

        headers.append(
            {
                "height": getattr(blk, "height", start_idx),
                "hash": blk.hash().hex() if hasattr(blk, "hash") else getattr(blk, "hash", ""),
                "prev_hash": prev_hash,
                "timestamp": getattr(blk, "timestamp", 0),
                "bits": getattr(blk, "bits", 0),
            }
        )
    more = (start_idx + limit) < len(chain)
    
    if CFG.DEBUG_BENCHMARKS:
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        log.debug("[GET_HEADERS] Benchmark : %.3f ms", result)
        
    return {
        "type": "HEADERS",
        "headers": headers,
        "more": more,
        "best_height": max(-1, len(chain) - 1),
    }


def _handle_get_blocks(self, message, addr):
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()
        
    heights = message.get("heights") or []
    if not isinstance(heights, list):
        return {"type": "BLOCKS", "blocks": []}

    limit = min(len(heights), CFG.BLOCK_DOWNLOAD_BATCH_MAX)
    blocks: List[dict] = []
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)

    for raw_h in heights[:limit]:
        h = int(raw_h)
        if 0 <= h < len(chain):
            blocks.append(chain[h].to_dict())
            
    if CFG.DEBUG_BENCHMARKS:
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        log.debug("[GET_BLOCKS] Benchmark : %.3f ms", result)
        
    return {"type": "BLOCKS", "blocks": blocks}


def _handle_get_full_sync(self, message, addr):
    ip = addr[0] if isinstance(addr, tuple) and len(addr) > 0 else "unknown"
    now = time.time()
    min_iv = CFG.FULL_SYNC_MIN_INTERVAL
    last_served = self._full_sync_served_at.get(ip, 0.0)
    if now - last_served < min_iv:
        retry_after = max(30.0, min_iv - (now - last_served))
        return {"type": "SYNC_REJECT", "reason": "rate_limited", "retry_after": retry_after}

    self._full_sync_served_at[ip] = now
    blocks_available = max(0, self.broadcast.blockchain.height + 1)
    if blocks_available > CFG.FULL_SYNC_MAX_BLOCKS:
        return {
            "type": "SYNC_REDIRECT",
            "reason": "too_large_chain",
            "limit_blocks": CFG.FULL_SYNC_MAX_BLOCKS,
        }
    full_obj, _, _, _ = self.broadcast.build_full_sync_payload()
    enc = json.dumps(full_obj, separators=CFG.CANONICAL_SEP, ensure_ascii=False).encode("utf-8")

    hard_cap = CFG.MAX_MSG - len(CFG.NETWORK_MAGIC)
    if len(enc) > hard_cap:
        return {
            "type": "SYNC_REDIRECT",
            "reason": "payload_would_exceed_limit",
            "limit_bytes": hard_cap,
        }
    return full_obj


def _handle_full_sync(self, message, addr):
    now = time.time()
    if now - getattr(self, "_last_fullsync_log", 0.0) > 5.0:
        log.trace("[_handle_full_sync] Received full sync from %s:%s", addr[0], addr[1] if len(addr) > 1 else 0)
        self._last_fullsync_log = now

    payload = message.get("data", message)
    self.broadcast.receive_full_sync(payload)
    return {"status": "ok"}

def _handle_get_block_at(self, height: int, src_tag: str | None = None) -> dict:
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()
        
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
    if height < 0 or height >= len(chain):
        return {"type": "BLOCK", "error": "height_out_of_range"}

    b = chain[height]
    d = self._serialize_block(b)
    d["type"] = "BLOCK"
    
    if CFG.DEBUG_BENCHMARKS:
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        tag = src_tag or "-"
        log.debug("[GET_BLOCK] 'height' Benchmark : %.3f ms src=%s", result, tag)
        
    return d

def _handle_get_block_by_hash(self, hx: str, src_tag: str | None = None) -> dict:
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()
        
    hx = (hx or "").strip().lower()
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
    for b in chain:
        if self._bhash_hex(b).lower() == hx:
            d = self._serialize_block(b)
            d["type"] = "BLOCK"
            
            if CFG.DEBUG_BENCHMARKS:
                end = time.perf_counter()
                result = round((end - start) * 1000.0, 3)
                tag = src_tag or "-"
                log.debug("[GET_BLOCK] 'hash' Benchmark : %.3f ms src=%s", result, tag)
                
            return d
    return {"type": "BLOCK", "error": "not_found"}


__all__ = (
    "_handle_hello",
    "_handle_get_headers",
    "_handle_get_blocks",
    "_handle_get_full_sync",
    "_handle_full_sync",
    "_handle_get_block_at",
    "_handle_get_block_by_hash",
)
