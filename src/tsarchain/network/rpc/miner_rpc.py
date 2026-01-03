# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import time
from typing import TYPE_CHECKING, Any, Optional

from ...utils import config as CFG

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.miner_rpc")

if TYPE_CHECKING:
    from ..node import Network

__all__ = ["handle_miner_rpc"]


def handle_miner_rpc(
    self: "Network",
    message: dict[str, Any],
    addr: Optional[tuple],
    mtype: str,
    *,
    src_node_id: Optional[str] = None,
    src_pubkey: Optional[str] = None,
) -> dict | None:
    """Handle miner-to-miner RPC messages."""
    
#----------------------#-------------------

    ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"

    if mtype == "HELLO":
        return self._handle_hello(message, addr, src_node_id=src_node_id, src_pubkey=src_pubkey)

#----------------------#-------------------

    if mtype == "NEW_BLOCK":
        start = time.perf_counter() if CFG.DEBUG_BENCHMARKS else None

        rl_key = f"miner:new_block:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_NEWBLOCK_RL_IP_BURST, CFG.MINER_NEWBLOCK_RL_WINDOW_S, CFG.MINER_NEWBLOCK_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_NEWBLOCK_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        self.broadcast.receive_block(message, addr, self.peers)
        
        if start is not None:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 500.0:
                log.warning("[NEW_BLOCK] Benchmark_total : %.3f ms", result)
        
        return {"status": "ok"}
    
#----------------------#-------------------
    
    if mtype == "GET_BLOCK_HASH":
        start = time.perf_counter() if CFG.DEBUG_BENCHMARKS else None

        rl_key = f"miner:get_block_hash:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_INFO_RL_IP_BURST, CFG.MINER_INFO_RL_WINDOW_S, CFG.MINER_INFO_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_INFO_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        h = int(message.get("height"))
        resp = self._handle_get_block_hash(h)
        
        if start is not None:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 15.0:
                log.warning(
                    "[GET_BLOCK_HASH] Benchmark : %.3f ms cache_hit=%s",
                    result,
                    resp.get("cache_hit") if isinstance(resp, dict) else None,
                )
            
        return resp
    
#----------------------#-------------------
    
    if mtype == "GET_INFO":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()

        rl_key = f"miner:get_info:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_INFO_RL_IP_BURST, CFG.MINER_INFO_RL_WINDOW_S, CFG.MINER_INFO_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_INFO_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        info = {
            "type": "INFO",
            "height": self.broadcast.blockchain.height,
            "blocks": len(self.broadcast.blockchain.chain),
            "mempool": len(self.broadcast.mempool.get_all_txs()),
            "utxos": len(self.broadcast.utxodb.utxos),
        }
        with self.lock:
            peers_sane = [(ip,p) for (ip,p) in self.peers if isinstance(p,int) and p>0]
        info["peers"] = len(peers_sane)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 15.0:
                log.warning("[GET_INFO] Benchmark : %.3f ms", result)
            
        return info

#----------------------#-------------------

    if mtype == "GET_FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"type": "SYNC_REDIRECT", "reason": "full_sync_disabled"}
        ts_val = int(message.get("ts", 0))
        nonce_val = str(message.get("nonce") or "")
        sender_key = src_node_id or ip
        if not (ts_val and nonce_val and self._nonce_guard("full_sync_req", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
            return {"type": "SYNC_REDIRECT", "reason": "replay_guard"}
        rl_key = f"miner:get_full_sync:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return self._handle_get_full_sync(message, addr)

#----------------------#-------------------

    if mtype == "GET_HEADERS":
        rl_key = f"miner:get_headers:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_HEADERS_RL_IP_BURST, CFG.MINER_HEADERS_RL_WINDOW_S, CFG.MINER_HEADERS_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_HEADERS_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return self._handle_get_headers(message, addr)

#----------------------#-------------------

    if mtype == "GET_BLOCKS":
        rl_key = f"miner:get_blocks:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_BLOCKS_RL_IP_BURST, CFG.MINER_BLOCKS_RL_WINDOW_S, CFG.MINER_BLOCKS_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_BLOCKS_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return self._handle_get_blocks(message, addr)

#----------------------#-------------------

    if mtype == "FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"status": "ignored", "reason": "full_sync_disabled"}
        ts_val = int(message.get("ts", 0))
        nonce_val = str(message.get("nonce") or "")
        sender_key = src_node_id or ip
        if not (ts_val and nonce_val and self._nonce_guard("full_sync", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
            log.warning("[FULL_SYNC] replay guard reject from %s", addr)
            return {"error": "replay_guard"}
        rl_key = f"miner:full_sync:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return self._handle_full_sync(message, addr)

#----------------------#-------------------

    if mtype == "CHAIN":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()

        rl_key = f"miner:chain:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        if self._validate_incoming_chain(message):
            if CFG.DEBUG_BENCHMARKS:
                end = time.perf_counter()
                result = round((end - start) * 1000.0, 3)
                log.debug("[CHAIN] Benchmark : %.3f ms", result)
                
            return {"status": "ok"}
        return None

#----------------------#-------------------

    if mtype == "MEMPOOL":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()

        rl_key = f"miner:mempool:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_MEMPOOL_RL_IP_BURST, CFG.MINER_MEMPOOL_RL_WINDOW_S, CFG.MINER_MEMPOOL_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_MEMPOOL_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        self.broadcast.receive_mempool(message)
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            if result > 15.0:
                log.warning("[MEMPOOL] Benchmark : %.3f ms", result)
        
        return {"status": "mempool received"}
    return None
