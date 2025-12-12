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


def handle_miner_rpc(self: "Network", message: dict[str, Any], addr: Optional[tuple], mtype: str) -> dict | None:
    """Handle miner-to-miner RPC messages."""
    
#----------------------#-------------------

    ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"

    if mtype == "HELLO":
        return self._handle_hello(message, addr)

#----------------------#-------------------

    if mtype == "NEW_BLOCK":
        start = time.perf_counter() if CFG.DEBUG_BENCHMARKS else None

        rl_key = f"miner:new_block:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}

        self.broadcast.receive_block(message, addr, self.peers)
        
        if start is not None:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[NEW_BLOCK] Benchmark_total : %.3f ms", result)
        
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
            log.debug(
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
            log.debug("[GET_INFO] Benchmark : %.3f ms", result)
            
        return info

#----------------------#-------------------

    if mtype == "GET_FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"type": "SYNC_REDIRECT", "reason": "full_sync_disabled"}
        rl_key = f"miner:get_full_sync:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return self._handle_get_full_sync(message, addr)

#----------------------#-------------------

    if mtype == "GET_HEADERS":
        rl_key = f"miner:get_headers:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return self._handle_get_headers(message, addr)

#----------------------#-------------------

    if mtype == "GET_BLOCKS":
        rl_key = f"miner:get_blocks:{ip}"
        if not self._tb_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self._backoff(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return self._handle_get_blocks(message, addr)

#----------------------#-------------------

    if mtype == "FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"status": "ignored", "reason": "full_sync_disabled"}
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
            log.debug("[MEMPOOL] Benchmark : %.3f ms", result)
        
        return {"status": "mempool received"}
    return None
