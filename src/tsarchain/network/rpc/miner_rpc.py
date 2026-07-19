# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md

from typing import TYPE_CHECKING, Any, Optional

from ..node_logic import handlers
from ...utils import config as CFG
from ...utils.benchmarks import benchmark

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.miner_rpc")

if TYPE_CHECKING:
    from ..node import Network


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
        return handlers.handle_hello(self, message, addr, src_node_id=src_node_id, src_pubkey=src_pubkey)

#----------------------#-------------------

    if mtype == "NEW_BLOCK":
        return _handle_miner_new_block(self, message, addr, ip)
    
#----------------------#-------------------
    
    if mtype == "GET_BLOCK_HASH":
        return _handle_miner_get_block_hash(self, message, ip)
    
#----------------------#-------------------
    
    if mtype == "GET_INFO":
        return _handle_miner_get_info(self, ip)

#----------------------#-------------------

    if mtype == "GET_FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"type": "SYNC_REDIRECT", "reason": "full_sync_disabled"}
        ts_val = int(message.get("ts", 0))
        nonce_val = str(message.get("nonce") or "")
        sender_key = src_node_id or ip
        if not (ts_val and nonce_val and self.nonce_guard("full_sync_req", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
            return {"type": "SYNC_REDIRECT", "reason": "replay_guard"}
        rl_key = f"miner:get_full_sync:{ip}"
        if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self.backoff_node(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return handlers.handle_get_full_sync(self, message, addr)

#----------------------#-------------------

    if mtype == "GET_HEADERS":
        rl_key = f"miner:get_headers:{ip}"
        if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_HEADERS_RL_IP_BURST, CFG.MINER_HEADERS_RL_WINDOW_S, CFG.MINER_HEADERS_RL_IP_BURST, backoff_key=rl_key):
            self.backoff_node(rl_key, CFG.MINER_HEADERS_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return handlers.handle_get_headers(self, message, addr)

#----------------------#-------------------

    if mtype == "GET_BLOCKS":
        rl_key = f"miner:get_blocks:{ip}"
        if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_BLOCKS_RL_IP_BURST, CFG.MINER_BLOCKS_RL_WINDOW_S, CFG.MINER_BLOCKS_RL_IP_BURST, backoff_key=rl_key):
            self.backoff_node(rl_key, CFG.MINER_BLOCKS_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return handlers.handle_get_blocks(self, message, addr)

#----------------------#-------------------

    if mtype == "FULL_SYNC":
        if not CFG.ENABLE_FULL_SYNC:
            return {"status": "ignored", "reason": "full_sync_disabled"}
        ts_val = int(message.get("ts", 0))
        nonce_val = str(message.get("nonce") or "")
        sender_key = src_node_id or ip
        if not (ts_val and nonce_val and self.nonce_guard("full_sync", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
            log.warning("[FULL_SYNC] replay guard reject from %s", addr)
            return {"error": "replay_guard"}
        rl_key = f"miner:full_sync:{ip}"
        if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_SYNC_RL_IP_BURST, CFG.MINER_SYNC_RL_WINDOW_S, CFG.MINER_SYNC_RL_IP_BURST, backoff_key=rl_key):
            self.backoff_node(rl_key, CFG.MINER_SYNC_RL_BACKOFF_S)
            return {"error": "rate_limited"}
        return handlers.handle_full_sync(self, message, addr)

#----------------------#-------------------

    if mtype == "MEMPOOL":
        return _handle_miner_mempool(self, message, ip)
    return None


# =============================================================================
# INTERNAL METHOD
# =============================================================================


@benchmark(label="miner_new_block", threshold_ms=500.0)
def _handle_miner_new_block(self, message, addr, ip):
    rl_key = f"miner:new_block:{ip}"
    if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_NEWBLOCK_RL_IP_BURST, CFG.MINER_NEWBLOCK_RL_WINDOW_S, CFG.MINER_NEWBLOCK_RL_IP_BURST, backoff_key=rl_key):
        self.backoff_node(rl_key, CFG.MINER_NEWBLOCK_RL_BACKOFF_S)
        return {"error": "rate_limited"}

    self.broadcast.receive_block(message, addr, self.peers)
    return {"status": "ok"}


@benchmark(label="miner_get_block_hash", threshold_ms=15.0)
def _handle_miner_get_block_hash(self, message, ip):
    rl_key = f"miner:get_block_hash:{ip}"
    if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_INFO_RL_IP_BURST, CFG.MINER_INFO_RL_WINDOW_S, CFG.MINER_INFO_RL_IP_BURST, backoff_key=rl_key):
        self.backoff_node(rl_key, CFG.MINER_INFO_RL_BACKOFF_S)
        return {"error": "rate_limited"}

    h = int(message.get("height"))
    return self.handle_get_block_hash(h)


@benchmark(label="miner_get_info", threshold_ms=15.0)
def _handle_miner_get_info(self, ip):
    rl_key = f"miner:get_info:{ip}"
    if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_INFO_RL_IP_BURST, CFG.MINER_INFO_RL_WINDOW_S, CFG.MINER_INFO_RL_IP_BURST, backoff_key=rl_key):
        self.backoff_node(rl_key, CFG.MINER_INFO_RL_BACKOFF_S)
        return {"error": "rate_limited"}

    info = {
        "type": "INFO",
        "height": self.broadcast.blockchain.height,
        "blocks": len(self.broadcast.blockchain.chain),
        "mempool": len(self.broadcast.mempool.get_all_txs()),
        "utxos": len(self.broadcast.utxodb.utxos),
    }
    with self.lock:
        peers_sane = [(ip_addr,p) for (ip_addr,p) in self.peers if isinstance(p,int) and p>0]
    info["peers"] = len(peers_sane)
    return info


@benchmark(label="miner_mempool", threshold_ms=15.0)
def _handle_miner_mempool(self, message, ip):
    rl_key = f"miner:mempool:{ip}"
    if not self.tb_node_allow(self.rl_ip, rl_key, CFG.MINER_MEMPOOL_RL_IP_BURST, CFG.MINER_MEMPOOL_RL_WINDOW_S, CFG.MINER_MEMPOOL_RL_IP_BURST, backoff_key=rl_key):
        self.backoff_node(rl_key, CFG.MINER_MEMPOOL_RL_BACKOFF_S)
        return {"error": "rate_limited"}

    self.broadcast.receive_mempool(message)
    return {"status": "mempool received"}