# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: Signal-X3DH; RFC7748-X25519

import random
from typing import TYPE_CHECKING, Any, Optional

# ---------------- Local Project ----------------
from .miner_rpc import handle_miner_rpc
from .storage_rpc import handle_storage_rpc
from .user_rpc import handle_user_rpc
from ...contracts import graffiti as GRAFFITI
from ...utils import config as CFG
from ..node_logic.ratelimit import ban_ip

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.processing_msg")


if TYPE_CHECKING:
    from ..node import Network

__all__ = ["process_message"]

# --------------------------------------------------------------------------
# RPC REGISTRY (role → allowed message types)
# --------------------------------------------------------------------------
MINER_RPC_TYPES = {
        "HELLO", "GET_INFO", "NEW_BLOCK", "GET_FULL_SYNC", "FULL_SYNC",
        "CHAIN", "MEMPOOL", "GET_HEADERS", "GET_BLOCKS", "GET_BLOCK_HASH"
}

STORAGE_RPC_TYPES = {
    "GRAFFITI_PROOF_SUBMIT", "GRAFFITI_BUILD_PAYOUT"
}

USER_RPC_TYPES = {
        "PING", "GET_BALANCES", "CREATE_TX", "GET_TX_HISTORY", "GET_TX_DETAIL", "NEW_TX", 
        "GET_UTXOS", "GET_PEERS", "GET_NETWORK_INFO", "GET_BLOCK", "GET_BLOCK_RANGE", "STOR_LIST",
        # Graffiti
        "CREATE_TX_MULTI", "GRAFFITI_GET_POSTS","GRAFFITI_GET_COMMENTS", "GRAFFITI_GET_ART",
        "GRAFFITI_GET_PAYOUTS",
        # Chat & storage listing
        "CHAT_REGISTER", "CHAT_LOOKUP_PUB", "CHAT_PRESENCE", "CHAT_SEND", "CHAT_PULL", "CHAT_RELAY",
        "CHAT_READ", "CHAT_GET_PREKEY", "CHAT_PUBLISH_PREKEYS", "CHAT_RCPT",
        # Mempool utilities
        "GET_MEMPOOL"
}

ROLE_RPC_MAP = {
    "MINER": MINER_RPC_TYPES,
    "STORAGE": STORAGE_RPC_TYPES,
    "USER": USER_RPC_TYPES
}

BOOTSTRAP_MINER_ALLOW = {
    "HELLO", "GET_FULL_SYNC", "FULL_SYNC", "GET_HEADERS"
}


def process_message(
    self: "Network",
    message: dict[str, Any],
    addr: Optional[tuple]=None,
    *,
    src_node_id: Optional[str] = None,
    src_pubkey: Optional[str] = None,
) -> dict | None:
    if not isinstance(message, dict):
        return {"error": "invalid message: expected JSON object"}

    mtype = message.get("type")
    if not isinstance(mtype, str):
        return {"error": "missing or invalid 'type'"}
    mtype = mtype.strip().upper()

    # ----------------------------------------------------------------------------------
    # GUARDIANS: role-based gate + limits
    # ----------------------------------------------------------------------------------

    def _sanitize_rpc_source(val: Any) -> str | None:
        if val is None:
            return None
        txt = str(val).strip().lower()
        if not txt:
            return None
        allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
        cleaned = "".join([c for c in txt if c in allowed])
        if not cleaned:
            return None
        if len(cleaned) > 32:
            cleaned = cleaned[:32]
        return cleaned

    def _is_storage_node_id(node_id: str | None) -> bool:
        if not node_id:
            return False
        try:
            peers = getattr(self, "storage_peers", None) or {}
        except Exception:
            return False
        for meta in peers.values():
            if isinstance(meta, dict) and meta.get("node_id") == node_id:
                return True
        return False

    def _is_miner_sender() -> bool:
        if not src_node_id:
            return False
        pinned = self.peer_pubkeys.get(src_node_id)
        if not pinned:
            return False
        if src_pubkey and pinned != src_pubkey:
            log.warning("[miner_auth] pinned mismatch for %s from %s", src_node_id[:12], addr)
            return False
        return True

    def _identify_rpc_role(mtype: str) -> tuple[str, str]:
        for role, allowed in ROLE_RPC_MAP.items():
            if mtype in allowed:
                category = f"{role}-AUTHORIZED" if (role == "MINER" and _is_miner_sender()) else role
                return role, category
        return "UNKNOWN", "UNKNOWN"

    def _client_ip() -> str:
        if isinstance(addr, tuple) and addr:
            return addr[0]
        return "0.0.0.0"

    role, category = _identify_rpc_role(mtype)
    raw_source = message.get("rpc_source") or message.get("source") or message.get("client")
    rpc_source = _sanitize_rpc_source(raw_source)
    if not rpc_source and _is_storage_node_id(src_node_id):
        rpc_source = "storage_node"
    if not rpc_source:
        if role == "MINER":
            rpc_source = "miner"
        elif role == "STORAGE":
            rpc_source = "storage"
        else:
            rpc_source = "user"
    message["rpc_source"] = rpc_source

    if role == "UNKNOWN":
        ip = _client_ip()
        ban_ip(ip, (CFG.BAN_MALICIOUS_RPC))
        log.warning("[process_message] unknown RPC %s from %s (temp-ban)", mtype, addr)
        return {"error": "unknown type", "drop": True}

    if (role == "MINER") and (mtype not in BOOTSTRAP_MINER_ALLOW) and (not _is_miner_sender()):
        ip = _client_ip()
        ban_ip(ip, (CFG.BAN_MALICIOUS_RPC))
        log.warning("[process_message] rejecting unauthorized miner: RPC %s from %s category %s (temp-ban)", mtype, addr, category)
        return {"error": "forbidden: miners-only endpoint", "drop": True}

    if role == "MINER":
        #log.debug("[process_message] %s response: msg: %s category: %s", role, mtype, category)
        return handle_miner_rpc(self, message, addr, mtype, src_node_id=src_node_id, src_pubkey=src_pubkey)
    
    if role == "STORAGE":
        #log.debug("[process_message] %s response: msg: %s", role, mtype)
        return handle_storage_rpc(self, message, addr, mtype, src_node_id=src_node_id, src_pubkey=src_pubkey)

    dispatch_result = handle_user_rpc(
        self,
        message,
        addr,
        mtype,
        client_ip=_client_ip,
        is_miner_sender=_is_miner_sender,
        overlay_realtime_mempool_stats=_overlay_realtime_mempool_stats,
        choose_relay_route=_choose_relay_route,
        relay_chain=_relay_chain,
        send_chat_relay=_send_chat_relay,
    )

    if dispatch_result is not None:
        #log.debug("[process_message] %s response: msg: %s", role, mtype)
        return dispatch_result
    
    return {"error": "Unknown message type"}


# -------- HELPERS ----------
def _overlay_realtime_mempool_stats(snapshot: dict, network: "Network") -> None:
    """Inject live mempool stats into the snapshot returned to clients."""
    if not isinstance(snapshot, dict):
        return

    tx_section = snapshot.setdefault("transactions", {})
    if not isinstance(tx_section, dict):
        return

    broadcast = getattr(network, "broadcast", None)
    pool = getattr(broadcast, "mempool", None) if broadcast else None
    if pool is None:
        return

    tx_count = None
    store = getattr(pool, "_pool", None)
    if isinstance(store, dict):
        tx_count = len(store)
    else:
        txs = pool.get_all_txs() or []
        tx_count = len(txs)

    tx_section["mempool_txs"] = int(tx_count)

    size_est = getattr(pool, "current_size", None)
    if size_est is not None:
        tx_section["mempool_vbytes_estimate"] = int(size_est)

    # Update live graffiti_on_mempool to avoid stale cache when mempool changes
    graff_section = snapshot.setdefault("graffiti", {})
    if isinstance(graff_section, dict):
        on_mem = 0
        for tx in pool.get_all_txs():
            for tx_out in getattr(tx, "outputs", []) or []:
                spk = getattr(tx_out, "script_pubkey", None)
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if meta and str(meta.get("event", "")).upper() == "POST":
                    on_mem += 1
        graff_section["graffiti_on_mempool"] = int(on_mem)

def _choose_relay_route(self, hops: int = 2) -> list[tuple]:
    with self.lock:
        pool = list(self.peers)
    random.shuffle(pool)
    return pool[:max(1,hops)]

def _relay_chain(self, route: list[tuple], inner: dict, src_addr=None):
    if not route:
        return
    first = route[0]
    payload = {"type":"CHAT_RELAY","route": route[1:], "inner": inner}
    self._send_chat_relay(first, payload)

def _send_chat_relay(self, peer: tuple, payload: dict):
    try:
        self._send_to_peer(peer, payload)
        return {"status":"ok"}
    except Exception:
        log.exception("[_send_chat_relay] send error to %s", peer)
        return {"status":"error"}
