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

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc(processing_msg)")


if TYPE_CHECKING:
    from ..node import Network

__all__ = ["process_message"]


def process_message(self: "Network", message: dict[str, Any], addr: Optional[tuple]=None) -> dict | None:
    if not isinstance(message, dict):
        return {"error": "invalid message: expected JSON object"}

    mtype = message.get("type")
    if not isinstance(mtype, str):
        return {"error": "missing or invalid 'type'"}
    mtype = mtype.strip().upper()

    # ----------------------------------------------------------------------------------
    # GUARDIANS: role-based gate + limits
    # ----------------------------------------------------------------------------------
    MINERS = {"HELLO", "NEW_BLOCK", "GET_FULL_SYNC", "FULL_SYNC", "CHAIN", "MEMPOOL",
              "GET_HEADERS", "HEADERS", "GET_BLOCKS", "BLOCKS"}

    NODE_STORAGE = {
        "GRAFFITI_GET_PAYOUTS", "GRAFFITI_PROOF_SUBMIT", "GRAFFITI_BUILD_PAYOUT",
    }

    USER = {
        "PING", "GET_BALANCES", "CREATE_TX", "CREATE_TX_MULTI", "GET_INFO",
        "GET_TX_HISTORY", "GET_TX_DETAIL", "NEW_TX", "GET_UTXOS", "GET_PEERS",
        "GET_NETWORK_INFO", "GET_BLOCK", "GET_BLOCK_HASH", "STOR_LIST",
        "GRAFFITI_GET_POSTS", "GRAFFITI_GET_COMMENTS", "GRAFFITI_GET_ART",

        # Chat & storage listing
        "CHAT_REGISTER", "CHAT_LOOKUP_PUB", "CHAT_PRESENCE", "CHAT_SEND", "CHAT_PULL", "CHAT_RELAY", "CHAT_READ",
        "CHAT_GET_PREKEY", "CHAT_PUBLISH_PREKEYS",

        # Mempool utilities
        "GET_MEMPOOL",
    }

    def _is_miner_sender() -> bool:
        if not isinstance(addr, tuple):
            return False
        if addr in self.peers:
            return True
        peer_port = int(message.get("port", -1))
        return (peer_port > 0) and ((addr[0], peer_port) in self.peers)

    def _client_ip() -> str:
        if isinstance(addr, tuple) and addr:
            return addr[0]
        return "0.0.0.0"

    BOOTSTRAP_ALLOW = {"HELLO", "GET_FULL_SYNC", "FULL_SYNC", "GET_HEADERS", "HEADERS"}
    if (mtype in MINERS) and (mtype not in BOOTSTRAP_ALLOW) and (not _is_miner_sender()):
        log.debug("[process_message] rejecting unauthorized miner RPC %s from %s", mtype, addr)
        return {"error": "forbidden: miners-only endpoint"}

    if (mtype not in MINERS) and (mtype not in USER) and (mtype not in NODE_STORAGE):
        return {"error": "unknown type"}

    if mtype in MINERS:
        return handle_miner_rpc(self, message, addr, mtype)

    if mtype in NODE_STORAGE:
        return handle_storage_rpc(self, message, addr, mtype)

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
                meta = None
                try:
                    meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                except Exception:
                    log.exception("[_overlay_realtime_mempool_stats] Failed to parse graffiti from script_pubkey")
                    meta = None
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
