# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: Merkle; Signal-X3DH

from __future__ import annotations

import socket
import threading
from typing import Any, Dict, List, Optional, Tuple, Set

# ---------------- Local Project ----------------
from ..utils import config as CFG
from ..core.block import Block
from .broadcast import Broadcast
from .protocol import build_envelope, load_or_create_node_keys
from .wallet_route import install_wallet_routes
from .peers_storage import load_peer_keys, save_peer_keys

from .node_logic import chat_state
from .node_logic import discovery as discovery_logic
from .node_logic import handlers as handlers_logic
from .node_logic import peers as peers_logic
from .node_logic import rpc_client as rpc_client_logic
from .node_logic import server as server_logic
from .node_logic import storage_registry
from .node_logic import sync as sync_logic

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node")


class Network:
    active_ports = set()
    _instance_lock = threading.Lock()

    def __init__(self, blockchain=None):
        self.lock = threading.RLock()

        self.port = self._find_available_port()
        if self.port is None:
            raise RuntimeError("[Network] No available ports. Cannot join network.")
        with Network._instance_lock:
            Network.active_ports.add(self.port)

        self.broadcast = Broadcast(blockchain=blockchain)
        self.broadcast.port = self.port
        self.broadcast.network = self
        self.node_id, self.pubkey, self.privkey = load_or_create_node_keys()
        self.node_ctx = {
            "net_id": CFG.DEFAULT_NET_ID,
            "node_id": self.node_id,
            "pubkey": self.pubkey,
            "privkey": self.privkey,
        }
        storage_registry.init_storage_registry(self)
        self.peer_pubkeys: dict[str, str] = {}
        
        try:
            self.broadcast._encode = lambda inner: build_envelope(inner, self.node_ctx, extra={"pubkey": self.pubkey})
        except Exception:
            pass
        
        self._peer_keys_lock = getattr(self, "_peer_keys_lock", None)
        if self._peer_keys_lock is None:
            self._peer_keys_lock = threading.RLock()
        
        self.peers: Set[Tuple[str, int]] = set()
        self.inbound_peers: Set[Tuple[str, int]] = set()
        self.outbound_peers: Set[Tuple[str, int]] = set()
        self.peer_scores: Dict[Tuple[str, int], int] = {}
        self._inbound_ips: Dict[str, int] = {}
        self._peer_last_sync: Dict[Tuple[str, int], float] = {}
        self._peer_last_mempool_sync: Dict[Tuple[str, int], float] = {}
        self._peer_best_height: Dict[Tuple[str, int], int] = {}
        self._peer_last_dial: Dict[Tuple[str, int], float] = {}
        self._full_sync_served_at: Dict[str, float] = {}
        self._full_sync_backoff: Dict[Tuple[str, int], float] = {}
        self._full_sync_last_request: Dict[Tuple[str, int], float] = {}
        self._last_headers_locator: Dict[Tuple[str, int], List[str]] = {}
        self._snapshot_unreachable: Set[Tuple[str, int]] = set()
        self._rpc_backoff: Dict[Tuple[str, int], float] = {}
        self._recent_gap_requests: Dict[Tuple[str, int], float] = {}
        
        self._sync_event = threading.Event()
        self._sync_fast_until = 0.0
        self.utxodb = self.broadcast.utxodb

        try:
            configured_bootstrap = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
        except Exception as exc:
            raise ValueError("Invalid BOOTSTRAP_NODES configuration") from exc

        bootstrap_nodes: Set[Tuple[str, int]] = set()
        for host, port in configured_bootstrap:
            try:
                bootstrap_nodes.add((str(host), int(port)))
            except Exception:
                continue

        if not bootstrap_nodes:
            raise ValueError("No valid bootstrap peers configured")

        primary_peer = self._normalize_peer(CFG.BOOTSTRAP_NODE) or next(iter(bootstrap_nodes))

        is_bootstrap_self = any(self._is_self_bootstrap(h, p) for h, p in bootstrap_nodes)
        if is_bootstrap_self:
            self.persistent_peers = {peer for peer in bootstrap_nodes if not self._is_self_bootstrap(*peer)}
        else:
            self.persistent_peers = set(bootstrap_nodes)
            if self.port == primary_peer[1] and not self._is_local_address(primary_peer[0]):
                try:
                    log.info("[__init__] Port %s matches bootstrap but host differs (%s); treating as client node", self.port, primary_peer[0])
                except Exception:
                    pass

        self.peers.update(self.persistent_peers)
        for peer in self.persistent_peers:
            self.peer_scores[peer] = CFG.PEER_SCORE_START
        
        # --- graceful shutdown controls ---
        self._stop = threading.Event()
        self._server_sock = None
        self._threads: list[threading.Thread] = []

        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.discovery_thread = threading.Thread(target=self.discover_peers_loop, daemon=True)
        self.sync_thread = threading.Thread(target=self.sync_loop, daemon=True)
        self._threads = [self.server_thread, self.discovery_thread, self.sync_thread]

        # --- Log throttles to reduce console spam
        self._last_p2p_log = 0.0
        self._last_sync_log = 0.0
        self._last_fullsync_log = 0.0
        self._last_sync_count = -1
            
        # ---- Persisted peer key pins (TOFU)
        try:
            self.peer_pubkeys = load_peer_keys()
        except Exception:
            log.exception("[__init__] Failed to load peer keys store")
            self.peer_pubkeys = {}

        # --- inject identity into Broadcast (setelah load TOFU) ---
        self.broadcast.node_id = self.node_id
        self.broadcast.pubkey  = self.pubkey
        self.broadcast.privkey = self.privkey
        self.broadcast.peer_pubkeys = self.peer_pubkeys
        
        # ---- P2P Chat ----
        chat_state.init_chat_state(self)
        self.server_thread.start()
        self.discovery_thread.start()
        self.sync_thread.start()

    # -------------------------- Server / Accept ---------------------------

    def _find_available_port(self) -> Optional[int]:
        for port in range(CFG.PORT_START, CFG.PORT_END + 1):
            if port in Network.active_ports:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.bind(('0.0.0.0', port))
                    return port
            except (socket.error, OSError):
                continue
        return None

    def _is_self_bootstrap(self, host: str, port: int) -> bool:
        try:
            if int(port) != int(getattr(self, "port", -1)):
                return False
        except Exception:
            return False
        return self._is_local_address(host)

    @staticmethod
    def _is_local_address(host: str) -> bool:
        if not host:
            return False
        
        host = str(host).strip()
        if not host:
            return False
        
        if host in ("127.0.0.1", "localhost", "::1"):
            return True

        target_ips: set[str] = set()
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except Exception:
            infos = []
            try:
                resolved = socket.gethostbyname(host)
                infos.append((None, None, None, None, (resolved, 0)))
            except Exception:
                return False
            
        for info in infos:
            try:
                ip = info[4][0]
                if ip:
                    target_ips.add(ip)
            except Exception:
                continue
            
        if not target_ips:
            return False

        local_ips: set[str] = {"127.0.0.1", "::1"}
        try:
            hn = socket.gethostname()
            local_ips.update(socket.gethostbyname_ex(hn)[2])
        except Exception:
            pass
        
        try:
            fqdn = socket.getfqdn()
            local_ips.update(socket.gethostbyname_ex(fqdn)[2])
        except Exception:
            pass
        
        try:
            for info in socket.getaddrinfo(None, 0, proto=socket.IPPROTO_TCP):
                ip = info[4][0]
                if ip:
                    local_ips.add(ip)
        except Exception:
            pass

        return any(ip in local_ips for ip in target_ips)

    def _normalize_peer(self, peer: Any) -> Optional[Tuple[str, int]]:
        return peers_logic.normalize_peer(self, peer)

    def _penalize_peer(self, peer: Any, amount: int) -> None:
        return peers_logic.penalize_peer(self, peer, amount)

    def _reward_peer(self, peer: Any, amount: int = CFG.PEER_SCORE_REWARD) -> None:
        return peers_logic.reward_peer(self, peer, amount)

    def start_server(self):
        return server_logic.start_server(self)

    def _get_pinned(self, nid: str):
        # may return None if not yet available
        try:
            return self.peer_pubkeys.get(nid)
        except Exception:
            return None

    def _set_pinned(self, nid: str, pk: str) -> None:
        try:
            with self._peer_keys_lock:
                if self.peer_pubkeys.get(nid) == pk:
                    return
                self.peer_pubkeys[nid] = pk
                save_peer_keys(self.peer_pubkeys)
        except Exception:
            log.exception("[_set_pinned] Error setting pinned peer key")

    def handle_connection(self, conn, addr):
        return server_logic.handle_connection(self, conn, addr)

    # --------------------------- Discovery / Sync -------------------------

    def discover_peers_loop(self):
        return discovery_logic.discover_peers_loop(self)

    def _attempt_hello(self, peer: Tuple[str, int]) -> bool:
        return discovery_logic._attempt_hello(self, peer)

    def _discover_peers(self):
        return discovery_logic._discover_peers(self)

    def sync_loop(self):
        return sync_logic.sync_loop(self)

    def request_sync(self, fast: bool = False) -> None:
        return sync_logic.request_sync(self, fast=fast)

    def sync_with_peers(self):
        return sync_logic.sync_with_peers(self)

    def _sync_peer(self, peer: Tuple[str, int]) -> bool:
        return sync_logic._sync_peer(self, peer)

    def is_caught_up(self, freshness: float = 10.0, height_slack: int = 0) -> bool:
        return sync_logic.is_caught_up(self, freshness=freshness, height_slack=height_slack)

    def get_best_peer_height(self) -> int:
        return sync_logic.get_best_peer_height(self)

    def _collect_broadcast_peers(self) -> Set[Tuple[str, int]]:
        return peers_logic.collect_broadcast_peers(self)

    def publish_block(self, block: "Block", exclude: Optional[Tuple[str, int]] = None, force: bool = True) -> int:
        return peers_logic.publish_block(self, block, exclude=exclude, force=force)

    def _build_locator(self) -> List[str]:
        return sync_logic._build_locator(self)

    def _request_headers(self, peer: Tuple[str, int], locator: List[str]) -> Optional[dict]:
        return sync_logic._request_headers(self, peer, locator)

    def _determine_missing_blocks(self, headers: List[dict]) -> List[int]:
        return sync_logic._determine_missing_blocks(self, headers)

    def _download_blocks(self, peer: Tuple[str, int], heights: List[int]) -> Tuple[int, float]:
        return sync_logic._download_blocks(self, peer, heights)

    def _apply_block_from_sync(self, block_obj: Dict[str, Any], peer: Tuple[str, int]) -> bool:
        return sync_logic._apply_block_from_sync(self, block_obj, peer)

    def handle_block_gap(self, block, origin: Optional[Tuple[str, int]]) -> None:
        return sync_logic.handle_block_gap(self, block, origin)

    def _rpc_request(self, peer: Tuple[str, int], payload: dict, timeout: Optional[float] = None) -> Optional[dict]:
        return rpc_client_logic._rpc_request(self, peer, payload, timeout)

    def _request_mempool_inline(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
        return rpc_client_logic._request_mempool_inline(self, peer, force=force)

    def _request_mempool_snapshot(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
        return rpc_client_logic._request_mempool_snapshot(self, peer, force=force)

    def _request_full_sync(self, peer: Tuple[str, int], *, force: bool = False) -> bool:
        return rpc_client_logic._request_full_sync(self, peer, force=force)

    def _handle_hello(self, message, addr):
        return handlers_logic._handle_hello(self, message, addr)

    def _handle_get_headers(self, message, addr):
        return handlers_logic._handle_get_headers(self, message, addr)

    def _handle_get_blocks(self, message, addr):
        return handlers_logic._handle_get_blocks(self, message, addr)

    def _handle_get_full_sync(self, message, addr):
        return handlers_logic._handle_get_full_sync(self, message, addr)

    def _handle_full_sync(self, message, addr):
        return handlers_logic._handle_full_sync(self, message, addr)

    def _handle_get_block_at(self, height: int) -> dict:
        return handlers_logic._handle_get_block_at(self, height)

    def _handle_get_block_by_hash(self, hx: str) -> dict:
        return handlers_logic._handle_get_block_by_hash(self, hx)

    # ------------------------------ Shutdown ------------------------------

    def shutdown(self):
        self._stop.set()
        try:
            if self._server_sock:
                self._server_sock.close()
        except Exception:
            pass
        
        for t in self._threads:
            try:
                if t.is_alive():
                    t.join(timeout=1.5)
            except Exception:
                pass
            
        with self.lock:
            Network.active_ports.discard(self.port)
        try:
            self.broadcast.shutdown()
        except Exception:
            pass
        
        log.info("[shutdown] Node at port %s stopped", self.port)
        
install_wallet_routes(Network)