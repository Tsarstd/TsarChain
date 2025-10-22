# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; Merkle; Signal-X3DH

from __future__ import annotations
import socket, threading, json, time, os, random
from bech32 import convertbits, bech32_encode
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import deque

# ---------------- Local Project ----------------
from ..utils import config as CFG
from ..core.block import Block
from ..core.tx import Tx
from .broadcast import Broadcast
from ..contracts.storage_nodes import StorageService
from ..utils.helpers import hash160
from .processing_msg import process_message
from .protocol import (send_message, recv_message,build_envelope, verify_and_unwrap,
                        load_or_create_node_keys, is_envelope, sniff_first_json_frame, SecureChannel)
from .wallet_route import install_wallet_routes
from .peers_storage import load_peer_keys, save_peer_keys

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network(node)")
    

# ---- Handshake rate-limit per IP (anti-DoS) ----
_handshake_hits: dict[str, deque] = {}
_temp_ban_until: dict[str, float] = {}

def _rl_prune(ip: str, now_ts: float):
    dq = _handshake_hits.get(ip)
    if not dq: return
    while dq and (now_ts - dq[0]) > CFG.HANDSHAKE_RL_PER_IP_WINDOW_S:
        dq.popleft()
    if not dq:
        _handshake_hits.pop(ip, None)

def _allow_handshake(ip: str, now_ts: float) -> bool:
    # Skip localhost (if necessary)
    if ip in ("127.0.0.1", "::1"):
        return True

    # Temp-ban?
    banned_until = _temp_ban_until.get(ip, 0.0)
    if now_ts < banned_until:
        return False

    dq = _handshake_hits.setdefault(ip, deque())
    _rl_prune(ip, now_ts)
    if len(dq) >= CFG.HANDSHAKE_RL_PER_IP_BURST:
        _temp_ban_until[ip] = now_ts + CFG.TEMP_BAN_SECONDS
        dq.clear()
        return False

    dq.append(now_ts)
    return True


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
            "privkey": self.privkey,}
        self.storage_service = None
        self.storage_peers = {}
        try:
            pkh = hash160(bytes.fromhex(self.pubkey))
            data = [0] + list(convertbits(pkh, 8, 5, True))
            self.storage_address = bech32_encode(CFG.ADDRESS_PREFIX, data)
        except Exception:
            self.storage_address = None
            
        try:
            self.storage_service = StorageService(self.storage_address or "unknown", self.node_id)
        except Exception:
            log.exception("[__init__] Failed to init StorageService")
            self.storage_service = None
            
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
        self.chat_lock = threading.Lock()
        self.chat_mailboxes: dict[str, deque] = {}
        self.chat_seen_ids: set[str] = set()
        self.chat_seen_order: deque[str] = deque(maxlen=5000)
        self.chat_presence_pub: dict[str, str] = {}
        self.chat_presence_seen: set[str] = set()
        self.chat_rate: dict[str, tuple[float, int]] = {}
        self.chat_window_sec = 2.0
        self.chat_burst_max  = 10
        self.chat_mailbox = {}
        self.chat_spend_pub = {}
        self.mailboxes = {}
        self.chat_global_count = 0
        self.chat_seen_mid = {}
        self.chat_seen_max = 512
        self.rl_addr = {}
        self.rl_ip   = {}
        self.backoff_until = {}
        self.chat_gc_last = 0
        self.chat_prekeys: dict[str, dict] = {}

        self.server_thread.start()
        self.discovery_thread.start()
        self.sync_thread.start()

    # -------------------------- Server / Accept ---------------------------

    def _find_available_port(self) -> Optional[int]:
        env_p = os.getenv("CFG.TSAR_LISTEN_PORT")
        if env_p:
            try:
                p = int(env_p)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.bind(('0.0.0.0', p))
                    return p
            except Exception:
                pass
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

    @staticmethod
    def _normalize_peer(peer: Any) -> Optional[Tuple[str, int]]:
        if not peer:
            return None
        if isinstance(peer, tuple) and len(peer) == 2:
            try:
                return (str(peer[0]), int(peer[1]))
            except Exception:
                return None
        if isinstance(peer, list) and len(peer) == 2:
            try:
                return (str(peer[0]), int(peer[1]))
            except Exception:
                return None
        return None

    def _penalize_peer(self, peer: Any, amount: int) -> None:
        norm = self._normalize_peer(peer)
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

    def _reward_peer(self, peer: Any, amount: int = CFG.PEER_SCORE_REWARD) -> None:
        norm = self._normalize_peer(peer)
        if norm is None:
            return
        delta = max(0, int(amount))
        with self.lock:
            score = self.peer_scores.get(norm, CFG.PEER_SCORE_START) + delta
            self.peer_scores[norm] = min(score, CFG.PEER_SCORE_START * 5)
            self.peers.add(norm)
            if len(self.outbound_peers) < CFG.MAX_OUTBOUND_PEERS or norm in self.outbound_peers:
                self.outbound_peers.add(norm)

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self._server_sock = s
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', self.port))
            s.listen(8)
            s.settimeout(1.0)
            log.info("[start_server] Listening on port %s...", self.port)
            while not self._stop.is_set():
                try:
                    conn, addr = s.accept()
                    try:
                        ip = addr[0]
                    except Exception:
                        ip = ""
                    now = time.time()
                    if not _allow_handshake(ip, now):
                        try:
                            conn.close()
                        except Exception:
                            pass
                        log.warning("[start_server] temp-ban handshake %s", ip)
                        continue

                    with self.lock:
                        inbound_total = len(self.inbound_peers)
                        inbound_from_ip = self._inbound_ips.get(ip, 0)
                    if inbound_total >= CFG.MAX_INBOUND_PEERS and inbound_from_ip == 0:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        log.debug("[start_server] inbound capacity full (total) %s", ip)
                        continue
                    if inbound_from_ip >= CFG.MAX_INBOUND_PER_IP:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        log.debug("[start_server] inbound capacity full for %s", ip)
                        continue
                    
                    threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True).start()
                except Exception:
                    if self._stop.is_set():
                        break
                    continue

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
        peer = (addr[0], int(addr[1]) if len(addr) > 1 else 0)
        try:
            with self.lock:
                self.inbound_peers.add(peer)
                ip = peer[0]
                self._inbound_ips[ip] = self._inbound_ips.get(ip, 0) + 1
                self.peer_scores.setdefault(peer, CFG.PEER_SCORE_START // 2)
            raw, first = sniff_first_json_frame(conn, timeout=2.0)

            # === Secure path (handshake HS1) ===
            if isinstance(first, dict) and first.get("type") == "P2P_HS1":
                try:
                    chan = SecureChannel(
                        conn, role="server",
                        node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                        get_pinned=self._get_pinned,
                        set_pinned=self._set_pinned,)
                    
                    chan.hs_server_from_obj(first)
                    send_fn = lambda b: chan.send(b)
                    recv_fn = lambda t: chan.recv(t)
                    try:
                        now = time.time()
                        if now - getattr(self, "_last_p2p_log", 0.0) > 5.0:
                            self._last_p2p_log = now
                    except Exception:
                        pass
                except Exception:
                    log.exception("[handle_connection] Handshake failed from %s ", addr)
                    return

                # Encrypted message loop
                while True:
                    payload = recv_fn(10.0)
                    if not payload:
                        break
                    try:
                        outer = json.loads(payload.decode("utf-8"))
                    except Exception:
                        break

                    msg = outer
                    if is_envelope(outer):
                        try:
                            msg = verify_and_unwrap(outer, lambda nid: self.peer_pubkeys.get(nid))
                            nid = outer.get("from"); pko = outer.get("pubkey")
                            if isinstance(nid, str) and isinstance(pko, str):
                                self.peer_pubkeys[nid] = pko
                                # Consistency: envelope pubkey must match the handshake result
                                if getattr(chan, "peer_node_pub", None) and pko != chan.peer_node_pub:
                                    log.warning("[handle_connection] Peer pubkey mismatch from %s", addr)
                                    continue
                        except Exception:
                            log.warning("[handle_connection] envelope verify failed",
                                        extra={
                                            "peer": "%s:%s" % (addr[0], addr[1] if len(addr) > 1 else 0),
                                            "height": int(self.broadcast.blockchain.height),
                                        },
                                    )
                            continue
                    elif CFG.ENVELOPE_REQUIRED:
                        log.warning("[handle_connection] rejecting legacy P2P from %s", addr)
                        continue

                    response = process_message(self, msg, addr)
                    if response is not None:
                        env = build_envelope(response, self.node_ctx, extra={"pubkey": self.pubkey})
                        send_fn(json.dumps(env).encode("utf-8"))
                return

            # === RPC plaintext path (wallet/miner) ===
            if not isinstance(first, dict):
                return

            # DEV: allow envelopes without SecureChannel if CFG.ALLOW_RPC_PLAINTEXT is True
            if CFG.P2P_ENC_REQUIRED and not CFG.ALLOW_RPC_PLAINTEXT:
                return

            msg = first
            if is_envelope(first):
                try:
                    msg = verify_and_unwrap(first, lambda nid: self.peer_pubkeys.get(nid))
                    nid = first.get("from"); pko = first.get("pubkey")
                    if isinstance(nid, str) and isinstance(pko, str):
                        self.peer_pubkeys[nid] = pko
                except Exception:
                    log.warning("[handle_connection] envelope verify failed",
                        extra={
                            "peer": "%s:%s" % (addr[0], addr[1] if len(addr) > 1 else 0),
                            "height": int(self.broadcast.blockchain.height)
                        }
                    )
                    return
            elif CFG.ENVELOPE_REQUIRED:
                log.warning(f"[handle_connection] rejecting legacy RPC from {addr}")
                return

            response = process_message(self, msg, addr)
            if response is not None:
                env = build_envelope(response, self.node_ctx, extra={"pubkey": self.pubkey})
                send_message(conn, json.dumps(env).encode("utf-8"))

        except Exception:
            log.exception("[handle_connection] Connection handler error from %s", addr)
        finally:
            with self.lock:
                self.inbound_peers.discard(peer)
                ip = peer[0]
                if ip in self._inbound_ips:
                    remaining = self._inbound_ips.get(ip, 1) - 1
                    if remaining > 0:
                        self._inbound_ips[ip] = remaining
                    else:
                        self._inbound_ips.pop(ip, None)
            try:
                conn.close()
            except Exception:
                pass

    # --------------------------- Discovery / Sync -------------------------

    def discover_peers_loop(self):
        while not self._stop.is_set():
            try:
                self._discover_peers()
                time.sleep(CFG.DISCOVERY_INTERVAL)
            except Exception:
                log.exception("[discover_peers_loop] Peer discovery error")
                time.sleep(CFG.DISCOVERY_INTERVAL * 2)

    def _attempt_hello(self, peer: Tuple[str, int]) -> bool:
        norm = self._normalize_peer(peer)
        if not norm:
            return False
        ip, port = norm
        if port <= 0:
            return False
        if ip in ("127.0.0.1", "localhost") and port == self.port:
            return False
        if (port == self.port) and self._is_local_address(ip):
            return False

        now = time.time()
        last_dial = self._peer_last_dial.get(norm, 0.0)
        if now - last_dial < max(2.0, CFG.DISCOVERY_INTERVAL / 2):
            return norm in self.outbound_peers

        hello_msg = {
            "type": "HELLO",
            "port": self.port,
            "height": self.broadcast.blockchain.height,
            "peers": [{"ip": h, "port": p} for h, p in list(self.peers)[:CFG.HEADERS_FANOUT]],
        }
        env = build_envelope(hello_msg, self.node_ctx, extra={"pubkey": self.pubkey})
        if CFG.ENFORCE_HELLO_PUBKEY or CFG.ENVELOPE_REQUIRED:
            env["pubkey"] = self.pubkey

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                timeout = 3.5 if norm in self.persistent_peers else 2.0
                s.settimeout(timeout)
                s.connect(norm)
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        s, role="client",
                        node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                        get_pinned=self._get_pinned,
                        set_pinned=self._set_pinned,
                    )
                    chan.handshake()
                    chan.send(json.dumps(env).encode("utf-8"))
                    try:
                        chan.recv(1)
                    except Exception:
                        pass
                else:
                    send_message(s, json.dumps(env).encode("utf-8"))
                    try:
                        recv_message(s, timeout=1)
                    except Exception:
                        pass
                    
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception:
            log.exception("[_attempt_hello] Error dialing %s", norm)
            return False
        finally:
            self._peer_last_dial[norm] = now
            
        try:
            self.broadcast.send_mempool_to_peer(norm)
        except Exception:
            log.exception("[_attempt_hello] mempool push error to %s", norm)
        try:
            if not CFG.ENABLE_FULL_SYNC:
                self._request_mempool_snapshot(norm, force=True)
        except Exception:
            log.exception("[_attempt_hello] mempool pull error from %s", norm)
            
        return True
    
    def _discover_peers(self):
        limit = max(1, int(CFG.MAX_OUTBOUND_PEERS))
        found_peers: Set[Tuple[str, int]] = set()

        with self.lock:
            candidates: List[Tuple[str, int]] = list(self.persistent_peers)
            scored = sorted(
                (p for p in self.peers if p not in self.persistent_peers),
                key=lambda p: self.peer_scores.get(p, 0),
                reverse=True,
            )
        candidates.extend(scored)
        random.shuffle(candidates)

        for peer in candidates:
            norm = self._normalize_peer(peer)
            if not norm:
                continue
            if norm in found_peers:
                continue
            if limit > 0 and len(found_peers) >= limit and norm not in self.outbound_peers:
                break
            if self._attempt_hello(norm):
                found_peers.add(norm)
                self._reward_peer(norm)
            else:
                self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)

        if len(found_peers) < limit:
            for port in range(CFG.PORT_START, CFG.PORT_END + 1):
                if port == self.port:
                    continue
                norm = ("127.0.0.1", port)
                if norm in found_peers:
                    continue
                if limit > 0 and len(found_peers) >= limit and norm not in self.outbound_peers:
                    break
                if self._attempt_hello(norm):
                    found_peers.add(norm)
                    self._reward_peer(norm)

        with self.lock:
            self.peers.update(found_peers)
            retained = {p for p in self.outbound_peers if p in found_peers}
            for peer in found_peers:
                if len(retained) < limit or peer in retained:
                    retained.add(peer)
            self.outbound_peers = retained

        if found_peers:
            try:
                log.trace("[_discover_peers] reachable=%s outbound=%s", len(found_peers), len(self.outbound_peers))
            except Exception:
                pass

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
            return

        now = time.time()
        if (len(selected) != getattr(self, "_last_sync_count", -1)) or (now - self._last_sync_log > float(CFG.SYNC_INFO_MIN_INTERVAL)):
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
                    elif inline_status is False:
                        if norm not in self._snapshot_unreachable:
                            self._request_mempool_snapshot(norm)
                        else:
                            log.debug("[sync_with_peers] Skipping snapshot pull for %s (unreachable)", norm)
                elif inline_status is False:
                    # Remote node does not support inline fetch; fall back to legacy snapshot push when viable.
                    if norm not in self._snapshot_unreachable:
                        self._request_mempool_snapshot(norm)
                    else:
                        log.debug("[sync_with_peers] Snapshot push skipped for %s (unreachable)", norm)
            except Exception:
                log.exception("[sync_with_peers] Error syncing with peer %s", norm)
                self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY * 2)
                
    def _sync_peer(self, peer: Tuple[str, int]) -> bool:
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
            return False
        
        headers = headers_resp.get("headers") or []
        best_height = -1
        try:
            best_height = int(headers_resp.get("best_height", -1))
        except Exception:
            best_height = -1
        if best_height < 0 and headers:
            try:
                best_height = max(int(h.get("height", -1)) for h in headers if isinstance(h, dict))
            except Exception:
                best_height = -1
        if best_height >= 0:
            with self.lock:
                self._peer_best_height[peer] = best_height

        if not headers:
            self._peer_last_sync[peer] = now
            self._reward_peer(peer)
            return True
        
        missing = self._determine_missing_blocks(headers)
        if not missing:
            self._peer_last_sync[peer] = now
            self._reward_peer(peer)
            return True
        
        downloaded = self._download_blocks(peer, missing)
        if downloaded:
            self._peer_last_sync[peer] = time.time()
            self._reward_peer(peer, CFG.PEER_SCORE_REWARD * 2)
            if headers_resp.get("more"):
                self.request_sync(fast=True)
            return True
        
        return False

    def is_caught_up(self, freshness: float = 10.0, height_slack: int = 0) -> bool:
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

    def _collect_broadcast_peers(self) -> Set[Tuple[str, int]]:
        with self.lock:
            targets: Set[Tuple[str, int]] = set(self.outbound_peers)
            targets.update(self.inbound_peers)
            if not targets:
                targets.update(self.peers)
        return targets

    def publish_block(self, block: "Block", exclude: Optional[Tuple[str, int]] = None, force: bool = True) -> int:
        Block = None
        if Block is not None and not isinstance(block, Block):
            raise TypeError("block must be a Block instance")
        peers = self._collect_broadcast_peers()
        if not peers:
            return 0
        return self.broadcast.broadcast_block(block, peers, exclude=exclude, force=force)

    def _build_locator(self) -> List[str]:
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
            "locator": locator[:CFG.HEADERS_LOCATOR_DEPTH],
            "limit": int(CFG.HEADERS_BATCH_MAX),
            "port": self.port,
        }
        return self._rpc_request(peer, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))

    def _determine_missing_blocks(self, headers: List[dict]) -> List[int]:
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

    def _download_blocks(self, peer: Tuple[str, int], heights: List[int]) -> bool:
        if not heights:
            return False
        
        unique_heights = sorted({int(h) for h in heights if isinstance(h, int)})
        if not unique_heights:
            return False
        
        batch_size = max(1, int(CFG.BLOCK_DOWNLOAD_BATCH_MAX))
        downloaded = False
        for idx in range(0, len(unique_heights), batch_size):
            chunk = unique_heights[idx: idx + batch_size]
            payload = {"type": "GET_BLOCKS", "heights": chunk, "port": self.port}
            resp = self._rpc_request(peer, payload, timeout=max(15.0, CFG.SYNC_TIMEOUT))
            if not resp:
                break
            
            if resp.get("type") == "BLOCKS":
                blocks = resp.get("blocks") or []
                for block_obj in blocks:
                    try:
                        applied = self._apply_block_from_sync(block_obj, peer)
                    except Exception:
                        log.exception("[_download_blocks] Failed applying block from %s", peer)
                        return downloaded
                    if applied:
                        downloaded = True
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
                        return downloaded
                    
            elif resp.get("type") == "SYNC_REJECT":
                retry = float(resp.get("retry_after", CFG.FULL_SYNC_BACKOFF_INITIAL))
                self._full_sync_backoff[peer] = time.time() + min(retry, CFG.FULL_SYNC_BACKOFF_MAX)
                break
            else:
                break
            
        return downloaded

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

    def _rpc_request(self, peer: Tuple[str, int], payload: dict, timeout: Optional[float] = None) -> Optional[dict]:
        norm = self._normalize_peer(peer)
        if not norm:
            return None
        
        now = time.time()
        retry_at = self._rpc_backoff.get(norm, 0.0)
        if now < retry_at:
            try:
                log.debug("[_rpc_request] backoff active for %s (%.1fs remaining)", norm, retry_at - now)
            except Exception:
                pass
            return None
        
        env = build_envelope(payload, self.node_ctx, extra={"pubkey": self.pubkey})
        timeout = float(timeout or CFG.SYNC_TIMEOUT)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(norm)
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        s, role="client",
                        node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                        get_pinned=self._get_pinned,
                        set_pinned=self._set_pinned,
                    )
                    chan.handshake()
                    chan.send(json.dumps(env).encode("utf-8"))
                    resp = chan.recv(timeout)
                else:
                    send_message(s, json.dumps(env).encode("utf-8"))
                    resp = recv_message(s, timeout=timeout)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        
        except Exception as exc:
            self._rpc_backoff[norm] = time.time() + max(5.0, float(CFG.TEMP_BAN_SECONDS))
            if isinstance(exc, AttributeError):
                try:
                    log.warning("[_rpc_request] Handshake aborted by %s; backing off", norm)
                except Exception:
                    pass
            else:
                log.exception("[_rpc_request] Error contacting %s", norm)
            return None
        
        self._rpc_backoff.pop(norm, None)
        if not resp:
            return None
        
        try:
            outer = json.loads(resp.decode("utf-8"))
        except Exception:
            return None
        
        if is_envelope(outer):
            nid = outer.get("from")
            pko = outer.get("pubkey")
            def _resolver(qnid: str):
                pk = self.peer_pubkeys.get(qnid)
                if pk:
                    return pk
                
                if isinstance(nid, str) and qnid == nid and isinstance(pko, str):
                    return pko
                return None
            
            try:
                inner = verify_and_unwrap(outer, _resolver)
            except Exception:
                log.warning("[_rpc_request] verify failed from %s", norm)
                return None
            
            if isinstance(nid, str) and isinstance(pko, str):
                self.peer_pubkeys[nid] = pko
        else:
            inner = outer
        return inner

    def _request_mempool_inline(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
        norm = self._normalize_peer(peer)
        if not norm:
            return False
        
        now = time.time()
        min_iv = float(CFG.MEMPOOL_SYNC_MIN_INTERVAL)
        if not force and now - self._peer_last_mempool_sync.get(norm, 0.0) < min_iv:
            return None
        retry_at = self._rpc_backoff.get(norm, 0.0)
        if now < retry_at:
            return None
        try:
            log.debug("[_request_mempool_inline] requesting from %s force=%s", norm, force)
        except Exception:
            pass

        payload = {
            "type": "GET_MEMPOOL",
            "mode": "inline_full",
            "port": self.port,
        }
        if self.node_id:
            payload["node_id"] = self.node_id

        resp = self._rpc_request(norm, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))
        if not resp:
            try:
                log.debug("[_request_mempool_inline] no response from %s", norm)
            except Exception:
                pass
            return None
        
        if resp.get("type") != "MEMPOOL":
            try:
                log.debug("[_request_mempool_inline] unexpected response %s from %s", resp.get("type"), norm)
            except Exception:
                pass
            return False

        resp_mode = str(resp.get("mode", "")).strip().lower()
        if resp_mode and resp_mode not in ("inline", "inline_full"):
            try:
                log.debug("[_request_mempool_inline] unsupported mode=%s from %s", resp_mode, norm)
            except Exception:
                pass
            return False

        txs = resp.get("txs") or resp.get("data")
        if not isinstance(txs, list):
            try:
                log.debug("[_request_mempool_inline] bad payload from %s (txs not list)", norm)
            except Exception:
                pass
            return False

        if txs and all(isinstance(x, (str, bytes)) for x in txs):
            # remote node returned only txids; fall back to legacy snapshot
            try:
                log.debug("[_request_mempool_inline] txids-only response from %s", norm)
            except Exception:
                pass
            return False

        added = 0
        for item in txs:
            try:
                tx_obj = Tx.from_dict(item) if isinstance(item, dict) else item
                if self.broadcast.mempool.add_valid_tx(tx_obj):
                    added += 1
            except Exception:
                log.debug("[_request_mempool_inline] Failed to add tx from %s", norm, exc_info=True)

        self._peer_last_mempool_sync[norm] = now
        self._snapshot_unreachable.discard(norm)
        try:
            log.debug("[_request_mempool_inline] added=%s total=%s from %s", added, len(txs), norm)
        except Exception:
            pass
        if added:
            self._reward_peer(norm, CFG.PEER_SCORE_REWARD)
        return True

    def _request_mempool_snapshot(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
        norm = self._normalize_peer(peer)
        if not norm:
            return False
        
        now = time.time()
        min_iv = float(CFG.MEMPOOL_SYNC_MIN_INTERVAL)
        if not force and now - self._peer_last_mempool_sync.get(norm, 0.0) < min_iv:
            return False

        payload = {
            "type": "GET_MEMPOOL",
            "mode": "snapshot",
            "port": self.port,
        }
        retry_at = self._rpc_backoff.get(norm, 0.0)
        if now < retry_at:
            return None
        if force:
            payload["force"] = True
            payload["min_interval"] = 0
        try:
            log.debug("[_request_mempool_snapshot] requesting from %s force=%s", norm, force)
        except Exception:
            pass

        resp = self._rpc_request(norm, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))
        if not resp:
            try:
                log.debug("[_request_mempool_snapshot] no response from %s", norm)
            except Exception:
                pass
            self._snapshot_unreachable.add(norm)
            self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)
            return None

        if resp.get("type") != "MEMPOOL_SYNC" or resp.get("status") == "error":
            try:
                log.debug("[_request_mempool_snapshot] reject from %s resp=%s", norm, resp)
            except Exception:
                pass
            self._snapshot_unreachable.add(norm)
            return False

        self._peer_last_mempool_sync[norm] = now
        self._snapshot_unreachable.discard(norm)
        try:
            if int(resp.get("count", 0)) > 0:
                self._reward_peer(norm, CFG.PEER_SCORE_REWARD)
        except Exception:
            pass
        return True
    
    def _request_full_sync(self, peer: Tuple[str, int], *, force: bool = False) -> bool:
        if not force and not CFG.ENABLE_FULL_SYNC:
            return self._request_mempool_snapshot(peer, force=True)
        
        norm = self._normalize_peer(peer)
        if not norm:
            return False
        
        now = time.time()
        if not force and now < self._full_sync_backoff.get(norm, 0.0):
            return False
        
        last_req = self._full_sync_last_request.get(norm, 0.0)
        if not force and now - last_req < CFG.FULL_SYNC_MIN_INTERVAL:
            return False

        payload = {
            "type": "GET_FULL_SYNC",
            "port": self.port,
            "height": self.broadcast.blockchain.height,
        }
        resp = self._rpc_request(norm, payload, timeout=max(20.0, CFG.SYNC_TIMEOUT * 2))
        self._full_sync_last_request[norm] = now
        if not resp:
            self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)
            return False
        
        if resp.get("type") == "SYNC_REJECT":
            retry = float(resp.get("retry_after", CFG.FULL_SYNC_BACKOFF_INITIAL))
            self._full_sync_backoff[norm] = now + min(retry, CFG.FULL_SYNC_BACKOFF_MAX)
            return False
        
        if resp.get("type") != "FULL_SYNC":
            return False

        data = resp.get("data", resp)
        ok = self.broadcast.receive_full_sync(data)
        if ok:
            self._peer_last_sync[norm] = time.time()
            self._reward_peer(norm, CFG.PEER_SCORE_REWARD * 3)
            self._full_sync_backoff.pop(norm, None)
            return True
        self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)
        return False

    def _handle_hello(self, message, addr):
        peer_ip = addr[0] if isinstance(addr, tuple) and len(addr) > 0 else str(message.get("ip", "")).strip()
        try:
            peer_port = int(message.get("port", 0))
        except Exception:
            peer_port = 0
        peer_tuple = (peer_ip, peer_port) if peer_ip and isinstance(peer_port, int) and peer_port > 0 else None

        role = str(message.get("role", "")).strip().upper()
        now = time.time()
        try:
            advertised_height = int(message.get("height", -1))
        except Exception:
            advertised_height = -1

        if role == "NODE_STORAGE":
            meta = {
                "addr": (message.get("address") or "").strip().lower(),
                "url": (message.get("url") or "").strip(),
                "ip": peer_ip,
                "port": int(peer_port or 0),
                "last_seen": int(now),
                "alive": True,
            }
            with self.lock:
                if not hasattr(self, "storage_peers") or self.storage_peers is None:
                    self.storage_peers = {}
                self.storage_peers[(peer_ip, meta["port"])] = meta

        incoming_peers = message.get("peers") or []
        normalized_incoming = []
        for entry in incoming_peers:
            if isinstance(entry, dict):
                ip = str(entry.get("ip") or entry.get("host") or "").strip()
                try:
                    port = int(entry.get("port", 0))
                except Exception:
                    port = 0
                if not ip or port <= 0:
                    continue
                if self._is_local_address(ip) and port == self.port:
                    continue
                normalized_incoming.append((ip, port))

        with self.lock:
            if peer_tuple and not (self._is_local_address(peer_tuple[0]) and peer_tuple[1] == self.port):
                self.peers.add(peer_tuple)
                self.peer_scores.setdefault(peer_tuple, CFG.PEER_SCORE_START)
                if advertised_height >= 0:
                    self._peer_best_height[peer_tuple] = advertised_height
                    
            for cand in normalized_incoming:
                if cand == peer_tuple:
                    continue
                self.peers.add(cand)
                self.peer_scores.setdefault(cand, CFG.PEER_SCORE_START // 2)

            sane_peers = [
                {"ip": ip, "port": port}
                for ip, port in self.peers
                if isinstance(port, int) and port > 0
            ]
            height = int(self.broadcast.blockchain.height)
            
            try:
                peer_port = int(message.get("port", -1))
            except Exception:
                peer_port = -1
            if isinstance(addr, tuple) and peer_port > 0:
                dst = (addr[0], peer_port)
                try:
                    self.broadcast.send_mempool_to_peer(dst)
                except Exception:
                    log.exception("[_handle_hello] failed to push mempool to %s", dst)

        if peer_tuple:
            self._reward_peer(peer_tuple)

        return {
            "type": "HELLO_RESPONSE",
            "port": self.port,
            "height": height,
            "peers": sane_peers,
        }

    def _handle_get_headers(self, message, addr):
        locator = message.get("locator") or []
        try:
            limit = int(message.get("limit", CFG.HEADERS_BATCH_MAX))
        except Exception:
            limit = CFG.HEADERS_BATCH_MAX
            
        limit = max(1, min(limit, CFG.HEADERS_BATCH_MAX))
        with self.broadcast.lock:
            chain = list(self.broadcast.blockchain.chain)
        start_idx = 0
        if locator:
            known = {}
            for idx, blk in enumerate(chain):
                try:
                    known[blk.hash().hex()] = idx
                except Exception:
                    continue
                
            for cand in locator:
                idx = known.get(str(cand))
                if idx is not None:
                    start_idx = idx + 1
                    break
                
        headers = []
        for blk in chain[start_idx:start_idx + limit]:
            try:
                prev_hash = blk.prev_block_hash.hex() if isinstance(blk.prev_block_hash, (bytes, bytearray)) else str(blk.prev_block_hash)
            except Exception:
                prev_hash = None
                
            headers.append({
                "height": getattr(blk, "height", start_idx),
                "hash": blk.hash().hex() if hasattr(blk, "hash") else getattr(blk, "hash", ""),
                "prev_hash": prev_hash,
                "timestamp": getattr(blk, "timestamp", 0),
                "bits": getattr(blk, "bits", 0),
            })
        more = (start_idx + limit) < len(chain)
        return {
            "type": "HEADERS",
            "headers": headers,
            "more": more,
            "best_height": max(-1, len(chain) - 1),
        }

    def _handle_get_blocks(self, message, addr):
        heights = message.get("heights") or []
        if not isinstance(heights, list):
            return {"type": "BLOCKS", "blocks": []}
        
        limit = min(len(heights), CFG.BLOCK_DOWNLOAD_BATCH_MAX)
        blocks: List[dict] = []
        with self.broadcast.lock:
            chain = list(self.broadcast.blockchain.chain)
            
        for raw_h in heights[:limit]:
            try:
                h = int(raw_h)
            except Exception:
                continue
            if 0 <= h < len(chain):
                try:
                    blocks.append(chain[h].to_dict())
                except Exception:
                    continue
        return {"type": "BLOCKS", "blocks": blocks}
    
    def _handle_get_full_sync(self, message, addr):
        ip = (addr[0] if isinstance(addr, tuple) and len(addr) > 0 else "unknown")
        now = time.time()
        min_iv = CFG.FULL_SYNC_MIN_INTERVAL
        last_served = self._full_sync_served_at.get(ip, 0.0)
        if now - last_served < min_iv:
            retry_after = max(30.0, min_iv - (now - last_served))
            return {"type": "SYNC_REJECT", "reason": "rate_limited", "retry_after": retry_after}
        
        self._full_sync_served_at[ip] = now
        try:
            if len(self.broadcast.blockchain.chain) > CFG.FULL_SYNC_MAX_BLOCKS:
                return {
                    "type": "SYNC_REDIRECT",
                    "reason": "too_large_chain",
                    "limit_blocks": CFG.FULL_SYNC_MAX_BLOCKS}
                
            with self.broadcast.lock:
                if not self.broadcast.blockchain.in_memory:
                    self.broadcast.blockchain.load_chain()
                chain_data = [blk.to_dict() for blk in self.broadcast.blockchain.chain]
                try:
                    utxo_dict = self.broadcast.utxodb.to_dict()
                except Exception:
                    utxo_dict = {}
                    
                txs   = [tx.to_dict() for tx in self.broadcast.mempool.get_all_txs()]
                state = self.broadcast.state
            full_obj = {
                "type": "FULL_SYNC",
                "data": {
                    "chain": chain_data,
                    "utxos": utxo_dict,
                    "state": state,
                    "mempool": txs}}
            try:
                enc = json.dumps(full_obj, separators=CFG.CANONICAL_SEP, ensure_ascii=False).encode("utf-8")
            except Exception as e:
                return {"type": "SYNC_REDIRECT", "reason": "serialize_failed", "detail": str(e)}
            
            hard_cap = min(CFG.FULL_SYNC_MAX_BYTES, CFG.MAX_MSG - len(CFG.NETWORK_MAGIC))
            if len(enc) > hard_cap:
                return {
                    "type": "SYNC_REDIRECT",
                    "reason": "payload_would_exceed_limit",
                    "limit_bytes": hard_cap
                    }
            return full_obj
        except Exception as e:
            return {"type": "SYNC_REDIRECT", "reason": "internal_error", "detail": str(e)}

    def _handle_full_sync(self, message, addr):
        try:
            now = time.time()
            if (now - getattr(self, "_last_fullsync_log", 0.0) > 5.0):
                log.trace("[_handle_full_sync] Received full sync from %s:%s", addr[0], addr[1] if len(addr)>1 else 0)
                self._last_fullsync_log = now
        except Exception:
            pass
        
        payload = message.get("data", message)
        self.broadcast.receive_full_sync(payload)
        return {"status": "ok"}
    
    def _handle_get_block_at(self, height: int) -> dict:
        try:
            with self.broadcast.lock:
                chain = list(self.broadcast.blockchain.chain)
            if height < 0 or height >= len(chain):
                return {"type": "BLOCK", "error": "height_out_of_range"}
            
            b = chain[height]
            d = self._serialize_block(b)
            d["type"] = "BLOCK"
            return d
        except Exception as e:
            return {"type": "BLOCK", "error": str(e)}

    def _handle_get_block_by_hash(self, hx: str) -> dict:
        try:
            hx = (hx or "").strip().lower()
            with self.broadcast.lock:
                chain = list(self.broadcast.blockchain.chain)
            for b in chain:
                if self._bhash_hex(b).lower() == hx:
                    d = self._serialize_block(b)
                    d["type"] = "BLOCK"
                    return d
            return {"type": "BLOCK", "error": "not_found"}
        
        except Exception as e:
            return {"type": "BLOCK", "error": str(e)}

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









