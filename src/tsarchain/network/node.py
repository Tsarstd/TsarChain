# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; Merkle; Signal-X3DH

import socket, threading, json, time, os
from bech32 import convertbits, bech32_encode
from typing import Set, Tuple, Optional, Any
from collections import deque

# ---------------- Local Project ----------------
from ..utils import config as CFG
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
        self.utxodb = self.broadcast.utxodb

        bootstrap_host, bootstrap_port = CFG.BOOTSTRAP_NODE
        if not self._is_self_bootstrap(bootstrap_host, bootstrap_port):
            self.persistent_peers = {CFG.BOOTSTRAP_NODE}
            self.peers.update(self.persistent_peers)
            if self.port == bootstrap_port:
                try:
                    log.info(
                        "[__init__] Port %s matches bootstrap but host differs (%s); treating as client node",
                        self.port,
                        bootstrap_host,
                    )
                except Exception:
                    pass
        else:
            self.persistent_peers = set()
            try:
                log.warning("[__init__] Running as bootstrap node (%s:%s)", bootstrap_host, bootstrap_port)
            except Exception:
                log.warning("[__init__] Running as bootstrap node")
        
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

        log.info("[__init__] Node ID: %s, Pubkey: %s..., Port: %s", self.node_id, self.pubkey[:16], self.port)
        log.info("[__init__] Storage Address: %s, Service: %s", self.storage_address, self.storage_service is not None)

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
        try:
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
                            log.info("[handle_connection] Handshake from %s:%s, node_id=%s, pubkey=%s...", addr[0], addr[1], chan.peer_node_id, str(chan.peer_node_pub)[:16])
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

    def _discover_peers(self):
        found_peers = set()

        # 1) Persistent
        for peer in self.persistent_peers:
            if not isinstance(peer, tuple) or len(peer) != 2:
                continue
            if peer[0] in ("127.0.0.1", "localhost") and peer[1] == self.port:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3.5)
                    if (peer[1] == self.port) and self._is_local_address(peer[0]):
                        continue
                    
                    s.connect(peer)
                    hello_msg = {
                        "type": "HELLO",
                        "port": self.port,
                        "height": self.broadcast.blockchain.height,
                        "peers": [{"ip": ip, "port": p} for ip, p in self.peers],
                    }
                    env = build_envelope(hello_msg, self.node_ctx, extra={"pubkey": self.pubkey})
                    if CFG.P2P_ENC_REQUIRED:
                        chan = SecureChannel(
                            s, role="client",
                            node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                            get_pinned=self._get_pinned,
                            set_pinned=self._set_pinned,
                        )
                        
                        chan.handshake()
                        chan.send(json.dumps(env).encode("utf-8"))
                        try: _ = chan.recv(1)
                        except Exception:
                            pass
                    else:
                        send_message(s, json.dumps(env).encode("utf-8"))
                        try: _ = recv_message(s, timeout=1)
                        except Exception:
                            pass
                    found_peers.add(peer)
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
            except Exception:
                log.exception("[_discover_peers] Error connecting to persistent peer %s", peer)
                continue

        # 2) Known peers
        for peer in list(self.peers):
            if not isinstance(peer, tuple) or len(peer) != 2:
                continue
            if peer[0] in ("127.0.0.1", "localhost") and peer[1] == self.port:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    if (peer[1] == self.port) and self._is_local_address(peer[0]):
                        continue
                    
                    s.connect(peer)
                    hello_msg = {
                        "type": "HELLO",
                        "port": self.port,
                        "height": self.broadcast.blockchain.height,
                        "peers": [{"ip": ip, "port": p} for ip, p in self.peers],
                    }
                    env = build_envelope(hello_msg, self.node_ctx, extra={"pubkey": self.pubkey})
                    if CFG.ENFORCE_HELLO_PUBKEY or CFG.ENVELOPE_REQUIRED:
                        env["pubkey"] = self.pubkey
                    if CFG.P2P_ENC_REQUIRED:
                        chan = SecureChannel(
                            s, role="client",
                            node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                            get_pinned=self._get_pinned,
                            set_pinned=self._set_pinned,
                        )
                        
                        chan.handshake()
                        chan.send(json.dumps(env).encode("utf-8"))
                        try: _ = chan.recv(1)
                        except Exception: pass
                    else:
                        send_message(s, json.dumps(env).encode("utf-8"))
                        try: _ = recv_message(s, timeout=1)
                        except Exception: pass
                    found_peers.add(peer)
            except (socket.timeout, ConnectionRefusedError, OSError):
                with self.lock:
                    self.peers.discard(peer)
                continue
            except Exception:
                continue

        # 3) Local sweep
        for port in range(CFG.PORT_START, CFG.PORT_END + 1):
            if port == self.port:
                continue
            peer = ("127.0.0.1", port)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if (peer[1] == self.port) and self._is_local_address(peer[0]):
                        continue
                    
                    s.connect(peer)
                    hello_msg = {
                        "type": "HELLO",
                        "port": self.port,
                        "height": self.broadcast.blockchain.height,
                        "peers": [{"ip": ip, "port": p} for ip, p in self.peers]
                    }
                    env = build_envelope(hello_msg, self.node_ctx, extra={"pubkey": self.pubkey})
                    if CFG.P2P_ENC_REQUIRED:
                        chan = SecureChannel(
                            s, role="client",
                            node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                            get_pinned=self._get_pinned,
                            set_pinned=self._set_pinned,
                        )
                        
                        chan.handshake()
                        chan.send(json.dumps(env).encode("utf-8"))
                        try: _ = chan.recv(1)
                        except Exception: pass
                    else:
                        send_message(s, json.dumps(env).encode("utf-8"))
                        try: _ = recv_message(s, timeout=1)
                        except Exception: pass
                    found_peers.add(peer)
            except Exception:
                pass

        with self.lock:
            sane = set()
            for (ip, p) in found_peers:
                try:
                    if isinstance(p, int) and p > 0:
                        if ip in ("127.0.0.1", "localhost") and p == self.port:
                            continue
                        sane.add((ip, p))
                except Exception:
                    continue
            self.peers.update(sane)
        if found_peers:
            log.info("[_discover_peers] Discovered %s peers, total known: %s", len(found_peers), len(self.peers))

    def sync_loop(self):
        while not self._stop.is_set():
            try:
                self.sync_with_peers()
                time.sleep(CFG.SYNC_INTERVAL)
            except Exception:
                log.exception("[sync_loop] Error during sync")

    def sync_with_peers(self):
        with self.lock:
            try:
                self.peers = {(ip, p) for (ip, p) in self.peers if isinstance(p, int) and p > 0}
            except Exception:
                self.peers = set()
        if not self.peers:
            return
        if not CFG.ENABLE_FULL_SYNC:
            return
        try:
            now = time.time()
            cnt = len(self.peers)

            min_iv = CFG.SYNC_INFO_MIN_INTERVAL

            if (self.port == CFG.BOOTSTRAP_NODE[1]) and getattr(CFG, "IS_DEV", str(getattr(CFG, "MODE", "dev")).lower() == "dev"):
                min_iv = CFG.SYNC_INFO_MIN_INTERVAL_BOOTSTRAP

            if (cnt != getattr(self, "_last_sync_count", -1)) or (now - self._last_sync_log > float(min_iv)):
                log.info("[sync_with_peers] Connecting %s peers...", cnt)
                self._last_sync_count = cnt
                self._last_sync_log = now
            else:
                pass
        except Exception:
            pass
        for peer in list(self.peers):
            try:
                self._request_full_sync(peer)
            except Exception:
                log.exception("[sync_with_peers] Error syncing with peer %s", peer)
                with self.lock:
                    self.peers.discard(peer)

    def _request_full_sync(self, peer):
        try:
            if not CFG.ENABLE_FULL_SYNC:
                return
            try:
                if isinstance(peer, tuple) and len(peer) == 2:
                    try:
                        same_port = int(peer[1]) == int(self.port)
                    except Exception:
                        same_port = False
                    if same_port and self._is_local_address(peer[0]):
                        return
                    
            except Exception:
                pass
            
            sync_msg = {"type": "GET_FULL_SYNC", "port": self.port, "height": self.broadcast.blockchain.height}
            try:
                log.debug("[_request_full_sync] Dialing %s:%s (height=%s)", peer[0], peer[1], self.broadcast.blockchain.height)
            except Exception:
                pass
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(peer)
                try:
                    log.debug("[_request_full_sync] Connected to %s:%s", peer[0], peer[1])
                except Exception:
                    pass
                timeout = max(float(getattr(CFG, "SYNC_TIMEOUT", 10.0)), 15.0)
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        s, role="client",
                        node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                        get_pinned=self._get_pinned,
                        set_pinned=self._set_pinned,
                    )
                    
                    chan.handshake()
                    try:
                        log.info("[_request_full_sync] Secure handshake established with %s:%s (peer_id=%s)", peer[0], peer[1], getattr(chan, "peer_node_id", "?"))
                    except Exception:
                        pass
                    payload = json.dumps(build_envelope(sync_msg, self.node_ctx, extra={"pubkey": self.pubkey})).encode("utf-8")
                    chan.send(payload)
                    try:
                        log.info("[_request_full_sync] Request sent to %s:%s (%s bytes)", peer[0], peer[1], len(payload))
                    except Exception:
                        pass
                    resp = chan.recv(timeout)
                else:
                    env = build_envelope(sync_msg, self.node_ctx, extra={"pubkey": self.pubkey})
                    send_message(s, json.dumps(env).encode("utf-8"))
                    resp = recv_message(s, timeout=timeout)
                if not resp:
                    try:
                        log.warning("[_request_full_sync] No response from %s within %.1fs", peer, timeout)
                    except Exception:
                        pass
                    return
                
                outer = json.loads(resp.decode("utf-8"))
                try:
                    log.info("[_request_full_sync] Response from %s:%s len=%s type=%s", peer[0], peer[1], len(resp), outer.get("type"))
                except Exception:
                    pass
                if is_envelope(outer):
                    nid = outer.get("from")
                    pko = outer.get("pubkey")
                    def _resolver(qnid):
                        pk = self.peer_pubkeys.get(qnid)
                        if pk:
                            return pk
                        if isinstance(nid, str) and qnid == nid and isinstance(pko, str):
                            return pko
                        return None

                    inner = verify_and_unwrap(outer, _resolver)
                    if isinstance(nid, str) and isinstance(pko, str):
                        self.peer_pubkeys[nid] = pko
                    try:
                        log.debug("[_request_full_sync] Envelope unwrap ok from %s", nid)
                    except Exception:
                        pass
                else:
                    inner = outer
                result = process_message(self, inner, peer)
                try:
                    log.info("[_request_full_sync] Processed response from %s:%s result_keys=%s", peer[0], peer[1], list(result.keys()) if isinstance(result, dict) else type(result).__name__)
                except Exception:
                    pass
                
        except Exception:
            log.exception("[_request_full_sync] Full sync request to %s failed", peer)

    # ------------------------------ Helpers -------------------------------

    def _validate_incoming_chain(self, message: dict[str, Any]) -> bool:
        try:
            chain_data = message.get("data", [])
            if not isinstance(chain_data, list) or not chain_data:
                return False
            if chain_data[0].get('height') != 0:
                return False
            prev_h = None
            for i, b in enumerate(chain_data):
                h = b.get('height')
                if h is None or (i > 0 and h != chain_data[i-1].get('height') + 1):
                    return False
                if i > 0 and b.get('prev_block_hash') != prev_h:
                    return False
                prev_h = b.get('hash')
            return True
        except Exception:
            log.exception("[_validate_incoming_chain] Error validating incoming chain")
            return False

    # ----------------------- Communications -------------------------
    
    def _handle_hello(self, message, addr):
        role = str(message.get("role","")).strip().upper()
        try:
            peer_port = int(message.get("port"))
        except Exception:
            peer_port = None

        peer_height = message.get("height", 0)
        peer_peers  = message.get("peers", [])
        peer_addr   = (addr[0], peer_port if isinstance(peer_port,int) else None)

        if role == "NODE_STORAGE":
            s_addr = (message.get("address") or "").strip().lower()
            s_url  = (message.get("url") or "").strip()
            ip     = addr[0]
            port   = int(peer_port or 0)

            meta = {
                "addr": s_addr, "url": s_url, "ip": ip,
                "port": port, "last_seen": int(time.time()), "alive": True
            }
            with self.lock:
                if not hasattr(self, "storage_peers"):
                    self.storage_peers = {}
                if (ip, 0) in self.storage_peers and port > 0:
                    self.storage_peers.pop((ip, 0), None)
                self.storage_peers[(ip, port)] = meta
            return {
                "type": "HELLO_RESPONSE",
                "port": self.port,
                "height": self.broadcast.blockchain.height,
                "peers": [{"ip": ip, "port": p} for ip, p in self.peers if isinstance(p,int) and p>0],}

        role = str(message.get("role","")).strip().upper()
        if role == "NODE_STORAGE":
            addr_b32 = (message.get("address") or "").strip().lower()
            url      = (message.get("url") or "").strip()
            try:
                st_port = int(message.get("port") or 0)
            except Exception:
                st_port = 0

            rec = {
                "ip": addr[0],
                "port": st_port,
                "address": addr_b32,
                "url": url,
                "pubkey": (message.get("pubkey") or ""),
                "last_seen": int(time.time()),
            }
            key = addr_b32 or f"{addr[0]}:{st_port}" or addr[0]
            with self.lock:
                self.storage_peers[key] = rec

        if isinstance(peer_port, int) and peer_port > 0 and peer_port != self.port and role != "NODE_STORAGE":
            with self.lock:
                self.peers.add(peer_addr)

        # --- Merge peers sent by the counterparty (only valid ones) ---
        for pi in peer_peers:
            try:
                peer_ip = (pi.get("ip") if isinstance(pi, dict) else None) or addr[0]
                pport = (pi.get("port") if isinstance(pi, dict) else None)
                if isinstance(pport, int) and pport > 0 and pport != self.port:
                    pt = (peer_ip, pport)
                    if isinstance(pt, tuple) and len(pt) == 2:
                        with self.lock:
                            self.peers.add(pt)
            except Exception:
                pass

        with self.lock:
            self.peers = {(ip, p) for (ip, p) in self.peers if isinstance(p, int) and p > 0}
            sane_peers = [{"ip": ip, "port": p} for (ip, p) in self.peers]

        try:
            log.debug("Current peers: %s", sane_peers)
        except Exception:
            log.exception("[_handle_hello] Error logging hello")
            pass

        return {
            "type": "HELLO_RESPONSE",
            "port": self.port,
            "height": self.broadcast.blockchain.height,
            "peers": sane_peers,
        }


    def _handle_get_full_sync(self, message, addr):
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
                enc = json.dumps(full_obj, separators=(',', ':'), ensure_ascii=False).encode("utf-8")
            except Exception as e:
                return {"type": "SYNC_REDIRECT", "reason": "serialize_failed", "detail": str(e)}
            hard_cap = min(CFG.FULL_SYNC_MAX_BYTES, CFG.MAX_MSG - len(CFG.NETWORK_MAGIC))
            if len(enc) > hard_cap:
                return {
                    "type": "SYNC_REDIRECT",
                    "reason": "payload_would_exceed_limit",
                    "limit_bytes": hard_cap}
            return full_obj
        except Exception as e:
            return {"type": "SYNC_REDIRECT", "reason": "internal_error", "detail": str(e)}

    def _handle_full_sync(self, message, addr):
        try:
            now = time.time()
            if (now - getattr(self, "_last_fullsync_log", 0.0) > 5.0):
                log.info("[_handle_full_sync] Received full sync from %s:%s", addr[0], addr[1] if len(addr)>1 else 0)
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

