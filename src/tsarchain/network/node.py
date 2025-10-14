# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; Merkle; Signal-X3DH

import socket, threading, json, time, collections, os, hashlib
from bech32 import convertbits, bech32_decode, bech32_encode
from typing import Set, Tuple, Optional, Any
from collections import deque

# ---------------- Local Project ----------------
from ..utils import config as CFG
from .broadcast import Broadcast
from ..core.tx import Tx, TxIn, TxOut
from ..contracts.storage_nodes import StorageService
from ..utils.helpers import Script, hash160, OP_RETURN, last_pushdata
from .processing_msg import process_message
from .protocol import (send_message, recv_message,build_envelope, verify_and_unwrap,
                        load_or_create_node_keys, is_envelope, sniff_first_json_frame, SecureChannel)
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
                if isinstance(peer, tuple) and len(peer) == 2 and int(peer[1]) == int(self.port):
                    return  # never sync with self
            except Exception:
                pass
            
            sync_msg = {"type": "GET_FULL_SYNC", "port": self.port, "height": self.broadcast.blockchain.height}
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(peer)
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        s, role="client",
                        node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                        get_pinned=self._get_pinned,
                        set_pinned=self._set_pinned,
                    )
                    
                    chan.handshake()
                    chan.send(json.dumps(build_envelope(sync_msg, self.node_ctx, extra={"pubkey": self.pubkey})).encode("utf-8"))
                    resp = chan.recv(5)
                else:
                    env = build_envelope(sync_msg, self.node_ctx, extra={"pubkey": self.pubkey})
                    send_message(s, json.dumps(env).encode("utf-8"))
                    resp = recv_message(s)
                if not resp:
                    return
                
                outer = json.loads(resp.decode("utf-8"))
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
                else:
                    inner = outer
                process_message(self, inner, peer)
                
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

# ------------------------------ P2P Chat ------------------------------
    def _send_to_peer(self, peer: tuple[str,int], payload: dict) -> None:
        """Kirim satu pesan ke peer tertentu, mengikuti kebijakan envelope & P2P_ENC."""
        if not isinstance(peer, tuple) or len(peer) != 2:
            raise ValueError("bad peer")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect(peer)
            env = build_envelope(payload, self.node_ctx, extra={"pubkey": self.pubkey})
            if getattr(CFG, "ENFORCE_HELLO_PUBKEY", False) or getattr(CFG, "ENVELOPE_REQUIRED", False):
                env["pubkey"] = self.pubkey
            raw = json.dumps(env).encode("utf-8")
            if getattr(CFG, "P2P_ENC_REQUIRED", True):
                chan = SecureChannel(
                    s, role="client",
                    node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                    get_pinned=self._get_pinned, set_pinned=self._set_pinned,
                )
                chan.handshake()
                chan.send(raw)
                try: _ = chan.recv(1)
                except Exception:
                    pass
            else:
                send_message(s, raw)
                try: _ = recv_message(s, timeout=1)
                except Exception:
                    pass

    def _chat_enqueue_locked(self, to_addr: str, msg: dict) -> None:
        mb = self.chat_mailboxes.get(to_addr)
        if mb is None:
            mb = deque(maxlen=500)       # batas 500 per inbox
            self.chat_mailboxes[to_addr] = mb
        mb.append(msg)

    def _chat_seen_add_locked(self, msg_id: str) -> bool:
        if msg_id in self.chat_seen_ids: return False
        self.chat_seen_ids.add(msg_id)
        self.chat_seen_order.append(msg_id)
        if len(self.chat_seen_ids) > 5000 and self.chat_seen_order:
            old = self.chat_seen_order.popleft()
            self.chat_seen_ids.discard(old)
        return True

    def _chat_rl_ok_locked(self, from_addr: str, now: float) -> bool:
        start, cnt = self.chat_rate.get(from_addr, (0.0, 0))
        if now - start > self.chat_window_sec:
            self.chat_rate[from_addr] = (now, 1); return True
        cnt += 1
        self.chat_rate[from_addr] = (start, cnt)
        return cnt <= self.chat_burst_max

    def _relay_chat(self, msg: dict, exclude=None) -> None:
        try:
            hops = int(msg.get("hops", 0))
            if hops >= 2: return
            msg2 = dict(msg); msg2["hops"] = hops + 1
            self.broadcast._broadcast(self.peers, {"type": "CHAT_RELAY", "data": msg2}, exclude=exclude)
        except Exception:
            pass

    def _relay_chat_async(self, msg: dict, exclude=None) -> None:
        threading.Thread(target=self._relay_chat, args=(msg, exclude), daemon=True).start()
        
    def _relay_presence(self, pres: dict, exclude=None) -> None:
        try:
            hops = int(pres.get("hops", 0))
            if hops >= 2:
                return
            pres2 = dict(pres); pres2["hops"] = hops + 1
            msg = {"type": "CHAT_PRESENCE", **pres2}
            self.broadcast._broadcast(self.peers, msg, exclude=exclude)
        except Exception:
            pass

    def _relay_presence_async(self, pres: dict, exclude=None) -> None:
        threading.Thread(target=self._relay_presence, args=(pres, exclude), daemon=True).start()
        
    def _tb_now(self):
        return time.time()

    def _tb_allow(self, table, key, rate_per_window, window_s, burst, backoff_key=None):
        now = self._tb_now()
        tokens, last = table.get(key, (burst, now))
        # refill
        if now > last:
            refill = (now - last) * (rate_per_window / float(window_s))
            tokens = min(burst, tokens + refill)
        # backoff?
        if backoff_key and self.backoff_until.get(backoff_key, 0) > now:
            return False
        if tokens >= 1.0:
            table[key] = (tokens - 1.0, now)
            return True
        return False

    def _backoff(self, key, secs):
        self.backoff_until[key] = max(self._tb_now() + secs, self.backoff_until.get(key, 0))

    def _mailbox_put(self, addr, item, ttl_s, per_addr_max, global_max):
        now = time.time()
        exp = now + ttl_s
        with self.chat_lock:
            dq = self.chat_mailbox.get(addr)
            if dq is None:
                dq = collections.deque()
                self.chat_mailbox[addr] = dq
            # lazy GC per addr
            while dq and dq[0][0] <= now:
                dq.popleft(); self.chat_global_count -= 1
            if len(dq) >= per_addr_max or self.chat_global_count >= global_max:
                return False  # mailbox full
            dq.append((exp, item))
            self.chat_global_count += 1
            return True
        
    def _enqueue_rcpt(self, to_addr, kind, mid, frm, to, ts):
        item = {
            "type": "CHAT_RCPT",
            "rcpt": kind,
            "msg_id": mid,
            "from": frm,
            "to": to,
            "ts": int(ts),
        }
        self._mailbox_put(to_addr, item, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)

    def _mailbox_pull(self, addr, nmax):
        now = time.time()
        out = []
        with self.chat_lock:
            dq = self.chat_mailbox.get(addr)
            if not dq:
                return out
            # prune expired entries first
            while dq and dq[0][0] <= now:
                dq.popleft(); self.chat_global_count -= 1
            while dq and len(out) < nmax:
                exp, it = dq.popleft()
                self.chat_global_count -= 1
                if exp > now:
                    out.append(it)
        return out

    def _dedup_mid(self, from_addr, msg_id):
        if msg_id is None: 
            return False
        rec = self.chat_seen_mid.get(from_addr)
        if rec is None:
            dq = collections.deque(maxlen=self.chat_seen_max)
            st = set()
            self.chat_seen_mid[from_addr] = (dq, st)
        else:
            dq, st = rec
        if msg_id in st:
            return True
        # tambah
        dq, st = self.chat_seen_mid[from_addr]
        if len(dq) == dq.maxlen:
            old = dq.popleft(); st.discard(old)
        dq.append(msg_id); st.add(msg_id)
        return False

    def _gc_mailboxes(self):
        now = time.time()
        if now - self.chat_gc_last < 30:
            return
        with self.chat_lock:
            for addr, dq in list(self.chat_mailbox.items()):
                changed = False
                while dq and dq[0][0] <= now:
                    dq.popleft(); self.chat_global_count -= 1; changed = True
                if not dq and changed:
                    self.chat_mailbox.pop(addr, None)
            # bersihkan backoff kadaluarsa
            for k, until in list(self.backoff_until.items()):
                if until <= now:
                    self.backoff_until.pop(k, None)
        self.chat_gc_last = now

    # ------------- HISTORY HELPERS (script <-> address, scan chain) -------------

    def _txin_prevkey(self, tin) -> str:
        txid = getattr(tin, "txid", None)
        if isinstance(txid, (bytes, bytearray)):
            ptx = txid.hex()
        elif isinstance(txid, str) and len(txid) >= 64:
            ptx = txid
        else:
            p0 = getattr(tin, "prev_tx", b"")
            if isinstance(p0, (bytes, bytearray)):
                ptx = p0.hex()
            else:
                ptx = str(p0 or "")
        idx = getattr(tin, "vout", getattr(tin, "prev_index", 0))
        try:
            idx = int(idx)
        except Exception:
            idx = 0
        return f"{ptx}:{idx}"

    def _is_coinbase_tx(self, tx) -> bool:
        ins = getattr(tx, "inputs", []) or []
        if len(ins) == 0:
            return True
        first = ins[0]
        p0 = getattr(first, "txid", None)
        if isinstance(p0, (bytes, bytearray)):
            b = p0
        elif isinstance(p0, str) and len(p0) == 64:
            try:
                b = bytes.fromhex(p0)
            except Exception:
                b = b""
        else:
            b = getattr(first, "prev_tx", b"")
            if not isinstance(b, (bytes, bytearray)):
                b = b""
        return b == b"\x00" * 32

    def _spkhex_to_address(self, spk_hex: str) -> str | None:
        try:
            if isinstance(spk_hex, bytes):
                spk_hex = spk_hex.hex()
            spk_hex = spk_hex.lower()
            if spk_hex.startswith("0014") and len(spk_hex) == 44:
                prog = bytes.fromhex(spk_hex[4:])
                data = [0] + convertbits(list(prog), 8, 5, True)
                return bech32_encode(CFG.ADDRESS_PREFIX, data)
        except Exception:
            pass
        return None

    def _txout_to_address(self, txout) -> str | None:
        try:
            spk = getattr(txout, "script_pubkey", None)
            if spk is None:
                return None
            if hasattr(spk, "serialize"):
                spk_hex = spk.serialize().hex()
            elif isinstance(spk, (bytes, bytearray)):
                spk_hex = bytes(spk).hex()
            elif isinstance(spk, str):
                spk_hex = spk
            else:
                return None
            return self._spkhex_to_address(spk_hex)
        except Exception:
            return None

    def _build_outpoint_map_chain(self, chain) -> dict:
        m: dict[str, tuple[int, str]] = {}
        for b in chain:
            txs = getattr(b, "transactions", []) or []
            for tx in txs:
                txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
                for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                    amount = int(getattr(o, "amount", 0))
                    addr = self._txout_to_address(o) or ""
                    m[f"{txid}:{idx}"] = (amount, addr)
        return m

    def _build_outpoint_map(self, chain, mem) -> dict:
        m: dict[str, tuple[int, str]] = {}
        for b in chain:
            txs = getattr(b, "transactions", []) or []
            for tx in txs:
                txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
                for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                    amount = int(getattr(o, "amount", 0))
                    addr = self._txout_to_address(o) or ""
                    m[f"{txid}:{idx}"] = (amount, addr)
        for tx in mem:
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                amount = int(getattr(o, "amount", 0))
                addr = self._txout_to_address(o) or ""
                m[f"{txid}:{idx}"] = (amount, addr)
        return m

    def _find_tx_and_meta(self, txid_hex: str):
        with self.broadcast.lock:
            chain = list(self.broadcast.blockchain.chain)
            tip_height = int(self.broadcast.blockchain.height)
            mem = self.broadcast.mempool.get_all_txs()
        for tx in mem:
            txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
            if txid == txid_hex:
                return ("mempool", tx, None, 0, chain, mem, tip_height)
        for b in chain:
            h = int(getattr(b, "height", 0))
            for tx in getattr(b, "transactions", []) or []:
                txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
                if txid == txid_hex:
                    conf = max(0, tip_height - h + 1)
                    return ("chain", tx, h, conf, chain, mem, tip_height)

        return (None, None, None, 0, chain, mem, tip_height)
    
    def _get_tx_history(self, address: str, limit: int = 50, offset: int = 0,
                    direction: str | None = None, status: str | None = None) -> dict:
        try:
            if not isinstance(address, str):
                return {"items": [], "total": 0, "limit": limit, "offset": offset}

            with self.broadcast.lock:
                chain = list(self.broadcast.blockchain.chain)
                tip_height = int(self.broadcast.blockchain.height)
                mem = self.broadcast.mempool.get_all_txs()
                
            opmap_all   = self._build_outpoint_map(chain, mem)
            opmap_chain = self._build_outpoint_map_chain(chain)
            items = []

            def _append_item(tx, where, h_or_none):
                txid = tx.txid.hex() if getattr(tx, "txid", None) else ""
                is_cb = self._is_coinbase_tx(tx)
                conf = 0
                height = None
                if where == "chain":
                    height = int(h_or_none or 0)
                    conf = max(0, tip_height - height + 1)

                received_to_addr = 0
                main_recipient, max_rec_amt = None, -1
                for o in getattr(tx, "outputs", []) or []:
                    amt = int(getattr(o, "amount", 0))
                    addr_o = self._txout_to_address(o)
                    if addr_o == address:
                        received_to_addr += amt
                    else:
                        if amt > max_rec_amt:
                            max_rec_amt = amt
                            main_recipient = addr_o

                spent_from_addr = 0
                sources = set()
                for tin in getattr(tx, "inputs", []) or []:
                    key = self._txin_prevkey(tin)
                    amt_addr = opmap_all.get(key) if where == "mempool" else opmap_chain.get(key)
                    if not amt_addr:
                        continue
                    amt_prev, addr_prev = amt_addr
                    if addr_prev == address:
                        spent_from_addr += int(amt_prev)
                    elif addr_prev:
                        sources.add(addr_prev)

                if spent_from_addr > 0:
                    net_amt = spent_from_addr - received_to_addr
                    if net_amt < 0:
                        net_amt = 0
                    dirn = "out"
                    frm = address
                    to  = main_recipient if (main_recipient and main_recipient != address) else None
                elif received_to_addr > 0:
                    dirn = "in"
                    net_amt = received_to_addr
                    frm = "coinbase" if is_cb else (next(iter(sources)) if sources else None)
                    to  = address
                else:
                    return

                st = "unconfirmed" if where == "mempool" else "confirmed"
                items.append({
                    "txid": txid,
                    "direction": dirn,
                    "amount": int(net_amt),
                    "status": st,
                    "confirmations": conf,
                    "height": height,
                    "from": frm,
                    "to": to,
                })

            for tx in mem:
                _append_item(tx, "mempool", None)
            for b in chain:
                h = int(getattr(b, "height", 0))
                for tx in getattr(b, "transactions", []) or []:
                    _append_item(tx, "chain", h)
                    
            by_id = {}
            for it in items:
                tid = it.get("txid")
                if not tid:
                    continue
                prev = by_id.get(tid)
                if prev is None:
                    by_id[tid] = it
                    continue
                rank_prev = (prev.get("status") == "confirmed", int(prev.get("height") or -1))
                rank_new  = (it.get("status") == "confirmed", int(it.get("height") or -1))
                if rank_new > rank_prev:
                    by_id[tid] = it
            items = list(by_id.values())
            
            if direction in ("in", "out"):
                items = [it for it in items if it["direction"] == direction]
            if status in ("confirmed", "unconfirmed"):
                items = [it for it in items if it["status"] == status]

            def _key(it):
                st = 0 if it["status"] == "unconfirmed" else 1
                h  = it["height"] if it["height"] is not None else -1
                return (st, -h)
            items.sort(key=_key)

            total = len(items)
            start = max(0, int(offset))
            end   = max(start, int(start + max(0, int(limit))))
            items = items[start:end]

            return {"items": items, "total": total, "limit": int(limit), "offset": int(offset)}
        except Exception:
            log.exception("[_get_tx_history] Error fetching tx history")
            return {"items": [], "total": 0, "limit": limit, "offset": offset}


    def _get_tx_detail(self, txid_hex: str) -> dict:
        where, tx, height, conf, chain, mem, tip_height = self._find_tx_and_meta(txid_hex)
        if tx is None:
            return {"error": "tx not found", "txid": txid_hex}

        opmap = self._build_outpoint_map_chain(chain)
        vin = []
        total_in = 0
        is_coinbase = self._is_coinbase_tx(tx)

        if not is_coinbase:
            for tin in (getattr(tx, "inputs", []) or []):
                key = self._txin_prevkey(tin)
                amt, a = opmap.get(key, (None, None))
                if amt is not None:
                    total_in += int(amt)
                prev_txid = key.split(":")[0]
                prev_index = int(key.split(":")[1]) if ":" in key else 0
                vin.append({
                    "prev_txid": prev_txid,
                    "prev_index": prev_index,
                    "amount": None if amt is None else int(amt),
                    "address": a
                })

        vout = []
        total_out = 0
        for n, o in enumerate(getattr(tx, "outputs", []) or []):
            amt = int(getattr(o, "amount", 0))
            total_out += amt
            vout.append({
                "index": n,
                "amount": amt,
                "address": self._txout_to_address(o)
            })

        fee = None
        if not is_coinbase and vin and total_in >= total_out:
            fee = total_in - total_out

        return {
            "type": "TX_DETAIL",
            "txid": txid_hex,
            "status": "unconfirmed" if where == "mempool" else "confirmed",
            "confirmations": conf,
            "height": height,
            "is_coinbase": is_coinbase,
            "inputs": vin,
            "outputs": vout,
            "total_in": None if is_coinbase else total_in,
            "total_out": total_out,
            "fee": fee
        }

    # ----------------------- Helpers For Block (wallet - explorer tab) -------------------------

    def _bhash_hex(self, b) -> str:
        # 1) Method .hash()
        try:
            h = getattr(b, "hash", None)
            if callable(h):
                v = h()
                if isinstance(v, (bytes, bytearray)):
                    return v.hex()
                if isinstance(v, str) and len(v) >= 64:
                    return v
            elif isinstance(h, (bytes, bytearray)):
                return h.hex()
            elif isinstance(h, str) and len(h) >= 64:
                return h
        except Exception:
            pass

        # 2) Method .header() -> bytes
        try:
            hdr_fn = getattr(b, "header", None)
            if callable(hdr_fn):
                bb = hdr_fn()
                if isinstance(bb, (bytes, bytearray)) and len(bb) > 0:
                    return hashlib.sha256(hashlib.sha256(bb).digest()).hexdigest()
        except Exception:
            pass

        # 3) Header object with serialize method(s)
        try:
            hdr_obj = getattr(b, "header", None)
            if hdr_obj is not None and not callable(hdr_obj):
                for meth in ("serialize_block", "serialize", "to_bytes", "serialize_header", "serialize_header_only"):
                    fn = getattr(hdr_obj, meth, None)
                    if callable(fn):
                        try:
                            bb = fn()
                            if isinstance(bb, (bytes, bytearray)) and len(bb) > 0:
                                return hashlib.sha256(hashlib.sha256(bb).digest()).hexdigest()
                        except Exception:
                            pass
        except Exception:
            pass
        return ""

    def _extract_block_id_from_block(self, b) -> str | None:
        try:
            txs = getattr(b, "transactions", None) or []
            if not txs:
                return None

            cb = txs[0]
            if not getattr(cb, "is_coinbase", False):
                for t in txs:
                    if getattr(t, "is_coinbase", False):
                        cb = t
                        break
                else:
                    return None

            if not getattr(cb, "inputs", None):
                return None
            vin0 = cb.inputs[0]

            if hasattr(vin0.script_sig, "serialize"):
                raw = vin0.script_sig.serialize()
            elif isinstance(vin0.script_sig, (bytes, bytearray)):
                raw = bytes(vin0.script_sig)
            else:
                return None

            data = last_pushdata(raw)
            if not data:
                return None
            try:
                return data.decode("utf-8", errors="ignore") or data.hex()
            except Exception:
                return data.hex()
        except Exception:
            return None


    def _handle_get_block_hash(self, height: int) -> dict:
        try:
            with self.broadcast.lock:
                chain = list(self.broadcast.blockchain.chain)
            if height < 0 or height >= len(chain):
                return {"type": "BLOCK_HASH", "error": "height_out_of_range"}
            b = chain[height]
            hx = self._bhash_hex(b)
            return {"type": "BLOCK_HASH", "height": height, "hash": hx or ""}
        except Exception as e:
            return {"type": "BLOCK_HASH", "error": str(e)}

    def _prevhash_hex(self, b) -> str:
        for name in ("prev_hash", "previous_hash", "prev_block_hash"):
            try:
                v = getattr(b, name, None)
                if isinstance(v, (bytes, bytearray)): return v.hex()
                if isinstance(v, str): return v
            except Exception:
                pass
        try:
            hdr = getattr(b, "header", None)
            if hdr is not None:
                v = getattr(hdr, "prev_hash", None)
                if isinstance(v, (bytes, bytearray)): return v.hex()
                if isinstance(v, str): return v
        except Exception:
            pass
        return ""

    def _serialize_tx_basic(self, tx) -> dict:
        txid = ""
        try:
            tid = getattr(tx, "txid", None)
            if isinstance(tid, (bytes, bytearray)): txid = tid.hex()
            elif isinstance(tid, str): txid = tid
        except Exception:
            pass
        try:
            n_in  = len(getattr(tx, "inputs", []) or [])
            n_out = len(getattr(tx, "outputs", []) or [])
        except Exception:
            n_in, n_out = 0, 0

        vout_list = []
        try:
            for idx, o in enumerate(getattr(tx, "outputs", []) or []):
                amt = int(getattr(o, "amount", 0))
                addr = self._txout_to_address(o) or ""
                vout_list.append({"index": idx, "amount": amt, "address": addr})
        except Exception:
            pass
        
        return {"txid": txid, "vin": [{} for _ in range(n_in)], "vout": vout_list}

    def _serialize_block(self, b) -> dict:
        def _to_hex(x):
            if isinstance(x, (bytes, bytearray)):
                return x.hex()
            if isinstance(x, str):
                return x
            return None

        # Height / time / nonce / difficulty
        try:
            height = int(getattr(b, "height", getattr(b, "index", 0)))
        except Exception:
            height = None

        ts = None
        for name in ("time", "timestamp"):
            try:
                v = getattr(b, name, None)
                if v is not None:
                    ts = int(v); break
            except Exception:
                pass

        nonce = None
        for obj in (b, getattr(b, "header", None)):
            if obj is None or callable(obj):
                continue
            try:
                v = getattr(obj, "nonce", None)
                if v is not None:
                    nonce = int(v); break
            except Exception:
                pass

        diff = None
        for obj in (b, getattr(b, "header", None)):
            if obj is None or callable(obj):
                continue
            try:
                v = getattr(obj, "difficulty", None)
                if v is not None:
                    diff = v; break
            except Exception:
                pass

        # Version / bits / merkle root
        version = getattr(b, "version", None)
        bits    = getattr(b, "bits", None)
        mroot   = getattr(b, "merkle_root", None)
        if mroot is None:
            hdr = getattr(b, "header", None)
            if hdr is not None and not callable(hdr):
                mroot = getattr(hdr, "merkle_root", None)
        mroot_hex = _to_hex(mroot)

        # Transactions (light)
        txs = []
        try:
            for tx in getattr(b, "transactions", []) or []:
                txs.append(self._serialize_tx_basic(tx))
        except Exception:
            pass

        blk_id = self._extract_block_id_from_block(b)
        return {
            "type": "BLOCK",
            "block_id": blk_id,
            "hash": self._bhash_hex(b),
            "prev_hash": self._prevhash_hex(b),
            "height": height,
            "time": ts,
            "nonce": nonce,
            "difficulty": diff,
            "version": version,
            "bits": bits,
            "merkle_root": mroot_hex,
            "tx": txs,
            "tx_count": len(txs),
        }


    # ----------------------- TX template (wallet) -------------------------

    def _addr_to_spk(self, addr: str) -> Script:
        addr = (addr or "").strip()
        hrp, data = bech32_decode(addr)
        if data is None:
            raise ValueError("invalid bech32 address")
        if (hrp or "").lower() != CFG.ADDRESS_PREFIX:
            raise ValueError(f"Address HRP must be {CFG.ADDRESS_PREFIX}, got '{hrp}'")
        decoded = convertbits(data[1:], 5, 8, False)
        if decoded is None:
            raise ValueError("decode bech32 failed")
        return Script([0, bytes(decoded)])

    def _estimate_tx_size(self, n_inputs, n_outputs, segwit=True):
        return CFG.TX_BASE_VBYTES + n_inputs * CFG.SEGWIT_INPUT_VBYTES + n_outputs * CFG.SEGWIT_OUTPUT_VBYTES

    def _select_utxos_for(self, utxos: list[dict], target_amount_sat: int, fee_rate: int):
        utxos_dict = {}
        for u in utxos:
            k = f"{u['txid']}:{u['index']}"
            utxos_dict[k] = {
                "amount": int(u.get("amount", 0)),
                "script_pubkey": u.get("scriptPubKey", b"").hex(),
            }

        candidates = []
        for key, v in utxos_dict.items():
            txid_hex, idx = key.split(":")
            candidates.append({
                "txid": txid_hex,
                "index": int(idx),
                "amount": int(v["amount"]),
                "scriptPubKey": bytes.fromhex(v["script_pubkey"])
            })
        candidates.sort(key=lambda x: x["amount"])

        selected, acc = [], 0
        n_outputs = 2
        est_fee = 0
        for c in candidates:
            selected.append(c)
            acc += c["amount"]
            est_size = self._estimate_tx_size(len(selected), n_outputs, True)
            est_fee  = fee_rate * est_size
            if acc >= target_amount_sat + est_fee:
                change = acc - target_amount_sat - est_fee
                if change < CFG.DUST_THRESHOLD_SAT:
                    n_outputs = 1
                    est_fee  = fee_rate * self._estimate_tx_size(len(selected), n_outputs, True)
                    if acc < target_amount_sat + est_fee:
                        continue
                    change = 0
                return selected, est_fee, change

        raise ValueError(f"insufficient funds: have={acc}, need={target_amount_sat + est_fee}")

    def _handle_create_tx(self, from_addr, to_addr, amount, fee_rate):
        if not isinstance(from_addr, str) or not isinstance(to_addr, str):
            raise ValueError("from/to address must be string")

        amt_sat = int(amount * CFG.TSAR) if isinstance(amount, float) else int(amount)

        try:
            # Ensure latest UTXO view from disk before building
            self.broadcast.utxodb._load()
        except Exception:
            pass
        utxos_map = self.broadcast.utxodb.get(from_addr) or {}

        tip_height = self.broadcast.blockchain.height
        utxos_list = []
        for k, v in utxos_map.items():
            try:
                txid_hex, idx_str = k.split(":")
                is_cb = bool(v.get("is_coinbase", False))
                born  = int(v.get("block_height", 0))
                if is_cb:
                    confirmations = max(0, (int(tip_height) - born) + 1)
                    if confirmations < CFG.COINBASE_MATURITY:
                        continue
                utxos_list.append({
                    "txid": txid_hex,
                    "index": int(idx_str),
                    "amount": int(v.get("amount", 0)),
                    "scriptPubKey": bytes.fromhex(v.get("script_pubkey", "")),
                    "height": born,
                    "is_coinbase": is_cb,
                })
            except Exception:
                continue

        if not utxos_list:
            raise ValueError("no spendable utxos")

        from_spk = self._addr_to_spk(from_addr)
        to_spk   = self._addr_to_spk(to_addr)

        selected, fee, change = self._select_utxos_for(utxos_list, amt_sat, fee_rate)

        ins  = [TxIn(bytes.fromhex(u["txid"]), u["index"], amount=int(u["amount"])) for u in selected]
        outs = [TxOut(amt_sat, to_spk)]
        if change >= CFG.DUST_THRESHOLD_SAT:
            outs.append(TxOut(change, from_spk))
        tx = Tx(version=1, inputs=ins, outputs=outs, locktime=0, is_coinbase=False)

        input_meta = [{
            "txid": u["txid"],
            "index": u["index"],
            "amount": int(u["amount"]),
            "script_pubkey": u["scriptPubKey"].hex(),
        } for u in selected]
        return {
            "tx": tx.to_dict(),
            "inputs": input_meta,
            "fee": fee,
            "change": change,
            "from": from_addr,
            "to": to_addr,
            "amount_sat": amt_sat
        }

    def _deserialize_spk_hex(self, spk_hex: str) -> Script:
        try:
            b = bytes.fromhex((spk_hex or "").strip())
            return Script.deserialize(b)
        except Exception:
            raise ValueError("bad spk_hex")

    def _handle_create_tx_multi(self, from_addr: str, outputs: list, fee_rate: int, force_inputs: list[str] | None = None):
        if not isinstance(from_addr, str):
            raise ValueError("from must be string")
        if not isinstance(outputs, list) or not outputs:
            raise ValueError("outputs must be non-empty list")

        fee_rate = int(max(CFG.MIN_FEE_RATE_SATVB, min(fee_rate, CFG.MAX_FEE_RATE_SATVB)))
        try:
            self.broadcast.utxodb._load()
        except Exception:
            pass
        utxos_map = self.broadcast.utxodb.get(from_addr) or {}
        tip_height = self.broadcast.blockchain.height
        utxos_list = []
        for k, v in (utxos_map.items() if isinstance(utxos_map, dict) else []):
            try:
                txid_hex, idx_str = k.split(":")
                is_cb = bool(v.get("is_coinbase", False))
                born  = int(v.get("block_height", 0))
                if is_cb:
                    confirmations = max(0, (int(tip_height) - born) + 1)
                    if confirmations < CFG.COINBASE_MATURITY:
                        continue
                utxos_list.append({
                    "txid": txid_hex,
                    "index": int(idx_str),
                    "amount": int(v.get("amount", 0)),
                    "scriptPubKey": bytes.fromhex(v.get("script_pubkey", "")),
                    "height": born,
                    "is_coinbase": is_cb,
                })
            except Exception:
                continue
        
        fixed_outs: list[tuple[int, Script]] = []
        total_target = 0
        for item in outputs:
            if not isinstance(item, dict):
                raise ValueError("output item must be dict")
            amt = int(item.get("amount", 0))
            if "spk_hex" in item:
                spk = self._deserialize_spk_hex(item["spk_hex"])
            elif "opret_hex" in item:
                data = bytes.fromhex(item["opret_hex"])
                spk = Script([OP_RETURN, data])
            elif "address" in item:
                spk = self._addr_to_spk(str(item["address"]))
            else:
                raise ValueError("output item must have spk_hex/opret_hex/address")
            fixed_outs.append((amt, spk))
            total_target += max(0, amt)

        preselected = []
        pre_acc = 0
        forced_keys = set(force_inputs or [])
        utxo_by_key = {f"{u['txid']}:{u['index']}": u for u in utxos_list}
        for key in forced_keys:
            u = utxo_by_key.get(key)
            if u:
                preselected.append(u)
                pre_acc += int(u["amount"])
        if force_inputs:
            missing = [k for k in forced_keys if k not in utxo_by_key]
            if missing:
                # Global UTXO map stores entries as {"tx_out": TxOut, "is_coinbase": bool, "block_height": int}
                global_utxos = getattr(self.broadcast.utxodb, "utxos", {})
                for key in list(missing):
                    try:
                        txid_hex, idx_str = key.split(":")
                        entry = global_utxos.get(key)
                        if not entry:
                            continue
                        tx_out = entry.get("tx_out")
                        amt = int(getattr(tx_out, "amount", 0))
                        spk = getattr(tx_out, "script_pubkey", None)
                        spk_bytes = spk.serialize() if hasattr(spk, "serialize") else (spk if isinstance(spk, (bytes, bytearray)) else b"")
                        is_cb = bool(entry.get("is_coinbase", False))
                        born  = int(entry.get("block_height", 0))
                        u = {
                            "txid": txid_hex,
                            "index": int(idx_str),
                            "amount": amt,
                            "scriptPubKey": spk_bytes,
                            "height": born,
                            "is_coinbase": is_cb,
                        }
                        utxos_list.append(u)
                        utxo_by_key[key] = u
                        preselected.append(u)
                        pre_acc += amt
                        missing.remove(key)
                    except Exception:
                        continue
            if missing:
                locks = {}
                try:
                    sender_spk = self._addr_to_spk(from_addr)
                    sender_spk_bytes = sender_spk.serialize()
                except Exception:
                    sender_spk_bytes = b""
                for key in list(missing):
                    try:
                        meta = locks.get(key)
                        if not isinstance(meta, dict):
                            continue
                        if str(meta.get("owner", "")).strip().lower() != str(from_addr).strip().lower():
                            continue
                        amt = int(meta.get("amount", 0))
                        if amt <= 0 or not sender_spk_bytes:
                            continue
                        txid_hex, idx_str = key.split(":")
                        u = {
                            "txid": txid_hex,
                            "index": int(idx_str),
                            "amount": amt,
                            "scriptPubKey": sender_spk_bytes,
                            "height": 0,
                            "is_coinbase": False,
                        }
                        utxos_list.append(u)
                        utxo_by_key[key] = u
                        preselected.append(u)
                        pre_acc += amt
                        missing.remove(key)
                    except Exception:
                        continue
            if any(k not in utxo_by_key for k in forced_keys):
                raise ValueError("forced_input_missing")

        if not utxos_list and not preselected:
            raise ValueError("no spendable utxos")
        candidates = [u for u in utxos_list if f"{u['txid']}:{u['index']}" not in forced_keys]
        candidates.sort(key=lambda x: x["amount"])

        selected = list(preselected)
        acc = pre_acc
        need = total_target
        change = 0
        fee_est = 0
        def _est_fee(n_in: int, n_out: int) -> int:
            return fee_rate * self._estimate_tx_size(n_in, n_out, True)

        # Greedy accumulate
        while True:
            fee_est = _est_fee(len(selected), len(fixed_outs) + 1)
            if acc >= need + fee_est:
                change = acc - need - fee_est
                if change < CFG.DUST_THRESHOLD_SAT:
                    fee_est2 = _est_fee(len(selected), len(fixed_outs))
                    if acc >= need + fee_est2:
                        change = 0
                        fee_est = fee_est2
                    else:
                        pass
                if acc >= need + fee_est:
                    break

            if not candidates:
                raise ValueError(f"insufficient funds: have={acc}, need={need + fee_est}")
            selected.append(candidates.pop(0))
            acc += int(selected[-1]["amount"])

        from_spk = self._addr_to_spk(from_addr)
        ins  = [TxIn(bytes.fromhex(u["txid"]), u["index"], amount=int(u["amount"])) for u in selected]
        non_opret, opret_outs = [], []
        for amt, spk in fixed_outs:
            try:
                is_opret = (isinstance(spk, Script) and getattr(spk, "cmds", None) and spk.cmds and spk.cmds[0] == OP_RETURN)
            except Exception:
                is_opret = False
            (opret_outs if is_opret else non_opret).append(TxOut(amt, spk))
        outs = non_opret
        if change >= CFG.DUST_THRESHOLD_SAT:
            outs.append(TxOut(change, from_spk))
        outs.extend(opret_outs)

        tx = Tx(version=1, inputs=ins, outputs=outs, locktime=0, is_coinbase=False)
        input_meta = [{
            "txid": u["txid"],
            "index": u["index"],
            "amount": int(u["amount"]),
            "script_pubkey": u["scriptPubKey"].hex(),
        } for u in selected]

        return {
            "tx": tx.to_dict(),
            "inputs": input_meta,
            "fee": fee_est,
            "change": change,
            "from": from_addr,
            "outputs": [
                {
                    "amount": int(amt),
                    "script_pubkey": spk.serialize().hex(),
                } for (amt, spk) in fixed_outs
            ]
        }


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

