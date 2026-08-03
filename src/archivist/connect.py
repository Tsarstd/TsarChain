# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE
"""
RPC client for archivist <-> node (storage role) communication.
This channel is used by archivists for handshakes, info, and STOR_* RPCs to nodes/miners.
"""

import time
import json
import socket
import hashlib
import threading

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from bech32 import bech32_encode, convertbits
from typing import Optional, Dict, Any, List, Tuple, Sequence

from tsarchain.network.protocol import (
    SecureChannel,
    is_envelope,
    send_message,
    recv_message,
    build_envelope,
    verify_and_unwrap,
)
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import hash160
from tsarchain.storage.kv import iter_prefix, batch
from tsarchain.network.peers_storage import load_node_key, save_node_key


from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.connect")

manual_bootstrap: Optional[Tuple[str, int]] = None


def create_keypair(path: str) -> tuple[str, str, str]:
    load_node_key(path)
    sk = SigningKey.generate()
    vk = sk.verify_key
    priv_hex = sk.encode(encoder=HexEncoder).decode()
    pub_hex  = vk.encode(encoder=HexEncoder).decode()
    node_id  = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
    payload = {"id": node_id, "pubkey": pub_hex, "privkey": priv_hex, "created": int(time.time())}
    save_node_key(path, payload)
    return node_id, pub_hex, priv_hex


def _load_stor_peer_keys() -> dict:
    m = {}
    for k, v in iter_prefix('stor_peer_keys', b'nid:'):
        nid = k.decode('utf-8')[4:]
        m[nid] = v.decode('utf-8')
    return m


def _save_stor_peer_keys(data: Optional[dict] = None) -> None:
    payload = data if data is not None else _STOR_PEER_KEYS
    if payload is None:
        payload = {}
    with batch('stor_peer_keys') as b:
        for nid, pk in payload.items():
            b.put(f"nid:{nid}".encode('utf-8'), pk.encode('utf-8'))


def _scan_nodes(start: int = CFG.PORT_START, end: int = CFG.PORT_END, manual_nodes: Optional[Sequence[Tuple[str,int]]] = None) -> List[Tuple[str,int]]:
    kp = load_node_key(CFG.ARCHIVIST_KEY_PATH)
    if kp is None:
        node_id, pub_hex, priv_hex = create_keypair(CFG.ARCHIVIST_KEY_PATH)
    else:
        node_id = kp["id"]
        pub_hex = kp["pubkey"]
        priv_hex = kp["privkey"]

    ctx = {"net_id": CFG.DEFAULT_NET_ID, "node_id": node_id, "privkey": priv_hex}
    candidates: List[Tuple[str,int]] = []
    if manual_bootstrap:
        candidates.append(manual_bootstrap)
    if manual_nodes:
        candidates.extend(list(manual_nodes))
    for port in range(start, end + 1):
        candidates.append(("127.0.0.1", port))
    if CFG.BOOTSTRAP_NODE not in candidates:
        candidates.append(CFG.BOOTSTRAP_NODE)

    seen: set[Tuple[str,int]] = set()
    uniq: List[Tuple[str,int]] = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            uniq.append(item)

    found: List[Tuple[str,int]] = []
    for ip, port in uniq:
        if _ping_node(ip, port, node_id, pub_hex, priv_hex, ctx):
            found.append((ip, port))

    log.info("_scan_nodes: ditemukan %d storage node", len(found))
    return found


def _connect_socket(host: str, port: int, timeout: float) -> socket.socket:
    if CFG.IPV6_MODE:
        last_exc = None
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            infos = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (host, port))]
        for family, socktype, proto, _, sockaddr in infos:
            try:
                s = socket.socket(family, socktype, proto)
                s.settimeout(timeout)
                s.connect(sockaddr)
                return s
            except OSError as exc:
                last_exc = exc
                continue
        if last_exc:
            raise last_exc
        raise OSError(f"Could not connect to {host}:{port}")
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s


def _ping_node(ip: str, port: int, node_id: str, pub_hex: str, priv_hex: str, ctx: dict) -> bool:
    try:
        with _connect_socket(ip, port, CFG.CONNECT_TIMEOUT_SCAN) as s:

            ping_env = build_envelope(
                {"type": "PING"},
                ctx,
                extra={"pubkey": pub_hex}
            )

            chan = SecureChannel(
                s, role="client",
                node_id=node_id, node_pub=pub_hex, node_priv=priv_hex,
                get_pinned=lambda nid: _STOR_PEER_KEYS.get(nid),
                set_pinned=lambda nid, pk: (_STOR_PEER_KEYS.__setitem__(nid, pk), _save_stor_peer_keys())[-1]
            )
            chan.handshake()
            chan.send(json.dumps(ping_env).encode("utf-8"))

            raw = chan.recv(CFG.CONNECT_TIMEOUT_SCAN)
            if not raw:
                return False

            outer = json.loads(raw.decode("utf-8"))
            if is_envelope(outer):
                inner = verify_and_unwrap(outer, lambda nid: None)
                if isinstance(inner, dict) and inner.get("type") == "PONG":
                    return True
    except Exception as e:
        log.warning("Scan node %s:%s failed: %s", ip, port, e)
    return False


_STOR_PEER_KEYS = _load_stor_peer_keys()


class NodeDirectory:
    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self.cache: list[tuple[str,int]] = []
        self.ts = 0.0
        self.last_good: Optional[tuple[str,int]] = None
        self.lock = threading.Lock()


    def get_nodes(self) -> list[tuple[str,int]]:
        with self.lock:
            if self.cache and (time.time() - self.ts) < self.ttl:
                nodes = list(self.cache)
                if self.last_good and self.last_good in nodes:
                    nodes.remove(self.last_good)
                    nodes.insert(0, self.last_good)
                return nodes
        nodes = _scan_nodes()
        with self.lock:
            self.cache = nodes
            self.ts = time.time()
        return nodes


    def mark_good(self, peer: tuple[str,int]) -> None:
        with self.lock:
            self.last_good = peer
            if peer not in self.cache:
                self.cache.insert(0, peer)
                self.ts = time.time()


class RPC:
    def __init__(self):
        node_id, pub, priv = create_keypair(CFG.ARCHIVIST_KEY_PATH)
        self.ctx = {"net_id": CFG.DEFAULT_NET_ID, "node_id": node_id, "privkey": priv}
        self.pub = pub
        self.priv = priv
        self.node: Optional[tuple[str,int]] = None
        self.sock = None
        self.lock = threading.RLock()

        pkh = hash160(bytes.fromhex(self.pub))
        data = [0] + list(convertbits(pkh, 8, 5, True))
        self._default_address = bech32_encode(CFG.ADDRESS_PREFIX, data)
        self.trusted = False


    def set_address_override(self, addr: Optional[str]) -> None:
        if not addr:
            self.address = self._default_address
            return
        cand = addr.strip().lower()
        if not cand.startswith(CFG.ADDRESS_PREFIX):
            raise ValueError("Invalid storage payout address")
        self.address = cand


    def set_trusted(self, flag: bool) -> None:
        self.trusted = bool(flag)


    def _send(self, inner: Dict[str, Any]) -> None:
        if not self.sock:
            raise RuntimeError("no socket")
        outer = build_envelope(inner, self.ctx, extra={"pubkey": self.pub})
        send_message(self.sock, json.dumps(outer).encode("utf-8"))


    def _recv(self, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        if not self.sock:
            return None
        raw = recv_message(self.sock, timeout)
        if not raw:
            return None
        outer = json.loads(raw.decode("utf-8"))
        if is_envelope(outer):
            return verify_and_unwrap(outer, lambda nid: None)
        return outer if isinstance(outer, dict) else None


    def connect(self, ip: str, port: int, my_listen_port: int = 0) -> bool:
        with self.lock:
            self.node = (ip, port)
            
        hello = {
            "type": "HELLO",
            "role": "NODE_STORAGE",
            "pubkey": self.pub,
            "address": self.address,
            "url": "",
            "port": int(my_listen_port) if my_listen_port else 0,
            "trusted": bool(self.trusted),
        }
        _ = self.call(hello, timeout=3.0)
        pong = self.call({"type":"PING"}, timeout=3.0)
        ok = isinstance(pong, dict) and (pong.get("type") == "PONG")
        if ok:
            log.info("[RPC.connect] storage handshake ok to %s:%s listen_port=%s", ip, port, my_listen_port)
        return ok


    def call(self, inner: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any] | None:
        with self.lock:
            if not self.node:
                raise RuntimeError("Not connected")
            ip, port = self.node
        payload = build_envelope(inner, self.ctx, extra={"pubkey": self.pub})
        with _connect_socket(ip, port, timeout) as s:
            raw = None
            chan = SecureChannel(
                s, role="client",
                node_id=self.ctx.get("node_id"), node_pub=self.pub, node_priv=self.priv,
                get_pinned=lambda nid: _STOR_PEER_KEYS.get(nid),
                set_pinned=lambda nid, pk: (_STOR_PEER_KEYS.__setitem__(nid, pk), _save_stor_peer_keys())[-1]
            )
            chan.handshake()
            chan.send(json.dumps(payload).encode("utf-8"))
            raw = chan.recv(timeout)
            if not raw:
                log.debug("[RPC.call] no response type=%s to %s:%s", inner.get("type"), ip, port)
                return None
            outer = json.loads(raw.decode("utf-8"))
            if not isinstance(outer, dict):
                return None
            if is_envelope(outer):
                return verify_and_unwrap(outer, lambda nid: None)
            return outer


__all__ = ["RPC", "NodeDirectory"]
