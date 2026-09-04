# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import time
import json
import socket
import threading

from ...utils import config as CFG
from .ratelimit import allow_handshake, ban_ip
from ..rpc.processing_msg import process_message
from ..protocol import (
    SecureChannel,
    build_envelope,
    is_envelope,
    sniff_first_json_frame,
    verify_and_unwrap,
)

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node_logic.server_node")


def start_server(self):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        self._server_sock = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        s.bind(("0.0.0.0", self.port))
        s.listen(8)
        s.settimeout(1.0)
        log.info("[start_server] Listening on 0.0.0.0 port %s...", self.port)
        while not self._stop.is_set():
            try:
                conn, addr = s.accept()
                try:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
                ip = addr[0]
                if ip.startswith("::ffff:"):
                    ip = ip[7:]
                now = time.time()
                if not allow_handshake(ip, now, precheck=True):
                    conn.close()
                    log.debug("[start_server] handshake precheck deny %s", ip)
                    continue
                with self.lock:
                    inbound_total = len(self.inbound_peers)
                    inbound_from_ip = self._inbound_ips.get(ip, 0)
                if inbound_total >= CFG.MAX_INBOUND_PEERS and inbound_from_ip == 0:
                    conn.close()
                    log.debug("[start_server] inbound capacity full (total) %s", ip)
                    continue
                if inbound_from_ip >= CFG.MAX_INBOUND_PER_IP:
                    conn.close()
                    log.debug("[start_server] inbound capacity full for %s", ip)
                    continue
                
                threading.Thread(target=_handle_connection, args=(self, conn, addr), daemon=True).start()
            except Exception:
                if self._stop.is_set():
                    break
                continue


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _handle_connection(self, conn, addr):
    raw_ip = addr[0]
    clean_ip = raw_ip[7:] if raw_ip.startswith("::ffff:") else raw_ip
    peer = (clean_ip, int(addr[1]) if len(addr) > 1 else 0)
    ip = peer[0]
    try:
        first = _setup_connection(self, conn, peer, ip)

        node_hint = None
        pow_proof = None
        if type(first) is dict:
            node_hint = str(first.get("from") or first.get("node_id") or "").strip().lower() or None
            pow_proof = first.get("pow")
        if not allow_handshake(ip, time.time(), node_id=node_hint, pow_proof=pow_proof):
            log.warning("[_handle_connection] handshake denied ip=%s node=%s", ip, (node_hint or "-"))
            return

        if type(first) is dict and first.get("type") == "P2P_HS1":
            _process_p2p_channel(self, conn, addr, ip, first)
        else:
            ban_ip(ip, CFG.BAN_MALICIOUS_RPC)

    except Exception:
        log.exception("[_handle_connection] Connection handler error from %s", addr)
    finally:
        _teardown_connection(self, conn, peer, ip)


def _setup_connection(self, conn, peer, ip):
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
    conn.settimeout(float(CFG.HANDSHAKE_TIMEOUT))
    with self.lock:
        self.inbound_peers.add(peer)
        self._inbound_ips[ip] = self._inbound_ips.get(ip, 0) + 1
        self.peer_scores.setdefault(peer, CFG.PEER_SCORE_START // 2)
        _, first = sniff_first_json_frame(conn, timeout=float(CFG.HANDSHAKE_TIMEOUT), peer_ip=ip, on_misbehave=ban_ip)
    return first


def _process_p2p_channel(self, conn, addr, ip, first): #NOSONAR
    chan = SecureChannel(
        conn,
        role="server",
        node_id=self.node_id,
        node_pub=self.pubkey,
        node_priv=self.privkey,
        get_pinned=self.get_pinned,
        set_pinned=self.set_pinned,
        peer_ip=ip,
        on_misbehave=ban_ip,
    )

    try:
        chan.hs_server_from_obj(first)
    except Exception:
        ban_ip(ip, CFG.BAN_MALICIOUS_RPC)
        log.warning("[_process_p2p_channel] bad P2P handshake from %s (temp-ban)", addr, exc_info=True)
        return
    
    send_fn = lambda b: chan.send(b)
    recv_fn = lambda t: chan.recv(t)
    now = time.time()
    last_log = self._last_p2p_log
    if now - last_log > 5.0:
        self._last_p2p_log = now
    conn.settimeout(None)

    while True:
        payload = recv_fn(float(CFG.RPC_CONN_TTL_SEC))
        if not payload:
            break
        
        outer = json.loads(payload.decode("utf-8"))
        msg = outer
        src_nid = None
        src_pub = None
        if is_envelope(outer):
            try:
                msg = verify_and_unwrap(outer, lambda nid: self.peer_pubkeys.get(nid))
            except Exception:
                ban_ip(ip, CFG.BAN_MALICIOUS_RPC)
                log.warning("[_process_p2p_channel] envelope verify fail from %s (temp-ban)", addr, exc_info=True)
                break
            
            src_nid = outer.get("from")
            src_pub = outer.get("pubkey")
            if type(src_nid) is str and type(src_pub) is str:
                self.peer_pubkeys[src_nid] = src_pub
                peer_pub = chan.peer_node_pub
                if peer_pub and src_pub != peer_pub:
                    log.warning("[_process_p2p_channel] Peer pubkey mismatch from %s", addr)
                    continue
                
        else:
            log.warning("[_process_p2p_channel] rejecting legacy P2P from %s", addr)
            continue

        response = process_message(self, msg, addr, src_node_id=src_nid, src_pubkey=src_pub)
        if response is not None:
            drop = bool(response.pop("drop", False)) if type(response) is dict else False
            env = build_envelope(response, self.node_ctx, extra={"pubkey": self.pubkey})
            send_fn(json.dumps(env).encode("utf-8"))
            if drop:
                break



def _teardown_connection(self, conn, peer, ip):
    with self.lock:
        self.inbound_peers.discard(peer)
        if ip in self._inbound_ips:
            remaining = self._inbound_ips.get(ip, 1) - 1
            if remaining > 0:
                self._inbound_ips[ip] = remaining
            else:
                self._inbound_ips.pop(ip, None)
    conn.close()