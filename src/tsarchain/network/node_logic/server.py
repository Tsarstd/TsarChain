# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import json
import socket
import threading
import time

from ...utils import config as CFG
from ..protocol import (
    SecureChannel,
    build_envelope,
    is_envelope,
    send_message,
    sniff_first_json_frame,
    verify_and_unwrap,
)
from ..rpc.processing_msg import process_message
from .ratelimit import allow_handshake

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node_logic.server")


def start_server(self):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        self._server_sock = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
        s.bind(("0.0.0.0", self.port))
        s.listen(8)
        s.settimeout(1.0)
        log.info("[start_server] Listening on port %s...", self.port)
        while not self._stop.is_set():
            try:
                conn, addr = s.accept()
                ip = addr[0]
                now = time.time()
                if not allow_handshake(ip, now):
                    conn.close()
                    log.warning("[start_server] temp-ban handshake %s", ip)
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
                
                threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True).start()
            except Exception:
                if self._stop.is_set():
                    break
                continue


def handle_connection(self, conn, addr):
    peer = (addr[0], int(addr[1]) if len(addr) > 1 else 0)
    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
        conn.settimeout(float(CFG.HANDSHAKE_TIMEOUT))
        with self.lock:
            self.inbound_peers.add(peer)
            ip = peer[0]
            self._inbound_ips[ip] = self._inbound_ips.get(ip, 0) + 1
            self.peer_scores.setdefault(peer, CFG.PEER_SCORE_START // 2)
            raw_first, first = sniff_first_json_frame(conn, timeout=float(CFG.HANDSHAKE_TIMEOUT))

        if isinstance(first, dict) and first.get("type") == "P2P_HS1":
            chan = SecureChannel(
                conn,
                role="server",
                node_id=self.node_id,
                node_pub=self.pubkey,
                node_priv=self.privkey,
                get_pinned=self._get_pinned,
                set_pinned=self._set_pinned,
            )

            chan.hs_server_from_obj(first)
            send_fn = lambda b: chan.send(b)
            recv_fn = lambda t: chan.recv(t)
            now = time.time()
            if now - getattr(self, "_last_p2p_log", 0.0) > 5.0:
                self._last_p2p_log = now
            conn.settimeout(None)

            while True:
                payload = recv_fn(10.0)
                if not payload:
                    break
                outer = json.loads(payload.decode("utf-8"))
                msg = outer
                src_nid = None
                src_pub = None
                if is_envelope(outer):
                    msg = verify_and_unwrap(outer, lambda nid: self.peer_pubkeys.get(nid))
                    src_nid = outer.get("from")
                    src_pub = outer.get("pubkey")
                    if isinstance(src_nid, str) and isinstance(src_pub, str):
                        self.peer_pubkeys[src_nid] = src_pub
                        if getattr(chan, "peer_node_pub", None) and src_pub != chan.peer_node_pub:
                            log.warning("[handle_connection] Peer pubkey mismatch from %s", addr)
                            continue
                        
                elif CFG.ENVELOPE_REQUIRED:
                    log.warning("[handle_connection] rejecting legacy P2P from %s", addr)
                    continue

                response = process_message(self, msg, addr, src_node_id=src_nid, src_pubkey=src_pub)
                if response is not None:
                    drop = bool(response.pop("drop", False)) if isinstance(response, dict) else False
                    env = build_envelope(response, self.node_ctx, extra={"pubkey": self.pubkey})
                    send_fn(json.dumps(env).encode("utf-8"))
                    if drop:
                        break
            return

        if not isinstance(first, dict):
            return

        if CFG.P2P_ENC_REQUIRED:
            return

        msg = first
        src_nid = None
        src_pub = None
        if is_envelope(first):
            msg = verify_and_unwrap(first, lambda nid: self.peer_pubkeys.get(nid))
            src_nid = first.get("from")
            src_pub = first.get("pubkey")
            if isinstance(src_nid, str) and isinstance(src_pub, str):
                self.peer_pubkeys[src_nid] = src_pub
                
        elif CFG.ENVELOPE_REQUIRED:
            log.warning(f"[handle_connection] rejecting legacy RPC from {addr}")
            return

        response = process_message(self, msg, addr, src_node_id=src_nid, src_pubkey=src_pub)
        if response is not None:
            drop = bool(response.pop("drop", False)) if isinstance(response, dict) else False
            env = build_envelope(response, self.node_ctx, extra={"pubkey": self.pubkey})
            send_message(conn, json.dumps(env).encode("utf-8"))
            if drop:
                return

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
        conn.close()


__all__ = ("start_server", "handle_connection")
