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
from ...utils.tsar_logging import get_ctx_logger
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

log = get_ctx_logger("tsarchain.network.node_logic.server")


def start_server(self):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        self._server_sock = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
        except Exception:
            pass
        s.bind(("0.0.0.0", self.port))
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
                if not allow_handshake(ip, now):
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


def handle_connection(self, conn, addr):
    peer = (addr[0], int(addr[1]) if len(addr) > 1 else 0)
    try:
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
            conn.settimeout(float(CFG.HANDSHAKE_TIMEOUT))
        except Exception:
            pass
        with self.lock:
            self.inbound_peers.add(peer)
            ip = peer[0]
            self._inbound_ips[ip] = self._inbound_ips.get(ip, 0) + 1
            self.peer_scores.setdefault(peer, CFG.PEER_SCORE_START // 2)
            raw_first, first = sniff_first_json_frame(conn, timeout=float(CFG.HANDSHAKE_TIMEOUT))

        if isinstance(first, dict) and first.get("type") == "P2P_HS1":
            try:
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
                try:
                    now = time.time()
                    if now - getattr(self, "_last_p2p_log", 0.0) > 5.0:
                        self._last_p2p_log = now
                except Exception:
                    pass
                try:
                    conn.settimeout(None)
                except Exception:
                    pass
            except Exception:
                log.exception("[handle_connection] Handshake failed from %s ", addr)
                return

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
                        nid = outer.get("from")
                        pko = outer.get("pubkey")
                        if isinstance(nid, str) and isinstance(pko, str):
                            self.peer_pubkeys[nid] = pko
                            if getattr(chan, "peer_node_pub", None) and pko != chan.peer_node_pub:
                                log.warning("[handle_connection] Peer pubkey mismatch from %s", addr)
                                continue
                    except Exception:
                        log.warning(
                            "[handle_connection] envelope verify failed",
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

        if not isinstance(first, dict):
            return

        if CFG.P2P_ENC_REQUIRED and not CFG.ALLOW_RPC_PLAINTEXT:
            return

        msg = first
        if is_envelope(first):
            try:
                msg = verify_and_unwrap(first, lambda nid: self.peer_pubkeys.get(nid))
                nid = first.get("from")
                pko = first.get("pubkey")
                if isinstance(nid, str) and isinstance(pko, str):
                    self.peer_pubkeys[nid] = pko
            except Exception:
                log.warning(
                    "[handle_connection] envelope verify failed",
                    extra={
                        "peer": "%s:%s" % (addr[0], addr[1] if len(addr) > 1 else 0),
                        "height": int(self.broadcast.blockchain.height),
                    },
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


__all__ = ("start_server", "handle_connection")
