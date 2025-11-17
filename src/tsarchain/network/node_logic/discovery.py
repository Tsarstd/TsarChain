# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import json
import random
import socket
import time
from typing import List, Set, Tuple

from ...utils import config as CFG
from ...utils.tsar_logging import get_ctx_logger
from ..protocol import SecureChannel, build_envelope, recv_message, send_message

log = get_ctx_logger("tsarchain.network.node_logic.discovery")


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
        "peers": [{"ip": h, "port": p} for h, p in list(self.peers)[: CFG.HEADERS_FANOUT]],
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
                    s,
                    role="client",
                    node_id=self.node_id,
                    node_pub=self.pubkey,
                    node_priv=self.privkey,
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


__all__ = ("discover_peers_loop", "_attempt_hello", "_discover_peers")
