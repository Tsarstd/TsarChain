# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import tkinter as tk

# ---------------- Local Project (With Node) ----------------
from tsarchain.network.protocol import (send_message, recv_message,build_envelope, verify_and_unwrap, is_envelope, SecureChannel,)
from ..utils import config as CFG



class NodeClient:
    class _Dir:
        def __init__(self, ttl: int):
            self.ttl = ttl
            self.cache: List[Tuple[str, int]] = []
            self.ts = 0.0
            self.last_good: Optional[Tuple[str, int]] = None
            self.lock = threading.Lock()

        def get(self) -> List[Tuple[str, int]]:
            with self.lock:
                if self.cache and (time.time() - self.ts) < self.ttl:
                    nodes = list(self.cache)
                    if self.last_good and self.last_good in nodes:
                        nodes.remove(self.last_good)
                        nodes.insert(0, self.last_good)
                    return nodes
                return []

        def set(self, peers: Sequence[Tuple[str, int]]) -> None:
            with self.lock:
                self.cache = list(dict.fromkeys(peers))
                self.ts = time.time()

        def mark_good(self, peer: Tuple[str, int]) -> None:
            with self.lock:
                self.last_good = peer
                if peer not in self.cache:
                    self.cache.insert(0, peer)
                    self.ts = time.time()

    def __init__(
        self,
        cfg_module,
        user_ctx: Dict[str, Any],
        root: Optional["tk.Misc"]=None,
        logger: Optional[Any]=None,
        pinned_get: Optional[Callable[[str], Optional[str]]] = None,
        pinned_set: Optional[Callable[[str, str], None]] = None,
        manual_bootstrap: Optional[Tuple[str, int]] = None,
    ) -> None:
        
        self.cfg = cfg_module
        self.user_ctx = user_ctx
        self.user_id = str(user_ctx.get("node_id", ""))
        self.user_pub = str(user_ctx.get("pubkey", ""))
        self.user_priv = str(user_ctx.get("privkey", ""))
        self.root = root
        self.log = logger
        self.pinned_get = pinned_get or (lambda _nid: None)
        self.pinned_set = pinned_set or (lambda _nid, _pk: None)
        self.manual_bootstrap = manual_bootstrap

        self.dir = self._Dir(ttl=CFG.NODE_CACHE_TTL)

    # ----------- Discovery -----------
    def scan(self,
             start: int = CFG.PORT_START,
             end: int = CFG.PORT_END,
             manual_nodes: Optional[Sequence[Tuple[str, int]]] = None
             ) -> List[Tuple[str, int]]:
        candidates: List[Tuple[str, int]] = []
        
        if self.manual_bootstrap:
            candidates.append(self.manual_bootstrap)
        if manual_nodes:
            candidates.extend(list(manual_nodes))
        for port in range(start, end + 1):
            candidates.append(("127.0.0.1", port))
        if CFG.BOOTSTRAP_NODE not in candidates:
            candidates.append(CFG.BOOTSTRAP_NODE)

        uniq: List[Tuple[str, int]] = []
        seen = set()
        for item in candidates:
            if item not in seen:
                seen.add(item)
                uniq.append(item)

        found: List[Tuple[str, int]] = []
        for ip, port in uniq:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(CFG.CONNECT_TIMEOUT_SCAN)
                    s.connect((ip, port))
                    ping_env = build_envelope({"type": "PING"}, self.user_ctx, extra={"pubkey": self.user_pub})
                    resp = None
                    try:
                        chan = SecureChannel(
                            s, role="client",
                            node_id=self.user_id, node_pub=self.user_pub, node_priv=self.user_priv,
                            get_pinned=self.pinned_get,
                            set_pinned=self.pinned_set,
                        )
                        chan.handshake()
                        chan.send(json.dumps(ping_env).encode("utf-8"))
                        resp = chan.recv(CFG.CONNECT_TIMEOUT_SCAN)
                    except Exception:
                        if CFG.P2P_ENC_REQUIRED:
                            raise
                        send_message(s, json.dumps(ping_env).encode("utf-8"))
                        resp = recv_message(s, timeout=CFG.CONNECT_TIMEOUT_SCAN)
                    if not resp:
                        continue
                    outer = json.loads(resp.decode("utf-8"))
                    if isinstance(outer, dict) and outer.get("type") == "PONG":
                        found.append((ip, port))
                        continue
                    if is_envelope(outer):
                        try:
                            inner = verify_and_unwrap(outer, get_pubkey_by_nodeid=None)
                            if isinstance(inner, dict) and inner.get("type") == "PONG":
                                found.append((ip, port))
                                continue
                        except Exception:
                            if CFG.ENVELOPE_REQUIRED:
                                continue
                            found.append((ip, port))
                            continue
            except Exception:
                continue
        if found:
            self.dir.set(found)
        return found

    # ----------- Core Send -----------
    def _try_send_one(self, peer: Tuple[str, int], message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CFG.RPC_TIMEOUT)
            s.connect(peer)
            env = build_envelope(message, self.user_ctx, extra={"pubkey": self.user_pub})
            resp = None
            try:
                chan = SecureChannel(
                    s, role="client",
                    node_id=self.user_id, node_pub=self.user_pub, node_priv=self.user_priv,
                    get_pinned=self.pinned_get,
                    set_pinned=self.pinned_set,
                )
                chan.handshake()
                chan.send(json.dumps(env).encode("utf-8"))
                resp = chan.recv(CFG.RPC_TIMEOUT)
            except Exception:
                if CFG.P2P_ENC_REQUIRED and not CFG.ALLOW_RPC_PLAINTEXT:
                    raise
                send_message(s, json.dumps(env).encode("utf-8"))
                resp = recv_message(s, timeout=CFG.RPC_TIMEOUT)

            if not resp:
                return None
            outer = json.loads(resp.decode("utf-8"))
            if is_envelope(outer):
                try:
                    inner = verify_and_unwrap(outer, get_pubkey_by_nodeid=None)
                    self.dir.mark_good(peer)
                    return inner
                except Exception:
                    if CFG.ENVELOPE_REQUIRED:
                        return None
                    self.dir.mark_good(peer)
                    return outer
            else:
                if CFG.ENVELOPE_REQUIRED:
                    return None
                self.dir.mark_good(peer)
                return outer

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        peers = self.dir.get() or self.scan()
        if not peers:
            return {"error": "No peers"}
        for round_idx in (0, 1):
            targets = peers if round_idx == 0 else self.scan()
            for peer in targets:
                try:
                    resp = self._try_send_one(peer, message)
                    if resp is not None:
                        return resp
                except Exception:
                    continue
        return {"error": "No response from any node"}

    def send_async(self, message: Dict[str, Any],
                   callback: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        def _safe_ui_callback(resp: Optional[Dict[str, Any]]) -> None:
            try:
                callback(resp)
            except Exception as e:
                if self.log:
                    try:
                        self.log.error("Callback error: %s", e)
                    except Exception:
                        pass

        def worker():
            if self.log:
                try:
                    self.log.debug("[Node] sending: %s", message)
                except Exception:
                    pass
            resp = self.send(message)
            if self.log:
                try:
                    self.log.debug("[Node] response: %s", resp)
                except Exception:
                    pass

            root = self.root or (tk._get_default_root() if tk else None)
            if root is not None:
                try:
                    root.after(0, _safe_ui_callback, resp)
                    return
                except Exception:
                    pass
            _safe_ui_callback(resp)

        threading.Thread(target=worker, daemon=True).start()
