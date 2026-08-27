# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import time
import json
import socket
import secrets
import logging
import threading
import tkinter as tk

from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ---------------- Local Project (With Node) ----------------
from tsarchain.utils import config as CFG
from tsarchain.network.protocol import send_message, recv_message, build_envelope, verify_and_unwrap, is_envelope, SecureChannel

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.services.rpc_kremlin")

_last_log_gate = {}


def _connect_socket(target: Tuple[str, int], timeout: float) -> socket.socket:
    host, port = str(target[0]), int(target[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def _mk_extra(peer=None, rpc=None, req=None):
    return {"peer": peer or "-", "rpc": rpc or "-", "req": req or "-"}

def _throttle(key: str, interval_sec: float) -> bool:
    now = time.time()
    last = _last_log_gate.get(key, 0.0)
    if now - last >= interval_sec:
        _last_log_gate[key] = now
        return True
    return False


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
        self.pinned_get = pinned_get or (lambda _nid: None)
        self.pinned_set = pinned_set or (lambda _nid, _pk: None)
        self.manual_bootstrap = manual_bootstrap

        self.dir = self._Dir(ttl=CFG.NODE_CACHE_TTL)
        self._send_lock = threading.Lock()
        self._last_send_ts = 0.0

    # ----------- Discovery -----------
    def scan(self, start: int = CFG.PORT_START, end: int = CFG.PORT_END, manual_nodes: Optional[Sequence[Tuple[str, int]]] = None) -> List[Tuple[str, int]]:
        candidates: List[Tuple[str, int]] = []

        def _within_range(port: int) -> bool:
            return start <= int(port) <= end

        def _append(peer: Optional[Tuple[str, int]]) -> None:
            if not peer:
                return
            ip, port = peer
            if _within_range(port):
                candidates.append((ip, int(port)))

        _append(self.manual_bootstrap)
        if manual_nodes:
            for peer in manual_nodes:
                _append(peer)

        bootstrap_nodes = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
        for peer in bootstrap_nodes:
            _append(peer)

        uniq: List[Tuple[str, int]] = []
        seen = set()
        for item in candidates:
            if item not in seen:
                seen.add(item)
                uniq.append(item)

        found: List[Tuple[str, int]] = []

        for ip, port in uniq:
            try:
                self._pace()
                with _connect_socket((ip, port), CFG.CONNECT_TIMEOUT_SCAN) as s:

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
                        log.exception("SecureChannel handshake or encrypted I/O failed for %s:%d.", ip, port)
                        raise

                    if not resp:
                        continue

                    outer = json.loads(resp.decode("utf-8"))
                    if outer.get("type") == "PONG":
                        found.append((ip, port))
                        continue

                    if is_envelope(outer):
                        try:
                            inner = verify_and_unwrap(outer, get_pubkey_by_nodeid=None)

                            if inner.get("type") == "PONG":
                                found.append((ip, port))
                                continue

                        except Exception:
                            log.exception("Failed to verify/unwrap envelope response from %s:%d.", ip, port)
                            continue

            except (TimeoutError, socket.timeout):
                continue
            
            except ConnectionRefusedError:
                continue
            
            except OSError as e:
                if log.isEnabledFor(logging.DEBUG):
                    log.exception("[scan] os error for %s:%d: %s", ip, port, e)
                continue
            
            except Exception:
                log.exception("[scan] unexpected scan error for %s:%d", ip, port)
                continue

        if found:
            self.dir.set(found)

        return found

    def _pace(self) -> None:
        interval = float(CFG.WALLET_RPC_MIN_INTERVAL or 0.0)
        if interval <= 0.0:
            return
        with self._send_lock:
            now = time.time()
            wait = (self._last_send_ts + interval) - now
            if wait > 0:
                self._last_send_ts = now + wait
            else:
                self._last_send_ts = now
                wait = 0
        if wait > 0:
            time.sleep(wait)


    # ----------- Core Send -----------
    def _try_send_one(self, peer: Tuple[str, int], message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with _connect_socket(peer, CFG.RPC_TIMEOUT) as s:
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
                log.exception("Unhandled exception")
                raise

            if not resp:
                return None
            outer = json.loads(resp.decode("utf-8"))
            if is_envelope(outer):
                try:
                    inner = verify_and_unwrap(outer, get_pubkey_by_nodeid=None)
                    self.dir.mark_good(peer)
                    return inner
                except Exception:
                    log.exception("Unhandled exception")
                    log.warning("[_try_send_one] envelope verify failed -> drop", extra=_mk_extra(f"{peer[0]}:{peer[1]}", message.get("type")))
                    return None
            else:
                log.warning("[_try_send_one] non-envelope response -> drop", extra=_mk_extra(f"{peer[0]}:{peer[1]}", message.get("type")))
                return None

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req = secrets.token_hex(6)
        did_scan = False
        peers = self.dir.get()
        if not peers:
            peers = self.scan()
            did_scan = True
        if not peers:
            if _throttle("no_peers", 10.0):
                log.warning("[send] no peers", extra=_mk_extra(req=req, rpc=message.get("type")))
            return {"error": "No peers"}

        for round_idx in (0, 1):
            if round_idx == 0:
                targets = peers
            else:
                if did_scan:
                    break
                targets = self.scan()
                did_scan = True
            for peer in targets:
                self._pace()
                resp = self._try_send_one(peer, message)
                if resp is not None:
                    return resp

        if _throttle("no_response", 10.0):
            log.error("[send] no response from any node", extra=_mk_extra(req=req, rpc=message.get("type")))
        
        return {"error": "No response from any node"}

    def send_async(self, message: Dict[str, Any], callback: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        def _safe_ui_callback(resp: Optional[Dict[str, Any]]) -> None:
            callback(resp)

        def worker():
            resp = self.send(message)
            root = self.root or (tk._get_default_root() if tk else None)
            if root is not None:
                root.after(0, _safe_ui_callback, resp)
                return
            _safe_ui_callback(resp)

        threading.Thread(target=worker, daemon=True).start()
