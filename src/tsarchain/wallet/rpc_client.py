# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import json, socket, threading, time, logging, secrets
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import tkinter as tk

# ---------------- Local Project (With Node) ----------------
from tsarchain.network.protocol import send_message, recv_message, build_envelope, verify_and_unwrap, is_envelope, SecureChannel
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet(rpc_client)")

_last_log_gate = {}


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

        if self.manual_bootstrap:
            candidates.append(self.manual_bootstrap)
        if manual_nodes:
            candidates.extend(list(manual_nodes))
        for port in range(start, end + 1):
            candidates.append(("127.0.0.1", port))
        bootstrap_nodes = tuple(getattr(CFG, "BOOTSTRAP_NODES", ()) or (CFG.BOOTSTRAP_NODE,))
        for peer in bootstrap_nodes:
            if peer not in candidates:
                candidates.append(peer)

        uniq: List[Tuple[str, int]] = []
        seen = set()
        for item in candidates:
            if item not in seen:
                seen.add(item)
                uniq.append(item)

        found: List[Tuple[str, int]] = []
        n_timeout = n_refused = n_other = 0

        for ip, port in uniq:
            try:
                self._pace()
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

            except (TimeoutError, socket.timeout):
                n_timeout += 1
                continue
            
            except ConnectionRefusedError:
                n_refused += 1
                continue
            
            except OSError as e:
                n_other += 1
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("[scan] os error for %s:%d: %s", ip, port, e)
                continue
            
            except Exception:
                n_other += 1
                log.exception("[scan] unexpected scan error for %s:%d", ip, port)
                continue

        if found:
            self.dir.set(found)

        level = logging.DEBUG if found else logging.INFO
        log.log(
            level,
            "[scan] done: %d node(s) found, %d timeout, %d refused, %d other over %d candidates",
            len(found), n_timeout, n_refused, n_other, len(uniq)
        )
        return found

    def _pace(self) -> None:
        try:
            interval = float(getattr(CFG, "WALLET_RPC_MIN_INTERVAL", 0.0) or 0.0)
        except Exception:
            interval = 0.0
        if interval <= 0.0:
            return
        with self._send_lock:
            now = time.time()
            wait = (self._last_send_ts + interval) - now
            if wait > 0:
                time.sleep(wait)
                now = time.time()
            self._last_send_ts = now


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
                log.warning("[_try_send_one] secure handshake failed, fallback to plaintext", extra=_mk_extra(f"{peer[0]}:{peer[1]}", message.get("type")))
                
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
                        log.warning("[_try_send_one] envelope verify failed (REQUIRED) -> drop", extra=_mk_extra(f"{peer[0]}:{peer[1]}", message.get("type")))
                        return None
                    self.dir.mark_good(peer)
                    return outer
            else:
                if CFG.ENVELOPE_REQUIRED:
                    log.warning("[_try_send_one] plaintext response but ENVELOPE_REQUIRED -> drop", extra=_mk_extra(f"{peer[0]}:{peer[1]}", message.get("type")))
                    return None
                self.dir.mark_good(peer)
                return outer

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req = secrets.token_hex(6)
        peers = self.dir.get() or self.scan()
        if not peers:
            if _throttle("no_peers", 10.0):
                log.warning("[send] no peers", extra=_mk_extra(req=req, rpc=message.get("type")))
            return {"error": "No peers"}

        for round_idx in (0, 1):
            targets = peers if round_idx == 0 else self.scan()
            for peer in targets:
                try:
                    self._pace()
                    resp = self._try_send_one(peer, message)
                    if resp is not None:
                        return resp
                except Exception:
                    if _throttle(f"send_err_{peer}", 5.0):
                        log.exception("[send] send error", extra=_mk_extra(f"{peer[0]}:{peer[1]}", message.get("type"), req))
                    continue

        if _throttle("no_response", 10.0):
            log.error("[send] no response from any node", extra=_mk_extra(req=req, rpc=message.get("type")))
        return {"error": "No response from any node"}

    def send_async(self, message: Dict[str, Any], callback: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        def _safe_ui_callback(resp: Optional[Dict[str, Any]]) -> None:
            try:
                callback(resp)
            except Exception:
                log.exception("[send_async] Async callback error")
                pass

        def worker():
            resp = self.send(message)
            root = self.root or (tk._get_default_root() if tk else None)
            if root is not None:
                try:
                    root.after(0, _safe_ui_callback, resp)
                    return
                except Exception:
                    pass
            _safe_ui_callback(resp)

        threading.Thread(target=worker, daemon=True).start()
