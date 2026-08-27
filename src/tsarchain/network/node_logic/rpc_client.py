# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import json
import socket
import time
import threading
from collections import OrderedDict
from typing import Optional, Tuple

from ...core.tx import Tx
from ...utils import config as CFG
from ..protocol import SecureChannel, build_envelope, is_envelope, recv_message, send_message, verify_and_unwrap

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node_logic.rpc_client")

_RPC_CONN_TTL = float(CFG.RPC_CONN_TTL_SEC)
_RPC_PREFETCH_TIMEOUT = float(CFG.RPC_PREFETCH_TIMEOUT)



def rpc_request(self, peer: Tuple[str, int], payload: dict, timeout: Optional[float] = None) -> Optional[dict]:
    norm = self.normalize_peer(peer)
    if not norm:
        return None

    now = time.time()
    retry_at = self._rpc_backoff.get(norm, 0.0)
    if now < retry_at:
        log.debug("[rpc_request] backoff active for %s (%.1fs remaining)", norm, retry_at - now)
        return None
    timeout = float(timeout or CFG.SYNC_TIMEOUT)
    cache = self._rpc_conn_cache
    cache_lock = self._rpc_conn_cache_lock
    max_cache = max(1, int(CFG.RPC_CONN_CACHE_MAX))
    if cache is None or cache_lock is None:
        cache = self._rpc_conn_cache = OrderedDict()
        cache_lock = self._rpc_conn_cache_lock = threading.RLock()

    entry = None
    with cache_lock:
        e = cache.get(norm)
        if e and (now - e.get("ts", 0.0)) < _RPC_CONN_TTL:
            entry = cache.pop(norm, None)
        elif e:
            cache.pop(norm, None)
            _rpc_cleanup(e)
    cache_hit = entry is not None

    resp = None
    try:
        if entry:
            resp, entry = _try_cached_connection(self, norm, entry, payload, timeout, now, cache, cache_lock)

        if resp is None:
            resp = _create_new_connection(self, norm, payload, timeout, cache, cache_lock, max_cache)

        if CFG.DEBUG_BENCHMARKS and not cache_hit:
            log.debug("[rpc_conn] cache_hit=%s peer=%s new_conn=%s", cache_hit, norm, resp is not None)
    except OSError:
        return None
    except AttributeError:
        self._rpc_backoff[norm] = time.time() + max(5.0, float(CFG.TEMP_BAN_SECONDS))
        log.warning("[rpc_request] Handshake aborted by %s; backing off", norm)
        return None
    except Exception:
        self._rpc_backoff[norm] = time.time() + max(5.0, float(CFG.TEMP_BAN_SECONDS))
        return None

    self._rpc_backoff.pop(norm, None)
    if not resp:
        return None

    return _process_rpc_response(self, resp)


def request_mempool_inline(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
    norm = self.normalize_peer(peer)
    if not norm:
        return False

    now = time.time()
    min_iv = float(CFG.MEMPOOL_SYNC_MIN_INTERVAL)
    if not force and now - self._peer_last_mempool_sync.get(norm, 0.0) < min_iv:
        return None
    retry_at = self._rpc_backoff.get(norm, 0.0)
    if now < retry_at:
        return None

    payload = {
        "type": "GET_MEMPOOL",
        "mode": "inline_full",
        "port": self.port,
    }
    if self.node_id:
        payload["node_id"] = self.node_id

    resp = self.rpc_request(norm, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))
    if not resp:
        return None

    if resp.get("type") != "MEMPOOL":
        return False

    resp_mode = str(resp.get("mode", "")).strip().lower()
    if resp_mode and resp_mode not in ("inline", "inline_full"):
        return False

    txs = resp.get("txs") or resp.get("data")
    if type(txs) is not list:
        return False

    if txs and all(type(x) in (str, bytes) for x in txs):
        return False

    added = 0
    for item in txs:
        tx_obj = Tx.from_dict(item) if type(item) is dict else item
        if self.broadcast.mempool.add_valid_tx(tx_obj):
            added += 1

    self._peer_last_mempool_sync[norm] = now
    self._snapshot_unreachable.discard(norm)
    if added:
        self.reward_peer(norm, CFG.PEER_SCORE_REWARD)
    return True


def request_mempool_snapshot(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
    norm = self.normalize_peer(peer)
    if not norm:
        return False

    now = time.time()
    min_iv = float(CFG.MEMPOOL_SYNC_MIN_INTERVAL)
    if not force and now - self._peer_last_mempool_sync.get(norm, 0.0) < min_iv:
        return False

    payload = {
        "type": "GET_MEMPOOL",
        "mode": "snapshot",
        "port": self.port,
    }
    retry_at = self._rpc_backoff.get(norm, 0.0)
    if now < retry_at:
        return None
    if force:
        payload["force"] = True
        payload["min_interval"] = 0

    resp = self.rpc_request(norm, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))
    if not resp:
        log.debug("[request_mempool_snapshot] no response from %s", norm)
        self._snapshot_unreachable.add(norm)
        self.penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)
        return None

    if resp.get("type") != "MEMPOOL_SYNC" or resp.get("status") == "error":
        self._snapshot_unreachable.add(norm)
        return False

    self._peer_last_mempool_sync[norm] = now
    self._snapshot_unreachable.discard(norm)
    if int(resp.get("count", 0)) > 0:
        self.reward_peer(norm, CFG.PEER_SCORE_REWARD)
    return True


def _connect_socket(target: Tuple[str, int], timeout: float) -> socket.socket:
    host, port = str(target[0]), int(target[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def prefetch_rpc_connections(self):
    """
    Dial bootstrap/persistent peers once at startup to warm up handshake+channel.
    """
    peers = list(self.persistent_peers)
    for peer in peers:
        prefetch_peer_channel(self, peer)


def prefetch_peer_channel(self, peer: Tuple[str, int]):
    """
    Warm a single peer channel (handshake + cache) with short timeout.
    """
    cache = self._rpc_conn_cache
    cache_lock = self._rpc_conn_cache_lock
    prefetched = self._rpc_prefetched
    if cache is None or cache_lock is None or prefetched is None:
        return
    norm = self.normalize_peer(peer)
    if not norm or norm in prefetched:
        return
    sock = None
    try:
        sock = _connect_socket(norm, _RPC_PREFETCH_TIMEOUT)
        chan = SecureChannel(
            sock,
            role="client",
            node_id=self.node_id,
            node_pub=self.pubkey,
            node_priv=self.privkey,
            get_pinned=self.get_pinned,
            set_pinned=self.set_pinned,
        )
        chan.handshake()
        sock.settimeout(float(CFG.SYNC_TIMEOUT))
        with cache_lock:
            cache[norm] = {"chan": chan, "sock": sock, "ts": time.time()}
        prefetched.add(norm)
        log.debug("[prefetch_peer_channel] warmed channel to %s", norm)
    except Exception:
        log.exception("[prefetch_peer_channel]")
        if sock:
            sock.close()
        return


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _rpc_cleanup(entry):
    sock = entry.get("sock")
    if sock:
        sock.close()


def _send_with_channel(node, chan, sock, payload, timeout):
    env = build_envelope(payload, node.node_ctx, extra={"pubkey": node.pubkey})
    env["pubkey"] = node.pubkey
    if chan:
        chan.send(json.dumps(env).encode("utf-8"))
        return chan.recv(timeout)
    send_message(sock, json.dumps(env).encode("utf-8"))
    return recv_message(sock, timeout=timeout)


def _try_cached_connection(node, norm, entry, payload, timeout, now, cache, cache_lock):
    resp = None
    sock = entry.get("sock")
    chan = entry.get("chan")
    try:
        idle = now - entry.get("ts", 0.0)
        if idle > (_RPC_CONN_TTL / 2):
            sock.settimeout(0.1)
            sock.send(b"")
        sock.settimeout(timeout)
        resp = _send_with_channel(node, chan, sock, payload, timeout)
        entry["ts"] = time.time()
        with cache_lock:
            cache[norm] = entry
    except Exception:
        _rpc_cleanup(entry)
        entry = None
    return resp, entry


def _create_new_connection(node, norm, payload, timeout, cache, cache_lock, max_cache):
    sock_new = None
    success = False
    try:
        sock_new = _connect_socket(norm, float(CFG.HANDSHAKE_TIMEOUT))
        chan = SecureChannel(
            sock_new,
            role="client",
            node_id=node.node_id,
            node_pub=node.pubkey,
            node_priv=node.privkey,
            get_pinned=node.get_pinned,
            set_pinned=node.set_pinned,
        )
        chan.handshake()

        sock_new.settimeout(timeout)
        resp = _send_with_channel(node, chan, sock_new, payload, timeout)
        
        with cache_lock:
            if norm in cache:
                cache.pop(norm, None)
            cache[norm] = {"chan": chan, "sock": sock_new, "ts": time.time()}
            while len(cache) > max_cache:
                _, victim = cache.popitem(last=False)
                _rpc_cleanup(victim)
        success = True
        return resp
    finally:
        if not success and sock_new:
            sock_new.close()


def _process_rpc_response(node, resp):
    outer = json.loads(resp.decode("utf-8"))
    if not is_envelope(outer):
        return outer

    nid = outer.get("from")
    pko = outer.get("pubkey")

    def resolver(qnid: str):
        pk = node.peer_pubkeys.get(qnid)
        if pk:
            return pk
        if type(nid) is str and qnid == nid and type(pko) is str:
            return pko
        return None

    inner = verify_and_unwrap(outer, resolver)
    if type(nid) is str and type(pko) is str:
        node.peer_pubkeys[nid] = pko
    return inner