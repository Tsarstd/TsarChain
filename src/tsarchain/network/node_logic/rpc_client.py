# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
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

_RPC_CONN_TTL = 30.0  # seconds a cached channel/socket stays warm before re-handshake
_RPC_PREFETCH_TIMEOUT = 1.5  # quick dial timeout for pre-connect


def _rpc_request(self, peer: Tuple[str, int], payload: dict, timeout: Optional[float] = None) -> Optional[dict]:
    norm = self._normalize_peer(peer)
    if not norm:
        return None

    now = time.time()
    retry_at = self._rpc_backoff.get(norm, 0.0)
    if now < retry_at:
        log.debug("[_rpc_request] backoff active for %s (%.1fs remaining)", norm, retry_at - now)
        return None
    timeout = float(timeout or CFG.SYNC_TIMEOUT)
    cache = getattr(self, "_rpc_conn_cache", None)
    cache_lock = getattr(self, "_rpc_conn_cache_lock", None)
    max_cache = None
    try:
        max_cache = max(1, int(CFG.RPC_CONN_CACHE_MAX))
    except Exception:
        max_cache = 32
    if cache is None or cache_lock is None:
        cache = self._rpc_conn_cache = OrderedDict()
        cache_lock = self._rpc_conn_cache_lock = threading.RLock()

    def _cleanup(entry):
        sock = entry.get("sock")
        if sock:
            sock.close()

    def _send_with_channel(chan, sock):
        env = build_envelope(payload, self.node_ctx, extra={"pubkey": self.pubkey})
        if CFG.ENFORCE_HELLO_PUBKEY or CFG.ENVELOPE_REQUIRED:
            env["pubkey"] = self.pubkey
        if CFG.P2P_ENC_REQUIRED and chan:
            chan.send(json.dumps(env).encode("utf-8"))
            return chan.recv(timeout)
        send_message(sock, json.dumps(env).encode("utf-8"))
        return recv_message(sock, timeout=timeout)

    entry = None
    with cache_lock:
        e = cache.get(norm)
        if e and (now - e.get("ts", 0.0)) < _RPC_CONN_TTL:
            entry = cache.pop(norm, None)
        elif e:
            cache.pop(norm, None)
            _cleanup(e)

    resp = None
    sock_new = None
    try:
        if entry:
            sock = entry.get("sock")
            chan = entry.get("chan")
            try:
                # lightweight keepalive: if idle too long, probe socket to detect closure
                idle = now - entry.get("ts", 0.0)
                if idle > (_RPC_CONN_TTL / 2):
                    try:
                        sock.settimeout(0.1)
                        sock.send(b"")
                    except Exception:
                        raise
                sock.settimeout(timeout)
                resp = _send_with_channel(chan, sock)
                entry["ts"] = time.time()
                with cache_lock:
                    cache[norm] = entry
            except Exception:
                _cleanup(entry)
                entry = None

        if resp is None:
            sock_new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_new.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
            sock_new.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
            sock_new.settimeout(float(CFG.HANDSHAKE_TIMEOUT))
            sock_new.connect(norm)

            chan = None
            if CFG.P2P_ENC_REQUIRED:
                chan = SecureChannel(
                    sock_new,
                    role="client",
                    node_id=self.node_id,
                    node_pub=self.pubkey,
                    node_priv=self.privkey,
                    get_pinned=self._get_pinned,
                    set_pinned=self._set_pinned,
                )
                chan.handshake()

            sock_new.settimeout(timeout)
            resp = _send_with_channel(chan, sock_new)
            # cache warm channel for reuse
            with cache_lock:
                if norm in cache:
                    cache.pop(norm, None)
                cache[norm] = {"chan": chan, "sock": sock_new, "ts": time.time()}
                while len(cache) > max_cache:
                    _, victim = cache.popitem(last=False)
                    _cleanup(victim)
            sock_new = None  # cached, do not auto-close
    except (socket.timeout, ConnectionRefusedError, OSError):
        if sock_new is not None:
            sock_new.close()
        return None

    except Exception as exc:
        if sock_new is not None:
            sock_new.close()
        self._rpc_backoff[norm] = time.time() + max(5.0, float(CFG.TEMP_BAN_SECONDS))
        if isinstance(exc, AttributeError):
            log.warning("[_rpc_request] Handshake aborted by %s; backing off", norm)
        return None

    self._rpc_backoff.pop(norm, None)
    if not resp:
        return None

    outer = json.loads(resp.decode("utf-8"))
    if is_envelope(outer):
        nid = outer.get("from")
        pko = outer.get("pubkey")

        def resolver(qnid: str):
            pk = self.peer_pubkeys.get(qnid)
            if pk:
                return pk

            if isinstance(nid, str) and qnid == nid and isinstance(pko, str):
                return pko
            return None

        inner = verify_and_unwrap(outer, resolver)
        if isinstance(nid, str) and isinstance(pko, str):
            self.peer_pubkeys[nid] = pko
    else:
        inner = outer
    return inner


def _request_mempool_inline(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
    norm = self._normalize_peer(peer)
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

    resp = self._rpc_request(norm, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))
    if not resp:
        return None

    if resp.get("type") != "MEMPOOL":
        return False

    resp_mode = str(resp.get("mode", "")).strip().lower()
    if resp_mode and resp_mode not in ("inline", "inline_full"):
        log.debug("[_request_mempool_inline] unsupported mode=%s from %s", resp_mode, norm)
        return False

    txs = resp.get("txs") or resp.get("data")
    if not isinstance(txs, list):
        return False

    if txs and all(isinstance(x, (str, bytes)) for x in txs):
        log.debug("[_request_mempool_inline] txids-only response from %s", norm)
        return False

    added = 0
    for item in txs:
        tx_obj = Tx.from_dict(item) if isinstance(item, dict) else item
        if self.broadcast.mempool.add_valid_tx(tx_obj):
            added += 1

    self._peer_last_mempool_sync[norm] = now
    self._snapshot_unreachable.discard(norm)
    log.debug("[_request_mempool_inline] added=%s total=%s from %s", added, len(txs), norm)
    if added:
        self._reward_peer(norm, CFG.PEER_SCORE_REWARD)
    return True


def _request_mempool_snapshot(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
    norm = self._normalize_peer(peer)
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

    resp = self._rpc_request(norm, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))
    if not resp:
        log.debug("[_request_mempool_snapshot] no response from %s", norm)
        self._snapshot_unreachable.add(norm)
        self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)
        return None

    if resp.get("type") != "MEMPOOL_SYNC" or resp.get("status") == "error":
        self._snapshot_unreachable.add(norm)
        return False

    self._peer_last_mempool_sync[norm] = now
    self._snapshot_unreachable.discard(norm)
    if int(resp.get("count", 0)) > 0:
        self._reward_peer(norm, CFG.PEER_SCORE_REWARD)
    return True


def _request_full_sync(self, peer: Tuple[str, int], *, force: bool = False) -> bool:
    if not force and not CFG.ENABLE_FULL_SYNC:
        return self._request_mempool_snapshot(peer, force=True)

    norm = self._normalize_peer(peer)
    if not norm:
        return False

    now = time.time()
    if not force and now < self._full_sync_backoff.get(norm, 0.0):
        return False

    last_req = self._full_sync_last_request.get(norm, 0.0)
    if not force and now - last_req < CFG.FULL_SYNC_MIN_INTERVAL:
        return False

    payload = {
        "type": "GET_FULL_SYNC",
        "port": self.port,
        "height": self.broadcast.blockchain.height,
    }
    sync_start = time.time()
    resp = self._rpc_request(norm, payload, timeout=max(20.0, CFG.SYNC_TIMEOUT * 2))
    self._full_sync_last_request[norm] = now
    if not resp:
        log.info("[_request_full_sync] %s did not respond (elapsed=%.2fs)", norm, time.time() - sync_start)
        self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)
        return False

    if resp.get("type") == "SYNC_REJECT":
        retry = float(resp.get("retry_after", CFG.FULL_SYNC_BACKOFF_INITIAL))
        self._full_sync_backoff[norm] = now + min(retry, CFG.FULL_SYNC_BACKOFF_MAX)
        log.info("[_request_full_sync] %s rejected request (retry %.1fs)", norm, min(retry, CFG.FULL_SYNC_BACKOFF_MAX))
        return False

    if resp.get("type") != "FULL_SYNC":
        log.info("[_request_full_sync] %s returned unexpected type=%s", norm, resp.get("type"))
        return False

    data = resp.get("data", resp)
    ok = self.broadcast.receive_full_sync(data)
    if ok:
        self._peer_last_sync[norm] = time.time()
        self._reward_peer(norm, CFG.PEER_SCORE_REWARD * 3)
        self._full_sync_backoff.pop(norm, None)
        chain_blocks = len(data.get("chain") or [])
        utxo_entries = len(data.get("utxos") or {})
        mempool_entries = len(data.get("mempool") or [])
        log.info(
            "[_request_full_sync] Applied snapshot from %s in %.2fs (blocks=%d, utxos=%d, mempool=%d)",
            norm,
            time.time() - sync_start,
            chain_blocks,
            utxo_entries,
            mempool_entries,
        )
        return True
    self._penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)
    log.info("[_request_full_sync] Snapshot from %s failed validation (elapsed=%.2fs)", norm, time.time() - sync_start)
    return False


def _prefetch_rpc_connections(self):
    """
    Dial bootstrap/persistent peers once at startup to warm up handshake+channel.
    """
    peers = list(getattr(self, "persistent_peers", []))
    cache = getattr(self, "_rpc_conn_cache", None)
    cache_lock = getattr(self, "_rpc_conn_cache_lock", None)
    prefetched = getattr(self, "_rpc_prefetched", None)
    if cache is None or cache_lock is None or prefetched is None:
        return
    for peer in peers:
        norm = self._normalize_peer(peer)
        if not norm or norm in prefetched:
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_RPC_PREFETCH_TIMEOUT)
            sock.connect(norm)
            chan = None
            if CFG.P2P_ENC_REQUIRED:
                chan = SecureChannel(
                    sock,
                    role="client",
                    node_id=self.node_id,
                    node_pub=self.pubkey,
                    node_priv=self.privkey,
                    get_pinned=self._get_pinned,
                    set_pinned=self._set_pinned,
                )
                chan.handshake()
            sock.settimeout(float(CFG.SYNC_TIMEOUT))
            with cache_lock:
                cache[norm] = {"chan": chan, "sock": sock, "ts": time.time()}
            prefetched.add(norm)
            log.debug("[_prefetch_rpc_connections] warmed channel to %s", norm)
        except Exception:
            log.exception("error__prefetch_rpc_connections")
            sock.close()
            continue


def _prefetch_peer_channel(self, peer: Tuple[str, int]):
    """
    Warm a single peer channel (handshake + cache) with short timeout.
    """
    cache = getattr(self, "_rpc_conn_cache", None)
    cache_lock = getattr(self, "_rpc_conn_cache_lock", None)
    prefetched = getattr(self, "_rpc_prefetched", None)
    if cache is None or cache_lock is None or prefetched is None:
        return
    norm = self._normalize_peer(peer)
    if not norm or norm in prefetched:
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_RPC_PREFETCH_TIMEOUT)
        sock.connect(norm)
        chan = None
        if CFG.P2P_ENC_REQUIRED:
            chan = SecureChannel(
                sock,
                role="client",
                node_id=self.node_id,
                node_pub=self.pubkey,
                node_priv=self.privkey,
                get_pinned=self._get_pinned,
                set_pinned=self._set_pinned,
            )
            chan.handshake()
        sock.settimeout(float(CFG.SYNC_TIMEOUT))
        with cache_lock:
            cache[norm] = {"chan": chan, "sock": sock, "ts": time.time()}
        prefetched.add(norm)
        log.debug("[_prefetch_peer_channel] warmed channel to %s", norm)
    except Exception:
        log.exception("error_prefetch_peer_channel")
        sock.close()
        return


__all__ = (
    "_rpc_request",
    "_request_mempool_inline",
    "_request_mempool_snapshot",
    "_request_full_sync",
    "_prefetch_rpc_connections",
    "_prefetch_peer_channel",
)
