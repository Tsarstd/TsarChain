# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import time
import json
import socket
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional, Set, Tuple

from ...core.block import Block
from ...core.tx import Tx
from ..protocol import SecureChannel, send_message
from ...utils import config as CFG


from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.gossip")


class GossipMixin:
    def _send(self, peer: Tuple[str, int], message: Dict[str, Any]) -> bool:
        port_start, port_end = int(CFG.PORT_START), int(CFG.PORT_END)
        if not (port_start <= int(peer[1]) <= port_end):
            log.debug("[_send] Skip peer %s out of port range %s-%s", peer, port_start, port_end)
            return False
        
        cache = getattr(self, "_gossip_conn_cache", None)
        cache_lock = getattr(self, "_gossip_conn_lock", None)
        if cache is None or cache_lock is None:
            cache = self._gossip_conn_cache = OrderedDict()
            cache_lock = self._gossip_conn_lock = threading.RLock()

        def _cleanup(entry: Dict[str, Any]):
            sock = entry.get("sock")
            if sock:
                try:
                    sock.close()
                except Exception:
                    log.exception("_cleanup")
                    pass

        now = time.time()
        connect_timeout = float(CFG.CONNECT_TIMEOUT)
        if connect_timeout <= 0:
            connect_timeout = float(CFG.SYNC_TIMEOUT)
        cache_ttl = max(1.0, float(getattr(CFG, "GOSSIP_CONN_TTL", 10.0)))
        max_cache = max(1, min(int(getattr(CFG, "MAX_OUTBOUND_PEERS", 16) * 2), 64))

        payload = json.dumps(self._encode(message)).encode("utf-8")
        entry = None
        with cache_lock:
            e = cache.get(peer)
            if e and (now - e.get("ts", 0.0)) < cache_ttl:
                entry = cache.pop(peer, None)
            elif e:
                cache.pop(peer, None)
                _cleanup(e)

        sock = None
        chan = None
        try:
            if entry:
                sock = entry.get("sock")
                chan = entry.get("chan")
                try:
                    sock.settimeout(0.2)
                    sock.send(b"")
                    sock.settimeout(CFG.SYNC_TIMEOUT)
                except Exception:
                    _cleanup(entry)
                    sock = None
                    chan = None

            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
                sock.settimeout(connect_timeout)
                sock.connect(peer)
                sock.settimeout(CFG.SYNC_TIMEOUT)
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        sock,
                        role="client",
                        node_id=self.node_id,
                        node_pub=self.pubkey,
                        node_priv=self.privkey,
                        get_pinned=lambda nid: self.peer_pubkeys.get(nid),
                        set_pinned=lambda nid, pk: self.peer_pubkeys.__setitem__(nid, pk),
                    )
                    chan.handshake()

            if CFG.P2P_ENC_REQUIRED and chan:
                chan.send(payload)
            else:
                send_message(sock, payload)

            fm = self._failmap.get(peer)
            if fm:
                self._failmap.pop(peer, None)

            with cache_lock:
                cache[peer] = {"sock": sock, "chan": chan, "ts": time.time()}
                while len(cache) > max_cache:
                    _, victim = cache.popitem(last=False)
                    _cleanup(victim)
            # socket kept in cache; prevent closing below
            sock = None
            return True

        except TimeoutError:
            log.info("[_send] Connect to %s timed out", peer)

        except ConnectionRefusedError:
            log.info("[_send] Connect to %s refused", peer)

        except OSError as e:
            log.warning("[_send] OSError sending to %s: %s", peer, getattr(e, "strerror", e))

        fm = self._failmap.get(peer) or {"fails": 0, "last": 0.0}
        fm["fails"] = int(fm["fails"]) + 1
        fm["last"] = time.time()
        self._failmap[peer] = fm
        if entry:
            _cleanup(entry)
        if sock is not None:
            _cleanup({"sock": sock})
        return False

    def _broadcast(
        self,
        peers: Set[Tuple[str, int]],
        message: Dict[str, Any],
        exclude: Optional[Tuple[str, int]] = None,
    ):
        success_count = 0
        attempted = 0
        skipped = 0
        start_time = time.time()
        now = start_time
        backoff_s = CFG.BROADCAST_FAIL_BACKOFF_S
        thr = CFG.BROADCAST_FAIL_THRESHOLD
        port_start, port_end = int(CFG.PORT_START), int(CFG.PORT_END)
        for peer in peers:
            if exclude and peer == exclude:
                continue
            if not (port_start <= int(peer[1]) <= port_end):
                skipped += 1
                continue

            fm = self._failmap.get(peer)
            if fm and int(fm.get("fails", 0)) >= thr and (now - float(fm.get("last", 0.0)) < backoff_s):
                log.debug("[_broadcast] Skipping %s due to backoff (fails=%s)", peer, fm.get("fails"))
                skipped += 1
                continue

            attempted += 1
            if self._send(peer, message):
                success_count += 1

        return success_count

    def broadcast_block(
        self,
        block: Block,
        peers: Set[Tuple[str, int]],
        exclude: Optional[Tuple[str, int]] = None,
        force: bool = False,
    ):
        block_id = block.hash().hex()
        with self.lock:
            if not force and block_id in self.seen_blocks:
                return 0
            self.seen_blocks.add(block_id)

        success = self._broadcast(
            peers,
            {
                "type": "NEW_BLOCK",
                "data": block.to_dict(),
                "port": getattr(self, "port", 0),
            },
            exclude,
        )

        return success

    def broadcast_tx(self, tx: Tx, peers: Set[Tuple[str, int]]):
        tx_id = tx.txid.hex()
        # Dandelion++ stem handling (optional)
        if getattr(self, "dandelion", None):
            handled = self.dandelion.handle_outbound(tx, tx_id, peers)
            if handled:
                return 1
        return self._broadcast_tx_fluff(tx, tx_id, peers)

    def _broadcast_tx_fluff(self, tx: Tx, tx_id: str, peers: Set[Tuple[str, int]], exclude: Optional[Tuple[str, int]] = None):
        with self.lock:
            if tx_id in self.seen_txs:
                return 0
            self.seen_txs.add(tx_id)

        msg = {"type": "NEW_TX", "data": tx.to_dict(), "phase": "fluff"}
        return self._broadcast(peers, msg, exclude)


__all__ = ["GossipMixin"]
