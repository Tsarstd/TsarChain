# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import json
import socket
import time
from typing import Any, Dict, Optional, Set, Tuple

from ...core.block import Block
from ...core.tx import Tx
from ..protocol import SecureChannel, send_message
from ...utils import config as CFG


from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.gossip")


class GossipMixin:
    def _send(self, peer: Tuple[str, int], message: Dict[str, Any]) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                connect_timeout = float(CFG.CONNECT_TIMEOUT)
                if connect_timeout <= 0:
                    connect_timeout = float(CFG.SYNC_TIMEOUT)

                s.settimeout(connect_timeout)
                s.connect(peer)
                s.settimeout(CFG.SYNC_TIMEOUT)
                payload = json.dumps(self._encode(message)).encode("utf-8")
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        s,
                        role="client",
                        node_id=self.node_id,
                        node_pub=self.pubkey,
                        node_priv=self.privkey,
                        get_pinned=lambda nid: self.peer_pubkeys.get(nid),
                        set_pinned=lambda nid, pk: self.peer_pubkeys.__setitem__(nid, pk),
                    )

                    chan.handshake()
                    chan.send(payload)
                else:
                    send_message(s, payload)
                try:
                    fm = self._failmap.get(peer)
                    if fm:
                        self._failmap.pop(peer, None)
                except Exception:
                    log.exception("_failmap_err")
                    pass
                return True

        except TimeoutError:
            log.info("[_send] Connect to %s timed out", peer)

        except ConnectionRefusedError:
            log.info("[_send] Connect to %s refused", peer)

        except OSError as e:
            log.warning("[_send] OSError sending to %s: %s", peer, getattr(e, "strerror", e))

        try:
            fm = self._failmap.get(peer) or {"fails": 0, "last": 0.0}
            fm["fails"] = int(fm["fails"]) + 1
            fm["last"] = time.time()
            self._failmap[peer] = fm

        except Exception:
            log.exception("fm_err")
            pass

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
        for peer in peers:
            if exclude and peer == exclude:
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
