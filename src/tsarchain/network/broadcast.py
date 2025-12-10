# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import json
import socket
import threading
from typing import Dict, Optional, Set, Tuple, TYPE_CHECKING

from .cast.chain_utils import ChainUtilsMixin
from .cast.fullsync import FullSyncMixin
from .cast.gossip import GossipMixin
from .cast.mempool_sync import MempoolSyncMixin
from .cast.receive import ReceiveMixin
from .cast.utxo_local import UTXOLocalMixin
from .dandelion_pp import DandelionPP

from .protocol import SecureChannel, is_envelope, recv_message, send_message, verify_and_unwrap
from ..consensus.blockchain import Blockchain
from ..mempool.pool import TxPoolDB
from ..storage.utxo import UTXODB
from ..utils import config as CFG

if TYPE_CHECKING:
    from .node import Network

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.broadcast")


class Broadcast(
    GossipMixin,
    ReceiveMixin,
    FullSyncMixin,
    MempoolSyncMixin,
    UTXOLocalMixin,
    ChainUtilsMixin,
):
    def __init__(self, blockchain=None, utxodb=None):
        self.lock = threading.RLock()
        self.blockchain = blockchain or Blockchain()
        shared_utxo = utxodb
        if shared_utxo is None and hasattr(self.blockchain, "get_utxo_store"):
            shared_utxo = self.blockchain.get_utxo_store()

        self._utxo_shared = shared_utxo is not None
        self.utxodb = shared_utxo or UTXODB()
        self.mempool = TxPoolDB(utxo_store=self.utxodb, inherit_state=True)
        self.state = {}
        self.seen_blocks: Set[str] = set()
        self.seen_txs: Set[str] = set()
        self._processing_blocks: Set[str] = set()

        if hasattr(self.blockchain, "attach_mempool"):
            self.blockchain.attach_mempool(self.mempool)  # type: ignore[arg-type]

        self.last_sync_time = 0
        self.port: Optional[int] = None
        self._encode = lambda m: m
        self.node_id = None
        self.pubkey = None
        self.privkey = None
        self.peer_pubkeys = {}
        self.network: Optional["Network"] = None
        self._failmap: Dict[Tuple[str, int], Dict[str, float | int]] = {}  # {peer: {"fails": int, "last": ts}}
        self._last_mempool_seq: Dict[Tuple[str, int], int] = {}
        self._utxo_flush_interval = max(1, int(CFG.UTXO_FLUSH_INTERVAL))
        self._utxo_last_flush_height = -1
        self.dandelion = DandelionPP(self)

    def _request_full_sync(self, peer: Tuple[str, int]) -> bool:
        if not CFG.ENABLE_FULL_SYNC:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CFG.SYNC_TIMEOUT)
            s.connect(peer)
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
                send_fn = lambda b: chan.send(b)
                recv_fn = lambda t: chan.recv(t)
            else:
                send_fn = lambda b: send_message(s, b)
                recv_fn = lambda t: recv_message(s, t)

            msg = {"type": "GET_FULL_SYNC", "port": getattr(self, "port", 0), "height": self.blockchain.height}
            payload = json.dumps(self._encode(msg)).encode("utf-8")
            send_fn(payload)
            resp = recv_fn(CFG.SYNC_TIMEOUT)
            if not resp:
                return False
            outer = json.loads(resp.decode("utf-8"))
            if not is_envelope(outer):
                return False
            inner = verify_and_unwrap(outer, lambda nid: None)
            if isinstance(inner, dict) and inner.get("type") == "FULL_SYNC":
                self.receive_full_sync(inner.get("data", inner))
                return True
            return False

    def shutdown(self):
        if hasattr(self, "_gossip_conn_cache"):
            for entry in list(getattr(self, "_gossip_conn_cache", {}).values()):
                sock = entry.get("sock")
                if sock:
                    sock.close()
                    
        with self.lock:
            self.seen_blocks.clear()
            self.seen_txs.clear()
        if hasattr(self.blockchain, "shutdown"):
            self.blockchain.shutdown()
        log.info("[shutdown] Shutdown complete")


__all__ = ["Broadcast"]
