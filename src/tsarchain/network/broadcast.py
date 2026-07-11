# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import threading
from typing import Dict, Optional, Set, Tuple, TYPE_CHECKING

from .cast.gossip import GossipMixin
from .cast.receive import ReceiveMixin
from .cast.fullsync import FullSyncMixin
from .cast.utxo_local import UTXOLocalMixin
from .cast.chain_utils import ChainUtilsMixin
from .cast.mempool_sync import MempoolSyncMixin

from ..storage.utxo import UTXODB
from ..utils import config as CFG
from ..mempool.pool import TxPoolDB
from .dandelion_pp import DandelionPP
from ..consensus.blockchain import Blockchain

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

    def shutdown(self):
        if hasattr(self, "_gossip_conn_cache"):
            sockets_to_close = []
            for entry in getattr(self, "_gossip_conn_cache", {}).values():
                sock = entry.get("sock")
                if sock:
                    sockets_to_close.append(sock)
            for sock in sockets_to_close:
                sock.close()
                    
        with self.lock:
            self.seen_blocks.clear()
            self.seen_txs.clear()
        if hasattr(self.blockchain, "shutdown"):
            self.blockchain.shutdown()
        log.info("[shutdown] Shutdown complete")


__all__ = ["Broadcast"]
