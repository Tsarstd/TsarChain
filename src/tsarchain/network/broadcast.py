# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import threading
from typing import Dict, Optional, Set, Tuple, TYPE_CHECKING

from .cast.gossip import GossipHandler
from .cast.receive import ReceiveHandler
from .cast.utxo_local import UTXOLocalHandler
from .cast.chain_utils import ChainUtilsHandler
from .cast.mempool_sync import MempoolSyncHandler

from ..storage.utxo import UTXODB
from ..mempool.pool import TxPool
from .dandelion_pp import DandelionPP
from ..consensus.blockchain import Blockchain

if TYPE_CHECKING:
    from .node import Network

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.broadcast")


class Broadcast:
    def __init__(self, blockchain=None, utxodb=None):
        self.gossip = GossipHandler(self)
        self.receive = ReceiveHandler(self)
        self.mempool_sync = MempoolSyncHandler(self)
        self.utxo_local = UTXOLocalHandler(self)
        self.chain_utils = ChainUtilsHandler(self)

        self.lock = threading.RLock()
        self.blockchain = blockchain or Blockchain()
        
        shared_utxo = utxodb
        if shared_utxo is None and hasattr(self.blockchain, "ensure_utxodb"):
            shared_utxo = self.blockchain.ensure_utxodb()

        self._utxo_shared = shared_utxo is not None
        self.utxodb = shared_utxo or UTXODB()
        
        self.mempool = TxPool(utxo_store=self.utxodb, inherit_state=True)
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
        self._utxo_last_flush_height = -1
        self.dandelion = DandelionPP(self)
        self._gossip_conn_cache: Dict = {}

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
        log.info("[shutdown] Broadcast Shutdown complete")

    def __getattr__(self, name):
        if self.__dict__.get('_in_getattr', False):
            raise AttributeError(name)
        self._in_getattr = True
        try:
            for handler in [self.gossip, self.receive, self.mempool_sync, self.utxo_local, self.chain_utils]:
                if hasattr(handler, name):
                    return getattr(handler, name)
        finally:
            self._in_getattr = False
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")


__all__ = ["Broadcast"]
