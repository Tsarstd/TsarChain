# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
from unittest.mock import patch, MagicMock

from tsarchain.network.cast.mempool_sync import MempoolSyncHandler

class DummySync(MempoolSyncHandler):
    def __init__(self):
        self.mempool = MagicMock()
        self._last_mempool_push = {}
        self._last_mempool_seq = {}
        self.port = 1234
    
    def _encode(self, msg):
        return msg
        
    def start_gossip(self, peer, payload):
        return True

@pytest.fixture
def sync():
    return DummySync()

def test_mempool_chunks(sync):
    tx1 = MagicMock(to_dict=lambda: {"txid": "T1"})
    tx2 = MagicMock(to_dict=lambda: {"txid": "T2"})
    sync.mempool.get_all_txs.return_value = [tx1, tx2]
    
    chunks = sync._mempool_chunks()
    assert len(chunks) == 1
    assert len(chunks[0]) == 2
    
    # Test artificial small max bytes
    with patch("tsarchain.network.cast.mempool_sync.CFG.MAX_MSG", 1):
        chunks = sync._mempool_chunks()
        # Even with max_msg=1, hard_cap has a max(1024, MAX_MSG) fallback!
        # So it will be 1024. If 1024 is still larger than the JSON size, it will fit in 1 chunk.
        assert len(chunks) == 1

def test_send_mempool_to_peer(sync):
    peer = ("127.0.0.1", 1111)
    
    # No TXs
    sync.mempool.get_all_txs.return_value = []
    assert sync.send_mempool_to_peer(peer, min_interval_s=0) == 0
    
    # 2 TXs
    tx1 = MagicMock(to_dict=lambda: {"txid": "T1"})
    tx2 = MagicMock(to_dict=lambda: {"txid": "T2"})
    sync.mempool.get_all_txs.return_value = [tx1, tx2]
    sync.mempool.change_seq = 1
    
    # First time, should send 2
    sent = sync.send_mempool_to_peer(peer, min_interval_s=0)
    assert sent == 2
    
    # Second time, immediately (within TTL), not forced
    sent2 = sync.send_mempool_to_peer(peer, min_interval_s=100)
    assert sent2 == 0
    
    # Force bypasses TTL
    sent3 = sync.send_mempool_to_peer(peer, min_interval_s=100, force=True)
    assert sent3 == 2
    
    # Same sequence bypasses? No, if seq is same and not forced, it's 0.
    # Set interval to 0 to bypass TTL, but keep seq same
    sync._last_mempool_seq[peer] = 1
    sent4 = sync.send_mempool_to_peer(peer, min_interval_s=0)
    assert sent4 == 0
    
    # Sequence changed
    sync.mempool.change_seq = 2
    sent5 = sync.send_mempool_to_peer(peer, min_interval_s=0)
    assert sent5 == 2
