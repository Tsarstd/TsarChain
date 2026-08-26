# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio

import pytest
from unittest.mock import MagicMock, patch

from tsarchain.network.cast.utxo_local import UTXOLocalHandler

class DummySync(UTXOLocalHandler):
    def __init__(self):
        self._utxo_shared = False
        self._utxo_last_flush_height = -1
        self.utxodb = MagicMock()
        self.blockchain = MagicMock()
        self.mempool = MagicMock()

@pytest.fixture
def sync():
    return DummySync()

def test_maybe_flush_local_utxo(sync):
    # Shared -> skips
    sync._utxo_shared = True
    sync.maybe_flush_local_utxo(100)
    assert sync.utxodb.flush.call_count == 0
    
    # Not shared, forced
    sync._utxo_shared = False
    sync.utxodb.flush.return_value = True
    sync.maybe_flush_local_utxo(100, force=True)
    assert sync.utxodb.flush.call_count == 1
    assert sync._utxo_last_flush_height == 100
    
    # Height None -> skips
    sync.maybe_flush_local_utxo(None)
    assert sync.utxodb.flush.call_count == 1 # unchanged
    
    # Not forced, interval hit (110 - 100 == 10)
    sync.maybe_flush_local_utxo(110)
    assert sync.utxodb.flush.call_count == 2
    assert sync._utxo_last_flush_height == 110
    
    # Interval not hit
    sync.maybe_flush_local_utxo(115)
    assert sync.utxodb.flush.call_count == 2 # unchanged

def test_rebuild_utxo_from_chain_locked(sync):
    sync._utxo_shared = True
    sync.rebuild_utxo_from_chain_locked()
    assert sync.utxodb.rebuild_from_chain.call_count == 0
    
    sync._utxo_shared = False
    sync.blockchain.chain = ["block1"]
    sync.blockchain.height = 5
    sync._clean_mempool_after_chain_replace = MagicMock()
    
    sync.rebuild_utxo_from_chain_locked()
    
    sync.utxodb.rebuild_from_chain.assert_called_once_with(["block1"])
    assert sync.utxodb.flush.call_count == 1
    sync._clean_mempool_after_chain_replace.assert_called_once()

def test_clean_mempool_after_chain_replace(sync):
    tx1 = MagicMock()
    tx1.txid.hex.return_value = "tx1_hex"
    
    tx2 = MagicMock()
    tx2.txid.hex.return_value = "tx2_hex"
    
    block_tx = MagicMock()
    block_tx.txid.hex.return_value = "tx1_hex"
    block = MagicMock()
    block.transactions = [block_tx]
    
    sync.mempool.get_all_txs.return_value = [tx1, tx2]
    sync.blockchain.chain = [block]
    
    # Method 1: has save_pool
    sync.mempool.save_pool = MagicMock()
    sync._clean_mempool_after_chain_replace()
    
    sync.mempool.save_pool.assert_called_once_with([tx2]) # tx1 is in chain
    
    # Method 2: no save_pool
    sync.mempool.save_pool = None
    sync._clean_mempool_after_chain_replace()
    
    sync.mempool.clear.assert_called_once()
    sync.mempool.add_tx.assert_called_once_with(tx2)
    sync.mempool.flush.assert_called_once()
