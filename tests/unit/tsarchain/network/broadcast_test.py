from unittest.mock import MagicMock, patch
from tsarchain.network.broadcast import Broadcast


@patch('tsarchain.network.broadcast.Blockchain')
@patch('tsarchain.network.broadcast.UTXODB')
@patch('tsarchain.network.broadcast.TxPool')
@patch('tsarchain.network.broadcast.DandelionPP')
def test_broadcast_init_with_mocks(mock_dandelion, mock_txpool, mock_utxodb_class, mock_blockchain_class):
    mock_blockchain = MagicMock()
    mock_utxodb = MagicMock()
    
    broadcast = Broadcast(blockchain=mock_blockchain, utxodb=mock_utxodb)
    
    assert broadcast.blockchain == mock_blockchain
    assert broadcast.utxodb == mock_utxodb
    mock_blockchain.attach_mempool.assert_called_once_with(broadcast.mempool)
    assert broadcast.seen_blocks == set()
    assert broadcast.seen_txs == set()
    assert broadcast._processing_blocks == set()
    
@patch('tsarchain.network.broadcast.Blockchain')
@patch('tsarchain.network.broadcast.UTXODB')
@patch('tsarchain.network.broadcast.TxPool')
@patch('tsarchain.network.broadcast.DandelionPP')
def test_broadcast_init_default(mock_dandelion, mock_txpool, mock_utxodb_class, mock_blockchain_class):
    # If ensure_utxodb exists, it will be used instead of creating a new UTXODB
    mock_blockchain_class.return_value.ensure_utxodb.return_value = None
    
    broadcast = Broadcast()
    
    assert broadcast.blockchain == mock_blockchain_class.return_value
    assert broadcast.utxodb == mock_utxodb_class.return_value
    broadcast.blockchain.attach_mempool.assert_called_once_with(broadcast.mempool)

@patch('tsarchain.network.broadcast.TxPool')
@patch('tsarchain.network.broadcast.DandelionPP')
def test_broadcast_shutdown(mock_dandelion, mock_txpool):
    mock_blockchain = MagicMock()
    mock_utxodb = MagicMock()
    
    broadcast = Broadcast(blockchain=mock_blockchain, utxodb=mock_utxodb)
    broadcast.seen_blocks.add("block1")
    broadcast.seen_txs.add("tx1")
    
    # Simulate a cached gossip connection socket
    mock_sock = MagicMock()
    broadcast._gossip_conn_cache = {"some_peer": {"sock": mock_sock}}
    
    broadcast.shutdown()
    
    assert len(broadcast.seen_blocks) == 0
    assert len(broadcast.seen_txs) == 0
    mock_blockchain.shutdown.assert_called_once()
    mock_sock.close.assert_called_once()


@patch('tsarchain.network.broadcast.TxPool')
@patch('tsarchain.network.broadcast.DandelionPP')
def test_broadcast_handler_proxy_delegation(mock_dandelion, mock_txpool):
    mock_blockchain = MagicMock()
    mock_utxodb = MagicMock()
    
    broadcast = Broadcast(blockchain=mock_blockchain, utxodb=mock_utxodb)
    
    # Verify Broadcast can access methods from its sub-handlers
    assert callable(broadcast.broadcast_block)
    assert callable(broadcast.receive_block)
    
    # Verify ReceiveHandler (via BroadcastHandlerProxy) can access GossipHandler methods
    assert callable(broadcast.receive.broadcast_block)
    assert callable(broadcast.receive.broadcast_tx_fluff)
    
    # Verify GossipHandler (via BroadcastHandlerProxy) can access ReceiveHandler methods
    assert callable(broadcast.gossip.receive_block)
    
    # Verify non-existent attribute raises AttributeError
    import pytest
    with pytest.raises(AttributeError):
        _ = broadcast.non_existent_method_xyz
    with pytest.raises(AttributeError):
        _ = broadcast.receive.non_existent_method_xyz

