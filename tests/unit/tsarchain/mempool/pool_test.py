# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

from unittest.mock import patch, MagicMock
from tsarchain.mempool.pool import TxPool
from tsarchain.storage.utxo import UTXODB

@patch('tsarchain.mempool.pool.TxPool._load_storage_pool', return_value=([], {}))
@patch('tsarchain.mempool.pool.TxPool._hydrate_pool')
def test_txpool_initialization(mock_hydrate, mock_load):
    pool = TxPool(filepath=":memory:", max_size_mb=10, inherit_state=False)
    assert pool.filepath == ":memory:"
    assert pool.max_size_mb == 10
    assert pool.current_size == 0
    assert pool._dirty is False
    assert isinstance(pool.utxo, UTXODB)
    mock_load.assert_called_once()
    mock_hydrate.assert_called_once_with([])

@patch('tsarchain.mempool.pool.TxPool._load_storage_pool', return_value=([], {}))
@patch('tsarchain.mempool.pool.TxPool._hydrate_pool')
@patch('tsarchain.mempool.pool.UTXODB')
def test_txpool_inherit_state(mock_utxo_class, mock_hydrate, mock_load):
    mock_utxo_instance = MagicMock()
    mock_utxo_class.return_value = mock_utxo_instance
    pool = TxPool(filepath=":memory:", inherit_state=True, utxo_store=mock_utxo_instance)
    mock_utxo_instance._load.assert_called_once()

@patch('tsarchain.mempool.pool.TxPool._load_storage_pool', return_value=([], {}))
@patch('tsarchain.mempool.pool.TxPool._hydrate_pool')
@patch('tsarchain.mempool.pool.TxPool.flush')
def test_txpool_del(mock_flush, mock_hydrate, mock_load):
    pool = TxPool(filepath=":memory:")
    pool.__del__()
    mock_flush.assert_called_once_with(force=False)
