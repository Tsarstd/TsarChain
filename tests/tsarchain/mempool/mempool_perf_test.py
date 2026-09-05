# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock
from tsarchain.mempool.validation import TxMempoolValidator

def test_utxo_snapshot_to_items_filters_inputs():
    validator = TxMempoolValidator()
    validator.utxo = MagicMock()
    validator.utxo._get_utxo_meta.return_value = (False, 100)
    
    # Create large mock snapshot (3,000 items)
    snapshot = {}
    for i in range(3000):
        txid_hex = f"{i:064x}"
        key = f"{txid_hex}:0"
        snapshot[key] = {
            "amount": 1000,
            "script_pubkey": "0014" + "01" * 20,
            "is_coinbase": False,
            "block_height": 100,
        }
    
    # Tx spending only 2 specific inputs
    spent_txid_1 = f"{10:064x}"
    spent_txid_2 = f"{20:064x}"
    target_keys = {f"{spent_txid_1}:0", f"{spent_txid_2}:0"}
    
    items = validator._utxo_snapshot_to_items(snapshot, target_keys=target_keys)
    assert len(items) == 2
    extracted_txids = {item[0].hex() for item in items}
    assert extracted_txids == {spent_txid_1, spent_txid_2}
