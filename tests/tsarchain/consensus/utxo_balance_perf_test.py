# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import pytest
from tsarchain.storage.utxo import UTXODB
from tsarchain.core.tx import TxOut
from tsarchain.utils.helpers import Script

def test_large_miner_balance_and_count_o1():
    db = UTXODB()
    db.utxos.clear()
    db._address_index = None
    db._addr_total_balance = {}
    db._recent_coinbases = {}
    
    miner_spk_hex = "0014" + "aa" * 20
    spk = Script.parse(bytes.fromhex(miner_spk_hex))
    # Simulate 2,000 mature coinbases (heights 0 to 1997) and 2 immature coinbases (heights 1998, 1999) at tip 1999
    tip_height = 1999
    maturity = 3
    # At tip 1999:
    # height 1999: conf = 1999 - 1999 + 1 = 1 (< 3, immature)
    # height 1998: conf = 1999 - 1998 + 1 = 2 (< 3, immature)
    # height 1997: conf = 1999 - 1997 + 1 = 3 (>= 3, mature)
    for i in range(2000):
        key = f"{i:064x}:0"
        tx_out = TxOut(1000, spk)
        entry = {"tx_out": tx_out, "is_coinbase": True, "block_height": i}
        db.utxos[key] = entry
        
    db._ensure_index_locked()
    
    start = time.perf_counter()
    count = db.count_utxos(miner_spk_hex)
    b = db.get_balance(miner_spk_hex, mode="breakdown", current_height=tip_height, maturity=maturity)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    
    assert count == 2000
    assert b["total"] == 2000 * 1000
    # 2 immature coinbases (1998 and 1999) of 1000 each = 2000
    assert b["immature"] == 2000
    assert b["mature"] == 1998 * 1000
    assert elapsed_ms < 5.0  # Must be fast sub-millisecond range
