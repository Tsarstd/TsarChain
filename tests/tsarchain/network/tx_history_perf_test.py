# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import threading
import collections
import pytest
from tsarchain.network.rpc_helper.history import HistoryHandler
from tsarchain.utils.helpers import Script, spkhex_to_address

class DummyScriptPubKey:
    def __init__(self, hex_str):
        self._hex = hex_str

    def serialize(self):
        return bytes.fromhex(self._hex)

class DummyTxOut:
    def __init__(self, amount=0, script_pubkey=None):
        self.amount = amount
        self.script_pubkey = script_pubkey

class DummyTxIn:
    def __init__(self, txid=None, vout=0):
        self.txid = txid
        self.vout = vout
        self.prev_tx = txid

class DummyTx:
    def __init__(self, txid=None, inputs=None, outputs=None):
        self.txid = txid
        self.inputs = inputs or []
        self.outputs = outputs or []

class DummyBlock:
    def __init__(self, height=0, timestamp=0, transactions=None, bhash=""):
        self.height = height
        self.timestamp = timestamp
        self.transactions = transactions or []
        self.hash = bhash

def test_history_indexing_submillisecond():
    class TestHandler(HistoryHandler):
        def bhash_hex(self, block):
            h = block.hash if hasattr(block, "hash") else ""
            return h.hex() if type(h) in (bytes, bytearray) else str(h)

        def addr_to_spk(self, addr):
            # parse bech32 or return dummy
            spk_hex = self._normalize_spk_hex(addr)
            return DummyScriptPubKey(spk_hex or ("0014" + "aa" * 20))

    miner_spk_hex = "0014" + "aa" * 20
    miner_addr = spkhex_to_address(miner_spk_hex)
    assert miner_addr is not None

    # Construct 2,500 blocks with 1 coinbase transaction each to miner_spk_hex
    chain = []
    spk_obj = DummyScriptPubKey(miner_spk_hex)
    for h in range(2500):
        txid_hex = f"{h:064x}"
        cb_tx = DummyTx(
            txid=bytes.fromhex(txid_hex),
            inputs=[DummyTxIn(txid=b"\x00" * 32, vout=0)],
            outputs=[DummyTxOut(amount=25000000000, script_pubkey=spk_obj)],
        )
        block = DummyBlock(
            height=h,
            timestamp=1700000000 + h * 60,
            transactions=[cb_tx],
            bhash=f"{h:064x}",
        )
        chain.append(block)

    handler = TestHandler(network=type("Dummy", (), {})())
    handler.broadcast = type("DummyBroadcast", (), {})()
    handler.broadcast.lock = threading.RLock()
    handler.broadcast.blockchain = type("DummyBC", (), {})()
    handler.broadcast.blockchain.chain = chain
    handler.broadcast.blockchain.height = 2499
    handler.broadcast.mempool = type("DummyMempool", (), {})()
    handler.broadcast.mempool.get_all_txs = lambda: []
    handler.broadcast.mempool.change_seq = 0

    # First lookup will trigger initial forward index build
    start = time.perf_counter()
    res1 = handler.process_history_lookup(miner_addr, limit=50)
    elapsed_init_ms = (time.perf_counter() - start) * 1000.0

    assert res1.get("total") == 2500
    assert len(res1.get("items", [])) == 50
    # Latest item should be height 2499 with 1 confirmation
    assert res1["items"][0]["height"] == 2499
    assert res1["items"][0]["confirmations"] == 1

    # Subsequent queries must be ultra fast sub-millisecond (< 3.0 ms)
    start = time.perf_counter()
    res2 = handler.process_history_lookup(miner_addr, limit=100)
    elapsed_subsequent_ms = (time.perf_counter() - start) * 1000.0

    assert len(res2.get("items", [])) == 100
    assert elapsed_subsequent_ms < 3.0

    # Test limit=1500
    res_1500 = handler.process_history_lookup(miner_addr, limit=1500)
    assert len(res_1500.get("items", [])) == 1500
    assert res_1500.get("total") == 2500

    # Simulate block 2500 being mined
    new_cb = DummyTx(
        txid=bytes.fromhex(f"{2500:064x}"),
        inputs=[DummyTxIn(txid=b"\x00" * 32, vout=0)],
        outputs=[DummyTxOut(amount=25000000000, script_pubkey=spk_obj)],
    )
    new_block = DummyBlock(
        height=2500,
        timestamp=1700000000 + 2500 * 60,
        transactions=[new_cb],
        bhash=f"{2500:064x}",
    )
    chain.append(new_block)
    handler.broadcast.blockchain.height = 2500

    # Lookup on newly mined block should incrementally index in < 3.0 ms
    start = time.perf_counter()
    res3 = handler.process_history_lookup(miner_addr, limit=10)
    elapsed_inc_ms = (time.perf_counter() - start) * 1000.0

    assert res3.get("total") == 2501
    assert len(res3.get("items", [])) == 10
    assert res3["items"][0]["height"] == 2500
    assert res3["items"][0]["confirmations"] == 1
    assert res3["items"][1]["height"] == 2499
    assert res3["items"][1]["confirmations"] == 2  # Height 2499 now has 2 confirmations
    assert elapsed_inc_ms < 3.0
