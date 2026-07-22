import pytest
import threading
from unittest.mock import patch, MagicMock

from tsarchain.storage.utxo_logic.validate import UTXOValidationMixin

class MockUTXOValidate(UTXOValidationMixin):
    def __init__(self):
        self.utxos = {}
        self._lock = threading.RLock()
        self._dirty = False
        self._dirty_keys = set()
        self._removed_keys = set()
        self._rewrite_all = False
        self.save_called = 0
        self.index_called = 0
        self.drop_called = 0
        self.graff_called = 0
        
    def _save(self, force=False):
        self.save_called += 1
        
    def _index_entry(self, key, tx_out):
        self.index_called += 1
        
    def _drop_index_entry(self, key):
        self.drop_called += 1
        
    def _bump_version(self):
        pass
        

        
    def _record_graffiti_event(self, tx, outputs, h, bh):
        self.graff_called += 1

class MockSPK:
    def __init__(self, data):
        self.data = data
    def serialize(self):
        return self.data

class MockTxOut:
    def __init__(self, spk, amt=0):
        self.script_pubkey = spk
        self.amount = amt

def test_txid_hex():
    obj = MockUTXOValidate()
    assert obj._txid_hex(None) is None
    assert obj._txid_hex(b"\xaa\xbb") == "aabb"
    assert obj._txid_hex("string") == "string"

def test_prevout_from_txin():
    obj = MockUTXOValidate()
    in1 = MagicMock(txid="abc", vout=1)
    assert obj._prevout_from_txin(in1) == ("abc", 1)
    
    in2 = MagicMock(prev_tx="def", prev_index=2, spec=["prev_tx", "prev_index"])
    assert obj._prevout_from_txin(in2) == ("def", 2)
    
def test_is_unspendable_opreturn():
    obj = MockUTXOValidate()
    assert obj._is_unspendable_opreturn(MockTxOut(None)) is False
    assert obj._is_unspendable_opreturn(MockTxOut(MockSPK(b"\x6a\x04"))) is True
    assert obj._is_unspendable_opreturn(MockTxOut(b"\x6a")) is True
    assert obj._is_unspendable_opreturn(MockTxOut("6a04")) is True
    assert obj._is_unspendable_opreturn(MockTxOut(123)) is False

@patch("tsarchain.storage.utxo_logic.validate.H")
@patch("tsarchain.storage.utxo_logic.validate.kv_enabled", return_value=False)
def test_apply_native_ops_for_txs(mock_kv, mock_h):
    obj = MockUTXOValidate()
    
    # Mock H.native_utxo_build_ops_compact
    # op tuple: (key, amount, spk_bytes, is_coinbase, born_height)
    mock_h.native_utxo_build_ops_compact.return_value = [
        ("tx1:0", 100, b"abcd", True, 10),
        ("tx_del:0", None, b"", False, 0),
        ("bad",) # too short
    ]
    
    obj.utxos["tx_del:0"] = {}
    
    txin = MagicMock(txid="a"*64, vout=0, witness=[b"1", "aa"])
    txout = MagicMock(amount=10, script_pubkey=MockSPK(b"abcd"))
    tx = MagicMock(txid="b"*64, inputs=[txin], outputs=[txout], is_coinbase=True)
    
    res = obj._apply_native_ops_for_txs([tx], 10)
    assert res is True
    assert "tx1:0" in obj.utxos
    assert "tx_del:0" not in obj.utxos
    assert obj.save_called == 1
    assert obj.index_called == 1
    assert obj.drop_called == 1
    assert obj.graff_called == 1
    
    # Bad inputs
    bad_tx = MagicMock(txid=123) # not str or bytes
    assert obj._apply_native_ops_for_txs([bad_tx], 10) is False
    
    bad_tx2 = MagicMock(txid="b"*64, inputs=[MagicMock(txid=123)])
    assert obj._apply_native_ops_for_txs([bad_tx2], 10) is False
    
    # Test update wrapper
    obj.update([tx], 10)
    with pytest.raises(RuntimeError):
        obj.update([bad_tx], 10)

def test_add_remove():
    obj = MockUTXOValidate()
    
    obj.add("tx1", 0, MockTxOut(b"123"), is_coinbase=True)
    assert "tx1:0" in obj.utxos
    assert obj.save_called == 1
    
    obj.add("tx1", 1, MockTxOut(b"\x6a")) # unspendable
    assert "tx1:1" not in obj.utxos
    
    obj.remove("tx1", 0)
    assert "tx1:0" not in obj.utxos
    assert obj.save_called == 2
    
    # spend input
    obj.add("tx2", 1, MockTxOut(b"123"))
    obj.spend_input(MagicMock(txid="tx2", vout=1))
    assert "tx2:1" not in obj.utxos

    with pytest.raises(AttributeError):
        obj.spend_input(MagicMock(spec=[]))

def test_rebuild_from_chain():
    obj = MockUTXOValidate()
    txin = MagicMock(txid="prev", vout=0)
    txout = MagicMock(amount=10, script_pubkey=b"123", address="addr")
    tx = MagicMock(txid="tx1", is_coinbase=False, inputs=[txin], outputs=[txout])
    block = MagicMock(height=1, transactions=[tx])
    block.hash.return_value.hex.return_value = "hash1"
    
    obj.utxos["prev:0"] = {} # should be spent
    
    obj.rebuild_from_chain([block])
    assert "prev:0" not in obj.utxos
    assert "tx1:0" in obj.utxos
    assert obj.save_called == 1

def test_apply_tx_to_utxoset():
    obj = MockUTXOValidate()
    
    utxos = {
        "prev1:0": {},
        ("prev2", 0): {},
        "prev3": {0: {}},
        "addr1": [{"txid": "prev4", "vout": 0}],
        "addr2": [{"txid_hex": "prev5", "index": 0}]
    }
    
    txin1 = MagicMock(txid="prev1", vout=0)
    txin2 = MagicMock(txid="prev2", vout=0)
    txin3 = MagicMock(txid="prev3", vout=0)
    txin4 = MagicMock(txid="prev4", vout=0)
    txin5 = MagicMock(txid="prev5", vout=0)
    
    txout1 = MagicMock(amount=10, script_pubkey=MockSPK(b"123"), address="addr3")
    txout2 = MagicMock(amount=0, script_pubkey=MockSPK(b"\x6a")) # unspendable
    
    tx = MagicMock(txid="tx1", is_coinbase=False, inputs=[txin1, txin2, txin3, txin4, txin5], outputs=[txout1, txout2])
    
    # Test flat string
    u_str = {"prev1:0": {}}
    res = obj.apply_tx_to_utxoset(tx, u_str, 1)
    assert "prev1:0" not in res
    assert "tx1:0" in res
    
    # Test flat tuple
    u_tuple = {("prev2", 0): {}}
    res = obj.apply_tx_to_utxoset(tx, u_tuple, 1)
    assert ("prev2", 0) not in res
    assert ("tx1", 0) in res
    
    # Test dict
    u_dict = {"prev3": {0: {}}}
    res = obj.apply_tx_to_utxoset(tx, u_dict, 1)
    assert "prev3" not in res
    assert "tx1" in res and 0 in res["tx1"]
    
    # Test list
    u_list = {"addr1": [{"txid": "prev4", "vout": 0}]}
    res = obj.apply_tx_to_utxoset(tx, u_list, 1)
    assert "addr1" not in res
    assert "addr3" in res # added output
    
    # None
    assert obj.apply_tx_to_utxoset(tx, None) is None
