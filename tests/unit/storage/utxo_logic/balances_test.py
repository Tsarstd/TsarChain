import pytest
import threading
from tsarchain.storage.utxo_logic.balances import UTXOBalanceMixin

class MockScriptPubKey:
    def __init__(self, data):
        self.data = data
    def serialize(self):
        return self.data

class MockTxOutObj:
    def __init__(self, amount=0, script_pubkey=None):
        self.amount = amount
        self.script_pubkey = script_pubkey

class MockTxOutSerialize:
    def __init__(self, data):
        self.data = data
    def serialize(self):
        return self.data

class MockUTXOSet(UTXOBalanceMixin):
    def __init__(self):
        self.utxos = {}
        self._lock = threading.RLock()
        self._address_index = None
        self._key_to_spk = {}
        self.tip_height = 100

    def _get_tip_height_from_state(self):
        return self.tip_height

def test_script_hex_from_tx_out():
    obj = MockUTXOSet()
    assert obj._script_hex_from_tx_out(None) is None
    
    # tx_out has script_pubkey (which has serialize)
    tx_out = MockTxOutObj(100, MockScriptPubKey(b"\x00\x14\xab\xcd"))
    assert obj._script_hex_from_tx_out(tx_out) == "0014abcd"
    
    # tx_out has script_pubkey (which is bytes)
    tx_out2 = MockTxOutObj(100, b"\x00\x14\xab\xcd")
    assert obj._script_hex_from_tx_out(tx_out2) == "0014abcd"
    
    # tx_out has script_pubkey (which is str)
    tx_out3 = MockTxOutObj(100, "0014ABCD")
    assert obj._script_hex_from_tx_out(tx_out3) == "0014abcd"
    
    # tx_out has script_pubkey (None)
    tx_out_none = MockTxOutObj(100, None)
    assert obj._script_hex_from_tx_out(tx_out_none) is None
    
    # tx_out is dict with script_pubkey
    tx_out_dict = {"script_pubkey": "0014ABCD"}
    assert obj._script_hex_from_tx_out(tx_out_dict) == "0014abcd"
    
    # tx_out has serialize
    tx_out_ser = MockTxOutSerialize(b"\x00\x14\xab\xcd")
    assert obj._script_hex_from_tx_out(tx_out_ser) == "0014abcd"
    
    # fallback
    assert obj._script_hex_from_tx_out(MockTxOutObj(100, 123)) is None

def test_amount_from_tx_out():
    obj = MockUTXOSet()
    assert obj._amount_from_tx_out({"amount": 50}) == 50
    assert obj._amount_from_tx_out({"amount": None}) == 0
    assert obj._amount_from_tx_out({}) == 0
    assert obj._amount_from_tx_out(MockTxOutObj(amount=100)) == 100
    assert obj._amount_from_tx_out(MockTxOutObj(amount=None)) == 0

def test_normalize_target_spk_hex():
    obj = MockUTXOSet()
    # tsar bech32 - p2wpkh
    # Generate a valid bech32 string for testing:
    from bech32 import bech32_encode, convertbits
    prog_20 = [0]*20
    data_20 = [0] + convertbits(prog_20, 8, 5, True)
    addr_20 = bech32_encode("tsar", data_20)
    assert obj._normalize_target_spk_hex(addr_20) == "0014" + ("00" * 20)
    
    # tsar bech32 - p2wsh
    prog_32 = [1]*32
    data_32 = [0] + convertbits(prog_32, 8, 5, True)
    addr_32 = bech32_encode("tsar", data_32)
    assert obj._normalize_target_spk_hex(addr_32) == "0020" + ("01" * 32)
    
    # invalid hrp
    bad_hrp = bech32_encode("bc", data_20)
    with pytest.raises(ValueError, match="invalid tsar bech32 address"):
        obj._normalize_target_spk_hex(bad_hrp)
        
    # invalid length prog
    prog_bad = [0]*15
    data_bad = [0] + convertbits(prog_bad, 8, 5, True)
    addr_bad = bech32_encode("tsar", data_bad)
    with pytest.raises(ValueError, match="invalid witness program length"):
        obj._normalize_target_spk_hex(addr_bad)
        
    # Hex variations
    assert obj._normalize_target_spk_hex("00" + "ab"*20) == "00" + "ab"*20
    assert obj._normalize_target_spk_hex("00" + "ab"*32) == "00" + "ab"*32
    assert obj._normalize_target_spk_hex("0014" + "ab"*20) == "0014" + "ab"*20
    assert obj._normalize_target_spk_hex("0020" + "ab"*32) == "0020" + "ab"*32
    assert obj._normalize_target_spk_hex("something_else") == "something_else"

def test_ensure_index_locked():
    obj = MockUTXOSet()
    obj.utxos = {
        "tx1:0": {"tx_out": {"script_pubkey": "0014abcd"}},
        "tx2:0": {"tx_out": {"script_pubkey": "0014abcd"}},
        "tx3:0": {"tx_out": None},
    }
    obj._ensure_index_locked()
    assert obj._address_index is not None
    assert set(obj._address_index["0014abcd"]) == {"tx1:0", "tx2:0"}
    assert obj._key_to_spk["tx1:0"] == "0014abcd"
    
    # second call should return early
    idx = obj._address_index
    obj._ensure_index_locked()
    assert obj._address_index is idx

def test_get_index_bucket():
    obj = MockUTXOSet()
    obj.utxos = {"tx1:0": {"tx_out": {"script_pubkey": "0014abcd"}}}
    bucket = obj._get_index_bucket("0014abcd")
    assert bucket == {"tx1:0"}
    assert obj._get_index_bucket("nonexistent") == set()
    assert obj._get_index_bucket(None) == set()

def test_index_entry():
    obj = MockUTXOSet()
    # when _address_index is None
    obj._index_entry("tx1:0", {"script_pubkey": "0014abcd"})
    assert obj._address_index is None
    
    obj._ensure_index_locked()
    obj._index_entry("tx1:0", {"script_pubkey": "0014abcd"})
    assert "tx1:0" in obj._address_index["0014abcd"]

def test_drop_index_entry():
    obj = MockUTXOSet()
    obj._drop_index_entry("tx1:0") # None case
    
    obj.utxos = {"tx1:0": {"tx_out": {"script_pubkey": "0014abcd"}}, "tx2:0": {"tx_out": {"script_pubkey": "0014abcd"}}}
    obj._ensure_index_locked()
    
    obj._drop_index_entry("tx3:0") # Not in key_to_spk
    
    obj._drop_index_entry("tx1:0")
    assert "tx1:0" not in obj._address_index["0014abcd"]
    
    # drop last entry, should remove key from dict
    obj._drop_index_entry("tx2:0")
    assert "0014abcd" not in obj._address_index

def test_get_balance():
    obj = MockUTXOSet()
    spk = "0014abcd"
    obj.utxos = {
        "tx1:0": {"tx_out": {"amount": 10, "script_pubkey": "0014abcd"}, "is_coinbase": False, "block_height": 10},
        "tx2:0": {"tx_out": {"amount": 20, "script_pubkey": "0014abcd"}, "is_coinbase": True, "block_height": 90}, # immature if tip=100 and maturity=100
        "tx3:0": {"tx_out": {"amount": 40, "script_pubkey": "0014abcd"}, "is_coinbase": True, "block_height": 1},  # mature
        "tx4:0": None # empty entry
    }
    obj._ensure_index_locked()
    
    # total balance
    assert obj.get_balance(spk, mode="total", current_height=100, maturity=100) == 70
    
    # spendable balance
    assert obj.get_balance(spk, mode="spendable", current_height=100, maturity=100) == 50
    
    # dict mode
    res = obj.get_balance(spk, mode="dict", current_height=100, maturity=100)
    assert res == {"total": 70, "mature": 50, "immature": 20}
    
    # test default height
    assert obj.get_balance(spk, mode="total") == 70

def test_count_utxos():
    obj = MockUTXOSet()
    spk = "0014abcd"
    obj.utxos = {
        "tx1:0": {"tx_out": {"amount": 10, "script_pubkey": "0014abcd"}, "is_coinbase": False, "block_height": 10},
    }
    obj._ensure_index_locked()
    
    # Add a phantom entry in index
    obj._address_index[spk].add("tx2:0")
    
    assert obj.count_utxos(spk) == 1

def test_get():
    obj = MockUTXOSet()
    spk = "0014abcd"
    obj.utxos = {
        "tx1:0": {"tx_out": {"amount": 10, "script_pubkey": "0014abcd"}, "is_coinbase": False, "block_height": 10},
        "tx2:0": None
    }
    obj._ensure_index_locked()
    
    res = obj.get(spk)
    assert "tx1:0" in res
    assert res["tx1:0"]["amount"] == 10
    assert res["tx1:0"]["script_pubkey"] == spk
    assert res["tx1:0"]["is_coinbase"] is False
    assert res["tx1:0"]["block_height"] == 10
    assert "tx2:0" not in res

def test_lookup_entry():
    obj = MockUTXOSet()
    obj.utxos = {"abc:1": {"data": "yes"}}
    assert obj.lookup_entry(None, 1) is None
    assert obj.lookup_entry("ABC", 1) == {"data": "yes"}
    assert obj.lookup_entry("def", 1) is None
