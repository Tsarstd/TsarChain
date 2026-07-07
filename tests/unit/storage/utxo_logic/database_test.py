import json
import threading
from unittest.mock import patch

from tsarchain.storage.utxo_logic.database import UTXODatabaseMixin

class MockTxOut:
    def __init__(self, amount=0, script_pubkey=None):
        self.amount = amount
        self.script_pubkey = script_pubkey
        
    def to_dict(self):
        return {"amount": self.amount, "script_pubkey": self.script_pubkey.serialize().hex() if hasattr(self.script_pubkey, "serialize") else self.script_pubkey}

    @classmethod
    def from_dict(cls, data):
        return cls(amount=data.get("amount", 0), script_pubkey=data.get("script_pubkey"))

class MockScriptPubkey:
    def __init__(self, data):
        self.data = data
    def serialize(self):
        return self.data

class MockUTXODatabase(UTXODatabaseMixin):
    def __init__(self):
        self.utxos = {}
        self._lock = threading.RLock()
        self.filepath = "dummy.json"
        self._dirty = False
        self._dirty_keys = set()
        self._removed_keys = set()
        self._rewrite_all = False
        self._address_index = None
        self._key_to_spk = {}
        self._version = 0
        self._tip_cache = {"ts": 0.0, "height": 0}
        self._tip_cache_ttl = 60.0
        self._persist_enabled = True
        self._meta = {}
        self.saved_data = None
        
    def script_to_address(self, spk):
        if spk:
            return "mock_address"
        return None
        
    def _is_unspendable_opreturn(self, tx_out):
        spk = getattr(tx_out, "script_pubkey", None)
        if hasattr(spk, "serialize") and spk.serialize().startswith(b"\x6a"):
            return True
        if isinstance(spk, str) and spk.startswith("6a"):
            return True
        return False
        
    def load_json(self, path):
        return {
            "_meta": {"a": 1},
            "tx1:0": {"tx_out": {"amount": 10, "script_pubkey": "0014abcd"}, "is_coinbase": True, "block_height": 10},
            "tx2:0": {"amount": 20, "script_pubkey": "0020abcd"},
            "tx3:0": {"tx_out": {"amount": 0, "script_pubkey": "6aabcd"}}, # unspendable
            "tx_inv:0": {"tx_out": {"not": "valid"}}, # invalid txo
            "tx_inv2:0": "not dict",
            "tx_inv3": {"tx_out": {"amount": 10, "script_pubkey": "123"}}
        }

    def save_json(self, path, data):
        self.saved_data = data


@patch("tsarchain.storage.utxo_logic.database.TxOut", MockTxOut)
def test_serialize_entry():
    db = MockUTXODatabase()
    # p2wpkh
    entry1 = {
        "tx_out": MockTxOut(10, MockScriptPubkey(b"\x00\x14" + b"a"*20)),
        "is_coinbase": True,
        "block_height": 100
    }
    res1 = db._serialize_entry(entry1)
    assert res1["script_type"] == "p2wpkh"
    assert res1["address"] == "mock_address"
    assert res1["is_coinbase"] is True
    assert res1["block_height"] == 100
    
    # p2wsh
    entry2 = {
        "tx_out": {"amount": 20, "script_pubkey": "0020" + "a"*64},
    }
    res2 = db._serialize_entry(entry2)
    assert res2["script_type"] == "p2wsh"
    assert res2["address"] == "mock_address"
    
    # other script
    entry3 = {
        "tx_out": MockTxOut(30, MockScriptPubkey(b"\x00\x151234")),
    }
    res3 = db._serialize_entry(entry3)
    assert res3["script_type"] is None


@patch("tsarchain.storage.utxo_logic.database.TxOut", MockTxOut)
def test_to_from_dict():
    db = MockUTXODatabase()
    db.utxos = {
        "tx1:0": {
            "tx_out": MockTxOut(10, MockScriptPubkey(b"\x00\x14" + b"a"*20)),
            "is_coinbase": True,
            "block_height": 10
        }
    }
    d = db.to_dict()
    assert "tx1:0" in d
    
    # Test from_dict
    data = {
        "tx1:0": {"tx_out": {"amount": 10, "script_pubkey": "0014abcd"}, "is_coinbase": True, "block_height": 10},
        "tx2:0": {"amount": 20, "script_pubkey": "0020abcd"},
        "invalid": "string",
        "tx_inv:0": {"tx_out": {"bad": "data"}}
    }
    db_new = MockUTXODatabase.from_dict(data)
    assert "tx1:0" in db_new.utxos
    assert db_new.utxos["tx1:0"]["tx_out"].amount == 10
    assert "tx2:0" in db_new.utxos
    assert db_new.utxos["tx2:0"]["tx_out"].amount == 20
    assert "invalid" not in db_new.utxos
    assert db_new._dirty is True
    assert db_new._rewrite_all is True


@patch("tsarchain.storage.utxo_logic.database.TxOut", MockTxOut)
@patch("tsarchain.storage.utxo_logic.database.kv_enabled", return_value=False)
def test_load_save_json(mock_kv):
    db = MockUTXODatabase()
    
    # test load_utxo_set
    nested = db.load_utxo_set()
    assert "tx1" in nested
    assert nested["tx1"][0]["tx_out"]["amount"] == 10
    
    # test _load
    db._load()
    assert "tx1:0" in db.utxos
    assert "tx2:0" in db.utxos
    assert "tx3:0" not in db.utxos # unspendable
    assert "tx_inv:0" not in db.utxos
    assert "tx_inv2:0" not in db.utxos
    assert db._meta == {"a": 1}
    
    # test _save
    db._dirty = True
    db._save()
    assert db.saved_data is not None
    assert db.saved_data["_meta"]["backend"] == "json"
    assert "tx1:0" in db.saved_data
    
    # flush
    assert db.flush(force=True) is True
    assert db.flush() is False # not dirty anymore

@patch("tsarchain.storage.utxo_logic.database.TxOut", MockTxOut)
@patch("tsarchain.storage.utxo_logic.database.kv_enabled", return_value=True)
def test_load_save_kv(mock_kv):
    db = MockUTXODatabase()
    
    def mock_iter_prefix(prefix, start):
        if prefix == "utxo":
            yield b"__meta__", json.dumps({"b": 2}).encode()
            yield b"tx1:0", json.dumps({"tx_out": {"amount": 10, "script_pubkey": "0014abcd"}}).encode()
            yield b"tx2:0", json.dumps({"tx_out": {"amount": 0, "script_pubkey": "6aabcd"}}).encode()
            yield b"tx_bad", b"bad json"
        elif prefix == "state":
            yield b"k:total_blocks", b"101"
            
    with patch("tsarchain.storage.utxo_logic.database.iter_prefix", mock_iter_prefix):
        nested = db.load_utxo_set()
        assert "tx1" in nested
        assert nested["tx1"][0]["tx_out"]["amount"] == 10
        
        # Test loading
        try:
            db._load(force=True)
        except json.JSONDecodeError:
            pass # ignore bad json in mock
        assert "tx1:0" in db.utxos
        
        # Test tip height
        h = db._get_tip_height_from_state(use_cache=False)
        assert h == 100
        
    class MockBatch:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def put(self, k, v): pass
        def delete(self, k): pass
        
    with patch("tsarchain.storage.utxo_logic.database.clear_db") as mock_clear, \
         patch("tsarchain.storage.utxo_logic.database.batch", return_value=MockBatch()):
        db._dirty = True
        db._rewrite_all = True
        db._save()
        mock_clear.assert_called_with("utxo")
        
        # Partial save
        db._dirty = True
        db._removed_keys.add("tx2:0")
        db._save()

def test_get_utxo_meta():
    db = MockUTXODatabase()
    c, h = db._get_utxo_meta({"is_coinbase": True, "block_height": 50})
    assert c is True
    assert h == 50
    
    c, h = db._get_utxo_meta(None)
    assert c is False
    assert h == 0

def test_bump_version():
    db = MockUTXODatabase()
    db._version = 10
    db._bump_version()
    assert db.version() == 11
    assert db._tip_cache["ts"] == 0.0

@patch("tsarchain.storage.utxo_logic.database.kv_enabled", return_value=False)
@patch("tsarchain.storage.utxo_logic.database.AtomicJSONFile")
def test_get_tip_height_json(mock_atomic, mock_kv):
    db = MockUTXODatabase()
    mock_instance = mock_atomic.return_value
    mock_instance.load.return_value = {"total_blocks": 5}
    h = db._get_tip_height_from_state(use_cache=False)
    assert h == 4
    
    h2 = db._get_tip_height_from_state(use_cache=True)
    assert h2 == 4 # from cache
