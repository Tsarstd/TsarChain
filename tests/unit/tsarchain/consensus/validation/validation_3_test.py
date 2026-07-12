"""
Validation tests Part 3: Validation Coverage Tests
Testing edge cases, error handling and txid computation coverage for validation.py
"""

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

from types import SimpleNamespace
from unittest.mock import Mock, patch, MagicMock

from tsarchain.consensus.validation import BlockValidator

class ValidationProxy:
    def __getattr__(self, name):
        if hasattr(self, 'validator') and hasattr(self.validator, name):
            return getattr(self.validator, name)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name != 'validator' and hasattr(self, 'validator') and hasattr(self.validator, name):
            setattr(self.validator, name, value)
        else:
            super().__setattr__(name, value)

"""
unit test for validation.py
"""

# =============================================================================
# CATEGORY 3: VALIDATION COVERAGE TESTS
# =============================================================================


# --- Tests from validation_coverage_test.py ---
class CovP1DummyBlock:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        for k, v in kwargs.items():
            setattr(self, k, v)
    def hash(self):
        return getattr(self, "_hash", b"hash")
    def header(self):
        return getattr(self, "_header", b"header")

class CovP1DummyTx:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        for k, v in kwargs.items():
            setattr(self, k, v)

class CovP1DummyConsensus(ValidationProxy):
    def __init__(self):
        self.validator = BlockValidator(self)
        self._last_block_validation_error = None

# --- _compute_txids_for_block ---
def test_compute_txids_for_block():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=b"raw")
    tx = CovP1DummyTx()
    b = CovP1DummyBlock(transactions=[tx])
    
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.hash256.return_value = b"txidbytes"
        assert c.compute_txids_for_block(b) is True
        assert tx.txid == b"txidbytes"

def test_compute_txids_for_block_serialize_fail():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=None)
    tx = CovP1DummyTx()
    b = CovP1DummyBlock(transactions=[tx])
    assert c.compute_txids_for_block(b) is False
    assert c._last_block_validation_error == "tx_serialize_failed"

def test_compute_txids_for_block_mismatch():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=b"raw")
    tx = CovP1DummyTx(txid=b"different")
    b = CovP1DummyBlock(transactions=[tx])
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.hash256.return_value = b"txidbytes"
        assert c.compute_txids_for_block(b) is False
        assert c._last_block_validation_error == "txid_mismatch"

def test_compute_txids_for_block_mismatch_str():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=b"raw")
    tx = CovP1DummyTx(txid="aa"*32) # hex string
    b = CovP1DummyBlock(transactions=[tx])
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.hash256.return_value = b"bb"*32
        assert c.compute_txids_for_block(b) is False
        assert c._last_block_validation_error == "txid_mismatch"

# --- _validate_pow ---
def test_validate_pow():
    c = CovP1DummyConsensus()
    b = CovP1DummyBlock(bits=0x1d00ffff, _hash=b"\x00\x00\x00\x01")
    with patch("tsarchain.consensus.validation.bits_to_target") as mock_btt:
        mock_btt.return_value = 0x0000000ffff00000000000000000000000000000000000000000000000000000
        assert c._validate_pow(b) is True
        
    b = CovP1DummyBlock(bits=0x1d00ffff, _hash=b"\xff\xff\x00\x01")
    with patch("tsarchain.consensus.validation.bits_to_target") as mock_btt:
        mock_btt.return_value = 1
        assert c._validate_pow(b) is False

# --- _validate_merkle ---
def test_validate_merkle():
    c = CovP1DummyConsensus()
    b = CovP1DummyBlock(transactions=[], merkle_root=b"merkle")
    with patch("tsarchain.consensus.validation.merkle_root") as mock_mr:
        mock_mr.return_value = b"merkle"
        assert c._validate_merkle(b) is True
        
    b = CovP1DummyBlock(transactions=[], merkle_root="6d65726b6c65") # hex for b"merkle"
    with patch("tsarchain.consensus.validation.merkle_root") as mock_mr:
        mock_mr.return_value = b"merkle"
        assert c._validate_merkle(b) is True

# --- tx limits ---
def setup_tx_limits_test_p1(mocker, cb_only=False):
    c = CovP1DummyConsensus()
    c._ensure_utxodb = Mock(return_value=None)
    cb = CovP1DummyTx(is_coinbase=True)
    txs = [cb] if cb_only else [cb, CovP1DummyTx()]
    b = CovP1DummyBlock(transactions=txs, height=1)
    
    cfg_mock = SimpleNamespace(
        MAX_BLOCK_BYTES=1000,
        MAX_TX_VSIZE=100,
        MIN_TX_VSIZE=10,
        MAX_TX_WEIGHT=400,
        MIN_TX_WEIGHT=40,
        MAX_TX_INPUTS=10,
        MAX_TX_OUTPUTS=10,
        GRAFFITI_MAGIC=b"G",
        MAX_GRAFFITI_OPRET=100,
    )
    mocker.patch("tsarchain.consensus.validation.CFG", cfg_mock)
    
    return c, b

def test_validate_tx_too_large(mocker):
    c, b = setup_tx_limits_test_p1(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x"*1001)
    assert c._validate_transactions(b) is False
    assert c._last_block_validation_error == "tx_too_large"

def test_validate_tx_weight_calc_failed(mocker):
    c, b = setup_tx_limits_test_p1(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.side_effect = Exception("err")
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "tx_weight_calc_failed"

def test_validate_tx_vsize_exceeds(mocker):
    c, b = setup_tx_limits_test_p1(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 101, 10, 10) # weight, vsize...
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "tx_vsize_exceeds_limit"

def test_validate_tx_vsize_below(mocker):
    c, b = setup_tx_limits_test_p1(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 9, 10, 10) 
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "tx_vsize_below_min"

def test_validate_tx_weight_exceeds(mocker):
    c, b = setup_tx_limits_test_p1(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (401, 50, 10, 10) 
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "tx_weight_exceeds_limit"

def test_validate_tx_weight_below(mocker):
    c, b = setup_tx_limits_test_p1(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (39, 50, 10, 10) 
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "tx_weight_below_min"

def test_validate_tx_inputs_outputs(mocker):
    c, b = setup_tx_limits_test_p1(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10) 
        b.transactions[1].inputs = [1]*11
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "tx_inputs_exceed_limit"
        
        b.transactions[1].inputs = [1]*5
        b.transactions[1].outputs = [1]*11
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "tx_outputs_exceed_limit"

# --- legacy lookup ---
def test_legacy_lookup():
    from tsarchain.consensus.validation import BlockValidator
    import threading
    class C(ValidationProxy):
        def __init__(self): self.lock = threading.Lock()
    c = C()
    
    b = CovP1DummyBlock(transactions=[CovP1DummyTx(is_coinbase=True), CovP1DummyTx(inputs=[CovP1DummyTx(txid="aa"*32, vout=0)])])
    
    snap = {
        f"{'aa'*32}:0": {"amount": 10, "script_pubkey": b"x"}
    }
    
    def dummy_legacy_lookup(snapshot_map, prev_txid_hex, prev_index):
        # We will directly call the nested function logic to test it.
        # But wait, it's defined inside `_validate_transactions`. We can just pass the snapshot.
        pass


# --- Tests from validation_coverage_part2_test.py ---
class CovP2DummyBlock:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        for k, v in kwargs.items():
            setattr(self, k, v)
    def hash(self):
        return getattr(self, "_hash", b"hash")

class CovP2DummyTx:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        self.fee = 0
        for k, v in kwargs.items():
            setattr(self, k, v)
    def compute_txid(self):
        self.txid = b"computed"
        self.txid_hex = "computed"

class CovP2DummyConsensus(ValidationProxy):
    def __init__(self):
        self.validator = BlockValidator(self)
        self._last_block_validation_error = None
        self.lock = Mock()
    def _ensure_utxodb(self):
        return None

def setup_tx_limits_test_p2(mocker, cb_only=False):
    c = CovP2DummyConsensus()
    c._ensure_utxodb = Mock(return_value=None)
    cb = CovP2DummyTx(is_coinbase=True)
    txs = [cb] if cb_only else [cb, CovP2DummyTx()]
    b = CovP2DummyBlock(transactions=txs, height=1)
    
    cfg_mock = SimpleNamespace(
        MAX_BLOCK_BYTES=1000,
        MAX_TX_VSIZE=100,
        MIN_TX_VSIZE=10,
        MAX_TX_WEIGHT=400,
        MIN_TX_WEIGHT=40,
        MAX_TX_INPUTS=10,
        MAX_TX_OUTPUTS=10,
        GRAFFITI_MAGIC=b"G",
        MAX_GRAFFITI_OPRET=10,
        GRAFFITI_MAX_SIZE_BYTES=100,
        GRAFFITI_COMMENT_MAX_BYTES=100,
        GRAFFITI_COMMENT_MIN_FEE=10,
        COINBASE_MATURITY=10,
        MAX_SIGOPS_PER_TX=10,
        MAX_SIGOPS_PER_BLOCK=10,
        MAX_SUPPLY=1000,
    )
    mocker.patch("tsarchain.consensus.validation.CFG", cfg_mock)
    
    return c, b

def test_validate_graffiti_various_spk(mocker):
    c, b = setup_tx_limits_test_p2(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10) 
        mock_H.last_pushdata.return_value = None
        
        # spk with serialize
        class SpkSer:
            def serialize(self): return b"serialize"
        
        # str invalid hex
        spk_str_invalid = "invalidhex"
        
        # None raw
        spk_none = None
        
        b.transactions[1].outputs = [
            Mock(script_pubkey=SpkSer()),
            Mock(script_pubkey=b"bytes"),
            Mock(script_pubkey=spk_str_invalid),
            Mock(script_pubkey=spk_none),
        ]
        
        # mock H native
        mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
        mock_H.tx_to_compact_tuple.return_value = None
        
        # need to return True at the end
        c._cumulative_supply_until = Mock(return_value=0)
        c._scheduled_reward = Mock(return_value=10)
        b.transactions[0].outputs = [Mock(amount=20)] # expected cb = reward + fee = 10 + 10 = 20
        
        with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
            mock_graf.parse_from_script.return_value = None
            # mock txid_hex and compute_txid to pass
            for tx in b.transactions:
                tx.txid = b"txid"
                tx.txid_hex = "txidhex"
                
            b.transactions[1].inputs = [Mock(txid=b"prev", vout=0)]
            mock_utxo = Mock()
            c._ensure_utxodb.return_value = mock_utxo
            mock_utxo.lookup_entry.return_value = {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}
            
            assert c._validate_transactions(b) is True

def test_validate_graffiti_opret_too_large(mocker):
    c, b = setup_tx_limits_test_p2(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10) 
        mock_H.last_pushdata.return_value = b"G" + b"x"*20 # larger than MAX_GRAFFITI_OPRET (10)
        
        b.transactions[1].outputs = [Mock(script_pubkey=b"bytes")]
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "graffiti_opreturn_too_large"

def test_validate_graffiti_payload_invalid(mocker):
    c, b = setup_tx_limits_test_p2(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10) 
        mock_H.last_pushdata.return_value = b"G" + b"x"
        
        with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
            mock_graf.parse_payload.return_value = None
            b.transactions[1].outputs = [Mock(script_pubkey=b"bytes")]
            assert c._validate_transactions(b) is False
            assert c._last_block_validation_error == "graffiti_payload_invalid"

def test_validate_graffiti_post_size_invalid(mocker):
    c, b = setup_tx_limits_test_p2(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10) 
        mock_H.last_pushdata.return_value = b"G" + b"x"
        
        with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
            mock_graf.parse_payload.return_value = {"event": "POST", "size": 0}
            b.transactions[1].outputs = [Mock(script_pubkey=b"bytes")]
            assert c._validate_transactions(b) is False
            assert c._last_block_validation_error == "graffiti_size_invalid"

def test_validate_graffiti_post_size_exceeds(mocker):
    c, b = setup_tx_limits_test_p2(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10) 
        mock_H.last_pushdata.return_value = b"G" + b"x"
        
        with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
            mock_graf.parse_payload.return_value = {"event": "POST", "size": 200}
            b.transactions[1].outputs = [Mock(script_pubkey=b"bytes")]
            assert c._validate_transactions(b) is False
            assert c._last_block_validation_error == "graffiti_size_exceeds_limit"

def test_native_snapshot_invalid_entry(mocker):
    c, b = setup_tx_limits_test_p2(mocker)
    c._serialize_tx_cached = Mock(return_value=b"x")
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10) 
        mock_H.last_pushdata.return_value = None
        
        for tx in b.transactions:
            tx.txid = b"txid"
            tx.txid_hex = "txidhex"
            
        b.transactions[1].inputs = [Mock(txid=b"prev", vout=0)]
        mock_utxo = Mock()
        c._ensure_utxodb.return_value = mock_utxo
        # missing script_pubkey will trigger native_snapshot_invalid_entry
        mock_utxo.lookup_entry.return_value = {"amount": 10, "is_coinbase": False, "block_height": 0}
        
        assert c._validate_transactions(b) is False
        assert c._last_block_validation_error == "native_snapshot_invalid_entry"


# --- Tests from validation_coverage_part3_test.py ---
class CovP3DummyTx:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        for k, v in kwargs.items():
            setattr(self, k, v)

class CovP3DummyBlock:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        for k, v in kwargs.items():
            setattr(self, k, v)

class CovP3DummyConsensus(ValidationProxy):
    def __init__(self):
        self.validator = BlockValidator(self)
        self._last_block_validation_error = None
        self.lock = Mock()
    def _entry_script_bytes(self, entry):
        if isinstance(entry, dict):
            return entry.get("script_pubkey")
        return getattr(entry, "script_pubkey", None)

def test_legacy_lookup():
    c = CovP3DummyConsensus()
    c._ensure_utxodb = Mock(return_value=None)
    
    cb = CovP3DummyTx(is_coinbase=True, txid=b"cb", txid_hex="cb")
    tx1 = CovP3DummyTx(is_coinbase=False, txid=b"tx1", txid_hex="tx1")
    tx1.inputs = [Mock(txid=b"a"*32, vout=0)]
    
    b = CovP3DummyBlock(transactions=[cb, tx1], height=1)
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_BLOCK_BYTES = 100000
        cfg_mock.MAX_TX_VSIZE = 1000
        cfg_mock.MIN_TX_VSIZE = 10
        cfg_mock.MAX_TX_WEIGHT = 4000
        cfg_mock.MIN_TX_WEIGHT = 40
        cfg_mock.MAX_TX_INPUTS = 10
        cfg_mock.MAX_TX_OUTPUTS = 10
        cfg_mock.GRAFFITI_MAGIC = b"G"
        cfg_mock.MAX_GRAFFITI_OPRET = 100
        cfg_mock.COINBASE_MATURITY = 1
        cfg_mock.MAX_SUPPLY = 1000000
        
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.last_pushdata.return_value = None
            mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
            mock_H.tx_to_compact_tuple.return_value = None
            
            c._cumulative_supply_until = Mock(return_value=0)
            c._scheduled_reward = Mock(return_value=0)
            c._serialize_tx_cached = Mock(return_value=b"x")
            
            # Create a mock store with utxos dict instead of lookup_entry
            store = Mock()
            store.lookup_entry = None
            # Test different lookup branches in _legacy_lookup
            txid_hex = "a"*64
            tx1.inputs[0].txid = txid_hex
            
            # 1. key string match
            store.utxos = {f"{txid_hex}:0": {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # 2. key.lower() match
            store.utxos = {f"{txid_hex.upper()}:0": {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # 3. key encoded as utf-8
            store.utxos = {f"{txid_hex}:0".encode("utf-8"): {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # 4. bucket match
            store.utxos = {txid_hex: {0: {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}}
            c._validate_transactions(b, utxo_store=store)
            
            # 5. tuple key string
            store.utxos = {(txid_hex, 0): {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # 6. tuple key bytes
            store.utxos = {(bytes.fromhex(txid_hex), 0): {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # 7. fallback iteration case-insensitive string
            store.utxos = {f"{txid_hex.upper()}:0": {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # 8. fallback iteration tuple
            store.utxos = {(bytes.fromhex(txid_hex), 0): {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # 9. None fallback
            store.utxos = {}
            assert c._validate_transactions(b, utxo_store=store) is False
            assert "prevout_missing" in c._last_block_validation_error
            
            # Not a dict
            store.utxos = "not a dict"
            assert c._validate_transactions(b, utxo_store=store) is False

def test_check_sigops_budget():
    c = CovP3DummyConsensus()
    
    cb = CovP3DummyTx(is_coinbase=True)
    tx1 = CovP3DummyTx(is_coinbase=False, inputs=[1,2,3]) # 3 sigops by default
    tx2 = CovP3DummyTx(is_coinbase=False)
    tx2.sigops_count = Mock(return_value=5)
    
    b = CovP3DummyBlock(transactions=[cb, tx1, tx2])
    
    store = Mock()
    store.lookup_entry = Mock(return_value={"script_pubkey": b"x"})
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_SIGOPS_PER_TX = 10
        cfg_mock.MAX_SIGOPS_PER_BLOCK = 20
        
        # total sigops = 3 + 5 = 8 <= 20. Pass.
        assert c._check_sigops_budget(b, store, None) is True
        
        # Exceed per tx
        tx1.inputs = [1]*11 # 11 sigops
        assert c._check_sigops_budget(b, store, None) is False
        assert c._last_block_validation_error == "sigops_per_tx_exceeded"
        
        # Exceed per block
        tx1.inputs = [1]*9 # 9 sigops
        cfg_mock.MAX_SIGOPS_PER_BLOCK = 12
        # total = 9 + 5 = 14 > 12
        assert c._check_sigops_budget(b, store, None) is False
        assert c._last_block_validation_error == "sigops_per_block_exceeded"


# --- Tests from validation_coverage_part4_test.py ---
class CovP4DummyConsensus(ValidationProxy):
    def __init__(self):
        self.validator = BlockValidator(self)
        self._last_block_validation_error = None
        self.lock = Mock()
    def _entry_script_bytes(self, entry):
        if isinstance(entry, dict):
            return entry.get("script_pubkey")
        return getattr(entry, "script_pubkey", None)
    def _cumulative_supply_until(self, h): return 0
    def _scheduled_reward(self, h): return 10
    def _ensure_utxodb(self): return None

class CovP4DummyTx:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        for k, v in kwargs.items():
            setattr(self, k, v)
    def compute_txid(self):
        self.txid = b"\x11\x22\x33"
        self.txid_hex = "112233"

class CovP4DummyBlock:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.height = 1
        for k, v in kwargs.items():
            setattr(self, k, v)

def test_legacy_lookup_fallback():
    c = CovP4DummyConsensus()
    c._ensure_utxodb = Mock(return_value=None)
    
    cb = CovP4DummyTx(is_coinbase=True, txid=b"cb", txid_hex="cb")
    tx1 = CovP4DummyTx(is_coinbase=False, txid=b"tx1", txid_hex="tx1")
    tx1.inputs = [Mock(txid=b"a"*32, vout=0)]
    
    b = CovP4DummyBlock(transactions=[cb, tx1])
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_BLOCK_BYTES = 100000
        cfg_mock.MAX_TX_VSIZE = 1000
        cfg_mock.MIN_TX_VSIZE = 10
        cfg_mock.MAX_TX_WEIGHT = 4000
        cfg_mock.MIN_TX_WEIGHT = 40
        cfg_mock.MAX_TX_INPUTS = 10
        cfg_mock.MAX_TX_OUTPUTS = 10
        cfg_mock.GRAFFITI_MAGIC = b"G"
        cfg_mock.MAX_GRAFFITI_OPRET = 100
        cfg_mock.COINBASE_MATURITY = 1
        cfg_mock.MAX_SUPPLY = 1000000
        
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.last_pushdata.return_value = None
            mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
            mock_H.tx_to_compact_tuple.return_value = None
            c._serialize_tx_cached = Mock(return_value=b"x")
            
            store = Mock()
            store.lookup_entry = None
            txid_hex = "a"*64
            tx1.inputs[0].txid = txid_hex
            
            # fallback string upper
            store.utxos = {(txid_hex.upper(), 0): {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}}
            c._validate_transactions(b, utxo_store=store)
            
            # test vout mismatch in loop
            store.utxos = {
                (bytes.fromhex(txid_hex), 1): {"amount": 10}, 
                (txid_hex.upper(), 0): {"amount": 10, "script_pubkey": b"s", "is_coinbase": False, "block_height": 0}
            }
            c._validate_transactions(b, utxo_store=store)

def test_normalize_snapshot_objects():
    c = CovP4DummyConsensus()
    cb = CovP4DummyTx(is_coinbase=True, txid=b"cb", txid_hex="cb")
    tx1 = CovP4DummyTx(is_coinbase=False, txid=b"tx1", txid_hex="tx1")
    tx1.inputs = [Mock(txid=b"a"*32, vout=0)]
    b = CovP4DummyBlock(transactions=[cb, tx1])
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_TX_VSIZE = 1000
        cfg_mock.MIN_TX_VSIZE = 10
        cfg_mock.MAX_TX_WEIGHT = 4000
        cfg_mock.MIN_TX_WEIGHT = 40
        cfg_mock.MAX_TX_INPUTS = 10
        cfg_mock.MAX_TX_OUTPUTS = 10
        cfg_mock.GRAFFITI_MAGIC = b"G"
        cfg_mock.COINBASE_MATURITY = 1
        cfg_mock.MAX_SUPPLY = 1000000
        
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
            mock_H.tx_to_compact_tuple.return_value = None
            c._serialize_tx_cached = Mock(return_value=b"x")
            
            store = Mock()
            class CandidateObj:
                def __init__(self):
                    self.validator = BlockValidator(self)
                    self.amount = 10
                    self.script_pubkey = b"s"
                    self.is_coinbase = False
                    self.block_height = 0
                    self.tx_out = self # recursive for branch
                    
            store.lookup_entry = Mock(return_value=CandidateObj())
            c._validate_transactions(b, utxo_store=store)
            
            class CandidateObjNoTxOut:
                def __init__(self):
                    self.validator = BlockValidator(self)
                    self.amount = 10
                    self.script_pubkey = b"s"
                    self.is_coinbase = False
                    self.height = 0
            store.lookup_entry = Mock(return_value=CandidateObjNoTxOut())
            c._validate_transactions(b, utxo_store=store)

def test_missing_txid_and_same_block_spend():
    c = CovP4DummyConsensus()
    
    cb = CovP4DummyTx(is_coinbase=True, txid=None, txid_hex=None) # triggers compute_txid
    tx1 = CovP4DummyTx(is_coinbase=False, txid=None, txid_hex=None)
    tx1.inputs = [Mock(txid="112233", vout=0)] # spends cb from same block
    
    tx2 = CovP4DummyTx(is_coinbase=False, txid_hex="tx2")
    tx2.inputs = [Mock(txid=None, prev_tx=None, vout=0)] # missing prev txid
    
    b = CovP4DummyBlock(transactions=[cb, tx1])
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_TX_VSIZE = 1000
        cfg_mock.MIN_TX_VSIZE = 10
        cfg_mock.MAX_TX_WEIGHT = 4000
        cfg_mock.MIN_TX_WEIGHT = 40
        cfg_mock.MAX_TX_INPUTS = 10
        cfg_mock.MAX_TX_OUTPUTS = 10
        cfg_mock.GRAFFITI_MAGIC = b"G"
        cfg_mock.COINBASE_MATURITY = 1
        cfg_mock.MAX_SUPPLY = 1000000
        
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.native_validate_block_txs_compact.return_value = (True, None, [0])
            mock_H.tx_to_compact_tuple.return_value = None
            c._serialize_tx_cached = Mock(return_value=b"x")
            
            store = Mock()
            store.lookup_entry.return_value = {"amount": 10, "script_pubkey": b"s"}
            c._validate_transactions(b, utxo_store=store)
            
            # missing prev txid
            b2 = CovP4DummyBlock(transactions=[cb, tx2])
            assert c._validate_transactions(b2, utxo_store=store) is False
            assert c._last_block_validation_error == "tx_input_missing_prev_txid"
            
            # snap_key duplicate
            tx3 = CovP4DummyTx(is_coinbase=False, txid_hex="tx3")
            tx3.inputs = [Mock(txid="223344", vout=0), Mock(txid="223344", vout=0)]
            b3 = CovP4DummyBlock(transactions=[cb, tx3])
            store.lookup_entry = Mock(return_value={"amount": 10, "script_pubkey": b"s"})
            c._validate_transactions(b3, utxo_store=store)

def test_build_payload_bytes_key():
    c = CovP4DummyConsensus()
    cb = CovP4DummyTx(is_coinbase=True, txid=b"cb", txid_hex="cb")
    tx1 = CovP4DummyTx(is_coinbase=False, txid=b"tx1", txid_hex="tx1")
    tx1.inputs = [Mock(txid=b"a"*32, vout=0)]
    b = CovP4DummyBlock(transactions=[cb, tx1])
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_TX_VSIZE = 1000
        cfg_mock.MIN_TX_VSIZE = 10
        cfg_mock.MAX_TX_WEIGHT = 4000
        cfg_mock.MIN_TX_WEIGHT = 40
        cfg_mock.MAX_TX_INPUTS = 10
        cfg_mock.MAX_TX_OUTPUTS = 10
        cfg_mock.GRAFFITI_MAGIC = b"G"
        cfg_mock.COINBASE_MATURITY = 1
        cfg_mock.MAX_SUPPLY = 1000000
        
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
            mock_H.tx_to_compact_tuple.return_value = None
            c._serialize_tx_cached = Mock(return_value=b"x")
            
            store = Mock()
            store.lookup_entry = None
            txid_hex = "a"*64
            pass # We'll need a trick for this one

# --- Tests from validation_coverage_part5_test.py ---
class CovP5DummyTx:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        for k, v in kwargs.items():
            setattr(self, k, v)
    def compute_txid(self):
        self.txid = b"computed"
        self.txid_hex = "computed"
    def to_dict(self):
        return {}

class CovP5DummyBlock:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.height = 1
        self.transactions = []
        for k, v in kwargs.items():
            setattr(self, k, v)
    def to_dict(self):
        return {}
    def header(self):
        return b"header"

class CovP5DummyConsensus(ValidationProxy):
    def __init__(self):
        self.validator = BlockValidator(self)
        self._last_block_validation_error = None
        self.lock = MagicMock()
    def _entry_script_bytes(self, entry):
        if isinstance(entry, dict):
            return entry.get("script_pubkey")
        return getattr(entry, "script_pubkey", None)
    def _cumulative_supply_until(self, h): return 0
    def _scheduled_reward(self, h): return 10
    def _ensure_utxodb(self): return None

def setup_validate_block_mock_p5(c):
    c._validate_pow = Mock(return_value=True)
    c.compute_txids_for_block = Mock(return_value=True)
    c._validate_merkle = Mock(return_value=True)
    c._ensure_unique_txids = Mock(return_value=True)
    c._check_block_limits = Mock(return_value=True)
    c._validate_chain_context_locked = Mock(return_value=True)
    c._chain_state_token_locked = Mock(return_value="token")
    c._check_sigops_budget = Mock(return_value=True)
    c._validate_transactions = Mock(return_value=True)
    c._process_block_transactions_locked = Mock(return_value=True)
    c._post_validate_graffiti = Mock(return_value=True)

def test_pow_ms_warning(mocker):
    c = CovP5DummyConsensus()
    setup_validate_block_mock_p5(c)
    
    store = Mock()
    c._ensure_utxodb = Mock(return_value=store)
    store.lookup_entry = None
    store.utxos = None
    store.load_utxo_set = Mock(return_value={})
    
    b = CovP5DummyBlock()
    b._cached_hash = b"hash"
    b.prev_block_hash = "prev"
    b.transactions = ["tx1"]
    
    with patch("tsarchain.consensus.validation.CFG.DEBUG_BENCHMARKS", True):
        with patch("time.perf_counter", side_effect=[0, 0.2]):
            c.validate_block(b)
    
    # asserts that store.load_utxo_set was called (covers 130-132)
    store.load_utxo_set.assert_called_once()

def test_native_validation_branches():
    c = CovP5DummyConsensus()
    
    cb = CovP5DummyTx(is_coinbase=True, txid=b"cb", txid_hex="cb")
    tx1 = CovP5DummyTx(is_coinbase=False, txid=b"tx1", txid_hex="tx1")
    tx1.inputs = [Mock(txid="112233", vout=0)]
    
    b = CovP5DummyBlock(transactions=[cb, tx1])
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_TX_VSIZE = 1000
        cfg_mock.MIN_TX_VSIZE = 10
        cfg_mock.MAX_TX_WEIGHT = 4000
        cfg_mock.MIN_TX_WEIGHT = 40
        cfg_mock.MAX_TX_INPUTS = 10
        cfg_mock.MAX_TX_OUTPUTS = 10
        cfg_mock.GRAFFITI_MAGIC = b"G"
        cfg_mock.COINBASE_MATURITY = 1
        cfg_mock.MAX_SUPPLY = 1000000
        
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.tx_to_compact_tuple.return_value = None
            c._serialize_tx_cached = Mock(return_value=b"x")
            
            store = Mock()
            store.lookup_entry.return_value = {"amount": 10, "script_pubkey": b"s"}
            
            # test native_validate_block_txs_compact returns False
            mock_H.native_validate_block_txs_compact.return_value = (False, "my_reason", None)
            assert c._validate_transactions(b, utxo_store=store) is False
            assert c._last_block_validation_error == "my_reason"
            
            # test fee_mismatch
            mock_H.native_validate_block_txs_compact.return_value = (True, None, [10, 20]) # 2 fees but only 1 non-cb tx
            assert c._validate_transactions(b, utxo_store=store) is False
            assert c._last_block_validation_error == "fee_mismatch"
            
            # test fees is not a list (covers fees_list = [int(getattr(t, "fee", 0)) ...])
            mock_H.native_validate_block_txs_compact.return_value = (True, None, None)
            with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
                mock_graf.parse_from_script.return_value = None
                mock_H.last_pushdata.return_value = None
                tx1.fee = 10
                
                # should pass but cb needs 10
                cb.outputs = [Mock(amount=20)] # reward(10) + fee(10)
                res = c._validate_transactions(b, utxo_store=store)
                assert res is True, f"Failed with: {c._last_block_validation_error}"
            
            # test fallback to native_validate_block_txs
            with patch.object(c.validator, "_validate_transactions") as mock_val:
                pass

def test_check_sigops_budget_lookup():
    c = CovP5DummyConsensus()
    cb = CovP5DummyTx(is_coinbase=True)
    tx1 = CovP5DummyTx(is_coinbase=False, inputs=[1])
    tx1.sigops_count = Mock(return_value=5)
    b = CovP5DummyBlock(transactions=[cb, tx1])
    
    store = Mock()
    # explicitly remove lookup_entry
    store.lookup_entry = None
    
    with patch("tsarchain.consensus.validation.CFG") as cfg_mock:
        cfg_mock.MAX_SIGOPS_PER_TX = 10
        cfg_mock.MAX_SIGOPS_PER_BLOCK = 20
        
        # Test utxo_view dict lookup
        utxo_view = {"112233:0": {"script_pubkey": b"x"}}

        def fake_sigops(lookup_fn):
            res = lookup_fn(b"\x11\x22\x33", 0)
            return 5 if res else 0
        tx1.sigops_count = fake_sigops
        
        assert c._check_sigops_budget(b, store, utxo_view) is True
        
        # test entry is None
        utxo_view_empty = {}
        assert c._check_sigops_budget(b, store, utxo_view_empty) is True # fake_sigops returns 0

# --- Tests from validation_coverage_part6_test.py ---
class CovP6DummyTx:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        self.txid = b"computed"
        self.txid_hex = "computed"
        for k, v in kwargs.items():
            setattr(self, k, v)
    def compute_txid(self):
        pass
    def to_dict(self):
        return {}

class CovP6DummyBlock:
    def __init__(self, **kwargs):
        self.validator = BlockValidator(self)
        self.height = 1
        self.transactions = []
        for k, v in kwargs.items():
            setattr(self, k, v)
    def to_dict(self):
        return {}

class CovP6DummyConsensus(ValidationProxy):
    def __init__(self):
        self.validator = BlockValidator(self)
        self._last_block_validation_error = None
        self.lock = Mock()
    def _entry_script_bytes(self, entry):
        return entry.get("script_pubkey")
    def _cumulative_supply_until(self, h): return 0
    def _scheduled_reward(self, h): return 10
    def _ensure_utxodb(self): return None

def setup_validate_block_mock_p6(c):
    c._validate_pow = Mock(return_value=True)
    c.compute_txids_for_block = Mock(return_value=True)
    c._validate_merkle = Mock(return_value=True)
    c._ensure_unique_txids = Mock(return_value=True)
    c._check_block_limits = Mock(return_value=True)
    c._validate_chain_context_locked = Mock(return_value=True)
    c._chain_state_token_locked = Mock(return_value="token")
    c._check_sigops_budget = Mock(return_value=True)
    c._process_block_transactions_locked = Mock(return_value=True)
    c._post_validate_graffiti = Mock(return_value=True)

def test_spk_to_address_p2wsh():
    c = CovP6DummyConsensus()
    setup_validate_block_mock_p6(c)
    spk_p2wsh = b"\x00\x20" + b"\x01" * 32
    cb = CovP6DummyTx(is_coinbase=True)
    tx1 = CovP6DummyTx(is_coinbase=False, inputs=[Mock(txid="112233", vout=0)])
    tx1.outputs = [Mock(script_pubkey=spk_p2wsh, amount=10)]
    b = CovP6DummyBlock(transactions=[cb, tx1])
    
    with patch("tsarchain.consensus.validation.CFG") as cfg:
        cfg.ADDRESS_PREFIX = "tsar"
        cfg.MAX_TX_VSIZE = 1000
        cfg.MIN_TX_VSIZE = 10
        cfg.MAX_TX_WEIGHT = 4000
        cfg.MIN_TX_WEIGHT = 40
        cfg.MAX_TX_INPUTS = 10
        cfg.MAX_TX_OUTPUTS = 10
        cfg.GRAFFITI_MAGIC = b"G"
        cfg.COINBASE_MATURITY = 1
        cfg.MAX_SUPPLY = 1000000
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.tx_to_compact_tuple.return_value = None
            mock_H.native_validate_block_txs_compact.return_value = (True, None, None)
            mock_H.last_pushdata.return_value = None
            store = Mock()
            store.lookup_entry.return_value = {"amount": 10, "script_pubkey": b"s"}
            
            with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
                mock_graf.parse_from_script.return_value = None
                c._validate_transactions(b, utxo_store=store)

def test_graffiti_post_missing_art_id_and_multiple_posts():
    c = CovP6DummyConsensus()
    setup_validate_block_mock_p6(c)
    
    cb = CovP6DummyTx(is_coinbase=True)
    tx1 = CovP6DummyTx(is_coinbase=False, inputs=[Mock(txid="112233", vout=0)])
    
    out1 = Mock(script_pubkey=b"g1", amount=10)
    out2 = Mock(script_pubkey=b"g2", amount=0) # test amt <= 0
    tx1.outputs = [out1, out2]
    b = CovP6DummyBlock(transactions=[cb, tx1])
    
    with patch("tsarchain.consensus.validation.CFG") as cfg:
        cfg.MAX_TX_VSIZE = 1000
        cfg.MIN_TX_VSIZE = 10
        cfg.MAX_TX_WEIGHT = 4000
        cfg.MIN_TX_WEIGHT = 40
        cfg.MAX_TX_INPUTS = 10
        cfg.MAX_TX_OUTPUTS = 10
        cfg.GRAFFITI_MAGIC = b"G"
        cfg.COINBASE_MATURITY = 1
        cfg.MAX_SUPPLY = 1000000
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.tx_to_compact_tuple.return_value = None
            mock_H.native_validate_block_txs_compact.return_value = (True, None, None)
            mock_H.last_pushdata.return_value = None
            
            store = Mock()
            store.lookup_entry.return_value = {"amount": 10, "script_pubkey": b"s"}
            
            with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
                # 347: art_id missing, sha_hex and creator present
                def fake_parse(spk):
                    if spk == b"g1": return {"event": "POST", "sha256": "abc", "creator": "me"}
                    if spk == b"g2": return {"event": "PAYOUT", "art_id": "123"}
                    return None
                mock_graf.parse_from_script.side_effect = fake_parse
                mock_graf.compute_art_id.return_value = "123"
                
                c._validate_transactions(b, utxo_store=store)
                mock_graf.compute_art_id.assert_called_once()

                # 350-351: multiple POSTs
                def fake_parse2(spk):
                    return {"event": "POST", "sha256": "abc", "creator": "me"}
                mock_graf.parse_from_script.side_effect = fake_parse2
                res = c._validate_transactions(b, utxo_store=store)
                assert res is False
                assert c._last_block_validation_error == "too_many_graffiti_posts"

def test_check_sigops_budget_callable_lookup():
    c = CovP6DummyConsensus()
    cb = CovP6DummyTx(is_coinbase=True)
    tx1 = CovP6DummyTx(is_coinbase=False)
    
    # fake sigops_count that calls the passed lookup_fn
    def fake_sigops(lookup_fn):
        res = lookup_fn(b"\x11\x22\x33", 0)
        return 5 if res else 0
    tx1.sigops_count = fake_sigops
    
    b = CovP6DummyBlock(transactions=[cb, tx1])
    
    store = Mock()
    store.lookup_entry = Mock(return_value={"script_pubkey": b"s"})
    
    with patch("tsarchain.consensus.validation.CFG") as cfg:
        cfg.MAX_SIGOPS_PER_TX = 10
        cfg.MAX_SIGOPS_PER_BLOCK = 20
        c._check_sigops_budget(b, store, None)
        
        store.lookup_entry.assert_called_once_with("112233", 0)

def test_normalize_snapshot_entry_object():
    c = CovP6DummyConsensus()
    
    class UtxoObj:
        def __init__(self):
            self.validator = BlockValidator(self)
            self.amount = 42
            self.script_pubkey = b"script"
            self.is_coinbase = True
            self.block_height = 100
    
    # 515-518, 524-525: object fallback
    # Test with amt <= 0 in paymap (covers 371)
    spk_p2wpkh = b"\x00\x14" + b"\x01" * 20
    setup_validate_block_mock_p6(c)
    cb = CovP6DummyTx(is_coinbase=True)
    tx1 = CovP6DummyTx(is_coinbase=False, inputs=[Mock(txid="112233", vout=0)])
    tx1.outputs = [Mock(script_pubkey=spk_p2wpkh, amount=0)]
    b = CovP6DummyBlock(transactions=[cb, tx1])
    with patch("tsarchain.consensus.validation.CFG") as cfg:
        cfg.ADDRESS_PREFIX = "tsar"
        cfg.MAX_TX_VSIZE = 1000
        cfg.MIN_TX_VSIZE = 10
        cfg.MAX_TX_WEIGHT = 4000
        cfg.MIN_TX_WEIGHT = 40
        cfg.MAX_TX_INPUTS = 10
        cfg.MAX_TX_OUTPUTS = 10
        cfg.GRAFFITI_MAGIC = b"G"
        cfg.COINBASE_MATURITY = 1
        cfg.MAX_SUPPLY = 1000000
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.compute_tx_weight_vsize.return_value = (100, 50, 10, 10)
            mock_H.tx_to_compact_tuple.return_value = None
            mock_H.native_validate_block_txs_compact.return_value = (True, None, None)
            mock_H.last_pushdata.return_value = None
            store = Mock()
            store.lookup_entry.return_value = UtxoObj()
            with patch("tsarchain.consensus.validation.GRAFFITI") as mock_graf:
                mock_graf.parse_from_script.return_value = None
                c._validate_transactions(b, utxo_store=store)
