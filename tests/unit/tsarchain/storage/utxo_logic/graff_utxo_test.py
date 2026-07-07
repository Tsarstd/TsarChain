from unittest.mock import patch, MagicMock

from tsarchain.storage.utxo_logic.graff_utxo import UTXOGraffitiMixin

class MockSPK:
    def __init__(self, b):
        self.b = b
    def serialize(self):
        return self.b

class MockUTXOGraff(UTXOGraffitiMixin):
    def __init__(self):
        self._graffiti_registry = MagicMock()
        self._graffiti_registry.data = {"payouts": {}}
        self.balance_mock = 100
        
    def _txid_hex(self, txid):
        return txid if isinstance(txid, str) else "txid123"
        
    def get_balance(self, addr, mode):
        return self.balance_mock

def test_script_bytes():
    assert UTXOGraffitiMixin._script_bytes(MockSPK(b"\x00\x14abcd")) == b"\x00\x14abcd"
    assert UTXOGraffitiMixin._script_bytes(b"123") == b"123"
    assert UTXOGraffitiMixin._script_bytes("0014abcd") == b"\x00\x14\xab\xcd"
    assert UTXOGraffitiMixin._script_bytes(None) == b""

@patch("tsarchain.storage.utxo_logic.graff_utxo.CFG")
def test_script_to_address(mock_cfg):
    mock_cfg.ADDRESS_PREFIX = "tsar"
    obj = MockUTXOGraff()
    
    # p2wpkh
    res = obj.script_to_address(b"\x00\x14" + b"a"*20)
    assert res.startswith("tsar1")
    
    # p2wsh
    res2 = obj.script_to_address(b"\x00\x20" + b"b"*32)
    assert res2.startswith("tsar1")
    
    # invalid
    assert obj.script_to_address(b"\x00\x15") is None

def test_read_opreturn_payload():
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a\x04abcd") == b"abcd"
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a\x4c\x04abcd") == b"abcd"
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a\x4d\x04\x00abcd") == b"abcd"
    assert UTXOGraffitiMixin._read_opreturn_payload(b"") is None
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a") is None
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a\x4c") is None
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a\x4d\x00") is None
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a\x76abcd") is None
    assert UTXOGraffitiMixin._read_opreturn_payload(b"\x6a\x05abcd") is None # out of bounds

@patch("tsarchain.storage.utxo_logic.graff_utxo.GRAFFITI")
def test_record_graffiti_event(mock_graff):
    obj = MockUTXOGraff()
    tx = MagicMock()
    tx.txid = "tx1"
    
    # Block height None
    obj._record_graffiti_event(tx, [], None)
    
    # Valid opreturn
    mock_graff.parse_payload.return_value = {"event": "POST"}
    outputs = [{"script_bytes": b"\x6a\x04abcd"}]
    
    with patch.object(obj, "_handle_graffiti_post") as mock_post:
        obj._record_graffiti_event(tx, outputs, 100)
        mock_post.assert_called_once()

    # COMMENT event
    mock_graff.parse_payload.return_value = {"event": "COMMENT"}
    with patch.object(obj, "_handle_graffiti_comment") as mock_comment:
        obj._record_graffiti_event(tx, outputs, 100)
        mock_comment.assert_called_once()
        
    # PAYOUT event
    mock_graff.parse_payload.return_value = {"event": "PAYOUT"}
    with patch.object(obj, "_handle_graffiti_payout") as mock_payout:
        obj._record_graffiti_event(tx, outputs, 100)
        mock_payout.assert_called_once()

@patch("tsarchain.storage.utxo_logic.graff_utxo.GRAFFITI")
def test_handle_graffiti_post(mock_graff):
    obj = MockUTXOGraff()
    mock_graff.compute_art_id.return_value = "art123"
    mock_graff.derive_pool_address.return_value = "pool_addr"
    mock_graff.calc_upload_fee_sats.return_value = 50
    
    meta = {"sha256": "sha123", "creator": "me", "size": 100}
    
    # Fee too low
    obj._handle_graffiti_post(meta, [{"address": "pool_addr", "amount": 10}], "tx1", 100)
    obj._graffiti_registry.record_post.assert_not_called()
    
    # Success
    obj._handle_graffiti_post(meta, [{"address": "pool_addr", "amount": 60}], "tx1", 100)
    obj._graffiti_registry.record_post.assert_called_once()
    
    # Missing art id logic
    meta_bad = {"sha256": "", "creator": ""}
    obj._handle_graffiti_post(meta_bad, [], "tx1", 100)

@patch("tsarchain.storage.utxo_logic.graff_utxo.GRAFFITI")
@patch("tsarchain.storage.utxo_logic.graff_utxo.CFG")
def test_handle_graffiti_comment(mock_cfg, mock_graff):
    mock_cfg.GRAFFITI_COMMENT_MIN_FEE = 10
    obj = MockUTXOGraff()
    
    # missing art id
    obj._handle_graffiti_comment({}, [], "tx1", 100)
    
    meta = {"art_id": "art1", "creator": "me", "amount": 20, "tip": 5}
    # unknown post
    obj._graffiti_registry.get_post.return_value = None
    obj._handle_graffiti_comment(meta, [], "tx1", 100)
    
    # fee too low
    obj._graffiti_registry.get_post.return_value = {"creator": "me", "pool_address": "pool"}
    meta_low = {"art_id": "art1", "amount": 5}
    obj._handle_graffiti_comment(meta_low, [], "tx1", 100)
    
    # success with shortfall warning logic
    mock_graff.calc_comment_split.return_value = {"creator_total": 15, "storage": 10}
    obj._handle_graffiti_comment(meta, [{"address": "me", "amount": 10}, {"address": "pool", "amount": 5}], "tx1", 100)
    obj._graffiti_registry.record_comment.assert_called_once()
    
    # Missing creator
    obj._graffiti_registry.get_post.return_value = {}
    obj._handle_graffiti_comment({"art_id": "art1"}, [], "tx1", 100)

@patch("tsarchain.storage.utxo_logic.graff_utxo.GRAFFITI")
def test_handle_graffiti_payout(mock_graff):
    obj = MockUTXOGraff()
    mock_graff.derive_pool_address.return_value = "pool"
    
    # missing art id
    obj._handle_graffiti_payout({}, [], "tx1", 100)
    
    # unknown post
    meta = {"art_id": "art1", "recipients": [{"address": "a1", "amount": 10}], "epoch": 2}
    obj._graffiti_registry.get_post.return_value = None
    obj._handle_graffiti_payout(meta, [], "tx1", 100)
    
    # missing recs
    obj._graffiti_registry.get_post.return_value = {"stats": {"pool_balance": 100, "last_paid_epoch": 1}}
    obj._handle_graffiti_payout({"art_id": "art1"}, [], "tx1", 100)
    
    # epoch rewind
    meta_rewind = {"art_id": "art1", "recipients": [{"address": "a1", "amount": 10}], "epoch": 0}
    obj._handle_graffiti_payout(meta_rewind, [], "tx1", 100)
    
    # epoch idempotent same tx
    obj._graffiti_registry.data = {"payouts": {"art1": [{"txid": "tx1"}]}}
    meta_same = {"art_id": "art1", "recipients": [{"address": "a1", "amount": 10}], "epoch": 1}
    obj._handle_graffiti_payout(meta_same, [], "tx1", 100)
    
    # success payout
    obj._graffiti_registry.data = {"payouts": {}}
    mock_graff.compute_proof_epoch.return_value = 2
    meta_ok = {
        "art_id": "art1", "epoch": 2, 
        "recipients": [{"address": "a1", "amount": 10}, {"address": "bad", "amount": 0}],
        "proof_height": 100, "proof_storer": "me", "proof_offset": 0, "proof_length": 10, "proof_hash": "a"*64
    }
    outputs = [{"address": "a1", "amount": 8}] # shortfall
    obj._handle_graffiti_payout(meta_ok, outputs, "tx2", 100)
    obj._graffiti_registry.record_payout.assert_called_once()
    obj._graffiti_registry.record_proof.assert_called_once()
    
    # total > pool
    obj._graffiti_registry.get_post.return_value = {"stats": {"pool_balance": 5, "last_paid_epoch": 1}}
    obj._handle_graffiti_payout(meta_ok, [{"address": "a1", "amount": 10}], "tx3", 100)
