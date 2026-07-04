# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
from unittest.mock import Mock, patch

import tsarchain.utils.config as CFG

from tsarchain.core.tx import Tx
from tsarchain.storage.utxo import UTXODB
from tsarchain.mempool.validation import TxMempoolValidator
from tsarchain.contracts.graffiti_registry import GraffitiRegistry

# --- Fixtures ---

@pytest.fixture
def mock_config():
    with patch.multiple(CFG,
        MAX_TX_VSIZE=400000,
        MIN_TX_VSIZE=60,
        MAX_TX_WEIGHT=4000000,
        MIN_TX_WEIGHT=600,
        MAX_TX_INPUTS=1000,
        MAX_TX_OUTPUTS=1000,
        MAX_GRAFFITI_OPRET=80,
        GRAFFITI_MAGIC=b'graf',
        GRAFFITI_MAX_SIZE_BYTES=100000,
        GRAFFITI_COMMENT_MAX_BYTES=1000,
        GRAFFITI_COMMENT_MIN_FEE=1000,
        MAX_GRAFFITI_ON_MEMPOOL=10,
        COINBASE_MATURITY=100,
        MAX_SIGOPS_PER_TX=100,
        MAX_SIGOPS_PER_BLOCK=1000,
        ADDRESS_PREFIX='tsar',
        ):
        yield

@pytest.fixture
def mock_utxo_db():
    db = Mock(spec=UTXODB)
    db._get_tip_height_from_state = Mock(return_value=1000)
    db._get_utxo_meta = Mock(return_value=(False, 0))
    db.lookup_entry = Mock(return_value=None)
    db._graffiti_registry = Mock(spec=GraffitiRegistry)
    return db

@pytest.fixture
def validator(mock_utxo_db):
    val = TxMempoolValidator()
    val.utxo = mock_utxo_db
    val._pool = {}
    val.last_error_reason = None
    return val

@pytest.fixture
def sample_tx():
    tx = Mock(spec=Tx)
    tx.is_coinbase = False
    tx.txid = "1234" * 16          # 64 karakter = 32 byte
    tx.version = 1
    tx.locktime = 0

    tx_in = Mock()
    tx_in.txid = "deadbeef" * 8     # 64 karakter = 32 byte
    tx_in.vout = 0
    tx_in.sequence = 0xffffffff
    tx_in.witness = []
    tx_in.script_sig = b''
    tx.inputs = [tx_in]

    tx_out = Mock()
    tx_out.amount = 50000
    tx_out.script_pubkey = bytes.fromhex("0014" + "00" * 40)  # 20 byte hash
    tx.outputs = [tx_out]

    tx.fee = None
    return tx

def mock_weight_ok(tx):
    return (1000, 250, 100, 250)

def mock_weight_too_large_weight_only(tx):
    return (5000000, 250, 100, 250)

def mock_weight_too_small(tx):
    return (500, 70, 50, 70)   # weight < 600, vsize > 60

def make_graffiti_payload(event, **kwargs):
    return {**kwargs, 'event': event}

# --- Tests ---

def test_valid_p2wpkh_tx(validator, sample_tx, mock_config):
    validator._utxo_snapshot_to_items = Mock(return_value=[
        (bytes.fromhex("deadbeef" * 8), 0, 100000,
            b"\x00\x14" + b"\x00" * 20, False, 0)
    ])
    validator.script_to_address = Mock(return_value="tsar1q...")

    with patch('tsarchain.mempool.validation.GRAFFITI.parse_from_script', return_value=None):
        with patch('tsarchain.mempool.validation.last_pushdata', return_value=None):
            with patch('tsarchain.mempool.validation.compute_tx_weight_vsize', side_effect=mock_weight_ok):
                with patch('tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact',
                            return_value=(True, "", 1000)) as mock_native:
                    utxo_set = {
                        "deadbeef" * 8 + ":0": {"tx_out": {"amount": 100000,
                                                            "script_pubkey": b"\x00\x14" + b"\x00" * 20}}
                    }
                    result = validator.validate_transaction(sample_tx, utxo_set)
                    assert result is True
                    assert sample_tx.fee == 1000
                    mock_native.assert_called_once()

def test_tx_size_limit_exceeded(validator, sample_tx, mock_config):
    with patch('tsarchain.mempool.validation.compute_tx_weight_vsize',
                side_effect=mock_weight_too_large_weight_only):
        result = validator.validate_transaction(sample_tx, {})
        assert result is False
        assert validator.last_error_reason == "tx_weight_exceeds_limit"

    with patch('tsarchain.mempool.validation.compute_tx_weight_vsize', side_effect=mock_weight_too_small):
        result = validator.validate_transaction(sample_tx, {})
        assert result is False
        assert validator.last_error_reason == "tx_weight_below_min"

def test_graffiti_post_success(validator, sample_tx, mock_config):
    tx = sample_tx
    payload = make_graffiti_payload('POST', size=100, data=b'abcdef')

    magic = CFG.GRAFFITI_MAGIC
    data_bytes = magic + b'\x01'
    script_bytes = b'\x6a' + bytes([len(data_bytes)]) + data_bytes

    spk = Mock()
    spk.serialize = Mock(return_value=script_bytes)
    tx_out = Mock()
    tx_out.amount = 0
    tx_out.script_pubkey = spk
    tx.outputs = [tx_out]

    # Provide a UTXO for the input
    validator._utxo_snapshot_to_items = Mock(return_value=[
        (bytes.fromhex("deadbeef" * 8), 0, 100000,
            b"\x00\x14" + b"\x00" * 20, False, 0)
    ])

    with patch('tsarchain.mempool.validation.last_pushdata', return_value=data_bytes):
        with patch('tsarchain.mempool.validation.GRAFFITI.parse_payload', return_value=payload):
            with patch('tsarchain.mempool.validation.GRAFFITI.parse_from_script', return_value=payload):
                with patch('tsarchain.mempool.validation.compute_tx_weight_vsize', side_effect=mock_weight_ok):
                    with patch('tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact',
                                return_value=(True, "", 500)) as mock_native:
                        utxo_set = {}
                        result = validator.validate_transaction(tx, utxo_set)
                        assert result is True
                        assert tx.fee == 500
                        mock_native.assert_called_once()

def test_graffiti_post_mempool_full(validator, sample_tx, mock_config):
    existing_tx = Mock(spec=Tx)
    existing_tx.outputs = []
    for _ in range(10):
        spk = Mock()
        spk.serialize = Mock(return_value=b'\x6a\x02GRF\x01')
        out = Mock()
        out.script_pubkey = spk
        out.amount = 0
        existing_tx.outputs.append(out)
    validator._pool = {f"tx{i}": existing_tx for i in range(10)}

    tx = sample_tx
    payload = make_graffiti_payload('POST', size=100)
    magic = CFG.GRAFFITI_MAGIC
    data_bytes = magic + b'\x01'
    script_bytes = b'\x6a' + bytes([len(data_bytes)]) + data_bytes
    spk = Mock()
    spk.serialize = Mock(return_value=script_bytes)
    tx_out = Mock()
    tx_out.amount = 0
    tx_out.script_pubkey = spk
    tx.outputs = [tx_out]

    # Provide a UTXO for the input so we pass the prevout check
    validator._utxo_snapshot_to_items = Mock(return_value=[
        (bytes.fromhex("deadbeef" * 8), 0, 100000,
            b"\x00\x14" + b"\x00" * 20, False, 0)
    ])

    with patch('tsarchain.mempool.validation.last_pushdata', return_value=data_bytes):
        with patch('tsarchain.mempool.validation.GRAFFITI.parse_payload', return_value=payload):
            with patch('tsarchain.mempool.validation.GRAFFITI.parse_from_script', return_value=payload):
                with patch('tsarchain.mempool.validation.compute_tx_weight_vsize', side_effect=mock_weight_ok):
                    with patch('tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact',
                                return_value=(True, "", 500)):
                        utxo_set = {}
                        result = validator.validate_transaction(tx, utxo_set)
                        assert result is False
                        assert validator.last_error_reason == "mempool_graffiti_full"

def test_graffiti_payout_success(validator, sample_tx, mock_config):
    tx = sample_tx
    art_id = "myart"
    recipients = [
        {"addr": "tsar1qabc", "amount": 20000},
        {"addr": "tsar1qdef", "amount": 30000}
    ]
    payout_payload = {
        'event': 'PAYOUT',
        'art_id': art_id,
        'epoch': 5,
        'recipients': recipients,
        'proof_epoch': 5,
    }

    # Two different output scripts for the two recipients
    script_a = b'\x00\x14' + b'\xaa' * 20   # for abc
    script_b = b'\x00\x14' + b'\xbb' * 20   # for def

    # Side effect must compare serialized script bytes, not the Mock object
    def script_to_addr_side_effect(spk):
        raw = spk.serialize() if hasattr(spk, 'serialize') else spk
        if raw == script_a:
            return "tsar1qabc"
        elif raw == script_b:
            return "tsar1qdef"
        return None
    validator.script_to_address = Mock(side_effect=script_to_addr_side_effect)

    pool_script_hash = "abcd" * 16          # <--- ubah dari *8 menjadi *16
    pool_script_bytes = b"\x00\x20" + bytes.fromhex(pool_script_hash)

    # Build outputs: OP_RETURN + two recipient outputs
    spk_payout = Mock()
    spk_payout.serialize = Mock(return_value=b'\x6a\x02GRF\x01')
    tx_out_payout = Mock()
    tx_out_payout.amount = 0
    tx_out_payout.script_pubkey = spk_payout

    outputs = [tx_out_payout]
    for rec, script in zip(recipients, [script_a, script_b]):
        spk = Mock()
        spk.serialize = Mock(return_value=script)
        out = Mock()
        out.amount = rec['amount']
        out.script_pubkey = spk
        outputs.append(out)
    tx.outputs = outputs

    # UTXO: one input spending from pool with sufficient total
    validator._utxo_snapshot_to_items = Mock(return_value=[
        (bytes.fromhex("deadbeef" * 8), 0, 60000, pool_script_bytes, False, 0)
    ])
    validator._lookup_utxo_entry = Mock(
        side_effect=lambda snap, txid, idx: {
            "deadbeef" * 8 + ":0": {"tx_out": {"amount": 60000, "script_pubkey": pool_script_bytes}}
        }.get(f"{txid}:{idx}")
    )
    validator._get_utxo_amount = Mock(return_value=60000)

    registry_mock = Mock(spec=GraffitiRegistry)
    registry_mock.get_post = Mock(return_value={"stats": {"pool_balance": 60000, "last_paid_epoch": 4}})
    registry_mock.get_latest_proof_epoch = Mock(return_value=5)
    validator.utxo._graffiti_registry = registry_mock
    
    def get_script_side_effect(data):
        if isinstance(data, dict) and "tx_out" in data:
            tx_out = data["tx_out"]
            if isinstance(tx_out, dict) and "script_pubkey" in tx_out:
                spk = tx_out["script_pubkey"]
                if hasattr(spk, "serialize"):
                    return spk.serialize()
                elif isinstance(spk, bytes):
                    return spk
        return pool_script_bytes

    with patch('tsarchain.mempool.validation.GRAFFITI.parse_from_script', return_value=payout_payload):
        with patch('tsarchain.mempool.validation.GRAFFITI.hash_pool_redeem_script',
                    return_value=pool_script_hash):
            with patch('tsarchain.mempool.validation.get_utxo_script_bytes', side_effect=get_script_side_effect):
                with patch('tsarchain.mempool.validation.compute_tx_weight_vsize', side_effect=mock_weight_ok):
                    with patch('tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact',
                                return_value=(True, "", 0)):
                        utxo_set = {
                            "deadbeef" * 8 + ":0": {"tx_out": {"amount": 60000, "script_pubkey": pool_script_bytes}}
                        }
                        result = validator.validate_transaction(tx, utxo_set)
                        assert result is True
                        assert tx.fee == 10000   # 60000 - 50000

def test_graffiti_payout_insufficient_pool(validator, sample_tx, mock_config):
    art_id = "myart"
    recipients = [
        {"addr": "tsar1qabc", "amount": 20000},
        {"addr": "tsar1qdef", "amount": 30000}
    ]
    payout_payload = {
        'event': 'PAYOUT',
        'art_id': art_id,
        'epoch': 5,
        'recipients': recipients,
        'proof_epoch': 5,
    }

    script_a = b'\x00\x14' + b'\xaa' * 20
    script_b = b'\x00\x14' + b'\xbb' * 20

    def script_to_addr_side_effect(spk):
        raw = spk.serialize() if hasattr(spk, 'serialize') else spk
        if raw == script_a:
            return "tsar1qabc"
        elif raw == script_b:
            return "tsar1qdef"
        return None
    validator.script_to_address = Mock(side_effect=script_to_addr_side_effect)

    pool_script_hash = "abcd" * 8
    pool_script_bytes = b"\x00\x20" + bytes.fromhex(pool_script_hash)

    # UTXO with enough amount, but pool balance is too low
    validator._utxo_snapshot_to_items = Mock(return_value=[
        (bytes.fromhex("deadbeef" * 8), 0, 100000, pool_script_bytes, False, 0)
    ])
    validator._lookup_utxo_entry = Mock(
        side_effect=lambda snap, txid, idx: {
            "deadbeef" * 8 + ":0": {"tx_out": {"amount": 100000, "script_pubkey": pool_script_bytes}}
        }.get(f"{txid}:{idx}")
    )
    validator._get_utxo_amount = Mock(return_value=100000)

    registry_mock = Mock(spec=GraffitiRegistry)
    registry_mock.get_post = Mock(return_value={"stats": {"pool_balance": 40000, "last_paid_epoch": 4}})
    registry_mock.get_latest_proof_epoch = Mock(return_value=5)
    validator.utxo._graffiti_registry = registry_mock

    # Build outputs
    spk_payout = Mock()
    spk_payout.serialize = Mock(return_value=b'\x6a\x02GRF\x01')
    tx_out_payout = Mock()
    tx_out_payout.amount = 0
    tx_out_payout.script_pubkey = spk_payout
    outputs = [tx_out_payout]
    for rec, script in zip(recipients, [script_a, script_b]):
        spk = Mock()
        spk.serialize = Mock(return_value=script)
        out = Mock()
        out.amount = rec['amount']
        out.script_pubkey = spk
        outputs.append(out)
    tx = sample_tx
    tx.outputs = outputs
    
    def get_script_side_effect(data):
        if isinstance(data, dict) and "tx_out" in data:
            tx_out = data["tx_out"]
            if isinstance(tx_out, dict) and "script_pubkey" in tx_out:
                spk = tx_out["script_pubkey"]
                if hasattr(spk, "serialize"):
                    return spk.serialize()
                elif isinstance(spk, bytes):
                    return spk
        return pool_script_bytes

    with patch('tsarchain.mempool.validation.GRAFFITI.parse_from_script', return_value=payout_payload):
        with patch('tsarchain.mempool.validation.GRAFFITI.hash_pool_redeem_script',
                    return_value=pool_script_hash):
            with patch('tsarchain.mempool.validation.get_utxo_script_bytes', side_effect=get_script_side_effect):
                with patch('tsarchain.mempool.validation.compute_tx_weight_vsize', side_effect=mock_weight_ok):
                    with patch('tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact',
                                return_value=(True, "", 0)):
                        utxo_set = {
                            "deadbeef" * 8 + ":0": {"tx_out": {"amount": 100000, "script_pubkey": pool_script_bytes}}
                        }
                        result = validator.validate_transaction(tx, utxo_set)
                        assert result is False
                        assert validator.last_error_reason == "payout_exceeds_pool"

def test_missing_utxo(validator, sample_tx, mock_config):
    art_id = "myart"
    recipients = [{"addr": "tsar1qabc", "amount": 20000}]
    payout_payload = {
        'event': 'PAYOUT',
        'art_id': art_id,
        'epoch': 5,
        'recipients': recipients,
        'proof_epoch': 5,
    }

    # Mock script_to_address for recipient output
    script_rec = b'\x00\x14' + b'\xaa' * 20
    def script_to_addr_side_effect(spk):
        raw = spk.serialize() if hasattr(spk, 'serialize') else spk
        if raw == script_rec:
            return "tsar1qabc"
        return None
    validator.script_to_address = Mock(side_effect=script_to_addr_side_effect)

    pool_script_hash = "abcd" * 8
    pool_script_bytes = b"\x00\x20" + bytes.fromhex(pool_script_hash)

    # No UTXO available
    validator._utxo_snapshot_to_items = Mock(return_value=[])
    validator._lookup_utxo_entry = Mock(return_value=None)

    registry_mock = Mock(spec=GraffitiRegistry)
    registry_mock.get_post = Mock(return_value={"stats": {"pool_balance": 50000, "last_paid_epoch": 4}})
    registry_mock.get_latest_proof_epoch = Mock(return_value=5)
    validator.utxo._graffiti_registry = registry_mock

    # Build outputs: OP_RETURN + one recipient
    spk_payout = Mock()
    spk_payout.serialize = Mock(return_value=b'\x6a\x02GRF\x01')
    tx_out_payout = Mock()
    tx_out_payout.amount = 0
    tx_out_payout.script_pubkey = spk_payout
    spk_rec = Mock()
    spk_rec.serialize = Mock(return_value=script_rec)
    out_rec = Mock()
    out_rec.amount = 20000
    out_rec.script_pubkey = spk_rec
    tx = sample_tx
    tx.outputs = [tx_out_payout, out_rec]
    
    def get_script_side_effect(data):
        if isinstance(data, dict) and "tx_out" in data:
            tx_out = data["tx_out"]
            if isinstance(tx_out, dict) and "script_pubkey" in tx_out:
                spk = tx_out["script_pubkey"]
                if hasattr(spk, "serialize"):
                    return spk.serialize()
                elif isinstance(spk, bytes):
                    return spk
        return pool_script_bytes

    with patch('tsarchain.mempool.validation.GRAFFITI.parse_from_script', return_value=payout_payload):
        with patch('tsarchain.mempool.validation.GRAFFITI.hash_pool_redeem_script',
                    return_value=pool_script_hash):
            with patch('tsarchain.mempool.validation.get_utxo_script_bytes', side_effect=get_script_side_effect):
                with patch('tsarchain.mempool.validation.compute_tx_weight_vsize', side_effect=mock_weight_ok):
                    with patch('tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact',
                                return_value=(True, "", 0)):
                        result = validator.validate_transaction(tx, {})
                        assert result is False
                        assert validator.last_error_reason == "missing_prevout"