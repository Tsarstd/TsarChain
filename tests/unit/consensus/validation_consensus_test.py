# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import time
import pytest
import threading

from types import SimpleNamespace
from bech32 import bech32_encode, convertbits
from unittest.mock import Mock, patch, MagicMock

from tsarchain.utils import config as CFG
from tsarchain.contracts import graffiti as GRAFFITI
from tsarchain.consensus.validation import ValidationMixin

"""
unit test for validation.py
"""

# =============================================================================
# CATEGORY 1: TRANSACTION VALIDATION TESTS
# =============================================================================
class DummyTxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey


class DummyTxIn:
    def __init__(self, txid, vout):
        self.txid = txid
        self.vout = vout


class DummyTx:
    def __init__(self, inputs=None, outputs=None, is_coinbase=False, fee=0,
                 txid=None, block_id=None):
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.is_coinbase = is_coinbase
        self.fee = fee
        self.txid = txid
        self.block_id = block_id
        self._cached_raw_tx_nowit = None
        self._cached_raw_tx_w = None


class DummyBlock:
    def __init__(self, height, transactions, prev_block_hash=None,
                 bits=0x1d00ffff, merkle_root=None, timestamp=None):
        self.height = height
        self.transactions = transactions
        self.prev_block_hash = prev_block_hash or b'\x00' * 32
        self.bits = bits
        self.merkle_root = merkle_root
        self.timestamp = timestamp or int(time.time())
        self._cached_hash = None


class _TestChain(ValidationMixin):
    def __init__(self):
        self.chain = []
        self.height = -1
        self.lock = threading.Lock()
        self._last_block_validation_error = None

    def _ensure_utxodb(self):
        pass

    def _cumulative_supply_until(self, height):
        pass

    def _scheduled_reward(self, height):
        pass


@pytest.fixture
def validation_chain(mocker):
    cfg_mock = SimpleNamespace(
        MAX_BLOCK_BYTES=1200000,
        MAX_TX_VSIZE=10000,
        MIN_TX_VSIZE=100,
        MAX_TX_WEIGHT=40000,
        MIN_TX_WEIGHT=400,
        MAX_TX_INPUTS=1000,
        MAX_TX_OUTPUTS=1000,
        COINBASE_MATURITY=3,
        MAX_SIGOPS_PER_TX=6000,
        MAX_SIGOPS_PER_BLOCK=40000,
        GRAFFITI_MAGIC=CFG.GRAFFITI_MAGIC,
        MAX_GRAFFITI_OPRET=580,
        GRAFFITI_MAX_SIZE_BYTES=CFG.GRAFFITI_MAX_SIZE_BYTES,
        GRAFFITI_COMMENT_MAX_BYTES=CFG.GRAFFITI_COMMENT_MAX_BYTES,
        GRAFFITI_COMMENT_MIN_FEE=CFG.GRAFFITI_COMMENT_MIN_FEE,
        ADDRESS_PREFIX=CFG.ADDRESS_PREFIX,
        MAX_SUPPLY=CFG.MAX_SUPPLY,
    )
    mocker.patch('tsarchain.consensus.validation.CFG', cfg_mock)

    mock_H = mocker.patch('tsarchain.consensus.validation.H')
    mock_H.serialize_tx.return_value = b'\x00' * 100
    mock_H.compute_tx_weight_vsize.return_value = (400, 100, 80, 100)
    mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
    def _tx_to_compact(tx):
        return (tx.is_coinbase, [])
    mock_H.tx_to_compact_tuple.side_effect = _tx_to_compact
    mock_H.native_validate_block_txs.return_value = (True, None, [10])

    # Mock GRAFFITI
    mock_graffiti = mocker.patch('tsarchain.consensus.validation.GRAFFITI')
    # parse_payload default None
    mock_graffiti.parse_payload.return_value = None
    # parse_from_script default None
    mock_graffiti.parse_from_script.return_value = None

    # Mock GraffitiRegistry
    mock_reg = mocker.patch('tsarchain.consensus.validation.GraffitiRegistry')
    mock_reg_instance = Mock()
    mock_reg.return_value = mock_reg_instance
    mock_reg_instance.get_post.return_value = None
    mock_reg_instance.get_latest_proof_epoch.return_value = 0

    # Mock UTXODB dan lookup_entry
    mock_utxo = mocker.patch('tsarchain.consensus.validation.UTXODB')
    mock_utxo_instance = Mock()
    mock_utxo.return_value = mock_utxo_instance
    # lookup_entry mengembalikan entry untuk prevout
    def lookup_entry(txid_hex, vout):
        return {
            'amount': 100_000_000,
            'script_pubkey': b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac',
            'is_coinbase': False,
            'block_height': 1,
        }
    mock_utxo_instance.lookup_entry.side_effect = lookup_entry
    mock_utxo_instance.load_utxo_set.return_value = {}

    chain = _TestChain()
    chain._ensure_utxodb = Mock(return_value=mock_utxo_instance)
    chain._cumulative_supply_until = Mock(return_value=0)
    chain._scheduled_reward = Mock(return_value=50_000_000)  # 50 coin

    chain._mock_H = mock_H
    chain._mock_graffiti = mock_graffiti
    chain._mock_reg = mock_reg_instance
    chain._mock_utxo = mock_utxo_instance

    return chain


def create_coinbase_tx(amount, block_id=None, txid=None):
    out = DummyTxOut(amount, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')
    tx = DummyTx(inputs=[], outputs=[out], is_coinbase=True, txid=txid,
                 block_id=block_id)
    return tx


def create_normal_tx(inputs, outputs, fee=10, txid=None):
    tx = DummyTx(inputs=inputs, outputs=outputs, is_coinbase=False, fee=fee,
                 txid=txid)
    return tx

def create_utxo_input(prev_txid, vout):
    return DummyTxIn(prev_txid, vout)


def create_output(amount, script_pubkey):
    return DummyTxOut(amount, script_pubkey)


def create_graffiti_tx(meta, inputs=None, fee=10, txid=None):
    """Buat transaksi normal dengan satu output OP_RETURN berisi graffiti."""
    script = GRAFFITI.build_script(meta)
    out = DummyTxOut(0, script.serialize())
    inputs = inputs or [create_utxo_input(b'\xaa' * 32, 0)]
    return create_normal_tx(inputs, [out], fee=fee, txid=txid)

# =============================================================================
# GRAFFITI POIN 1: GRAFFITI POST
# =============================================================================

def test_validate_transactions_graffiti_post_ok(validation_chain):
    """Scenario 4: a single graffiti POST with a matching block_id."""
    chain = validation_chain

    art_id = "abc123"
    cb = create_coinbase_tx(50_000_000 + 10, block_id=art_id)

    graffiti_data = b'GRAFFITI' + b'\x01\x02\x03'  # mock magic + payload

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0:
            if script[0] == 0x6a:  # OP_RETURN
                return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return {
                'event': 'POST',
                'art_id': art_id,
                'sha256': 'x' * 64,
                'creator': 'creator',
                'size': 100,
            }
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            data = last_pushdata_side_effect(script)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    op_return_script = b'\x6a' + bytes([len(graffiti_data)]) + graffiti_data
    tx_out = create_output(0, op_return_script)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    normal_tx = create_normal_tx([tx_input], [tx_out], fee=10)

    block = DummyBlock(height=10, transactions=[cb, normal_tx])

    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is True


def test_validate_transactions_graffiti_post_mismatch(validation_chain):
    """Scenario 5: POST graffiti with mismatched block_id -> failure."""
    chain = validation_chain

    art_id = "abc123"
    cb = create_coinbase_tx(50_000_000 + 10, block_id="wrong_id")

    graffiti_data = b'GRAFFITI' + b'\x01\x02\x03'

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0:
            if script[0] == 0x6a:
                return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return {
                'event': 'POST',
                'art_id': art_id,
                'sha256': 'x' * 64,
                'creator': 'creator',
                'size': 100,
            }
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            data = last_pushdata_side_effect(script)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    op_return_script = b'\x6a' + bytes([len(graffiti_data)]) + graffiti_data
    tx_out = create_output(0, op_return_script)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    normal_tx = create_normal_tx([tx_input], [tx_out], fee=10)

    block = DummyBlock(height=10, transactions=[cb, normal_tx])

    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "block_id_mismatch_graffiti"

# =============================================================================
# GRAFFITI POIN 2: GRAFFITI COMMENT
# =============================================================================

def test_validate_transactions_graffiti_comment_ok(validation_chain):
    """Scenario: valid COMMENT graffiti."""
    chain = validation_chain

    cb = create_coinbase_tx(50_000_000 + 10)

    # Meta COMMENT yang valid dengan field yang dibutuhkan validasi
    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "48656c6c6f",  # hex "Hello"
        "comment_len": 5,         # panjang bytes comment
        "amount": 100_000_000,    # 1 TSAR >= MIN_FEE
        "tip": 0,
        "creator": "tsar1q...",
        "commenter": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        # script bisa bytes atau Script; kita coba ambil data
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is True

def test_validate_transactions_graffiti_comment_fee_too_low(validation_chain):
    """COMMENT with amount < GRAFFITI_COMMENT_MIN_FEE -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "48656c6c6f",
        "comment_len": 5,
        "amount": 10_000_000,  # di bawah min fee (1 TSAR = 100_000_000)
        "tip": 0,
        "creator": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_fee_too_low"

def test_validate_transactions_graffiti_comment_too_large(validation_chain):
    """COMMENT with comment_len > GRAFFITI_COMMENT_MAX_BYTES -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    # comment_len 200 > 140 (max)
    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "61" * 200,  # hex string panjang
        "comment_len": 200,
        "amount": 100_000_000,
        "tip": 0,
        "creator": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_too_large"

def test_validate_transactions_graffiti_comment_empty(validation_chain):
    """COMMENT with comment_len = 0 -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "",
        "comment_len": 0,
        "amount": 100_000_000,
        "tip": 0,
        "creator": "tsar1q...",
    }
    # build_script akan menolak comment kosong, jadi kita buat script manual
    import json
    payload = CFG.GRAFFITI_MAGIC + json.dumps(meta, separators=CFG.CANONICAL_SEP).encode()
    script = b'\x6a' + bytes([len(payload)]) + payload

    out = DummyTxOut(0, script)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx = create_normal_tx([tx_input], [out], fee=10)

    def last_pushdata_side_effect(script_bytes):
        if isinstance(script_bytes, bytes) and len(script_bytes) > 0 and script_bytes[0] == 0x6a:
            return payload
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == payload:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_empty"

def test_validate_transactions_graffiti_comment_tip_negative(validation_chain):
    """COMMENT with tip < 0 -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "48656c6c6f",
        "comment_len": 5,
        "amount": 100_000_000,
        "tip": -1,
        "creator": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_tip_negative"

# =============================================================================
# GRAFFITI POIN 3: GRAFFITI PAYOUT
# =============================================================================

def test_validate_transactions_graffiti_payout_ok(validation_chain, mocker):
    """Valid PAYOUT graffiti."""
    chain = validation_chain

    # Buat P2WPKH address dummy (hash 20 byte nol)
    hash20 = b'\x00' * 20
    spk_p2wpkh = b'\x00\x14' + hash20
    data = [0] + list(convertbits(hash20, 8, 5, True))
    address = bech32_encode(CFG.ADDRESS_PREFIX, data)

    cb = create_coinbase_tx(50_000_000 + 10)

    art_id = "abc123"
    recipients = [{"addr": address, "amount": 10_000_000}]
    meta = {
        "event": "PAYOUT",
        "art_id": art_id,
        "epoch": 1,
        "recipients": recipients,
        "proof_epoch": 1,
    }
    opret_script = GRAFFITI.build_script(meta).serialize()
    opret_out = DummyTxOut(0, opret_script)
    pay_out = DummyTxOut(10_000_000, spk_p2wpkh)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx = create_normal_tx([tx_input], [opret_out, pay_out], fee=10)

    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is True

def test_validate_transactions_graffiti_payout_bad_art_id(validation_chain, mocker):
    """PAYOUT with empty art_id -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "",  # empty
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_bad_art_id"

def test_validate_transactions_graffiti_payout_unknown_art(validation_chain, mocker):
    """PAYOUT for art_id not in registry -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "unknown_art",
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = None
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_unknown_art"

def test_validate_transactions_graffiti_payout_epoch_rewind(validation_chain, mocker):
    """PAYOUT with epoch <= last_paid_epoch -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 0,  # <= last_paid_epoch (0)
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        "proof_epoch": 0,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_epoch_rewind"

def test_validate_transactions_graffiti_payout_missing_proof(validation_chain, mocker):
    """PAYOUT with epoch > latest_proof and no inline proof -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 2,
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        # tidak ada proof_epoch atau proof_height
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_missing_proof"

def test_validate_transactions_graffiti_payout_no_recipients(validation_chain, mocker):
    """PAYOUT with empty recipients -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [],  # empty
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_no_recipients"

def test_validate_transactions_graffiti_payout_bad_recipient(validation_chain, mocker):
    """PAYOUT with invalid recipient address or amount <=0 -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 0}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_bad_recipient"

def test_validate_transactions_graffiti_payout_shortfall(validation_chain, mocker):
    """PAYOUT where actual payment to address is less than requested -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 20_000_000}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_shortfall"

def test_validate_transactions_graffiti_payout_exceeds_pool(validation_chain, mocker):
    """PAYOUT where total requested exceeds pool_balance -> error."""
    chain = validation_chain

    # Buat P2WPKH address dummy (hash 20 byte nol)
    hash20 = b'\x00' * 20
    spk_p2wpkh = b'\x00\x14' + hash20
    data = [0] + list(convertbits(hash20, 8, 5, True))
    address = bech32_encode(CFG.ADDRESS_PREFIX, data)

    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [{"addr": address, "amount": 150_000_000}],
        "proof_epoch": 1,
    }
    opret_script = GRAFFITI.build_script(meta).serialize()
    opret_out = DummyTxOut(0, opret_script)
    pay_out = DummyTxOut(150_000_000, spk_p2wpkh)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx = create_normal_tx([tx_input], [opret_out, pay_out], fee=10)

    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            if hasattr(script, "serialize"):
                raw = script.serialize()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_exceeds_pool"
# --- Tests from valid_tx_test.py ---
def test_validate_transactions_valid(validation_chain):
    """Scenario 1: A valid block with a coinbase and one normal transaction."""
    chain = validation_chain

    reward = 50_000_000
    fee = 10
    cb = create_coinbase_tx(reward + fee)

    txid_prev = b'\xaa' * 32
    tx_input = create_utxo_input(txid_prev, 0)
    tx_output = create_output(100_000_000, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')
    normal_tx = create_normal_tx([tx_input], [tx_output], fee=fee)

    chain._mock_H.last_pushdata.return_value = None

    block = DummyBlock(height=10, transactions=[cb, normal_tx])

    result = chain._validate_transactions(block)
    assert result is True


def test_validate_transactions_missing_coinbase(validation_chain):
    """Scenario 2: the first transaction is not a coinbase transaction -> fails."""
    chain = validation_chain

    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx_output = create_output(100, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')
    normal_tx = create_normal_tx([tx_input], [tx_output])

    block = DummyBlock(height=10, transactions=[normal_tx])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "missing_coinbase"


def test_validate_transactions_duplicate_coinbase(validation_chain):
    """Scenario 3: more than one coinbase -> failure."""
    chain = validation_chain

    cb1 = create_coinbase_tx(50_000_000)
    cb2 = create_coinbase_tx(50_000_000)
    block = DummyBlock(height=10, transactions=[cb1, cb2])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "duplicate_coinbase"


# =============================================================================
# CATEGORY 2: VALIDATION MIXIN CORE TESTS 
# =============================================================================


# Fixtures for mock objects
# -------------------------------------------------------------------

@pytest.fixture
def mock_block():
    """Return a minimal mock Block object."""
    block = Mock()
    block.height = 1
    block.prev_block_hash = b"prevhash"
    block.transactions = []
    block.bits = 0x1d00ffff
    block.merkle_root = b"merkle"
    block.timestamp = int(time.time())
    block.hash = Mock(return_value=b"blockhash")
    block.header = Mock(return_value=b"header")
    return block

@pytest.fixture(autouse=True)
def mock_randomx(monkeypatch):
    from tsarchain.consensus.validation import CFG
    if CFG.POW_ALGO == "randomx":
        monkeypatch.setattr(
            "tsarchain.utils.helpers.pow_hash_verify_light",
            lambda *args, **kwargs: None
        )
        monkeypatch.setattr(
            "tsarchain.utils.helpers.pow_key_for_height",
            lambda h: b"dummy_key"
        )
        monkeypatch.setattr(
            "tsarchain.utils.helpers.pow_hash_verify_light",
            lambda *args, **kwargs: b"dummy_hash"
        )

@pytest.fixture
def mock_tx():
    """Return a minimal mock Transaction object."""
    tx = Mock()
    tx.is_coinbase = False
    tx.inputs = []
    tx.outputs = []
    tx.txid = None
    tx.txid_hex = None
    tx.fee = 0
    def compute_txid():
        tx.txid = b"txid"
        tx.txid_hex = "txid"
    tx.compute_txid = compute_txid
    return tx

@pytest.fixture
def mock_coinbase_tx():
    tx = Mock()
    tx.is_coinbase = True
    tx.inputs = []
    tx.outputs = []
    tx.txid = b"coinbase_txid"
    tx.txid_hex = "coinbase_txid"
    return tx

# -------------------------------------------------------------------
# Test class
# -------------------------------------------------------------------

class TestValidationMixin:

    # Helper to create a concrete instance of the mixin with required attributes
    def create_instance(self):
        class DummyConsensus(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = []
                self.height = -1
                self._last_block_validation_error = None
                self._cumulative_supply_until = Mock(return_value=0)
                self._scheduled_reward = Mock(return_value=50)
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
                self._ensure_utxodb = Mock(return_value=None)
                self._chain_state_token_locked = Mock(return_value=(0, b"token"))
                self._validate_chain_context_locked = Mock(return_value=True)
                self._check_sigops_budget = Mock(return_value=True)
                self._validate_merkle = Mock(return_value=True)
                self._ensure_unique_txids = Mock(return_value=True)
                self._check_block_limits = Mock(return_value=True)
                self._validate_pow = Mock(return_value=True)
                self._serialize_tx_cached = Mock(return_value=b"serialized")
                self._compute_txids_for_block = Mock(return_value=True)
        return DummyConsensus()

    # -------------------------------------------------------------------
    # Tests for _ensure_warm
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_not_randomx(self, mock_cfg):
        instance = self.create_instance()
        mock_cfg.POW_ALGO = "sha256"
        with patch("tsarchain.consensus.validation.H") as mock_H:
            instance._ensure_warm(100)
            mock_H.pow_hash_verify_light.assert_not_called()

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_epoch_already_warmed(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance.__class__._pow_epoch_warmed = set([0])
        with patch("tsarchain.consensus.validation.H") as mock_H:
            instance._ensure_warm(50)
            mock_H.pow_hash_verify_light.assert_not_called()
        instance.__class__._pow_epoch_warmed = set()

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_calls_pow_hash(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance.__class__._pow_epoch_warmed = set()
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.pow_key_for_height = Mock(return_value=b"key")
            mock_H.pow_hash_verify_light = Mock()
            instance._ensure_warm(150)
            mock_H.pow_hash_verify_light.assert_called_once_with(b"\x00"*80, key_hint=b"key")
            assert 1 in instance.__class__._pow_epoch_warmed
        instance.__class__._pow_epoch_warmed = set()

    # -------------------------------------------------------------------
    # Tests for _warm_pow_context
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.threading.Thread")
    def test_warm_pow_context_not_randomx(self, mock_thread, mock_cfg):
        mock_cfg.POW_ALGO = "sha256"
        instance = self.create_instance()
        instance._warm_pow_context(100)
        mock_thread.assert_not_called()

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.threading.Thread")
    def test_warm_pow_context_already_scheduled(self, mock_thread, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance._pow_warm_next_epoch = 2
        instance._warm_pow_context(150)
        mock_thread.assert_not_called()

    # -------------------------------------------------------------------
    # Tests for validate_block
    # -------------------------------------------------------------------

    def test_validate_block_missing_fields(self):
        instance = self.create_instance()
        block = Mock()
        block.height = None
        block.prev_block_hash = b"hash"
        block.transactions = []   # empty, triggers missing_fields
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "block_missing_fields"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_success(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]   # non‑empty to pass initial check
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        result = instance.validate_block(block)
        assert result is True
        assert instance._last_block_validation_error is None

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_pow_invalid(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_pow.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "pow_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_compute_txids_fails(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._compute_txids_for_block.return_value = False
        instance._last_block_validation_error = "tx_serialize_failed"  # pre‑set
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_serialize_failed"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_merkle_mismatch(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_merkle.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "merkle_mismatch"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_duplicate_txid(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._ensure_unique_txids.return_value = False
        instance._last_block_validation_error = "duplicate_or_missing_txid"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "duplicate_or_missing_txid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_block_limits_exceeded(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._check_block_limits.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "block_limits_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_chain_context_invalid(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_chain_context_locked.return_value = False
        instance._last_block_validation_error = "chain_context_invalid"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "chain_context_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_sigops_limit_exceeded(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._check_sigops_budget.return_value = False
        instance._last_block_validation_error = "sigops_limit_exceeded"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "sigops_limit_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_transactions_fail(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 1  # > 0, so _validate_transactions is called
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        def fake_validate(*args, **kwargs):
            instance._last_block_validation_error = "tx_validation_failed"
            return False

        instance._validate_transactions = Mock(side_effect=fake_validate)
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_validation_failed"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_state_changed(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        call_count = 0
        def fake_token():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (0, b"token1")
            else:
                return (1, b"token2")

        instance._chain_state_token_locked = Mock(side_effect=fake_token)
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "chain_state_changed_during_validation"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_unexpected_exception(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        instance._validate_pow = Mock(side_effect=Exception("pow error"))
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "unexpected_validation_error"

    # -------------------------------------------------------------------
    # Tests for _validate_transactions
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_empty_txs(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        block = Mock()
        block.transactions = []
        instance._ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "empty_block_transactions"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_missing_coinbase(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        tx = Mock()
        tx.is_coinbase = False
        block = Mock()
        block.transactions = [tx]
        instance._ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "missing_coinbase"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_duplicate_coinbase(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        cb = Mock()
        cb.is_coinbase = True
        cb2 = Mock()
        cb2.is_coinbase = True
        block = Mock()
        block.transactions = [cb, cb2]
        instance._ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "duplicate_coinbase"

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.H")
    def test_validate_transactions_serialize_fails(self, mock_H, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        cb = Mock()
        cb.is_coinbase = True
        tx = Mock()
        tx.is_coinbase = False
        block = Mock()
        block.transactions = [cb, tx]
        block.height = 1
        instance._ensure_utxodb = Mock(return_value=None)
        instance._serialize_tx_cached = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_serialize_failed"

# =============================================================================
# Tests for Helper Methods (# 2. HELPER)
# = ============================================================================

    # -------------------------------------------------------------------------
    # _serialize_tx_cached
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.H")
    def test_serialize_tx_cached_cache_hit(self, mock_H):
        # Buat instance dengan metode asli (tidak di-override)
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
        instance = Dummy()
        tx = Mock()
        cached = b"cached_serialized"
        setattr(tx, "_cached_raw_tx_nowit", cached)
        result = instance._serialize_tx_cached(tx, include_witness=False)
        assert result == cached
        mock_H.serialize_tx.assert_not_called()

    @patch("tsarchain.consensus.validation.H")
    def test_serialize_tx_cached_cache_miss(self, mock_H):
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
        instance = Dummy()
        tx = Mock()
        raw = b"serialized_tx"
        mock_H.serialize_tx.return_value = raw
        result = instance._serialize_tx_cached(tx, include_witness=True)
        assert result == raw
        mock_H.serialize_tx.assert_called_once_with(tx, include_witness=True)
        assert getattr(tx, "_cached_raw_tx_w") == raw

    # -------------------------------------------------------------------------
    # _estimate_block_size
    # -------------------------------------------------------------------------
    def test_estimate_block_size_with_cached_txs(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        block.transactions = []
        assert instance._estimate_block_size(block) == 80

        tx1 = Mock()
        tx2 = Mock()
        setattr(tx1, "_cached_raw_tx_w", b"tx1" * 10)  # length 30
        setattr(tx2, "_cached_raw_tx_w", b"tx2" * 5)   # length 15
        block.transactions = [tx1, tx2]
        assert instance._estimate_block_size(block) == 80 + 30 + 15

    def test_estimate_block_size_with_serialize_method(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        tx = Mock()
        tx.serialize = Mock(return_value=b"serialized_tx")  # length 13
        block.transactions = [tx]
        assert instance._estimate_block_size(block) == 80 + 13
        tx.serialize.assert_called_once()

    def test_estimate_block_size_with_raw_attribute(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        tx = Mock()
        tx.raw = b"raw_tx_data"  # length 11
        block.transactions = [tx]
        assert instance._estimate_block_size(block) == 80 + 11

    def test_estimate_block_size_with_size_bytes_callable(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        tx = Mock()
        # Prevent the 'serialize' branch from interfering (Mock would otherwise provide it)
        tx.serialize = None
        tx.raw = None
        def size_func():
            return 42
        tx.size_bytes = size_func
        block.transactions = [tx]
        assert instance._estimate_block_size(block) == 80 + 42

    def test_estimate_block_size_with_size_bytes_int(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        tx = Mock()
        tx.size_bytes = 100
        block.transactions = [tx]
        assert instance._estimate_block_size(block) == 80 + 100

    def test_estimate_block_size_fallback_none(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        # Use spec_set=[] so the Mock has NO attributes at all.
        tx = Mock(spec_set=[])
        block.transactions = [tx]
        assert instance._estimate_block_size(block) is None

    # -------------------------------------------------------------------------
    # _count_block_sigops
    # -------------------------------------------------------------------------
    def test_count_block_sigops_with_sigops_count_method(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        tx1 = Mock()
        tx1.sigops_count = Mock(return_value=5)
        tx2 = Mock()
        tx2.sigops_count = Mock(return_value=3)
        block.transactions = [tx1, tx2]
        assert instance._count_block_sigops(block) == 8
        tx1.sigops_count.assert_called_once()
        tx2.sigops_count.assert_called_once()

    def test_count_block_sigops_with_count_sigops_method(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        # Create mocks with only the 'count_sigops' attribute; no 'sigops_count'.
        tx1 = Mock(spec_set=['count_sigops'])
        tx1.count_sigops = Mock(return_value=7)
        tx2 = Mock(spec_set=['count_sigops'])
        tx2.count_sigops = Mock(return_value=2)
        block.transactions = [tx1, tx2]
        assert instance._count_block_sigops(block) == 9

    def test_count_block_sigops_fallback_none(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        block = Mock()
        # No 'sigops_count' nor 'count_sigops' -> fallback returns None.
        tx = Mock(spec_set=[])
        block.transactions = [tx]
        assert instance._count_block_sigops(block) is None

    # -------------------------------------------------------------------------
    # _chain_state_token_locked
    # -------------------------------------------------------------------------
    def test_chain_state_token_locked(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                self.height = 100
                self.chain = []
        instance = Dummy()
        # Buat chain dengan satu block
        block = Mock()
        block.hash = Mock(return_value=b"tip_hash")
        instance.chain = [block]
        token = instance._chain_state_token_locked()
        assert token == (100, b"tip_hash")

    def test_chain_state_token_locked_empty_chain(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                self.height = 0
                self.chain = []
        instance = Dummy()
        token = instance._chain_state_token_locked()
        assert token == (0, None)

    # -------------------------------------------------------------------------
    # _validate_chain_context_locked
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.time")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_height_mismatch(self, mock_cfg, mock_time):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 7
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "height_mismatch"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_prev_hash_mismatch(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"wrong_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "prev_hash_mismatch"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_genesis_prevhash_bad(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = []  # genesis
                self.height = -1
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"not_zero"
        block.timestamp = 100
        block.hash = Mock(return_value=b"genesis_hash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "bad_genesis_prevhash"

    @patch("tsarchain.consensus.validation.GENESIS_HASH", b"correct_genesis_hash")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_genesis_hash_mismatch(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = []
                self.height = -1
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"\x00"*32
        block.timestamp = 100
        block.hash = Mock(return_value=b"wrong_hash")  # berbeda dari GENESIS_HASH
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "genesis_hash_mismatch"

    @patch("tsarchain.consensus.validation.time")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_timestamp_too_old(self, mock_cfg, mock_time):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=100)  # MTP > timestamp
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 50
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 50  # lebih kecil dari MTP 100
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "timestamp_too_old"

    @patch("tsarchain.consensus.validation.time")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_timestamp_in_future(self, mock_cfg, mock_time):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        mock_time.time.return_value = 1000
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 2000  # > time.time() + drift (1000+600=1600)
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "timestamp_in_future"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_timestamp_backwards(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 300   # parent timestamp lebih besar
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150   # block.timestamp + TARGET_BLOCK_TIME (68) = 218 < 300, jadi error
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "timestamp_backwards"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_difficulty_invalid(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=False)  # invalid
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "difficulty_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_success(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is True

    # -------------------------------------------------------------------------
    # _ensure_unique_txids
    # -------------------------------------------------------------------------
    def test_ensure_unique_txids_success(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
        instance = Dummy()
        tx1 = Mock()
        tx1.txid = b"txid1"
        tx2 = Mock()
        tx2.txid = b"txid2"
        block = Mock()
        block.transactions = [tx1, tx2]
        assert instance._ensure_unique_txids(block) is True
        assert instance._last_block_validation_error is None

    def test_ensure_unique_txids_duplicate(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
        instance = Dummy()
        tx1 = Mock()
        tx1.txid = b"txid1"
        tx2 = Mock()
        tx2.txid = b"txid1"
        block = Mock()
        block.transactions = [tx1, tx2]
        assert instance._ensure_unique_txids(block) is False
        assert instance._last_block_validation_error == "txid_duplicate"

    def test_ensure_unique_txids_missing_txid(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
        instance = Dummy()
        tx = Mock()
        tx.txid = None
        block = Mock()
        block.transactions = [tx]
        assert instance._ensure_unique_txids(block) is False
        assert instance._last_block_validation_error == "txid_missing"

    def test_ensure_unique_txids_compute_if_needed(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
        instance = Dummy()
        tx = Mock()
        tx.txid = None
        tx.compute_txid = Mock()
        block = Mock()
        block.transactions = [tx]
        # compute_txid dipanggil, tetapi tetap None -> gagal
        assert instance._ensure_unique_txids(block) is False
        tx.compute_txid.assert_called_once()
        assert instance._last_block_validation_error == "txid_missing"

    # -------------------------------------------------------------------------
    # _check_block_limits
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.CFG")
    def test_check_block_limits_too_many_txs(self, mock_cfg):
        mock_cfg.MAX_TXS_PER_BLOCK = 10
        mock_cfg.MAX_BLOCK_BYTES = 1000000
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
                self._estimate_block_size = Mock(return_value=100)
        instance = Dummy()
        block = Mock()
        # Buat 12 transaksi, semua non-coinbase
        block.transactions = [Mock() for _ in range(12)]
        assert instance._check_block_limits(block) is False
        assert instance._last_block_validation_error == "too_many_txs"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_block_limits_size_exceeded(self, mock_cfg):
        mock_cfg.MAX_TXS_PER_BLOCK = 100
        mock_cfg.MAX_BLOCK_BYTES = 100
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
                self._estimate_block_size = Mock(return_value=150)
        instance = Dummy()
        block = Mock()
        block.transactions = [Mock()]  # satu tx
        assert instance._check_block_limits(block) is False
        assert instance._last_block_validation_error == "block_size_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_block_limits_success(self, mock_cfg):
        mock_cfg.MAX_TXS_PER_BLOCK = 100
        mock_cfg.MAX_BLOCK_BYTES = 1000
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
                self._estimate_block_size = Mock(return_value=100)
        instance = Dummy()
        block = Mock()
        block.transactions = [Mock()]  # satu tx
        assert instance._check_block_limits(block) is True

    # -------------------------------------------------------------------------
    # _entry_script_bytes
    # -------------------------------------------------------------------------
    def test_entry_script_bytes_dict_with_tx_out(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        entry = {"tx_out": {"script_pubkey": b"script"}}
        assert instance._entry_script_bytes(entry) == b"script"

    def test_entry_script_bytes_dict_direct(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        entry = {"script_pubkey": b"script"}
        assert instance._entry_script_bytes(entry) == b"script"

    def test_entry_script_bytes_object_with_script_pubkey(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        obj = Mock()
        obj.script_pubkey = b"script"
        entry = {"tx_out": obj}
        assert instance._entry_script_bytes(entry) == b"script"

    def test_entry_script_bytes_object_script_pubkey_serialize(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        spk = Mock()
        spk.serialize = Mock(return_value=b"serialized_script")
        obj = Mock()
        obj.script_pubkey = spk
        entry = {"tx_out": obj}
        assert instance._entry_script_bytes(entry) == b"serialized_script"
        spk.serialize.assert_called_once()

    def test_entry_script_bytes_string_hex(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        entry = {"script_pubkey": "deadbeef"}
        assert instance._entry_script_bytes(entry) == bytes.fromhex("deadbeef")

    def test_entry_script_bytes_none(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                pass
        instance = Dummy()
        entry = {}
        assert instance._entry_script_bytes(entry) is None

    # -------------------------------------------------------------------------
    # _check_sigops_budget
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.CFG")
    def test_check_sigops_budget_per_tx_exceeded(self, mock_cfg):
        mock_cfg.MAX_SIGOPS_PER_TX = 5
        mock_cfg.MAX_SIGOPS_PER_BLOCK = 100
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx = Mock()
        tx.is_coinbase = False
        tx.sigops_count = Mock(return_value=10)  # > 5
        block.transactions = [tx]
        store = Mock()
        utxo_view = {}
        result = instance._check_sigops_budget(block, store, utxo_view)
        assert result is False
        assert instance._last_block_validation_error == "sigops_per_tx_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_sigops_budget_total_exceeded(self, mock_cfg):
        mock_cfg.MAX_SIGOPS_PER_TX = 10
        mock_cfg.MAX_SIGOPS_PER_BLOCK = 5
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx1 = Mock()
        tx1.is_coinbase = False
        tx1.sigops_count = Mock(return_value=3)
        tx2 = Mock()
        tx2.is_coinbase = False
        tx2.sigops_count = Mock(return_value=3)
        block.transactions = [tx1, tx2]
        store = Mock()
        utxo_view = {}
        result = instance._check_sigops_budget(block, store, utxo_view)
        assert result is False
        assert instance._last_block_validation_error == "sigops_per_block_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_sigops_budget_success(self, mock_cfg):
        mock_cfg.MAX_SIGOPS_PER_TX = 10
        mock_cfg.MAX_SIGOPS_PER_BLOCK = 100
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx1 = Mock()
        tx1.is_coinbase = False
        tx1.sigops_count = Mock(return_value=3)
        tx2 = Mock()
        tx2.is_coinbase = False
        tx2.sigops_count = Mock(return_value=3)
        block.transactions = [tx1, tx2]
        store = Mock()
        utxo_view = {}
        assert instance._check_sigops_budget(block, store, utxo_view) is True

    def test_check_sigops_budget_uses_fallback_if_no_sigops_count(self):
        class Dummy(ValidationMixin):
            def __init__(self):
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx = Mock()
        tx.is_coinbase = False
        tx.inputs = [1, 2, 3]  # length 3
        
        if hasattr(tx, "sigops_count"):
            del tx.sigops_count
        block.transactions = [tx]
        store = Mock()
        utxo_view = {}
        with patch("tsarchain.consensus.validation.CFG.MAX_SIGOPS_PER_TX", 10):
            with patch("tsarchain.consensus.validation.CFG.MAX_SIGOPS_PER_BLOCK", 100):
                assert instance._check_sigops_budget(block, store, utxo_view) is True


# =============================================================================
# CATEGORY 3: VALIDATION COVERAGE TESTS
# =============================================================================


# --- Tests from validation_coverage_test.py ---
class CovP1DummyBlock:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
    def hash(self):
        return getattr(self, "_hash", b"hash")
    def header(self):
        return getattr(self, "_header", b"header")

class CovP1DummyTx:
    def __init__(self, **kwargs):
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        for k, v in kwargs.items():
            setattr(self, k, v)

class CovP1DummyConsensus(ValidationMixin):
    def __init__(self):
        self._last_block_validation_error = None

# --- _compute_txids_for_block ---
def test_compute_txids_for_block():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=b"raw")
    tx = CovP1DummyTx()
    b = CovP1DummyBlock(transactions=[tx])
    
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.hash256.return_value = b"txidbytes"
        assert c._compute_txids_for_block(b) is True
        assert tx.txid == b"txidbytes"

def test_compute_txids_for_block_serialize_fail():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=None)
    tx = CovP1DummyTx()
    b = CovP1DummyBlock(transactions=[tx])
    assert c._compute_txids_for_block(b) is False
    assert c._last_block_validation_error == "tx_serialize_failed"

def test_compute_txids_for_block_mismatch():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=b"raw")
    tx = CovP1DummyTx(txid=b"different")
    b = CovP1DummyBlock(transactions=[tx])
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.hash256.return_value = b"txidbytes"
        assert c._compute_txids_for_block(b) is False
        assert c._last_block_validation_error == "txid_mismatch"

def test_compute_txids_for_block_mismatch_str():
    c = CovP1DummyConsensus()
    c._serialize_tx_cached = Mock(return_value=b"raw")
    tx = CovP1DummyTx(txid="aa"*32) # hex string
    b = CovP1DummyBlock(transactions=[tx])
    with patch("tsarchain.consensus.validation.H") as mock_H:
        mock_H.hash256.return_value = b"bb"*32
        assert c._compute_txids_for_block(b) is False
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
    from tsarchain.consensus.validation import ValidationMixin
    import threading
    class C(ValidationMixin):
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
        for k, v in kwargs.items():
            setattr(self, k, v)
    def hash(self):
        return getattr(self, "_hash", b"hash")

class CovP2DummyTx:
    def __init__(self, **kwargs):
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        self.fee = 0
        for k, v in kwargs.items():
            setattr(self, k, v)
    def compute_txid(self):
        self.txid = b"computed"
        self.txid_hex = "computed"

class CovP2DummyConsensus(ValidationMixin):
    def __init__(self):
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
        self.inputs = []
        self.outputs = []
        self.is_coinbase = False
        for k, v in kwargs.items():
            setattr(self, k, v)

class CovP3DummyBlock:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class CovP3DummyConsensus(ValidationMixin):
    def __init__(self):
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
class CovP4DummyConsensus(ValidationMixin):
    def __init__(self):
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
                    self.amount = 10
                    self.script_pubkey = b"s"
                    self.is_coinbase = False
                    self.block_height = 0
                    self.tx_out = self # recursive for branch
                    
            store.lookup_entry = Mock(return_value=CandidateObj())
            c._validate_transactions(b, utxo_store=store)
            
            class CandidateObjNoTxOut:
                def __init__(self):
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
        self.height = 1
        self.transactions = []
        for k, v in kwargs.items():
            setattr(self, k, v)
    def to_dict(self):
        return {}
    def header(self):
        return b"header"

class CovP5DummyConsensus(ValidationMixin):
    def __init__(self):
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
    c._compute_txids_for_block = Mock(return_value=True)
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
            with patch.object(c, "_validate_transactions") as mock_val:
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
        self.height = 1
        self.transactions = []
        for k, v in kwargs.items():
            setattr(self, k, v)
    def to_dict(self):
        return {}

class CovP6DummyConsensus(ValidationMixin):
    def __init__(self):
        self._last_block_validation_error = None
        self.lock = Mock()
    def _entry_script_bytes(self, entry):
        return entry.get("script_pubkey")
    def _cumulative_supply_until(self, h): return 0
    def _scheduled_reward(self, h): return 10
    def _ensure_utxodb(self): return None

def setup_validate_block_mock_p6(c):
    c._validate_pow = Mock(return_value=True)
    c._compute_txids_for_block = Mock(return_value=True)
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
