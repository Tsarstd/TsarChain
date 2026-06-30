# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import time
import threading
from unittest.mock import Mock
from types import SimpleNamespace

import pytest

from tsarchain.consensus.validation import ValidationMixin
from tsarchain.utils import config as CFG


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

    # Mock helper H
    mock_H = mocker.patch('tsarchain.consensus.validation.H')
    # serialize_tx mengembalikan bytes dummy
    mock_H.serialize_tx.return_value = b'\x00' * 100
    # compute_tx_weight_vsize -> (weight, vsize, base_size, total_size)
    mock_H.compute_tx_weight_vsize.return_value = (400, 100, 80, 100)
    # last_pushdata: kita akan override per test
    # native_validate_block_txs_compact: default valid
    mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
    # tx_to_compact_tuple: return tuple sederhana
    def _tx_to_compact(tx):
        return (tx.is_coinbase, [])  # cukup
    mock_H.tx_to_compact_tuple.side_effect = _tx_to_compact
    # native_validate_block_txs (fallback)
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


# ----------------------------------------------------------------------
# TESTS
# ----------------------------------------------------------------------

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