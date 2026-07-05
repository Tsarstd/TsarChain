# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
import bech32
from unittest.mock import MagicMock, patch

from tsarchain.utils import config as CFG
from tsarchain.core.tx import Tx, TxIn, TxOut
from tsarchain.contracts import graffiti as GRAFF
from tsarchain.utils.helpers import Script, OP_RETURN
from tsarchain.network.rpc_helper.tx_mixin import TxMixin


@pytest.fixture
def mock_config(monkeypatch):
    """Set config constants for predictable tests."""
    monkeypatch.setattr(CFG, "ADDRESS_PREFIX", "tsar")
    monkeypatch.setattr(CFG, "DUST_THRESHOLD_SAT", 294)
    monkeypatch.setattr(CFG, "MAX_TX_VSIZE", 10000)
    monkeypatch.setattr(CFG, "MIN_TX_VSIZE", 100)
    monkeypatch.setattr(CFG, "MAX_TX_WEIGHT", 40000)
    monkeypatch.setattr(CFG, "MIN_TX_WEIGHT", 400)
    monkeypatch.setattr(CFG, "MAX_TX_INPUTS", 1000)
    monkeypatch.setattr(CFG, "MAX_TX_OUTPUTS", 1000)
    monkeypatch.setattr(CFG, "TX_BASE_VBYTES", 10)
    monkeypatch.setattr(CFG, "SEGWIT_INPUT_VBYTES", 68)
    monkeypatch.setattr(CFG, "SEGWIT_OUTPUT_VBYTES", 31)
    monkeypatch.setattr(CFG, "GRAFFITI_MAGIC", b"TSAR_GRAF1|")
    monkeypatch.setattr(CFG, "GRAFFITI_COMMENT_MIN_FEE", 1 * CFG.TSAR)
    monkeypatch.setattr(CFG, "GRAFFITI_MAX_SIZE_BYTES", 150 * 1024 * 1024)
    monkeypatch.setattr(CFG, "TSAR", 100_000_000)
    return monkeypatch


@pytest.fixture
def mixin(mock_config):
    """Create a TxMixin instance with mocked broadcast and subcomponents."""
    mixin = TxMixin()
    mixin.broadcast = MagicMock()
    mixin.broadcast.utxodb = MagicMock()
    mixin.broadcast.blockchain = MagicMock()
    mixin.broadcast.blockchain.height = 100
    return mixin


def make_bech32_addr(program_bytes):
    """Create a valid tsar bech32 address from witness program (20 or 32 bytes)."""
    data = [0] + list(bech32.convertbits(program_bytes, 8, 5, True))
    return bech32.bech32_encode(CFG.ADDRESS_PREFIX, data)


def make_spk_from_addr(addr):
    """Helper to get script pubkey from address using the same logic as _addr_to_spk."""
    hrp, data = bech32.bech32_decode(addr)
    if data is None:
        raise ValueError("invalid bech32")
    decoded = bech32.convertbits(data[1:], 5, 8, False)
    return Script([0, bytes(decoded)])


# ---------- Tests for _addr_to_spk ----------
def test_addr_to_spk_valid(mixin):
    prog = bytes.fromhex("aabbccddeeff" * 4)  # 20 bytes
    addr = make_bech32_addr(prog)
    spk = mixin._addr_to_spk(addr)
    assert spk.cmds == [0, prog]


def test_addr_to_spk_invalid_bech32(mixin):
    with pytest.raises(ValueError, match="invalid bech32 address"):
        mixin._addr_to_spk("invalid")


def test_addr_to_spk_wrong_hrp(mixin):
    prog = bytes.fromhex("aabbccddeeff" * 4)
    # Encode with wrong prefix
    data = [0] + list(bech32.convertbits(prog, 8, 5, True))
    addr = bech32.bech32_encode("wrong", data)
    with pytest.raises(ValueError, match="Address HRP must be tsar"):
        mixin._addr_to_spk(addr)


def test_addr_to_spk_decode_fails(mixin):
    addr = "tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    with pytest.raises(ValueError, match="invalid bech32 address"):
        mixin._addr_to_spk(addr)


# ---------- Tests for _estimate_tx_size ----------
def test_estimate_tx_size(mixin):
    # Formula: base + n_inputs * input_vbytes + n_outputs * output_vbytes
    n_in, n_out = 2, 3
    expected = CFG.TX_BASE_VBYTES + n_in * CFG.SEGWIT_INPUT_VBYTES + n_out * CFG.SEGWIT_OUTPUT_VBYTES
    assert mixin._estimate_tx_size(n_in, n_out) == expected


# ---------- Tests for _check_tx_limits ----------
def test_check_tx_limits_ok(mixin):
    tx = Tx(version=1,
            inputs=[TxIn(b"0"*32, i) for i in range(2)],
            outputs=[TxOut(1000, Script([0, b"a"*20]))],
            locktime=0, is_coinbase=False)
    mixin._check_tx_limits(tx)


def test_check_tx_limits_vsize_exceeds(mixin, monkeypatch):
    monkeypatch.setattr(CFG, "MAX_TX_VSIZE", 10)
    tx = Tx(version=1, inputs=[], outputs=[], locktime=0, is_coinbase=False)
    # Force a large tx by adding many outputs
    for _ in range(100):
        tx.outputs.append(TxOut(1000, Script([0])))
    with pytest.raises(ValueError, match="tx_vsize_exceeds_limit"):
        mixin._check_tx_limits(tx)


def test_check_tx_limits_vsize_below_min(mixin, monkeypatch):
    monkeypatch.setattr(CFG, "MIN_TX_VSIZE", 1000)
    tx = Tx(version=1, inputs=[], outputs=[], locktime=0, is_coinbase=False)
    with pytest.raises(ValueError, match="tx_vsize_below_min"):
        mixin._check_tx_limits(tx)


def test_check_tx_limits_weight_exceeds(mixin, monkeypatch):
    monkeypatch.setattr(CFG, "MAX_TX_WEIGHT", 1000)
    tx = Tx(version=1,
            inputs=[TxIn(b"0"*32, i) for i in range(100)],
            outputs=[],
            locktime=0)
    with pytest.raises(ValueError, match="tx_weight_exceeds_limit"):
        mixin._check_tx_limits(tx)


def test_check_tx_limits_inputs_exceed(mixin, monkeypatch):
    monkeypatch.setattr(CFG, "MAX_TX_INPUTS", 2)
    monkeypatch.setattr(CFG, "MAX_TX_VSIZE", 1000000)
    monkeypatch.setattr(CFG, "MAX_TX_WEIGHT", 1000000)
    tx = Tx(version=1,
            inputs=[TxIn(b"0"*32, i) for i in range(3)],
            outputs=[],
            locktime=0)
    with pytest.raises(ValueError, match="tx_inputs_exceed_limit"):
        mixin._check_tx_limits(tx)


def test_check_tx_limits_outputs_exceed(mixin, monkeypatch):
    monkeypatch.setattr(CFG, "MAX_TX_OUTPUTS", 2)
    monkeypatch.setattr(CFG, "MAX_TX_VSIZE", 1000000)
    monkeypatch.setattr(CFG, "MAX_TX_WEIGHT", 1000000)
    monkeypatch.setattr(CFG, "MIN_TX_VSIZE", 1)
    monkeypatch.setattr(CFG, "MIN_TX_WEIGHT", 1)
    tx = Tx(version=1,
            inputs=[],
            outputs=[TxOut(1000, Script([0])) for _ in range(3)],
            locktime=0)
    with pytest.raises(ValueError, match="tx_outputs_exceed_limit"):
        mixin._check_tx_limits(tx)


# ---------- Tests for _select_utxos_for ----------
def test_select_utxos_for_success(mixin):
    utxos = [
        {"txid": "a"*64, "index": 0, "amount": 1000, "scriptPubKey": b"spk1"},
        {"txid": "b"*64, "index": 1, "amount": 2000, "scriptPubKey": b"spk2"},
        {"txid": "c"*64, "index": 2, "amount": 3000, "scriptPubKey": b"spk3"},
    ]
    target = 4000
    fee_rate = 34
    fee_rate = 1
    selected, fee, change = mixin._select_utxos_for(utxos, target, fee_rate)
    assert len(selected) == 3
    assert fee == 276
    assert change == 6000 - target - fee


def test_select_utxos_for_change_below_dust(mixin, monkeypatch):
    # Simulate case where change < dust, so output count reduces to 1
    monkeypatch.setattr(CFG, "DUST_THRESHOLD_SAT", 500)
    utxos = [{"txid": "a"*64, "index": 0, "amount": 1000, "scriptPubKey": b"spk1"}]
    target = 500  # after fee, change small
    fee_rate = 1
    selected, fee, change = mixin._select_utxos_for(utxos, target, fee_rate)
    assert len(selected) == 1
    assert fee == 109
    assert change == 0


def test_select_utxos_for_insufficient_funds(mixin):
    utxos = [{"txid": "a"*64, "index": 0, "amount": 100, "scriptPubKey": b"spk1"}]
    target = 200
    fee_rate = 34
    with pytest.raises(ValueError, match="insufficient funds"):
        mixin._select_utxos_for(utxos, target, fee_rate)


# ---------- Tests for _guard_graffiti_output ----------
def test_guard_graffiti_output_no_magic(mixin):
    spk = Script([OP_RETURN, b"some data"])
    mixin._guard_graffiti_output(spk)  # Should not raise


def test_guard_graffiti_output_post_valid(mixin):
    meta = {
        "event": "POST",
        "sha256": "a"*64,
        "size": 1000,
        "mime": "image/jpeg",
        "storer": make_bech32_addr(b"a"*20),
        "receipt": "abc",
        "creator": make_bech32_addr(b"b"*20),
    }
    payload = GRAFF.encode_payload(meta)
    spk = Script([OP_RETURN, payload])
    mixin._guard_graffiti_output(spk)  # Should not raise


def test_guard_graffiti_output_post_size_exceeds(mixin, monkeypatch):
    monkeypatch.setattr(CFG, "GRAFFITI_MAX_SIZE_BYTES", 100)
    meta = {
        "event": "POST",
        "sha256": "a"*64,
        "size": 200,
        "mime": "image/jpeg",
        "storer": make_bech32_addr(b"a"*20),
        "receipt": "abc",
        "creator": make_bech32_addr(b"b"*20),
    }
    payload = GRAFF.encode_payload(meta)
    spk = Script([OP_RETURN, payload])
    with pytest.raises(ValueError, match="graffiti_size_exceeds_limit"):
        mixin._guard_graffiti_output(spk)


def test_guard_graffiti_output_post_size_invalid(mixin):
    meta = {
        "event": "POST",
        "sha256": "a"*64,
        "size": 0,
        "mime": "image/jpeg",
        "storer": make_bech32_addr(b"a"*20),
        "receipt": "abc",
        "creator": make_bech32_addr(b"b"*20),
    }
    payload = GRAFF.encode_payload(meta)
    spk = Script([OP_RETURN, payload])
    with pytest.raises(ValueError, match="graffiti_size_invalid"):
        mixin._guard_graffiti_output(spk)


def test_guard_graffiti_output_comment_valid(mixin):
    meta = {
        "event": "COMMENT",
        "art_id": "graf" + "a"*60,
        "comment": "68656c6c6f",  # "hello"
        "amount": CFG.GRAFFITI_COMMENT_MIN_FEE,
        "tip": 0,
        "creator": make_bech32_addr(b"c"*20),
        "commenter": make_bech32_addr(b"d"*20),
    }
    payload = GRAFF.encode_payload(meta)
    spk = Script([OP_RETURN, payload])
    mixin._guard_graffiti_output(spk)  # Should not raise


def test_guard_graffiti_output_invalid_payload(mixin):
    payload = CFG.GRAFFITI_MAGIC + b"invalid json"
    spk = Script([OP_RETURN, payload])
    with pytest.raises(ValueError, match="graffiti_payload_invalid"):
        mixin._guard_graffiti_output(spk)


# ---------- Tests for _create_template_tx ----------
def test_create_template_tx_success(mixin):
    from_addr = make_bech32_addr(b"a"*20)
    to_addr = make_bech32_addr(b"b"*20)
    amount = 1.5
    fee_rate = 34

    utxos_map = {
        "a"*64 + ":0": {"amount": 2 * CFG.TSAR, "script_pubkey": "deadbeef", "block_height": 50, "is_coinbase": False},
        "b"*64 + ":1": {"amount": 1 * CFG.TSAR, "script_pubkey": "beefdead", "block_height": 60, "is_coinbase": False},
    }
    mixin.broadcast.utxodb.get.return_value = utxos_map
    selected_utxos = [
        {"txid": "a"*64, "index": 0, "amount": 2 * CFG.TSAR, "scriptPubKey": b"deadbeef"},
        {"txid": "b"*64, "index": 1, "amount": 1 * CFG.TSAR, "scriptPubKey": b"beefdead"},
    ]

    fee = 1000
    change = 0
    with patch.object(mixin, "_select_utxos_for", return_value=(selected_utxos, fee, change)):
        result = mixin._create_template_tx(from_addr, to_addr, amount, fee_rate)

    assert result["from"] == from_addr
    assert result["to"] == to_addr
    assert result["amount_sat"] == int(amount * CFG.TSAR)
    assert result["fee"] == fee
    assert result["change"] == change
    assert "tx" in result
    assert "inputs" in result
    # Check that the tx is built correctly
    tx_dict = result["tx"]
    assert tx_dict["version"] == 1
    assert len(tx_dict["inputs"]) == 2
    assert len(tx_dict["outputs"]) == 1  # no change


def test_create_template_tx_with_change(mixin):
    from_addr = make_bech32_addr(b"a"*20)
    to_addr = make_bech32_addr(b"b"*20)
    amount = 1.5
    fee_rate = 34

    # Mock UTXOs
    utxos_map = {
        "a"*64 + ":0": {"amount": 5 * CFG.TSAR, "script_pubkey": "deadbeef", "block_height": 50, "is_coinbase": False},
    }
    mixin.broadcast.utxodb.get.return_value = utxos_map

    selected_utxos = [{"txid": "a"*64, "index": 0, "amount": 5 * CFG.TSAR, "scriptPubKey": b"deadbeef"}]
    fee = 2000
    change = 1000  # > dust
    with patch.object(mixin, "_select_utxos_for", return_value=(selected_utxos, fee, change)):
        result = mixin._create_template_tx(from_addr, to_addr, amount, fee_rate)

    assert result["change"] == change
    tx_dict = result["tx"]
    assert len(tx_dict["outputs"]) == 2  # to + change


def test_create_template_tx_coinbase_maturity(mixin):
    from_addr = make_bech32_addr(b"a"*20)
    to_addr = make_bech32_addr(b"b"*20)
    amount = 1.0
    fee_rate = 34

    # UTXO is coinbase with insufficient confirmations
    utxos_map = {
        "txid1:0": {"amount": 2 * CFG.TSAR, "script_pubkey": "deadbeef", "block_height": 100, "is_coinbase": True},
    }
    mixin.broadcast.utxodb.get.return_value = utxos_map
    mixin.broadcast.blockchain.height = 101  # confirmations = 101-100+1=2, less than 3

    with pytest.raises(ValueError, match="no spendable utxos"):
        mixin._create_template_tx(from_addr, to_addr, amount, fee_rate)


def test_create_template_tx_no_utxos(mixin):
    from_addr = make_bech32_addr(b"a"*20)
    to_addr = make_bech32_addr(b"b"*20)
    mixin.broadcast.utxodb.get.return_value = {}
    with pytest.raises(ValueError, match="no spendable utxos"):
        mixin._create_template_tx(from_addr, to_addr, 1.0, 34)


# ---------- Tests for _create_template_tx_multi ----------
def test_create_template_tx_multi_simple(mixin):
    from_addr = make_bech32_addr(b"a"*20)
    outputs = [
        {"address": make_bech32_addr(b"b"*20), "amount": 1000},
        {"address": make_bech32_addr(b"c"*20), "amount": 2000},
    ]
    fee_rate = 34

    # Mock UTXOs
    utxos_map = {
        "a"*64 + ":0": {"amount": 9000, "script_pubkey": "deadbeef", "block_height": 50, "is_coinbase": False},
    }
    mixin.broadcast.utxodb.get.return_value = utxos_map
    result = mixin._create_template_tx_multi(from_addr, outputs, fee_rate)

    assert result["from"] == from_addr
    assert "tx" in result
    assert "inputs" in result
    assert "fee" in result
    assert "change" in result
    tx_dict = result["tx"]
    assert len(tx_dict["inputs"]) == 1  # one UTXO selected
    fee_est = result["fee"]
    change = result["change"]
    expected_change = 5000 - 1000 - 2000 - fee_est
    if expected_change >= CFG.DUST_THRESHOLD_SAT:
        assert change == expected_change
        assert len(tx_dict["outputs"]) == 3
    else:
        assert change == 0
        assert len(tx_dict["outputs"]) == 2


def test_create_template_tx_multi_with_opret(mixin):
    from_addr = make_bech32_addr(b"a"*20)
    # Build a graffiti POST output
    meta = {
        "event": "POST",
        "sha256": "a"*64,
        "size": 1000,
        "mime": "image/jpeg",
        "storer": make_bech32_addr(b"storer"*4),
        "receipt": "receipt123",
        "creator": from_addr,
    }
    spk = GRAFF.build_script(meta)
    opret_hex = spk.serialize().hex()
    outputs = [
        {"address": make_bech32_addr(b"b"*20), "amount": 1000},
        {"opret_hex": opret_hex, "amount": 0},
    ]
    fee_rate = 34

    utxos_map = {
        "a"*64 + ":0": {"amount": 7600, "script_pubkey": "deadbeef", "block_height": 50, "is_coinbase": False},
    }
    mixin.broadcast.utxodb.get.return_value = utxos_map
    result = mixin._create_template_tx_multi(from_addr, outputs, fee_rate)
    
    tx_dict = result["tx"]
    last_out = tx_dict["outputs"][-1]
    assert last_out["script_pubkey"].startswith("6a")  # OP_RETURN


# ---------- Tests for _deserialize_spk_hex ----------
def test_deserialize_spk_hex(mixin):
    spk = Script([0, b"a"*20])
    hex_str = spk.serialize().hex()
    deserialized = mixin._deserialize_spk_hex(hex_str)
    assert deserialized.serialize() == spk.serialize()


def test_deserialize_spk_hex_invalid(mixin):
    with pytest.raises(Exception):
        mixin._deserialize_spk_hex("invalidhex")