# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import patch
from tsarchain.core.coinbase import CoinbaseTx, _int_to_le_bytes
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import Script

def test_int_to_le_bytes():
    assert _int_to_le_bytes(0) == b"\x00"
    assert _int_to_le_bytes(-1) == b"\x00"
    assert _int_to_le_bytes(1) == b"\x01"
    assert _int_to_le_bytes(255) == b"\xff"
    assert _int_to_le_bytes(256) == b"\x00\x01"

@patch("tsarchain.core.coinbase.block_id_generator")
@patch("tsarchain.core.coinbase.Script")
@patch("tsarchain.core.coinbase.TxIn")
@patch("tsarchain.core.coinbase.TxOut")
def test_coinbase_tx_init(mock_txout, mock_txin, mock_script, mock_gen):
    mock_gen.return_value = "generated_block_id"
    mock_script.p2wpkh_script.return_value = "mocked_spk"
    mock_script.return_value = "mocked_sig"
    
    # default block_id, height > 0
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        cb = CoinbaseTx(to_address="addr", reward=50, height=1)
        assert cb.to_address == "addr"
        assert cb.reward == 50
        assert cb.height == 1
        assert cb.block_id == "generated_block_id"
        assert cb.is_coinbase is True

    # height = 0, default block_id
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        cb = CoinbaseTx(to_address="addr", reward=50, height=0)
        assert cb.block_id == CFG.GENESIS_BLOCK_ID_DEFAULT

    # provided block_id
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        cb = CoinbaseTx(to_address="addr", reward=50, block_id="custom_id")
        assert cb.block_id == "custom_id"

def test_coinbase_tx_init_invalid():
    with pytest.raises(ValueError):
        CoinbaseTx(to_address="", reward=50)
    with pytest.raises(ValueError):
        CoinbaseTx(to_address="addr", reward=0)
    with pytest.raises(ValueError):
        CoinbaseTx(to_address="addr", reward=-1)

@patch("tsarchain.core.coinbase.block_id_generator")
@patch("tsarchain.core.coinbase.Script.p2wpkh_script")
def test_coinbase_tx_init_long_graffiti(mock_p2wpkh, mock_gen, monkeypatch):
    mock_p2wpkh.return_value = Script([])
    monkeypatch.setattr(CFG, "MAX_COINBASE_EXTRADATA", 5)
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        cb = CoinbaseTx(to_address="addr", reward=50, block_id="1234567890")
        assert cb.block_id == "12345"
        
@patch("tsarchain.core.coinbase.TxOut")
@patch("tsarchain.core.coinbase.TxIn")
@patch("tsarchain.core.coinbase.Script")
def test_coinbase_to_dict(mock_script, mock_txin, mock_txout):
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        cb = CoinbaseTx(to_address="addr", reward=50, block_id="b1", height=1)
        cb.txid = b"cb_txid"
        
        # mock super().to_dict
        with patch("tsarchain.core.tx.Tx.to_dict", return_value={"txid": "cb_txid"}):
            d = cb.to_dict()
            assert d["type"] == "Coinbase"
            assert d["to_address"] == "addr"
            assert d["reward"] == 50
            assert d["block_id"] == "b1"
            assert d["height"] == 1
            assert d["txid"] == "cb_txid"

@patch("tsarchain.core.coinbase.Script.p2wpkh_script")
def test_coinbase_from_dict(mock_p2wpkh):
    mock_p2wpkh.return_value = Script([])
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        d = {
            "to_address": "addr",
            "reward": 50,
            "block_id": "b1",
            "height": 1,
            "inputs": [{"txid": "00"*32, "vout": 0}],
            "outputs": [{"amount": 50, "script_pubkey": "00"}],
            "txid": "11"*32
        }
        with patch("tsarchain.core.coinbase.TxIn.from_dict") as mock_in, \
             patch("tsarchain.core.coinbase.TxOut.from_dict") as mock_out:
            mock_in.return_value = "mock_in"
            mock_out.return_value = "mock_out"
            
            cb = CoinbaseTx.from_dict(d)
            assert cb.to_address == "addr"
            assert cb.reward == 50
            assert cb.block_id == "b1"
            assert cb.height == 1
            assert cb.inputs == ["mock_in"]
            assert cb.outputs == ["mock_out"]
            assert cb.is_coinbase is True
            assert cb.fee == 0
            assert cb.txid == bytes.fromhex("11"*32)
            
        # Missing txid, and address alias
        d2 = d.copy()
        del d2["txid"]
        d2["address"] = d2.pop("to_address")
        with patch("tsarchain.core.coinbase.TxIn.from_dict"), \
             patch("tsarchain.core.coinbase.TxOut.from_dict"), \
             patch("tsarchain.core.coinbase.CoinbaseTx.compute_txid") as mock_compute:
            cb2 = CoinbaseTx.from_dict(d2)
            assert cb2.to_address == "addr"
            assert mock_compute.call_count == 2
            
def test_coinbase_from_dict_invalid():
    with pytest.raises(TypeError):
        CoinbaseTx.from_dict([])

@patch("tsarchain.core.coinbase.Script.p2wpkh_script")
def test_coinbase_repr(mock_p2wpkh):
    mock_p2wpkh.return_value = Script([])
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        cb = CoinbaseTx(to_address="addr", reward=50, height=1)
        cb.txid = b"a"*32
        r = repr(cb)
        assert "<CoinbaseTx" in r
        assert "reward=50" in r
        assert "height=1" in r
