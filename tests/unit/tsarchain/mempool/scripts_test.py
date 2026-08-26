# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
import tsarchain.mempool.scripts
from tsarchain.mempool.scripts import get_utxo_script_bytes


class DummyScript:
    def __init__(self, spk_hex):
        self.spk_hex = spk_hex
    def serialize(self):
        return bytes.fromhex(self.spk_hex)


tsarchain.mempool.scripts.Script = DummyScript

class DummyTxOut:
    def __init__(self, spk):
        self.script_pubkey = spk

class DummyEntry:
    def __init__(self, spk=None, tx_out=None):
        self.serialize = None
        self.script_pubkey = spk
        self.tx_out = tx_out

def test_get_utxo_script_bytes_dict_with_tx_out_obj():
    spk_hex = '0014' + 'a'*40
    entry = {"tx_out": DummyTxOut(DummyScript(spk_hex))}
    assert get_utxo_script_bytes(entry) == bytes.fromhex(spk_hex)
    
def test_get_utxo_script_bytes_dict_with_tx_out_dict():
    spk_hex = '0014' + 'b'*40
    entry = {"tx_out": {"script_pubkey": spk_hex}}
    assert get_utxo_script_bytes(entry) == bytes.fromhex(spk_hex)
    
def test_get_utxo_script_bytes_flat_dict():
    spk_bytes = b'\x00\x14' + b'c'*20
    entry = {"script_pubkey": spk_bytes}
    assert get_utxo_script_bytes(entry) == spk_bytes

def test_get_utxo_script_bytes_object_with_tx_out():
    spk_bytes = b'\x00\x14' + b'd'*20
    entry = DummyEntry(tx_out=DummyTxOut(spk_bytes))
    assert get_utxo_script_bytes(entry) == spk_bytes

def test_get_utxo_script_bytes_object_flat():
    spk_bytes = b'\x00\x14' + b'e'*20
    entry = DummyEntry(spk=spk_bytes)
    assert get_utxo_script_bytes(entry) == spk_bytes

def test_get_utxo_script_bytes_script_obj():
    spk_hex = '0014' + 'f'*40
    entry = DummyScript(spk_hex)
    assert get_utxo_script_bytes(entry) == bytes.fromhex(spk_hex)

def test_get_utxo_script_bytes_invalid():
    with pytest.raises(ValueError):
        get_utxo_script_bytes({"invalid": "data"})
