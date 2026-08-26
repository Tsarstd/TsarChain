# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock

from tsarchain.utils import config as CFG
from tsarchain.network.cast.chain_utils import ChainUtilsHandler

class DummyCaster(ChainUtilsHandler):
    pass

@pytest.fixture
def caster():
    return DummyCaster(MagicMock())

def test_parse_bits(caster):
    assert caster._parse_bits(None) is None
    assert caster._parse_bits(1.0) == 1
    with pytest.raises(TypeError):
        caster._parse_bits(1.5)
    
    assert caster._parse_bits(0x1d00ffff) == 0x1d00ffff
    assert caster._parse_bits(-1) == 0xffffffff
    
    assert caster._parse_bits("123") == 123
    assert caster._parse_bits("0x1d00ffff") == 0x1d00ffff
    
    with pytest.raises(TypeError):
        caster._parse_bits([])

def test_work_from_bits(caster):
    # Genesis bits for many chains: 0x1d00ffff (exp=29, mant=0xffff)
    # Target = 0xffff * 2^(8*(29-3)) = 0xffff * 2^208
    # Work = 2^256 / (Target + 1)
    work = caster._work_from_bits(0x1d00ffff)
    assert work > 0
    
    # Very small exp
    work2 = caster._work_from_bits(0x0200ffff)
    assert work2 > 0
    
    # Target 0
    work_zero = caster._work_from_bits(0x00000000)
    assert work_zero == 0

def test_calc_chainwork_from_list(caster):
    # Using dictionaries
    chain = [
        {"bits": "0x1d00ffff"},
        {"bits": "0x1d00ffff"},
    ]
    total = caster.calc_chainwork_from_list(chain)
    single_work = caster._work_from_bits(0x1d00ffff)
    assert total == single_work * 2
    
    # Missing bits uses fallback or previous
    chain2 = [
        {}, # Fallback to CFG.INITIAL_BITS
        {"bits": CFG.MAX_BITS + 1}, # Capped to MAX_BITS
        {} # Uses previous (MAX_BITS)
    ]
    total2 = caster.calc_chainwork_from_list(chain2)
    assert total2 > 0
    
    # Using objects
    class DummyBlock:
        def __init__(self, bits):
            self.bits = bits
        def get(self, key, default=None):
            return self.bits if key == "bits" else default
    chain3 = [DummyBlock(0x1d00ffff)]
    assert caster.calc_chainwork_from_list(chain3) == single_work

def test_validate_incoming_chain(caster):
    # Empty
    assert caster.validate_incoming_chain({"data": []}) is False
    
    # Invalid block 0 height
    assert caster.validate_incoming_chain({"data": [{"height": 1}]}) is False
    
    # Valid single block
    assert caster.validate_incoming_chain({"data": [{"height": 0, "hash": "A"}]}) is True
    
    # Valid multiple blocks
    assert caster.validate_incoming_chain({
        "data": [
            {"height": 0, "hash": "A"},
            {"height": 1, "prev_block_hash": "A", "hash": "B"},
            {"height": 2, "prev_block_hash": "B", "hash": "C"}
        ]
    }) is True
    
    # Invalid sequence height
    assert caster.validate_incoming_chain({
        "data": [
            {"height": 0, "hash": "A"},
            {"height": 2, "prev_block_hash": "A", "hash": "B"}
        ]
    }) is False
    
    # Invalid prev hash
    assert caster.validate_incoming_chain({
        "data": [
            {"height": 0, "hash": "A"},
            {"height": 1, "prev_block_hash": "X", "hash": "B"}
        ]
    }) is False
