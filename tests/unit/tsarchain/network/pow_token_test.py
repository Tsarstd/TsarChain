# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
from unittest.mock import patch

from tsarchain.network import pow_token

def test_leading_zero_bits():
    assert pow_token._leading_zero_bits(b"\x00\x0f") == 12
    assert pow_token._leading_zero_bits(b"\x00\x00\x01") == 23
    assert pow_token._leading_zero_bits(b"\xff") == 0

def test_issue_pow():
    with patch("time.time", return_value=1000.0):
        pow_obj = pow_token.issue_pow("test_scope", "Test_Identity ", 5, 10.0)
    
    assert pow_obj["scope"] == "test_scope"
    assert pow_obj["identity"] == "test_identity"
    assert pow_obj["exp"] == 1010
    assert pow_obj["difficulty"] == 5
    assert "salt" in pow_obj
    assert "token" in pow_obj

def test_verify_pow_valid():
    pow_obj = pow_token.issue_pow("test_scope", "test_id", 1, 100.0)
    solved = pow_token.solve_pow(pow_obj, identity="test_id")
    assert solved is not None
    assert "nonce" in solved
    
    assert pow_token.verify_pow(solved, solved["nonce"], expected_scope="test_scope", identity="test_id") is True

def test_verify_pow_invalid_scope():
    pow_obj = pow_token.issue_pow("test_scope", "test_id", 1, 100.0)
    solved = pow_token.solve_pow(pow_obj, identity="test_id")
    
    assert pow_token.verify_pow(solved, solved["nonce"], expected_scope="wrong_scope", identity="test_id") is False

def test_verify_pow_invalid_identity():
    pow_obj = pow_token.issue_pow("test_scope", "test_id", 1, 100.0)
    solved = pow_token.solve_pow(pow_obj, identity="test_id")
    
    assert pow_token.verify_pow(solved, solved["nonce"], expected_scope="test_scope", identity="wrong_id") is False

def test_verify_pow_expired():
    # Since issue_pow computes exp based on time.time(), 
    # and verify_pow checks against time.time(),
    # we can mock time.time to simulate expiry.
    pow_obj = pow_token.issue_pow("test_scope", "test_id", 1, 10.0)
    solved = pow_token.solve_pow(pow_obj, identity="test_id")
    
    with patch("time.time", return_value=time.time() + 1000):
        assert pow_token.verify_pow(solved, solved["nonce"], expected_scope="test_scope", identity="test_id") is False

def test_verify_pow_tampered_token():
    pow_obj = pow_token.issue_pow("test_scope", "test_id", 1, 100.0)
    solved = pow_token.solve_pow(pow_obj, identity="test_id")
    solved["token"] = "tampered"
    
    assert pow_token.verify_pow(solved, solved["nonce"], expected_scope="test_scope", identity="test_id") is False

def test_verify_pow_invalid_input():
    assert pow_token.verify_pow(None, "nonce", expected_scope="s", identity="i") is False
    assert pow_token.verify_pow({}, "nonce", expected_scope="s", identity="i") is False
    assert pow_token.verify_pow({"scope": "s", "identity": "i"}, None, expected_scope="s", identity="i") is False
    # missing salt and diff
    pow_obj = {"scope": "s", "identity": "i", "token": "t"}
    assert pow_token.verify_pow(pow_obj, "nonce", expected_scope="s", identity="i") is False

def test_solve_pow_invalid_input():
    assert pow_token.solve_pow(None, identity="id") is None
    assert pow_token.solve_pow({}, identity="id") is None
    pow_obj = {"scope": "test"}
    assert pow_token.solve_pow(pow_obj, identity="id") is None

def test_solve_pow_max_iters_reached():
    pow_obj = pow_token.issue_pow("s", "i", 255, 100) # diff 255
    solved = pow_token.solve_pow(pow_obj, identity="i", max_iters=10)
    assert solved is None
