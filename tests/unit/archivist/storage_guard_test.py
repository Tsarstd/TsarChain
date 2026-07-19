# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import time
import pytest
from unittest.mock import patch

from archivist.storage_guard import StorageGuard

@pytest.fixture
def guard():
    return StorageGuard()

def test_subnet():
    assert StorageGuard._subnet("192.168.1.100") == "192.168.1"
    assert StorageGuard._subnet("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:0db8:85a3:0000"
    assert StorageGuard._subnet("invalid_ip") == "invalid_ip"

def test_is_local():
    assert StorageGuard._is_local("127.0.0.1") is True
    assert StorageGuard._is_local("::1") is True
    assert StorageGuard._is_local("192.168.1.1") is False

def test_identity():
    assert StorageGuard._identity(" user1 ", "1.2.3.4") == "user1"
    assert StorageGuard._identity("", "1.2.3.4") == "ip:1.2.3.4"

def test_ban_and_is_banned(guard):
    # Local IP should never be banned
    guard.ban_ip("127.0.0.1", 10)
    assert not guard.is_banned("127.0.0.1")
    
    # Ban normal IP
    guard.ban_ip("1.2.3.4", 0.1)
    assert guard.is_banned("1.2.3.4")
    
    # Wait for ban to expire
    time.sleep(0.15)
    assert not guard.is_banned("1.2.3.4")
    
    # Ban with identity
    guard.ban_ip("2.3.4.5", 1.0, identity="bad_guy")
    assert guard.is_banned("2.3.4.5", identity="bad_guy")
    # Using a different IP but same identity should be banned
    assert guard.is_banned("8.8.8.8", identity="bad_guy")
    assert not guard.is_banned("8.8.8.8", identity="good_guy")

@patch("archivist.storage_guard.time.time")
def test_backoff(mock_time, guard):
    mock_time.return_value = 100.0
    guard._backoff("test_key", 10.0)
    assert guard.backoff_until["test_key"] == 110.0
    
    # Backoff extends
    guard._backoff("test_key", 20.0)
    assert guard.backoff_until["test_key"] == 120.0

@patch("archivist.storage_guard.verify_pow")
@patch("archivist.storage_guard.issue_pow")
def test_allow(mock_issue_pow, mock_verify_pow, guard):
    # 1. Local IP
    res = guard.allow("127.0.0.1", "STOR_INIT")
    assert res["ok"] is True
    assert res["category"] == "local"
    
    # 2. Banned IP
    guard.ban_ip("1.2.3.4", 10)
    res = guard.allow("1.2.3.4", "STOR_INIT")
    assert res["ok"] is False
    assert res["error"] == "banned"
    
    # 3. Unknown type
    res = guard.allow("5.5.5.5", "UNKNOWN_MSG")
    assert res["ok"] is False
    assert res["error"] == "unknown_type"
    assert guard.is_banned("5.5.5.5")
    
    # 4. PoW accepted
    mock_verify_pow.return_value = True
    res = guard.allow("8.8.8.8", "STOR_INIT", pow_obj={"nonce": 123})
    assert res["ok"] is True
    assert res["pow"] == "accepted"
    
    # 5. Rate limit allow
    # STOR_GET_BY_ART
    res = guard.allow("9.9.9.9", "STOR_GET_BY_ART")
    assert res["ok"] is True
    assert res["category"] == "wallet_get"
    
    # 6. Rate limit deny (simulate by setting burst to 0 temporarily)
    with patch.dict("archivist.storage_guard.RULES", {"wallet_get": {"burst": 0, "window": 10, "backoff": 5}}):
        mock_issue_pow.return_value = {"challenge": "mocked"}
        res = guard.allow("10.10.10.10", "STOR_GET_BY_ART")
        assert res["ok"] is False
        assert res["error"] == "pow_required"
        assert res["pow_challenge"] == {"challenge": "mocked"}
        assert res["retry_after"] == 5

def test_tb_allow_refill(guard):
    now = time.time()
    table = {}
    key = "test"
    # First call, should allow
    assert guard._tb_allow(table, key, rate_per_window=10, window_s=1, burst=10) is True
    assert table[key][0] < 10.0
    
    # Exhaust tokens
    for _ in range(9):
        assert guard._tb_allow(table, key, rate_per_window=10, window_s=1, burst=10) is True
    
    # Denied
    assert guard._tb_allow(table, key, rate_per_window=10, window_s=1, burst=10) is False
    
    # Refill by advancing time
    with patch("archivist.storage_guard.StorageGuard._now", return_value=now + 1.1):
        assert guard._tb_allow(table, key, rate_per_window=10, window_s=1, burst=10) is True
