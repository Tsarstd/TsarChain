# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import threading
import pytest
from unittest.mock import Mock, patch

from tsarchain.network.rpc_helper.guard import GuardHandler

@pytest.fixture(autouse=True)
def mock_config(monkeypatch):
    class MockConfig:
        NONCE_PER_SENDER_MAX = 3
    monkeypatch.setattr('tsarchain.network.rpc_helper.guard.CFG', MockConfig())

@pytest.fixture(autouse=True)
def mock_logger(monkeypatch):
    mock_log = Mock()
    monkeypatch.setattr('tsarchain.network.rpc_helper.guard.log', mock_log)
    return mock_log

@pytest.fixture
def guard():
    obj = GuardHandler(network=type('Dummy', (), {})())
    obj.backoff_until = {}
    obj._nonce_guard_table = {}
    obj._nonce_guard_lock = threading.RLock()
    return obj

# ---- Test _tb_now ----
def test_tb_now(guard, monkeypatch):
    fake_now = 123456.789
    monkeypatch.setattr(time, 'time', lambda: fake_now)
    assert guard._tb_now() == fake_now

# ---- Test tb_node_allow ----
def test_tb_allow_initial_allow(guard, monkeypatch):
    fake_now = 1000.0
    monkeypatch.setattr(time, 'time', lambda: fake_now)
    table = {}
    rate = 10.0
    window = 5.0
    burst = 5.0
    key = "test_key"
    
    assert guard.tb_node_allow(table, key, rate, window, burst) is True
    tokens, last = table[key]
    assert tokens == burst - 1.0
    assert last == fake_now

def test_tb_allow_deny_when_no_tokens(guard, monkeypatch):
    fake_now = 1000.0
    monkeypatch.setattr(time, 'time', lambda: fake_now)
    table = {}
    rate = 10.0
    window = 5.0
    burst = 1.0
    
    assert guard.tb_node_allow(table, "key", rate, window, burst) is True
    assert guard.tb_node_allow(table, "key", rate, window, burst) is False
    
    tokens, last = table["key"]
    assert tokens == 0.0

def test_tb_allow_refill(guard, monkeypatch):
    start = 1000.0
    monkeypatch.setattr(time, 'time', lambda: start)
    table = {}
    rate = 10.0
    window = 5.0
    burst = 5.0
    key = "key"
    
    for _ in range(int(burst)):
        guard.tb_node_allow(table, key, rate, window, burst)
    
    new_time = start + 2.0
    monkeypatch.setattr(time, 'time', lambda: new_time)
    assert guard.tb_node_allow(table, key, rate, window, burst) is True
    tokens, last = table[key]
    assert tokens == 3.0
    assert last == new_time

def test_tb_allow_backoff_active(guard, monkeypatch):
    fake_now = 1000.0
    monkeypatch.setattr(time, 'time', lambda: fake_now)
    table = {}
    key = "key"
    backoff_key = "backoff_key"
    guard.backoff_until[backoff_key] = 1010.0
    assert guard.tb_node_allow(table, key, 10, 5, 5, backoff_key=backoff_key) is False
    assert key not in table

def test_tb_allow_backoff_not_active(guard, monkeypatch):
    fake_now = 1000.0
    monkeypatch.setattr(time, 'time', lambda: fake_now)
    table = {}
    key = "key"
    backoff_key = "backoff_key"
    guard.backoff_until[backoff_key] = 999.0
    assert guard.tb_node_allow(table, key, 10, 5, 5, backoff_key=backoff_key) is True

def test_tb_allow_backoff_none(guard, monkeypatch):
    fake_now = 1000.0
    monkeypatch.setattr(time, 'time', lambda: fake_now)
    table = {}
    key = "key"
    assert guard.tb_node_allow(table, key, 10, 5, 5) is True

# ---- Test backoff_node ----
def test_backoff(guard, monkeypatch):
    fake_now = 1000.0
    monkeypatch.setattr(time, 'time', lambda: fake_now)
    key = "backoff_key"
    secs = 5.0
    guard.backoff_node(key, secs)
    assert guard.backoff_until[key] == fake_now + secs
    
    guard.backoff_node(key, 2.0)
    assert guard.backoff_until[key] == fake_now + 5.0

    guard.backoff_node(key, 10.0)
    assert guard.backoff_until[key] == fake_now + 10.0

# ---- Test nonce_guard ----
def test_nonce_guard_invalid_params(guard):
    assert guard.nonce_guard("", "sender", "nonce123", 123, 60) is False
    assert guard.nonce_guard("scope", "", "nonce123", 123, 60) is False
    assert guard.nonce_guard("scope", "sender", "", 123, 60) is False
    assert guard.nonce_guard("scope", "sender", "nonce123", "123", 60) is False

def test_nonce_guard_timestamp_window(guard, monkeypatch):
    now = 1000
    monkeypatch.setattr(time, 'time', lambda: now)
    assert guard.nonce_guard("scope", "sender", "nonce1", 900, 60) is False
    assert guard.nonce_guard("scope", "sender", "nonce2", 1100, 60) is False
    assert guard.nonce_guard("scope", "sender", "nonce3", 950, 60) is True

def test_nonce_guard_replay(guard, monkeypatch):
    now = 1000
    monkeypatch.setattr(time, 'time', lambda: now)
    scope = "scope"
    sender = "sender"
    nonce = "abc123"
    window = 60
    assert guard.nonce_guard(scope, sender, nonce, now, window) is True
    assert guard.nonce_guard(scope, sender, nonce, now + 10, window) is False

def test_nonce_guard_pruning_expired(guard, monkeypatch):
    now = 1000
    monkeypatch.setattr(time, 'time', lambda: now)
    scope = "scope"
    sender = "sender"
    nonce = "expired_nonce"
    window = 60
    bucket_key = f"{scope}:{sender}"
    table = guard._nonce_guard_table.setdefault(bucket_key, {})
    table[nonce] = 900  # expired (int)

    assert guard.nonce_guard(scope, sender, nonce, now, window) is True
    # Nonce yang lama dihapus, lalu nonce yang sama ditambahkan dengan timestamp baru
    assert nonce in table
    assert table[nonce] == now

def test_nonce_guard_enforce_max_entries(guard, monkeypatch):
    now = 1000
    monkeypatch.setattr(time, 'time', lambda: now)
    scope = "scope"
    sender = "sender"
    window = 60
    bucket_key = f"{scope}:{sender}"
    table = guard._nonce_guard_table.setdefault(bucket_key, {})
    
    nonces = ["n1", "n2", "n3"]
    for i, n in enumerate(nonces):
        table[n] = now + i * 10  # int
    
    new_nonce = "n4"
    assert guard.nonce_guard(scope, sender, new_nonce, now + 30, window) is True
    assert "n1" not in table
    assert "n2" in table
    assert "n3" in table
    assert "n4" in table
    assert len(table) <= 3

def test_nonce_guard_clean_table_if_not_exists(guard):
    assert guard._nonce_guard_table == {}

def test_nonce_guard_lock_created_if_missing(guard):
    assert guard._nonce_guard_lock is not None
    assert hasattr(guard._nonce_guard_lock, 'acquire')
    assert hasattr(guard._nonce_guard_lock, 'release')