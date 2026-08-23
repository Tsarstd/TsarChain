# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import logging
import threading
from unittest.mock import patch

from tsarchain.utils.tsar_logging import (
    RedactFilter, RateLimitFilter, JsonFormatter, SafeFormatter,
    TRACE, setup_logging, get_logger, get_ctx_logger, _module_from_logger_name
)


def test_module_from_logger_name():
    assert _module_from_logger_name("tsarchain.network.peer") == "network"
    assert _module_from_logger_name("tsarchain.wallet") == "wallet"
    assert _module_from_logger_name("tsarchain.core.mempool (1)") == "core"
    assert _module_from_logger_name("apps.cli_node_miner") == "node_miner"
    assert _module_from_logger_name("apps.cli_archivist") == "archivist"
    assert _module_from_logger_name("kremlin.services") == "wallet"
    assert _module_from_logger_name("archivist.storage") == "archivist"
    assert _module_from_logger_name(None) is None


def test_get_logger():
    logger = get_logger("tsarchain.test")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "tsarchain.test"

    default_logger = get_logger()
    assert default_logger.name == "tsarchain"


def test_get_ctx_logger_and_context_persistence():
    ctx_logger = get_ctx_logger("tsarchain.test_ctx", peer="127.0.0.1", height=42)
    assert ctx_logger.logger.name == "tsarchain.test_ctx"
    assert ctx_logger.extra["peer"] == "127.0.0.1"
    assert ctx_logger.extra["height"] == 42

    # Verify adapter process properly retains and merges extra kwargs
    msg, kwargs = ctx_logger.process("test message", {})
    assert kwargs["extra"]["peer"] == "127.0.0.1"
    assert kwargs["extra"]["height"] == 42
    assert kwargs["extra"]["block"] == "-"

    # Verify overriding extra for a single log call
    msg, kwargs = ctx_logger.process("test message", {"extra": {"block": "abc"}})
    assert kwargs["extra"]["peer"] == "127.0.0.1"
    assert kwargs["extra"]["block"] == "abc"


def test_trace_level():
    assert logging.getLevelName(TRACE) == "TRACE"
    logger = get_logger("tsarchain.trace_test")
    assert hasattr(logger, "trace")
    logger.trace("Trace string")

    ctx_logger = get_ctx_logger("tsarchain.trace_ctx")
    ctx_logger.trace("Contextual trace string")


def test_redact_filter_secrets_and_preserves_hashes():
    f = RedactFilter()
    
    # 1) Mnemonic seed should be redacted
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "test seed: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", (), None)
    f.filter(record)
    assert "[REDACTED_MNEMONIC]" in record.msg

    # 2) Sensitive keys should be redacted
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, 'ik: "0123456789abcdef0123456789abcdef"', (), None)
    f.filter(record)
    assert "[REDACTED_HEX]" in record.msg

    record = logging.LogRecord("test", logging.INFO, "test.py", 1, 'privkey: "a1b2c3d4e5f60718293a4b5c6d7e8f"', (), None)
    f.filter(record)
    assert "[REDACTED_HEX]" in record.msg

    # 3) Public block hashes & txids (64 hex characters) MUST NOT be redacted
    block_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, f"Connected block {block_hash} with tx {txid}", (), None)
    f.filter(record)
    assert block_hash in record.msg
    assert txid in record.msg
    assert "[REDACTED_HEX]" not in record.msg


def test_rate_limit_filter_bounded_and_thread_safe():
    f = RateLimitFilter(min_interval=0.1, max_cache_size=5)
    
    # Normal rate limiting
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "msg_1", (), None)
    assert f.filter(record) is True
    assert f.filter(record) is False  # Duplicate within min_interval is filtered

    # Capacity eviction
    for i in range(10):
        rec = logging.LogRecord("test", logging.INFO, "test.py", 1, f"msg_batch_{i}", (), None)
        f.filter(rec)
    assert len(f._last) <= 5

    # Multi-threaded concurrent access test
    errors = []
    def worker():
        try:
            for j in range(50):
                rec = logging.LogRecord("test", logging.INFO, "test.py", 1, f"thread_msg_{j % 5}", (), None)
                f.filter(rec)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(errors) == 0


def test_json_formatter():
    f = JsonFormatter()
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "json message", (), None)
    record.processName = "MainProcess"
    record.height = 100
    record.block = "0000abcd"
    
    try:
        raise ValueError("test error")
    except ValueError:
        import sys
        record.exc_info = sys.exc_info()

    formatted = f.format(record)
    data = json.loads(formatted)
    assert data["msg"] == "json message"
    assert data["lvl"] == "INFO"
    assert data["logger"] == "test"
    assert data["height"] == 100
    assert data["block"] == "0000abcd"
    assert "exc" in data


def test_safe_formatter():
    f = SafeFormatter("%(asctime)s [%(levelname)s] [%(height)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "safe formatted message", (), None)
    out = f.format(record)
    assert "safe formatted message" in out
    assert "[-]" in out


def test_setup_logging_with_and_without_file():
    with patch("tsarchain.utils.tsar_logging.RotatingFileHandler"), \
         patch("tsarchain.utils.tsar_logging.logging.basicConfig"):
        
        # 1) With file
        logger = setup_logging(log_file="test.log", to_console=True, force=True, level="DEBUG")
        assert logger.name == "tsarchain"

        # 2) Without file (log_file=None should NOT throw TypeError)
        logger_no_file = setup_logging(log_file=None, to_console=True, force=True, level="TRACE")
        assert logger_no_file.name == "tsarchain"
