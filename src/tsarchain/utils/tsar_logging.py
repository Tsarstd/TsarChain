# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

'''
HOW TO USE logging in your code:

First, import the logger from tsar_logging:

from tsarchain.utils.tsar_logging import get_ctx_logger, setup_logging
log = get_ctx_logger('your_module_name')

Then log messages at different levels:

log.trace("very technical details, like : PING , mining detail, etc.")
log.debug("technical details for diagnosis")
log.info("normal event / milestone")
log.warning("a non-fatal condition that needs attention")
log.error("handled error")
log.critical("fatal condition")
log.exception("context message when an exception occurs")

In the entry point of your main app, call setup_logging() to configure logging:

if __name__ == "__main__":
    setup_logging("logging/node.log", force=True)
'''

from __future__ import annotations

import os
import re
import sys
import json
import time
import logging
import threading

from pathlib import Path
from typing import Optional, Any
from collections import OrderedDict
from logging.handlers import RotatingFileHandler

from tsarchain.utils import config as CFG

# ===== TRACE level (below DEBUG) =====
TRACE = 9
logging.addLevelName(TRACE, "TRACE")

def _trace(self, msg, *a, **k):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, a, **k)

logging.Logger.trace = _trace  # type: ignore

# Default formats
if getattr(CFG, "LOG_SHOW_PROCESS", False):
    _DEFAULT_FMT = "%(asctime)s [%(levelname)s] %(processName)s %(name)s: %(message)s"
else:
    _proc_placeholder = getattr(CFG, "LOG_PROC_PLACEHOLDER", "-")
    _DEFAULT_FMT = f"%(asctime)s [%(levelname)s] {_proc_placeholder} %(name)s: %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


def _module_from_logger_name(name: str | None) -> str | None:
    """Extract module category name from a hierarchical logger name."""
    if not name:
        return None
    base = name.split("(", 1)[0].strip()
    parts = base.split(".")
    
    if "tsarchain" in parts:
        i = parts.index("tsarchain")
        if i + 1 < len(parts):
            return parts[i + 1].strip().lower()
        return "core"
    
    if "apps" in parts:
        i = parts.index("apps")
        if i + 1 < len(parts):
            raw = parts[i + 1].strip().lower()
            if raw.startswith("cli_"):
                raw = raw[4:]
            return raw
        return "apps"
        
    if "kremlin" in parts:
        return "wallet"
    if "archivist" in parts:
        return "archivist"

    return parts[0].strip().lower() if parts else None


def _ensure_log_file(path: Path) -> None:
    """Ensure directory exists and file is touch-created."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch()
    except Exception:
        pass


# =========================
# Filters & Formatters
# =========================

class RedactFilter(logging.Filter):
    """
    Redacts sensitive cryptographic secrets (seed phrases, private keys, sensitive keys)
    while preserving public blockchain consensus artifacts (block hashes, txids).
    """
    RE_SEED = re.compile(r"\b([a-z]{3,}\s){11,23}[a-z]{3,}\b", re.I)
    RE_WIF  = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
    _SENSITIVE_KEYS = (
        "ik", "spk", "sig", "opk", "spend_pub", "chat_pub", "from_pub", "from_static",
        "chat_sig", "pull_sig", "read_sig", "used_opk", "nonce", "ct",
        "rk", "cks", "ckr", "dhs", "dhr", "my_identity", "their_identity", "my_static_hex",
        "enc", "bundle", "payload", "privkey", "private_key", "seed", "secret",
    )
    RE_HEX_FIELD = re.compile(
        r"(?i)(\"?(?:"
        + "|".join(_SENSITIVE_KEYS)
        + r")\"?\s*[:=]\s*)(['\"]?)([0-9a-f]{12,})(['\"]?)"
    )

    @staticmethod
    def _mask_hex_field(match: re.Match) -> str:
        prefix = match.group(1)
        quote = match.group(2) or ""
        suffix = match.group(4) or ""
        return f"{prefix}{quote}[REDACTED_HEX]{suffix}"

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            msg = self.RE_SEED.sub("[REDACTED_MNEMONIC]", msg)
            msg = self.RE_WIF.sub("[REDACTED_WIF]", msg)
            msg = self.RE_HEX_FIELD.sub(self._mask_hex_field, msg)
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True


class RateLimitFilter(logging.Filter):
    """
    Thread-safe and memory-bounded rate limiter for duplicate log messages.
    Uses bounded LRU cache to prevent memory leaks in long-running processes.
    """
    def __init__(self, min_interval: float = 2.0, max_cache_size: int = 2048):
        super().__init__()
        self.min_interval = float(min_interval)
        self.max_cache_size = max_cache_size
        self._last: OrderedDict[tuple[str, int, str], float] = OrderedDict()
        self._lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        if self.min_interval <= 0.0:
            return True

        key = (record.name, record.levelno, str(record.msg))
        now = time.monotonic()

        with self._lock:
            last = self._last.get(key, 0.0)
            if (now - last) < self.min_interval:
                return False

            self._last[key] = now
            self._last.move_to_end(key)

            # Evict oldest entries when capacity is exceeded
            while len(self._last) > self.max_cache_size:
                self._last.popitem(last=False)

        return True


class JsonFormatter(logging.Formatter):
    """Structured JSON log formatter with context metadata."""
    def format(self, record: logging.LogRecord) -> str:
        show_proc = getattr(CFG, "LOG_SHOW_PROCESS", False)
        proc_placeholder = getattr(CFG, "LOG_PROC_PLACEHOLDER", "-")

        d: dict[str, Any] = {
            "ts": self.formatTime(record, _DEFAULT_DATEFMT),
            "lvl": record.levelname,
            "logger": record.name,
            "proc": record.processName if show_proc else proc_placeholder,
            "msg": record.getMessage(),
        }
        for k in ("height", "block", "peer"):
            v = getattr(record, k, None)
            if v not in (None, "-"):
                d[k] = v
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, ensure_ascii=False)


class SafeFormatter(logging.Formatter):
    """Plain-text formatter ensuring contextual tokens have safe default values."""
    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "height"): record.height = "-"
        if not hasattr(record, "block"):  record.block  = "-"
        if not hasattr(record, "peer"):   record.peer   = "-"
        return super().format(record)


class ContextAdapter(logging.LoggerAdapter):
    """
    Adapter preserving persistent contextual metadata across all log invocations.
    Correctly merges self.extra with any invocation-specific extra dictionary.
    """
    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        extra = dict(self.extra) if self.extra else {}
        if "extra" in kwargs and isinstance(kwargs["extra"], dict):
            extra.update(kwargs["extra"])
        extra.setdefault("height", "-")
        extra.setdefault("block", "-")
        extra.setdefault("peer", "-")
        kwargs["extra"] = extra
        return msg, kwargs

    def isEnabledFor(self, level: int) -> bool:
        return self.logger.isEnabledFor(level)

    def trace(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        if self.logger.isEnabledFor(TRACE):
            self.log(TRACE, msg, *args, **kwargs)


# =========================
# Core APIs
# =========================

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Retrieve standard logger instance."""
    base = "tsarchain" if not name else name
    return logging.getLogger(base)


def get_ctx_logger(name: str = "tsarchain", **ctx: Any) -> ContextAdapter:
    """Retrieve logger wrapped in ContextAdapter with persistent contextual metadata."""
    return ContextAdapter(get_logger(name), ctx)


def setup_logging(
    log_file: str | os.PathLike | None = None,
    level: int | str | None = None,
    to_console: bool | None = None,
    rotate_max_bytes: int | None = None,
    backup_count: int | None = None,
    force: bool = False,
    fmt: str = _DEFAULT_FMT,
    datefmt: str = _DEFAULT_DATEFMT,
) -> logging.Logger:
    """
    Configure global TsarChain logging with file rotation and optional console output.
    """
    if level is None:
        level = getattr(CFG, "LOG_LEVEL", "INFO")
    if to_console is None:
        to_console = bool(getattr(CFG, "LOG_TO_CONSOLE", False))
    if rotate_max_bytes is None:
        rotate_max_bytes = int(getattr(CFG, "LOG_ROTATE_MAX_BYTES", 10_000_000))
    if backup_count is None:
        backup_count = int(getattr(CFG, "LOG_BACKUP_COUNT", 7))
    enable_redact = bool(getattr(CFG, "FILTER_REDAX", False))

    handlers: list[logging.Handler] = []
    as_json = str(getattr(CFG, "LOG_FORMAT", "plain")).lower() == "json"
    rate_seconds_console = float(getattr(CFG, "LOG_RATE_LIMIT_SECONDS", 0.0))
    rate_seconds_file    = float(getattr(CFG, "LOG_FILE_RATE_LIMIT_SECONDS", 0.0))

    # --- File handler ---
    if log_file:
        log_path = Path(log_file)
        _ensure_log_file(log_path)
        fh = RotatingFileHandler(
            log_path,
            maxBytes=int(rotate_max_bytes),
            backupCount=int(backup_count),
            encoding="utf-8",
            delay=True,
        )
        file_fmt = JsonFormatter() if as_json else SafeFormatter(fmt, datefmt)
        fh.setFormatter(file_fmt)
        if enable_redact:
            fh.addFilter(RedactFilter())
        if rate_seconds_file > 0.0:
            fh.addFilter(RateLimitFilter(rate_seconds_file))
        handlers.append(fh)

    # --- Console handler ---
    if to_console:
        console_fmt = JsonFormatter() if as_json else SafeFormatter(fmt, datefmt)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(console_fmt)
        if enable_redact:
            sh.addFilter(RedactFilter())
        if rate_seconds_console > 0.0:
            sh.addFilter(RateLimitFilter(rate_seconds_console))
        handlers.append(sh)

    # If neither file nor console is selected, provide a NullHandler
    if not handlers:
        handlers.append(logging.NullHandler())

    # Level normalization
    lvl = level
    if isinstance(lvl, str):
        lvl_up = lvl.upper()
        if lvl_up == "TRACE":
            lvl = TRACE
        else:
            lvl = logging._nameToLevel.get(lvl_up, logging.INFO)

    logging.basicConfig(level=lvl, handlers=handlers, force=force)
    return logging.getLogger("tsarchain")
