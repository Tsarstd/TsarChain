# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
"""
Guard & rate limiter specifically for storage nodes (Archivist).
- Protects STOR_* endpoints from request flooding/DoS attacks.
- Separates wallet-facing (upload/download) and admin/node-facing rules.
"""

from __future__ import annotations

import threading
import time
from typing import Dict

from ...utils import config as CFG
from ...utils.tsar_logging import get_ctx_logger

log = get_ctx_logger("tsarchain.contracts.storage_node.storage_guard")

# ---------- Mapping RPC type -> limiter category ----------
TYPE_TO_RULE = {
    # Wallet-facing upload/download
    "STOR_INIT": "wallet_init",
    "STOR_PUT": "wallet_put",
    "STOR_COMMIT": "wallet_commit",
    "STOR_GET_BY_ART": "wallet_get",
    "PING": "ping",
    # Node/admin ops
    "STOR_INDEX": "admin",
    "STOR_PAID": "admin",
    "STOR_GC": "admin",
    "STOR_PROOF_RUN": "admin",
}


def _rule(burst: int, window_s: int, backoff_s: int) -> Dict[str, float]:
    return {
        "burst": float(max(1, burst)),
        "window": float(max(1, window_s)),
        "backoff": float(max(0, backoff_s)),
    }


RULES = {
    "wallet_init": _rule(CFG.STOR_INIT_RL_IP_BURST, CFG.STOR_INIT_RL_WINDOW_S, CFG.STOR_INIT_RL_BACKOFF_S),
    "wallet_put": _rule(CFG.STOR_PUT_RL_IP_BURST, CFG.STOR_PUT_RL_WINDOW_S, CFG.STOR_PUT_RL_BACKOFF_S),
    "wallet_commit": _rule(CFG.STOR_COMMIT_RL_IP_BURST, CFG.STOR_COMMIT_RL_WINDOW_S, CFG.STOR_COMMIT_RL_BACKOFF_S),
    "wallet_get": _rule(CFG.STOR_GET_RL_IP_BURST, CFG.STOR_GET_RL_WINDOW_S, CFG.STOR_GET_RL_BACKOFF_S),
    "admin": _rule(CFG.STOR_ADMIN_RL_IP_BURST, CFG.STOR_ADMIN_RL_WINDOW_S, CFG.STOR_ADMIN_RL_BACKOFF_S),
    "ping": _rule(20, 10, 2),  # light, for a quick health check
}


class StorageGuard:
    def __init__(self) -> None:
        self.rl_ip: Dict[str, tuple[float, float]] = {}
        self.backoff_until: Dict[str, float] = {}
        self.ban_until: Dict[str, float] = {}
        self.lock = threading.RLock()

    # ---------- helpers ----------
    @staticmethod
    def _now() -> float:
        return time.time()

    @staticmethod
    def _is_local(ip: str) -> bool:
        return ip in ("127.0.0.1", "::1")

    def _tb_allow(self, table, key, rate_per_window, window_s, burst, backoff_key=None) -> bool:
        now = self._now()
        with self.lock:
            tokens, last = table.get(key, (burst, now))
            if now > last:
                refill = (now - last) * (rate_per_window / float(window_s))
                tokens = min(burst, tokens + refill)
            if backoff_key and self.backoff_until.get(backoff_key, 0) > now:
                log.warning("[stor_guard] backoff active key=%s until=%.2f now=%.2f", backoff_key, self.backoff_until.get(backoff_key, 0), now)
                return False
            if tokens >= 1.0:
                table[key] = (tokens - 1.0, now)
                return True
        log.warning("[stor_guard] ratelimit deny key=%s rate=%s/%ss burst=%s", backoff_key or key, rate_per_window, window_s, burst)
        return False

    def _backoff(self, key: str, secs: float) -> None:
        now = self._now()
        until = now + secs
        with self.lock:
            self.backoff_until[key] = max(until, self.backoff_until.get(key, 0))

    # ---------- ban helpers ----------
    def is_banned(self, ip: str, now: float | None = None) -> bool:
        if self._is_local(ip):
            return False
        now = now or self._now()
        with self.lock:
            return self.ban_until.get(ip, 0.0) > now

    def ban_ip(self, ip: str, seconds: float) -> None:
        if not ip or self._is_local(ip):
            return
        duration = max(0.0, float(seconds))
        until = self._now() + duration
        with self.lock:
            if until > self.ban_until.get(ip, 0.0):
                self.ban_until[ip] = until
        log.warning("[stor_guard] ban ip=%s for %.1fs", ip, duration)

    # ---------- main API ----------
    def allow(self, ip: str, mtype: str) -> Dict[str, object]:
        mtype_norm = (mtype or "").strip().upper()
        if self._is_local(ip):
            return {"ok": True, "category": "local"}

        now = self._now()
        if self.is_banned(ip, now):
            return {"ok": False, "drop": True, "error": "banned"}

        rule_name = TYPE_TO_RULE.get(mtype_norm)
        if not rule_name:
            self.ban_ip(ip, CFG.BAN_UNKNOWN_STORAGE_RPC)
            return {"ok": False, "drop": True, "error": "unknown_type"}

        rule = RULES.get(rule_name)
        if not rule:
            return {"ok": True, "category": rule_name}

        key = f"{rule_name}:{ip}"
        allowed = self._tb_allow(
            self.rl_ip,
            key,
            rate_per_window=rule["burst"],
            window_s=rule["window"],
            burst=rule["burst"],
            backoff_key=key,
        )
        if not allowed:
            self._backoff(key, rule.get("backoff", 0))
            return {"ok": False, "error": "rate_limited", "category": rule_name}

        return {"ok": True, "category": rule_name}


__all__ = ["StorageGuard", "TYPE_TO_RULE", "RULES"]
