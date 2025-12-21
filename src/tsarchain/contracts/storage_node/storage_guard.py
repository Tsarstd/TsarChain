# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
"""
Guard & rate limiter specifically for storage nodes (Archivist).
- Protects STOR_* endpoints from request flooding/DoS attacks.
- Separates wallet-facing (upload/download) and admin/node-facing rules.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Dict

from ...utils import config as CFG
from ...utils.tsar_logging import get_ctx_logger
from ...network.pow_token import issue_pow, verify_pow

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

    @staticmethod
    def _subnet(ip: str) -> str:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if obj.version == 4:
            parts = ip.split(".")
            return ".".join(parts[:3]) if len(parts) >= 3 else ip
        parts = ip.split(":")
        return ":".join(parts[:4]) if len(parts) >= 4 else ip

    @staticmethod
    def _identity(identity: str | None, ip: str) -> str:
        ident = (identity or "").strip().lower()
        return ident if ident else f"ip:{ip}"

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
    def is_banned(self, ip: str, now: float | None = None, *, identity: str | None = None) -> bool:
        if self._is_local(ip):
            return False
        now = now or self._now()
        with self.lock:
            if identity:
                ident_key = self._identity(identity, ip)
                if self.ban_until.get(ident_key, 0.0) > now:
                    return True
            return self.ban_until.get(ip, 0.0) > now

    def ban_ip(self, ip: str, seconds: float, *, identity: str | None = None) -> None:
        if not ip or self._is_local(ip):
            return
        duration = max(0.0, float(seconds))
        until = self._now() + duration
        with self.lock:
            if until > self.ban_until.get(ip, 0.0):
                self.ban_until[ip] = until
            if identity:
                ident_key = self._identity(identity, ip)
                if until > self.ban_until.get(ident_key, 0.0):
                    self.ban_until[ident_key] = until
        log.warning("[stor_guard] ban ip=%s ident=%s for %.1fs", ip, (identity or "-"), duration)

    def _keyset(self, rule_name: str, ip: str, identity: str | None) -> list[str]:
        ident = (identity or "").strip().lower()
        keys = []
        if ident:
            keys.append(f"{rule_name}:id:{ident}")
        keys.append(f"{rule_name}:ip:{ip}")
        subnet = self._subnet(ip)
        if subnet:
            keys.append(f"{rule_name}:subnet:{subnet}")
        return keys

    # ---------- main API ----------
    def allow(self, ip: str, mtype: str, *, identity: str | None = None, pow_obj: dict | None = None) -> Dict[str, object]:
        mtype_norm = (mtype or "").strip().upper()
        if self._is_local(ip):
            return {"ok": True, "category": "local"}

        now = self._now()
        if self.is_banned(ip, now, identity=identity):
            return {"ok": False, "drop": True, "error": "banned"}

        rule_name = TYPE_TO_RULE.get(mtype_norm)
        if not rule_name:
            self.ban_ip(ip, CFG.BAN_UNKNOWN_STORAGE_RPC, identity=identity)
            return {"ok": False, "drop": True, "error": "unknown_type"}

        rule = RULES.get(rule_name)
        if not rule:
            return {"ok": True, "category": rule_name}

        pow_identity = self._identity(identity, ip)
        pow_scope = f"stor:{rule_name}"
        if pow_obj and verify_pow(pow_obj, pow_obj.get("nonce"), expected_scope=pow_scope, identity=pow_identity):
            return {"ok": True, "category": rule_name, "pow": "accepted"}

        keys = self._keyset(rule_name, ip, identity)
        burst_base = rule["burst"]
        window_s = rule["window"]
        backoff_s = rule.get("backoff", 0)
        ip_multiplier = float(CFG.CGNAT_IP_BURST_MULT)

        for key in keys:
            burst = burst_base
            if ":ip:" in key:
                burst = int(max(burst_base, burst_base * ip_multiplier))
            elif ":subnet:" in key:
                burst = int(max(burst_base * ip_multiplier, burst_base * ip_multiplier * 2))
            allowed = self._tb_allow(
                self.rl_ip,
                key,
                rate_per_window=burst,
                window_s=window_s,
                burst=burst,
                backoff_key=key,
            )
            if not allowed:
                self._backoff(key, backoff_s)
                challenge = issue_pow(pow_scope, pow_identity, CFG.STOR_POW_DIFFICULTY, CFG.POW_TOKEN_TTL_S)
                return {
                    "ok": False,
                    "error": "pow_required",
                    "category": rule_name,
                    "retry_after": max(backoff_s, 1),
                    "pow_challenge": challenge,
                }

        return {"ok": True, "category": rule_name}


__all__ = ["StorageGuard", "TYPE_TO_RULE", "RULES"]
