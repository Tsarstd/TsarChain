# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

from collections import deque
import time

from ...utils import config as CFG
_handshake_hits: dict[str, deque] = {}
_temp_ban_until: dict[str, float] = {}


def _rl_prune(ip: str, now_ts: float) -> None:
    dq = _handshake_hits.get(ip)
    if not dq:
        return
    while dq and (now_ts - dq[0]) > CFG.HANDSHAKE_RL_PER_IP_WINDOW_S:
        dq.popleft()
    if not dq:
        _handshake_hits.pop(ip, None)

def is_banned(ip: str, now_ts: float | None = None) -> bool:
    if ip in ("127.0.0.1", "::1"):
        return False
    ts = _temp_ban_until.get(ip, 0.0)
    if ts <= 0.0:
        return False
    if now_ts is None:
        now_ts = time.time()
    return now_ts < ts

def ban_ip(ip: str, seconds: float) -> None:
    if not ip:
        return
    if ip in ("127.0.0.1", "::1"):
        return
    now = time.time()
    duration = max(0.0, float(seconds))
    until = now + duration
    existing = _temp_ban_until.get(ip, 0.0)
    if until <= existing:
        return
    _temp_ban_until[ip] = until


def allow_handshake(ip: str, now_ts: float) -> bool:
    if ip in ("127.0.0.1", "::1"):
        return True

    if is_banned(ip, now_ts):
        return False

    dq = _handshake_hits.setdefault(ip, deque())
    _rl_prune(ip, now_ts)
    if len(dq) >= CFG.HANDSHAKE_RL_PER_IP_BURST:
        _temp_ban_until[ip] = now_ts + CFG.TEMP_BAN_SECONDS
        dq.clear()
        return False

    dq.append(now_ts)
    return True


__all__ = ("allow_handshake", "ban_ip", "is_banned")
