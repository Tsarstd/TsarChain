# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import time
import ipaddress
from collections import deque

from ...utils import config as CFG
from ..pow_token import verify_pow

_handshake_hits_ip: dict[str, deque] = {}
_handshake_hits_id: dict[str, deque] = {}
_handshake_hits_subnet: dict[str, deque] = {}
_temp_ban_ip: dict[str, float] = {}
_temp_ban_id: dict[str, float] = {}


def ban_ip(ip: str, seconds: float) -> None:
    _ban_peer(ip, seconds)


def allow_handshake(
    ip: str,
    now_ts: float,
    *,
    node_id: str | None = None,
    pow_proof: dict | None = None,
    precheck: bool = False,
) -> bool:
    if ip in ("127.0.0.1", "::1"):
        return True

    if _is_banned(ip, now_ts, node_id=node_id):
        return False

    identity_key = (node_id or "").strip().lower() or None
    if _check_handshake_pow(pow_proof, identity_key, ip):
        return True

    ip_burst = int(CFG.HANDSHAKE_RL_PER_IP_BURST)
    ip_window = float(CFG.HANDSHAKE_RL_PER_IP_WINDOW_S)
    subnet_burst = int(CFG.HANDSHAKE_RL_SUBNET_BURST)
    subnet_window = float(CFG.HANDSHAKE_RL_SUBNET_WINDOW_S)
    id_burst = int(CFG.HANDSHAKE_RL_PER_NODE_BURST)
    id_window = float(CFG.HANDSHAKE_RL_PER_NODE_WINDOW_S)

    if identity_key:
        factor = max(1.0, float(CFG.CGNAT_IP_BURST_MULT))
        ip_burst = max(ip_burst, int(ip_burst * factor))
        subnet_burst = max(subnet_burst, int(subnet_burst * factor))

    if precheck:
        # Use a softer gate for accept() loop; no bans applied here.
        ip_burst = max(1, int(ip_burst * 0.5))
        subnet_burst = max(1, int(subnet_burst * 0.5))

    subnet = _subnet_key(ip)
    if precheck:
        return _do_precheck(ip, subnet, identity_key, now_ts, ip_burst, ip_window, subnet_burst, subnet_window, id_burst, id_window)

    return _do_hit_check(ip, subnet, identity_key, now_ts, ip_burst, ip_window, subnet_burst, subnet_window, id_burst, id_window)


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _subnet_key(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if obj.version == 4:
        parts = ip.split(".")
        return ".".join(parts[:3]) if len(parts) >= 3 else ip
    parts = ip.split(":")
    return ":".join(parts[:4]) if len(parts) >= 4 else ip


def _rl_prune(table: dict[str, deque], key: str, window_s: float, now_ts: float) -> None:
    dq = table.get(key)
    if not dq:
        return
    while dq and (now_ts - dq[0]) > window_s:
        dq.popleft()
    if not dq:
        table.pop(key, None)


def _hit(table: dict[str, deque], key: str, window_s: float, burst: int, now_ts: float) -> bool:
    dq = table.setdefault(key, deque())
    _rl_prune(table, key, window_s, now_ts)
    dq.append(now_ts)
    return len(dq) <= burst


def _would_allow(table: dict[str, deque], key: str, window_s: float, burst: int, now_ts: float) -> bool:
    dq = table.get(key)
    if not dq:
        return True
    _rl_prune(table, key, window_s, now_ts)
    dq = table.get(key)
    if not dq:
        return True
    return len(dq) < burst


def _is_banned(ip: str, now_ts: float | None = None, *, node_id: str | None = None) -> bool:
    if ip in ("127.0.0.1", "::1"):
        return False
    now = now_ts or time.time()
    if node_id and _temp_ban_id.get(node_id, 0.0) > now:
        return True
    return _temp_ban_ip.get(ip, 0.0) > now


def _ban_peer(ip: str, seconds: float, *, node_id: str | None = None) -> None:
    if not ip:
        return
    if ip in ("127.0.0.1", "::1"):
        return
    now = time.time()
    duration = max(0.0, float(seconds))
    until = now + duration
    if node_id:
        existing = _temp_ban_id.get(node_id, 0.0)
        if until > existing:
            _temp_ban_id[node_id] = until
    existing_ip = _temp_ban_ip.get(ip, 0.0)
    if until > existing_ip:
        _temp_ban_ip[ip] = until


def _check_handshake_pow(pow_proof: dict | None, identity_key: str | None, ip: str) -> bool:
    if not pow_proof:
        return False
    nonce = pow_proof.get("nonce")
    return verify_pow(pow_proof, nonce, expected_scope="handshake", identity=identity_key or f"ip:{ip}")


def _do_precheck(ip: str, subnet: str, identity_key: str | None, now_ts: float, 
                 ip_burst: int, ip_window: float, 
                 subnet_burst: int, subnet_window: float, 
                 id_burst: int, id_window: float) -> bool:
    if subnet and not _would_allow(_handshake_hits_subnet, subnet, subnet_window, subnet_burst, now_ts):
        return False
    if identity_key and not _would_allow(_handshake_hits_id, identity_key, id_window, id_burst, now_ts):
        return False
    if not _would_allow(_handshake_hits_ip, ip, ip_window, ip_burst, now_ts):
        return False
    return True


def _do_hit_check(ip: str, subnet: str, identity_key: str | None, now_ts: float, 
                  ip_burst: int, ip_window: float, 
                  subnet_burst: int, subnet_window: float, 
                  id_burst: int, id_window: float) -> bool:
    if subnet and not _hit(_handshake_hits_subnet, subnet, subnet_window, subnet_burst, now_ts):
        return False

    if identity_key:
        if not _hit(_handshake_hits_id, identity_key, id_window, id_burst, now_ts):
            _ban_peer(ip, CFG.TEMP_BAN_SECONDS, node_id=identity_key)
            return False

    if not _hit(_handshake_hits_ip, ip, ip_window, ip_burst, now_ts):
        if identity_key:
            # back off IP briefly but do not nuke other CGNAT users
            backoff = now_ts + max(5.0, CFG.TEMP_BAN_SECONDS * 0.5)
            _temp_ban_ip[ip] = max(_temp_ban_ip.get(ip, 0.0), backoff)
        else:
            _ban_peer(ip, CFG.TEMP_BAN_SECONDS)
        return False

    return True
