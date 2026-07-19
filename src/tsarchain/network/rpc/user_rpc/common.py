# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import hashlib
import ipaddress
from typing import TYPE_CHECKING, Any

from ....utils import config as CFG
from ...pow_token import issue_pow, verify_pow
from ....contracts import graffiti as GRAFFITI
from ....utils.helpers import batch_verify_der_low_s

# ---------------- Logger ----------------
from ....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.common")

if TYPE_CHECKING:
    from ...node import Network


def verify_chat_signatures(tasks: list[tuple[str, str, bytes, str]]) -> dict[str, bool]:
    """
    tasks: [(label, pub_hex, payload_bytes, sig_hex), ...]
    Returns mapping label -> bool
    """
    verdict: dict[str, bool] = {}
    normalized: list[tuple[str, bytes, bytes, bytes]] = []
    for label, pub_hex, payload, sig_hex in tasks:
        verdict[label] = False
        if not (pub_hex and sig_hex and isinstance(payload, (bytes, bytearray)) and payload):
            continue
        pub_b = bytes.fromhex(pub_hex)
        sig_b = bytes.fromhex(sig_hex)
        normalized.append((label, pub_b, bytes(payload), sig_b))

    if not normalized:
        return verdict

    triples = [
        (pub_b, hashlib.sha256(payload).digest(), sig_b)
        for _, pub_b, payload, sig_b in normalized
    ]
    results = batch_verify_der_low_s(triples, enforce_low_s=True, parallel=False)

    for (label, _, _, _), ok in zip(normalized, results):
        verdict[label] = bool(ok)
    return verdict


def identity_from_msg(message: dict[str, Any] | None) -> str | None:
    if not isinstance(message, dict):
        return None
    candidates = [
        message.get("wallet_addr"),
        message.get("creator_addr"),
        message.get("from_addr"),
        message.get("from"),
        message.get("address"),
        message.get("addr"),
        message.get("sender"),
        message.get("node_id"),
    ]
    if isinstance(message.get("addresses"), list) and message.get("addresses"):
        candidates.append(message.get("addresses")[0])
    data = message.get("data") if isinstance(message.get("data"), dict) else None
    if isinstance(data, dict):
        candidates.append(data.get("from_addr"))
        candidates.append(data.get("addr"))
    for cand in candidates:
        ident = _norm_identity(cand)
        if ident:
            return ident
    return None


def summarize_block(self: "Network", b: Any) -> dict:
    height     = getattr(b, "height")
    ts         = getattr(b, "timestamp")
    txs        = getattr(b, "transactions", []) or []
    first_tx   = txs[0]
    block_id   = getattr(first_tx, "block_id")
    tx_count   = len(txs)
    
    graffiti_posts = 0
    graffiti_comments = 0
    graffiti_payouts = 0

    for tx in txs:
        for tx_out in getattr(tx, "outputs", []) or []:
            spk = getattr(tx_out, "script_pubkey", None)
            if not spk:
                continue
                
            out_meta = GRAFFITI.parse_from_script(spk)
            if out_meta is None:
                continue
            
            ev = str(out_meta.get("event", "")).upper()
            if ev == "POST":
                graffiti_posts += 1
            elif ev == "COMMENT":
                graffiti_comments += 1
            elif ev == "PAYOUT":
                graffiti_payouts += 1

    return {
        "height": height,
        "hash": self.bhash_hex(b),
        "block_id": block_id,
        "timestamp": ts,
        "tx_count": tx_count,
        "graffiti_posts": graffiti_posts,
        "graffiti_comments": graffiti_comments,
        "graffiti_payouts": graffiti_payouts,
        "graffiti_count": graffiti_posts + graffiti_comments + graffiti_payouts,
    }


def allow_rpc_with_pow(
    self,
    *,
    scope: str,
    table: dict,
    ip: str,
    identity: str | None,
    key_label: str,
    burst: int,
    window_s: int,
    backoff_s: int,
    pow_obj: dict | None,
    difficulty: int,
) -> tuple[bool, dict | None]:
    ident = _norm_identity(identity) or f"ip:{ip}"
    subnet = _subnet_key(ip)
    keys: list[str] = []
    if ip:
        keys.append(f"{key_label}:ip:{ip}")
    if subnet:
        keys.append(f"{key_label}:sub:{subnet}")
    if ident:
        keys.append(f"{key_label}:id:{ident}")

    if pow_obj:
        nonce = pow_obj.get("nonce") if isinstance(pow_obj, dict) else None
        try:
            if verify_pow(pow_obj, nonce, expected_scope=scope, identity=ident):
                return True, None
        except Exception:
            pass

    allowed = True
    for k in keys:
        if not self.tb_node_allow(table, k, burst, window_s, burst, backoff_key=k):
            allowed = False
    if allowed:
        return True, None

    if backoff_s:
        for k in keys:
            try:
                self.backoff_node(k, backoff_s)
            except Exception:
                pass
    challenge = issue_pow(scope, ident, difficulty, CFG.POW_TOKEN_TTL_S)
    return False, {
        "error": "pow_required",
        "retry_after": max(1, backoff_s or 1),
        "pow_challenge": challenge,
    }


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _norm_identity(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, list) and val:
        val = val[0]
    s = str(val or "").strip().lower()
    return s or None


def _subnet_key(ip: str) -> str | None:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if obj.version == 4:
        parts = ip.split(".")
        return ".".join(parts[:3]) if len(parts) >= 3 else None
    parts = ip.split(":")
    return ":".join(parts[:4]) if len(parts) >= 4 else None