# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import time

from .....utils import config as CFG
from ...user_rpc import common as CM
from .....contracts import graffiti as GRAFFITI

# ---------------- Logger ----------------
from .....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.category.graff_activities")


def get_posts(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    
    ok, pow_resp = CM._allow_rpc_with_pow(
        self,
        scope="rpc:graffiti",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="graf",
        burst=CFG.GRAFFITI_RL_IP_BURST,
        window_s=CFG.GRAFFITI_RL_WINDOW_S,
        backoff_s=CFG.GRAFFITI_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    limit = int(message.get("limit", 50) or 50)
    offset = int(message.get("offset", 0) or 0)
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
    posts = reg.list_posts(limit, offset) if reg else []
        
    return {"type": "GRAFFITI_GET_POSTS", "posts": posts}

def get_comments(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()
    ok, pow_resp = CM._allow_rpc_with_pow(
        self,
        scope="rpc:graffiti",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="graf",
        burst=CFG.GRAFFITI_RL_IP_BURST,
        window_s=CFG.GRAFFITI_RL_WINDOW_S,
        backoff_s=CFG.GRAFFITI_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    art_id = str(message.get("art_id") or "").strip().lower()
    if not art_id:
        return {"type": "GRAFFITI_GET_COMMENTS", "comments": []}
    limit = int(message.get("limit", 100) or 100)
    limit = max(1, min(limit, 500))
    reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
    comments = reg.list_comments(art_id, limit) if reg else []
    
    if CFG.DEBUG_BENCHMARKS:
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        src_tag = (message.get("rpc_source") or "-")
        if result > 15.0:
            log.debug("[GRAFFITI_GET_COMMENTS] Benchmark : %.3f ms src=%s", result, src_tag)
        
    return {"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id, "comments": comments}

def get_art(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()
        
    ok, pow_resp = CM._allow_rpc_with_pow(
        self,
        scope="rpc:graffiti",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="graf",
        burst=CFG.GRAFFITI_RL_IP_BURST,
        window_s=CFG.GRAFFITI_RL_WINDOW_S,
        backoff_s=CFG.GRAFFITI_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    art_id_raw = str(message.get("art_id") or "").strip()
    if not art_id_raw:
        return {"type": "GRAFFITI_GET_ART", "error": "missing_art_id"}
    art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
    reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
    post = reg.get_post(art_id) if reg else None
    if not post:
        return {"type": "GRAFFITI_GET_ART", "art_id": art_id, "error": "not_found"}
    
    if CFG.DEBUG_BENCHMARKS:
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        src_tag = (message.get("rpc_source") or "-")
        if result > 15.0:
            log.debug("[GRAFFITI_GET_ART] Benchmark : %.3f ms src=%s", result, src_tag)
        
    return {"type": "GRAFFITI_GET_ART", "art_id": art_id, "post": post}

def get_payouts(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs): #NOTE : not used yet
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()

    ok, pow_resp = CM._allow_rpc_with_pow(
        self,
        scope="rpc:graffiti",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="graf",
        burst=CFG.GRAFFITI_RL_IP_BURST,
        window_s=CFG.GRAFFITI_RL_WINDOW_S,
        backoff_s=CFG.GRAFFITI_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    art_id = str(message.get("art_id") or "").strip().lower()
    if not art_id:
        return {"type": "GRAFFITI_GET_PAYOUTS", "payouts": []}
    limit = int(message.get("limit", 100) or 100)
    limit = max(1, min(limit, 500))
    reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
    payouts = reg.list_payouts(art_id, limit) if reg else []
    
    if CFG.DEBUG_BENCHMARKS:
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        log.debug("[GRAFFITI_GET_PAYOUTS] Benchmark : %.3f ms", result)
        
    return {"type": "GRAFFITI_GET_PAYOUTS", "art_id": art_id, "payouts": payouts}

