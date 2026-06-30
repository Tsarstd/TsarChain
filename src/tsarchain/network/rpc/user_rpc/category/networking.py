# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import time

from .....utils import config as CFG
from ...user_rpc import common as CM

# ---------------- Logger ----------------
from .....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.category.networking")


def ping(self, message, pow_obj, base_identity, addr, mtype, *,
                     client_ip, is_miner_sender, **kwargs):
    
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:ping",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="ping",
        burst=CFG.PING_RL_IP_BURST,
        window_s=CFG.PING_RL_IP_WINDOW_S,
        backoff_s=CFG.PING_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp
    
    return {"type": "PONG"}

def get_peers(self, message, pow_obj, base_identity, addr, mtype, *,
                     client_ip, is_miner_sender, **kwargs):
    
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:get_peers",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="get_peers",
        burst=CFG.GET_PEERS_RL_IP_BURST,
        window_s=CFG.GET_PEERS_RL_IP_WINDOW_S,
        backoff_s=CFG.GET_PEERS_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp
    
    if not is_miner_sender():
        return {"type": "PEERS", "peers": []}
    return {"type": "PEERS", "peers": list(self.peers)}

def stor_list(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    if CFG.DEBUG_BENCHMARKS:
        start = time.perf_counter()

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:stor_list",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="stor_list",
        burst=CFG.STOR_LIST_RL_IP_BURST,
        window_s=CFG.STOR_LIST_RL_WINDOW_S,
        backoff_s=CFG.STOR_LIST_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    by_addr = {}
    for v in self.storage_peers.values():
        k = (v.get("address") or "").lower()
        old = by_addr.get(k)
        if not old:
            by_addr[k] = dict(v)
        else:
            cand = dict(v)
            if (old.get("port") or 0) == 0 and (cand.get("port") or 0) > 0:
                by_addr[k] = cand
            elif int(cand.get("last_seen") or 0) > int(old.get("last_seen") or 0):
                by_addr[k] = cand

    items = []
    with self.lock:
        for (ip, p), meta in (self.storage_peers or {}).items():
            if not isinstance(meta, dict): 
                continue
            items.append({
                "addr": meta.get("addr"),
                "url": meta.get("url",""),
                "ip": ip,
                "port": int(meta.get("port",0)),
                "last_seen": int(meta.get("last_seen",0)),
                "alive": bool(meta.get("alive",False)),
            })
            
    if CFG.DEBUG_BENCHMARKS:
        end = time.perf_counter()
        result = round((end - start) * 1000.0, 3)
        src_tag = (message.get("rpc_source") or "-")
        if result > 15.0:
            log.debug("[STOR_LIST] Benchmark : %.3f ms src=%s", result, src_tag)
        
    return {"type":"STOR_LIST","storers": items}