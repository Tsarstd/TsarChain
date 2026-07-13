# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import time
from .....utils.benchmarks import benchmark

from .....utils import config as CFG
from ...user_rpc import common as CM

# ---------------- Logger ----------------
from .....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.category.networking")


@benchmark(label="PING", threshold_ms=15.0)
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


@benchmark(label="GET_PEERS", threshold_ms=15.0)
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


@benchmark(label="STOR_LIST", threshold_ms=15.0)
def stor_list(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
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
    with self.lock:
        for v in self.storage_peers.values():
            if not isinstance(v, dict):
                continue
            addr = v.get("addr")
            if not addr:
                continue
            addr = addr.lower()
            old = by_addr.get(addr)
            if old is None:
                by_addr[addr] = dict(v)
            else:
                cand = dict(v)
                if ((old.get("port") or 0) == 0 and (cand.get("port") or 0) > 0) or \
                   (int(cand.get("last_seen") or 0) > int(old.get("last_seen") or 0)):
                    by_addr[addr] = cand

    items = []
    for meta in by_addr.values():
        items.append({
            "addr": meta.get("addr"),
            "url": meta.get("url", ""),
            "ip": meta.get("ip", ""),
            "port": int(meta.get("port", 0)),
            "last_seen": int(meta.get("last_seen", 0)),
            "alive": bool(meta.get("alive", False)),
        })

    return {"type": "STOR_LIST", "storers": items}