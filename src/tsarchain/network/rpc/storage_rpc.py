# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
"""
A limited RPC bridge between nodes and graffiti modules.
Focus: payout & proof (no storage/archivist flow).
"""

import time
from typing import TYPE_CHECKING, Any, Optional
from bech32 import convertbits, bech32_encode

from ...contracts import graffiti as GRAFFITI
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.storage_rpc")

if TYPE_CHECKING:
    from ..node import Network


__all__ = ["handle_storage_rpc"]


def _spkhex_to_address(spk_hex: str) -> str | None:
    if isinstance(spk_hex, bytes):
        spk_hex = spk_hex.hex()
    spk_hex = spk_hex.lower()
    if spk_hex.startswith("0014") and len(spk_hex) == 44:
        prog = bytes.fromhex(spk_hex[4:])
        data = [0] + convertbits(list(prog), 8, 5, True)
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    if spk_hex.startswith("0020") and len(spk_hex) == 68:
        prog = bytes.fromhex(spk_hex[4:])
        data = [0] + convertbits(list(prog), 8, 5, True)
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    return None


def handle_storage_rpc(
    self: "Network",
    message: dict[str, Any],
    addr,
    mtype: str,
    *,
    src_node_id: Optional[str] = None,
    src_pubkey: Optional[str] = None,
) -> dict | None:
    ip = addr[0] if isinstance(addr, tuple) else "0.0.0.0"
    rl_key = f"storage_rpc:{ip}"
    if not self._tb_allow(self.rl_ip, rl_key, CFG.STORAGE_RPC_RL_IP_BURST, CFG.STORAGE_RPC_RL_WINDOW_S, CFG.STORAGE_RPC_RL_IP_BURST, backoff_key=rl_key):
        self._backoff(rl_key, CFG.STORAGE_RPC_RL_BACKOFF_S)
        return {"error": "rate_limited"}

    def _is_storage_sender() -> bool:
        if not src_node_id:
            return False
        peer_port = int(message.get("port", 0))
        with self.lock:
            peers = dict(getattr(self, "storage_peers", {}) or {})
        for (peer_ip, peer_port_known), meta in peers.items():
            pinned_nid = (meta or {}).get("node_id")
            pinned_pk = (meta or {}).get("pubkey")
            if pinned_nid and pinned_nid != src_node_id:
                continue
            if pinned_pk and not src_pubkey:
                continue
            if pinned_pk and src_pubkey and pinned_pk != src_pubkey:
                log.warning("[storage_auth] pubkey mismatch nid=%s ip=%s", pinned_nid or "-", ip)
                continue
            if peer_ip != ip:
                continue
            if peer_port_known > 0 and peer_port > 0 and peer_port_known == peer_port:
                return True
            if peer_port_known == 0 or peer_port == 0:
                return True
        return False

    if not _is_storage_sender():
        log.warning("[storage_auth] forbidden storage RPC %s from %s", mtype, addr)
        return {"error": "forbidden: storage-only endpoint"}

    if mtype == "GRAFFITI_PROOF_SUBMIT":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        ts_val = int(message.get("ts", 0))
        nonce_val = str(message.get("nonce") or "")
        sender_key = src_node_id or ip
        if not (ts_val and nonce_val and self._nonce_guard("storage_proof", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
            return {"error": "replay_guard"}
             
        art_id_raw = str(message.get("art_id") or "").strip()
        art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
        epoch = int(message.get("epoch", -1))
        offset = int(message.get("offset", -1))
        length = int(message.get("length", -1))
        proof_hash = str(message.get("hash") or "").strip().lower()
        storer = str(message.get("storer") or "").strip().lower()
        height = int(message.get("height", 0) or 0)
        seed = str(message.get("seed") or "").strip().lower()
        if epoch < 0 or offset < 0 or length <= 0 or len(proof_hash) != 64:
            return {"error": "bad_fields"}
        if not storer:
            return {"error": "missing_storer"}
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        if not reg:
            return {"error": "registry_unavailable"}
        post = reg.get_post(art_id)
        if not post:
            return {"error": "unknown_art_id"}
        size = int(post.get("size") or 0)
        if size <= 0 or (offset + length) > size:
            return {"error": "out_of_range", "size": size}
        if height < 0:
            height = 0
        if GRAFFITI.compute_proof_epoch(height) != epoch:
            return {"error": "epoch_mismatch"}
        challenge = GRAFFITI.calc_proof_challenge(art_id, size, height)
        if int(challenge.get("offset", -1)) != offset or int(challenge.get("length", -1)) != length:
            return {"error": "challenge_mismatch"}
        if seed and seed != challenge.get("seed"):
            return {"error": "seed_mismatch"}
        reg.record_proof(
            art_id=art_id,
            storer=storer,
            epoch=epoch,
            offset=offset,
            length=length,
            proof_hash=proof_hash,
            height=height,
            seed=str(challenge.get("seed", "")),
        )
        
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GRAFFITI_PROOF_SUBMIT] Benchmark : %.3f ms", result)
            
        return {"status": "ok", "art_id": art_id, "epoch": epoch}

    elif mtype == "GRAFFITI_BUILD_PAYOUT":
        if CFG.DEBUG_BENCHMARKS:
            start = time.perf_counter()
        ts_val = int(message.get("ts", 0))
        nonce_val = str(message.get("nonce") or "")
        sender_key = src_node_id or ip
        if not (ts_val and nonce_val and self._nonce_guard("storage_payout", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
            return {"error": "replay_guard"}
            
        art_id_raw = str(message.get("art_id") or "").strip()
        art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
        recipients = message.get("recipients") or []
        if not recipients and message.get("recipient") and message.get("amount"):
            amt = int(message.get("amount", 0))
            recipients = [{"addr": str(message.get("recipient")).strip(), "amount": amt}]
        fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
        epoch = int(message.get("epoch", -1))
        utxo = getattr(self.broadcast, "utxodb", None)
        if utxo is None:
            return {"error": "utxo_unavailable"}
        utxo._load()

        reg = getattr(utxo, "_graffiti_registry", None)
        proof_entry = reg.get_latest_proof(art_id) if reg else None
        proof_meta = None
        if proof_entry:
            proof_meta = {
                "offset": proof_entry.get("offset"),
                "length": proof_entry.get("length"),
                "hash": proof_entry.get("hash"),
                "seed": proof_entry.get("seed"),
                "height": proof_entry.get("height"),
                "epoch": proof_entry.get("epoch"),
                "storer": proof_entry.get("storer"),
            }

        if epoch >= 0:
            if not proof_entry or int(proof_entry.get("epoch", -1)) < epoch:
                return {"error": "missing_proof", "requested_epoch": epoch, "have": proof_entry.get("epoch", -1) if proof_entry else None}
        else:
            if proof_entry:
                epoch = int(proof_entry.get("epoch", -1))

        tx_obj = GRAFFITI.build_payout_tx(
            utxo_db=utxo,
            art_id=art_id,
            recipients=recipients,
            fee_rate=fee_rate,
            epoch=epoch if epoch >= 0 else None,
            proof=proof_meta,
        )

        outs = []
        for o in getattr(tx_obj, "outputs", []) or []:
            amt = int(getattr(o, "amount", 0) or 0)
            addr = _spkhex_to_address(o.script_pubkey.serialize().hex())
            outs.append((amt, addr))

        broadcast_flag = bool(message.get("broadcast"))
        if broadcast_flag:
            tx_msg = {"type": "NEW_TX", "data": tx_obj.to_dict(include_txid=True)}
            if CFG.ENABLE_DANDELION_PP:
                tx_msg["phase"] = "stem"
            ok = self.broadcast.receive_tx(tx_msg, None, self.peers)
            if not ok:
                log.warning("[payout] broadcast failed art=%s", art_id[:16])
                return {"error": "broadcast_failed"}
            
        if CFG.DEBUG_BENCHMARKS:
            end = time.perf_counter()
            result = round((end - start) * 1000.0, 3)
            log.debug("[GRAFFITI_BUILD_PAYOUT] Benchmark : %.3f ms", result)
            
        return {"status": "ok", "tx": tx_obj.to_dict(include_txid=True)}

    return None
