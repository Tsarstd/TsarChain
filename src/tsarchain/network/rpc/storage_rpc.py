# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
"""
A limited RPC bridge between nodes and graffiti modules.
Focus: payout & proof (no storage/archivist flow).
"""

from typing import TYPE_CHECKING, Any
from bech32 import convertbits, bech32_encode

from ...contracts import graffiti as GRAFFITI
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc(storage_rpc)")

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


def handle_storage_rpc(self: "Network", message: dict[str, Any], addr, mtype: str) -> dict | None:
    if mtype == "GRAFFITI_GET_PAYOUTS":
        art_id = str(message.get("art_id") or "").strip().lower()
        if not art_id:
            return {"type": "GRAFFITI_GET_PAYOUTS", "payouts": []}
        limit = int(message.get("limit", 100) or 100)
        limit = max(1, min(limit, 500))
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        payouts = reg.list_payouts(art_id, limit) if reg else []
        return {"type": "GRAFFITI_GET_PAYOUTS", "art_id": art_id, "payouts": payouts}

    elif mtype == "GRAFFITI_PROOF_SUBMIT":
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
        return {"status": "ok", "art_id": art_id, "epoch": epoch}

    elif mtype == "GRAFFITI_BUILD_PAYOUT":
        art_id_raw = str(message.get("art_id") or "").strip()
        try:
            art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
        except Exception:
            return {"error": "bad_art_id"}
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
                try:
                    epoch = int(proof_entry.get("epoch", -1))
                except Exception:
                    log.exception("[payout] invalid proof epoch")
                    epoch = -1

        log.info("[payout] build request art=%s recips=%s epoch=%s fee_rate=%s", art_id[:16], len(recipients), epoch, fee_rate)
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
            addr = None
            try:
                addr = _spkhex_to_address(o.script_pubkey.serialize().hex())
            except Exception:
                log.exception("[payout] error converting script_pubkey to address")
                try:
                    addr = _spkhex_to_address(o.script_pubkey.hex())
                except Exception:
                    log.exception("[payout] error converting script_pubkey hex to address")
                    addr = None
            outs.append((amt, addr))
        log.info("[payout] tx outputs art=%s %s", art_id[:16], outs)

        broadcast_flag = bool(message.get("broadcast"))
        if broadcast_flag:
            tx_msg = {"type": "NEW_TX", "data": tx_obj.to_dict(include_txid=True)}
            if CFG.ENABLE_DANDELION_PP:
                tx_msg["phase"] = "stem"
            ok = self.broadcast.receive_tx(tx_msg, None, self.peers)
            if not ok:
                log.warning("[payout] broadcast failed art=%s", art_id[:16])
                return {"error": "broadcast_failed"}
        log.info("[payout] build ok art=%s txid=%s", art_id[:16], tx_obj.txid.hex() if getattr(tx_obj, "txid", None) else "?")
        return {"status": "ok", "tx": tx_obj.to_dict(include_txid=True)}

    return None
