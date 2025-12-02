# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os, json
from typing import TYPE_CHECKING, Any, Optional

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc(storage_rpc)")
from ...utils import config as CFG
from ...contracts import graffiti as GRAFFITI
from bech32 import convertbits, bech32_encode

if TYPE_CHECKING:
    from ..node import Network


__all__ = ["handle_storage_rpc"]


def _storage_index_path() -> str:
    return os.path.join(CFG.STORAGE_DIR, "index.json")

def _load_storage_index() -> dict[str, Any]:
    default = {"files": {}, "bytes_used": 0, "art_map": {}}
    try:
        with open(_storage_index_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("files", {})
    data.setdefault("bytes_used", 0)
    data.setdefault("art_map", {})
    return data

def _save_storage_index(data: dict[str, Any]) -> None:
    path = _storage_index_path()
    if not os.path.isfile(path):
        raise FileNotFoundError("storage_index_absent")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def _spkhex_to_address(spk_hex: str) -> str | None:
    try:
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
    except Exception:
        return None
    return None


def handle_storage_rpc(self: "Network", message: dict[str, Any], addr: Optional[tuple], mtype: str) -> dict | None:

    if mtype == "STOR_INDEX":
        idx = _load_storage_index()
        # Recompute bytes_used to avoid stale values
        try:
            idx["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (idx.get("files") or {}).values())
        except Exception:
            pass
        return {"type": "STOR_INDEX", "status": "ok", **idx}

    if mtype == "STOR_STATUS":
        aid = str(message.get("graffiti_id") or "").strip()
        idx = _load_storage_index()
        meta = (idx.get("files") or {}).get(aid)
        return {"type": "STOR_STATUS", "found": bool(meta), "meta": meta}

    if mtype == "STOR_PAID":
        aid = str(message.get("graffiti_id") or "").strip()
        txid = str(message.get("txid") or "").strip()
        try:
            block_h = int(message.get("block_height", 0) or 0)
        except Exception:
            block_h = 0
        if not os.path.isfile(_storage_index_path()):
            return {"status": "error", "reason": "storage_disabled"}
        idx = _load_storage_index()
        files = idx.setdefault("files", {})
        meta = files.get(aid)
        if not aid or not isinstance(meta, dict):
            return {"status": "error", "reason": "no_such"}
        meta["paid"] = True
        if txid:
            meta["txid_paid"] = txid
        if block_h > 0:
            meta["confirmed_at_height"] = block_h
            try:
                meta["expire_at_height"] = block_h + int(CFG.GRAFFITI_EXPIRE_AFTER_BLOCKS)
            except Exception:
                meta["expire_at_height"] = block_h
        files[aid] = meta
        try:
            idx["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        except Exception:
            pass
        _save_storage_index(idx)
        return {"status": "ok", "graffiti_id": aid}

    if mtype == "STOR_GC":
        if not os.path.isfile(_storage_index_path()):
            return {"type": "STOR_GC", "status": "error", "reason": "storage_disabled", "expired": 0}
        try:
            tip_h = int(message.get("tip_height", 0) or 0)
        except Exception:
            tip_h = 0
        idx = _load_storage_index()
        files = idx.get("files") or {}
        expired = 0
        remove_keys: list[str] = []
        for gid, meta in files.items():
            try:
                expire_h = int(meta.get("expire_at_height", 0) or 0)
            except Exception:
                expire_h = 0
            if expire_h and tip_h and expire_h <= tip_h:
                remove_keys.append(gid)
        for gid in remove_keys:
            meta = files.pop(gid, None) or {}
            expired += 1
            try:
                path = meta.get("path")
                if path and os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass
        idx["files"] = files
        try:
            idx["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        except Exception:
            idx["bytes_used"] = 0
        _save_storage_index(idx)
        return {"type": "STOR_GC", "status": "ok", "expired": expired}

    if mtype == "GRAFFITI_GET_PAYOUTS":
        art_id = str(message.get("art_id") or "").strip().lower()
        if not art_id:
            return {"type": "GRAFFITI_GET_PAYOUTS", "payouts": []}
        limit = int(message.get("limit", 100) or 100)
        limit = max(1, min(limit, 500))
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        payouts = reg.list_payouts(art_id, limit) if reg else []
        return {"type": "GRAFFITI_GET_PAYOUTS", "art_id": art_id, "payouts": payouts}

    elif mtype == "GRAFFITI_POOL_PAYOUT":
        art_id = str(message.get("art_id") or "").strip().lower()
        try:
            amount = int(message.get("amount", 0))
        except Exception:
            amount = 0
        recipient = str(message.get("recipient") or "").strip().lower() or "storage"
        txid = str(message.get("txid") or "").strip() or "offchain"
        if not art_id or amount <= 0:
            return {"error": "bad_request"}
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        if not reg:
            return {"error": "registry_unavailable"}
        post = reg.get_post(art_id)
        if not post:
            return {"error": "unknown_art_id"}
        stats = post.setdefault("stats", {})
        pool_balance = int(stats.get("pool_balance", 0))
        if pool_balance < amount:
            return {"error": "insufficient_pool_balance", "pool_balance": pool_balance}
        height = getattr(getattr(self.broadcast, "blockchain", None), "height", 0)
        required_epoch = GRAFFITI.compute_proof_epoch(height)
        last_epoch = reg.get_latest_proof_epoch(art_id, recipient)
        if last_epoch < required_epoch:
            return {"error": "missing_proof", "required_epoch": required_epoch, "last_epoch": last_epoch}
        reg.record_payout(art_id, {recipient: amount}, txid, height)
        return {"status": "ok", "art_id": art_id, "pool_balance": int(stats.get("pool_balance", 0))}

    elif mtype == "GRAFFITI_PROOF_SUBMIT":
        art_id_raw = str(message.get("art_id") or "").strip()
        try:
            art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
        except Exception:
            return {"error": "bad_art_id"}
        try:
            epoch = int(message.get("epoch", -1))
        except Exception:
            epoch = -1
        try:
            offset = int(message.get("offset", -1))
            length = int(message.get("length", -1))
        except Exception:
            offset = -1; length = -1  # noqa: E702
        proof_hash = str(message.get("hash") or "").strip().lower()
        storer = str(message.get("storer") or "").strip().lower()
        try:
            height = int(message.get("height", 0) or 0)
        except Exception:
            height = 0
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
        # Validate challenge deterministically
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

    elif mtype == "GRAFFITI_PROOF_STATUS":
        art_id_raw = str(message.get("art_id") or "").strip()
        storer = str(message.get("storer") or "").strip().lower()
        try:
            art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
        except Exception:
            return {"error": "bad_art_id"}
        reg = getattr(getattr(self.broadcast, "utxodb", None), "_graffiti_registry", None)
        if not reg:
            return {"error": "registry_unavailable"}
        proof = reg.get_latest_proof(art_id, storer or None)
        return {"status": "ok", "art_id": art_id, "proof": proof or {}}

    elif mtype == "GRAFFITI_BUILD_PAYOUT":
        art_id_raw = str(message.get("art_id") or "").strip()
        try:
            art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
        except Exception:
            return {"error": "bad_art_id"}
        recipients = message.get("recipients") or []
        # shorthand recipient/amount fields
        if not recipients and message.get("recipient") and message.get("amount"):
            try:
                amt = int(message.get("amount", 0))
            except Exception:
                amt = 0
            recipients = [{"addr": str(message.get("recipient")).strip(), "amount": amt}]
        try:
            fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
        except Exception:
            fee_rate = CFG.DEFAULT_FEE_RATE_SATVB
        try:
            epoch = int(message.get("epoch", -1))
        except Exception:
            epoch = -1
        utxo = getattr(self.broadcast, "utxodb", None)
        if utxo is None:
            return {"error": "utxo_unavailable"}
        try:
            utxo._load()
        except Exception:
            pass
        log.info("[payout] build request art=%s recips=%s epoch=%s fee_rate=%s", art_id[:16], len(recipients), epoch, fee_rate)
        try:
            tx_obj = GRAFFITI.build_payout_tx(
                utxo_db=utxo,
                art_id=art_id,
                recipients=recipients,
                fee_rate=fee_rate,
                epoch=epoch if epoch >= 0 else None,
            )
        except Exception as exc:
            log.warning("[payout] build failed art=%s err=%s", art_id[:16], exc)
            return {"error": str(exc)}
        # Log ringkas outputs
        try:
            outs = []
            for o in getattr(tx_obj, "outputs", []) or []:
                amt = int(getattr(o, "amount", 0) or 0)
                addr = None
                try:
                    addr = _spkhex_to_address(o.script_pubkey.serialize().hex())
                except Exception:
                    try:
                        addr = _spkhex_to_address(o.script_pubkey.hex())
                    except Exception:
                        addr = None
                outs.append((amt, addr))
            log.info("[payout] tx outputs art=%s %s", art_id[:16], outs)
        except Exception:
            pass

        broadcast_flag = bool(message.get("broadcast"))
        if broadcast_flag:
            try:
                ok = self.broadcast.receive_tx({"type": "NEW_TX", "data": tx_obj.to_dict(include_txid=True)}, None, self.peers)
                if not ok:
                    log.warning("[payout] broadcast failed art=%s", art_id[:16])
                    return {"error": "broadcast_failed"}
            except Exception as exc:
                log.exception("[payout] broadcast error art=%s", art_id[:16])
                return {"error": f"broadcast_error:{exc}"}
        log.info("[payout] build ok art=%s txid=%s", art_id[:16], tx_obj.txid.hex() if getattr(tx_obj, "txid", None) else "?")
        return {"status": "ok", "tx": tx_obj.to_dict(include_txid=True)}

    return None
