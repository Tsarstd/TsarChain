# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

from typing import Any
from bech32 import bech32_encode, convertbits

from ...contracts import graffiti as GRAFFITI
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic(graff_utxo)")


class UTXOGraffitiMixin:
    @staticmethod
    def _script_bytes(spk) -> bytes:
        if hasattr(spk, "serialize"):
            try:
                return spk.serialize()
            except Exception:
                return b""
        if isinstance(spk, (bytes, bytearray)):
            return bytes(spk)
        if isinstance(spk, str):
            try:
                return bytes.fromhex(spk)
            except Exception:
                return b""
        return b""

    def script_to_address(self, script) -> str | None:
        """
        Attempt to turn common script types (P2WPKH) into a bech32 address.
        Needed for Graffiti payout validation.
        """
        b = self._script_bytes(script)
        if len(b) == 22 and b[0] == 0x00 and b[1] == 0x14:
            try:
                data = [0] + list(convertbits(b[2:], 8, 5, True))
                return bech32_encode(CFG.ADDRESS_PREFIX, data)
            except Exception:
                return None
        return None

    def _record_graffiti_event(self, tx, outputs_info: list[dict[str, Any]], block_height: int | None, block_hash: str | None = None) -> None:
        if block_height is None:
            return
        try:
            txid_hex = self._txid_hex(getattr(tx, "txid", None))
            meta = None
            for info in outputs_info:
                script_bytes = info.get("script_bytes") or b""
                if script_bytes and script_bytes[0] == 0x6a:
                    payload = self._read_opreturn_payload(script_bytes)
                    if payload:
                        candidate = GRAFFITI.parse_payload(payload)
                        if candidate:
                            meta = candidate
                            break
            if not meta:
                return
            
            event = str(meta.get("event", "POST")).upper()
            if event == "POST":
                self._handle_graffiti_post(meta, outputs_info, txid_hex, block_height, block_hash)
            elif event == "COMMENT":
                self._handle_graffiti_comment(meta, outputs_info, txid_hex, block_height)
                
        except Exception:
            log.exception("[graffiti] failed to record event tx=%s", getattr(tx, "txid", None))

    def _handle_graffiti_post(
        self,
        meta: dict[str, Any],
        outputs_info: list[dict[str, Any]],
        txid_hex: str,
        block_height: int,
        block_hash: str | None = None,
        ) -> None:
        
        sha_hex = str(meta.get("sha256") or "")
        creator = (meta.get("creator") or "").strip().lower()
        art_id = str(meta.get("art_id") or "").strip().lower()
        if not art_id and sha_hex and creator:
            try:
                art_id = GRAFFITI.compute_art_id(sha_hex, creator)
            except Exception:
                art_id = ""
        if not art_id:
            log.warning("[graffiti] POST missing art_id/creator sha=%s tx=%s", sha_hex[:16], txid_hex)
            return
        pool_addr = GRAFFITI.derive_pool_address(art_id)
        min_fee = int(GRAFFITI.calc_upload_fee_sats(int(meta.get("size") or 0)))
        
        paid = sum(int(info.get("amount") or 0) for info in outputs_info if info.get("address") == pool_addr)
        if paid < min_fee:
            log.warning("[graffiti] POST fee too low: paid=%s required=%s tx=%s", paid, min_fee, txid_hex)
            return
        
        entry = {
            "sha256": sha_hex,
            "size": int(meta.get("size") or 0),
            "mime": meta.get("mime"),
            "storer": meta.get("storer"),
            "receipt": meta.get("receipt"),
            "creator": creator,
            "block_hash": block_hash,
        }
        self._graffiti_registry.record_post(art_id, entry, txid_hex, block_height, pool_addr, paid, block_hash=block_hash)

    def _handle_graffiti_comment(
        self,
        meta: dict[str, Any],
        outputs_info: list[dict[str, Any]],
        txid_hex: str,
        block_height: int) -> None:
        
        art_id = str(meta.get("art_id") or "").lower()
        if not art_id:
            return

        post_entry = self._graffiti_registry.get_post(art_id)
        if not post_entry:
            log.warning("[graffiti] COMMENT references unknown art_id=%s tx=%s", art_id, txid_hex)
            return

        pool_addr = post_entry.get("pool_address") or GRAFFITI.derive_pool_address(art_id)
        creator_addr = post_entry.get("creator") or meta.get("creator")
        if not creator_addr:
            log.warning("[graffiti] COMMENT missing creator for art_id=%s", art_id)
            return

        base_amount = int(meta.get("amount") or 0)
        tip = int(meta.get("tip") or 0)
        if base_amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
            log.warning("[graffiti] COMMENT amount %s below minimum for art_id=%s", base_amount, art_id)
            return

        split = GRAFFITI.calc_comment_split(base_amount, tip)
        paid_creator = sum(int(info.get("amount") or 0) for info in outputs_info if info.get("address") == creator_addr)
        paid_pool = sum(int(info.get("amount") or 0) for info in outputs_info if info.get("address") == pool_addr)

        if paid_creator < split["creator_total"]:
            log.warning("[graffiti] COMMENT royalty shortfall for art_id=%s paid=%s req=%s", art_id, paid_creator, split["creator_total"])
        if paid_pool < split["storage"]:
            log.warning("[graffiti] COMMENT storage share shortfall for art_id=%s paid=%s req=%s", art_id, paid_pool, split["storage"])
            
        self._graffiti_registry.record_comment(
            art_id=art_id,
            meta=meta,
            txid=txid_hex,
            block_height=block_height,
            creator_paid=paid_creator,
            storage_paid=paid_pool,
        )

    @staticmethod
    def _read_opreturn_payload(script_bytes: bytes) -> bytes | None:
        if not script_bytes or script_bytes[0] != 0x6a:
            return None
        i = 1
        if i >= len(script_bytes):
            return None
        first = script_bytes[i]
        i += 1
        if 1 <= first <= 75:
            n = first
            end = i + n
        elif first == 0x4c:
            if i >= len(script_bytes):
                return None
            n = script_bytes[i]
            i += 1
            end = i + n
        elif first == 0x4d:
            if i + 1 >= len(script_bytes):
                return None
            n = int.from_bytes(script_bytes[i:i+2], "little")
            i += 2
            end = i + n
        else:
            return None
        if end > len(script_bytes):
            return None
        return script_bytes[i:end]
