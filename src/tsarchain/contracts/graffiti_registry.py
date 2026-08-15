# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import os
import time
import json
import struct
from typing import Any, Dict

from ..utils import config as CFG
from ..storage.kv import iter_prefix, batch

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.contracts.graffiti_registry')


# =============================================================================
# BINARY SERIALIZATION / DESERIALIZATION HELPERS
# =============================================================================

def serialize_post_binary(entry: dict) -> bytes:
    stats = entry.get("stats") or {}
    pool_bal = int(stats.get("pool_balance") or 0)
    creator_paid = int(stats.get("creator_paid") or 0)
    storage_paid = int(stats.get("storage_paid") or 0)
    comments = int(stats.get("comments") or 0)
    last_paid_epoch = int(stats.get("last_paid_epoch", -1))
    height = int(entry.get("block_height") or 0)
    amt_paid = int(entry.get("amount_paid") or 0)
    
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack("<QQQQIIiI", amt_paid, pool_bal, creator_paid, storage_paid, height, comments, last_paid_epoch, len(payload))
    return header + payload


def deserialize_post_binary(raw: bytes, art_id: str = "") -> dict:
    if raw.startswith(b"{"):
        return json.loads(raw.decode("utf-8"))
    header_size = struct.calcsize("<QQQQIIiI")
    if len(raw) < header_size:
        return json.loads(raw.decode("utf-8"))
    amt_paid, pool_bal, creator_paid, storage_paid, height, comments, last_paid_epoch, payload_len = struct.unpack_from("<QQQQIIiI", raw, 0)
    payload_json = raw[header_size:header_size + payload_len].decode("utf-8")
    data = json.loads(payload_json)
    if art_id and "art_id" not in data:
        data["art_id"] = art_id
    return data


def serialize_comment_binary(entry: dict) -> bytes:
    height = int(entry.get("block_height") or 0)
    amount = int(entry.get("amount") or 0)
    tip = int(entry.get("tip") or 0)
    creator_paid = int(entry.get("creator_paid") or 0)
    storage_paid = int(entry.get("storage_paid") or 0)
    ts = int(entry.get("ts") or 0)
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack("<IQQQQQI", height, amount, tip, creator_paid, storage_paid, ts, len(payload))
    return header + payload


def deserialize_comment_binary(raw: bytes) -> dict:
    if raw.startswith(b"{"):
        return json.loads(raw.decode("utf-8"))
    header_size = struct.calcsize("<IQQQQQI")
    if len(raw) < header_size:
        return json.loads(raw.decode("utf-8"))
    height, amount, tip, creator_paid, storage_paid, ts, payload_len = struct.unpack_from("<IQQQQQI", raw, 0)
    payload_json = raw[header_size:header_size + payload_len].decode("utf-8")
    return json.loads(payload_json)


def serialize_payout_binary(entry: dict) -> bytes:
    height = int(entry.get("block_height") or 0)
    amount = int(entry.get("amount") or 0)
    epoch = int(entry.get("epoch", -1) if entry.get("epoch") is not None else -1)
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack("<IQiI", height, amount, epoch, len(payload))
    return header + payload


def deserialize_payout_binary(raw: bytes) -> dict:
    if raw.startswith(b"{"):
        return json.loads(raw.decode("utf-8"))
    header_size = struct.calcsize("<IQiI")
    if len(raw) < header_size:
        return json.loads(raw.decode("utf-8"))
    height, amount, epoch, payload_len = struct.unpack_from("<IQiI", raw, 0)
    payload_json = raw[header_size:header_size + payload_len].decode("utf-8")
    return json.loads(payload_json)


def serialize_proof_binary(entry: dict) -> bytes:
    epoch = int(entry.get("epoch") or 0)
    offset = int(entry.get("offset") or 0)
    length = int(entry.get("length") or 0)
    height = int(entry.get("height") or 0)
    ts = int(entry.get("ts") or 0)
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack("<QQIIQI", epoch, offset, length, height, ts, len(payload))
    return header + payload


def deserialize_proof_binary(raw: bytes) -> dict:
    if raw.startswith(b"{"):
        return json.loads(raw.decode("utf-8"))
    header_size = struct.calcsize("<QQIIQI")
    if len(raw) < header_size:
        return json.loads(raw.decode("utf-8"))
    epoch, offset_val, length, height, ts, payload_len = struct.unpack_from("<QQIIQI", raw, 0)
    payload_json = raw[header_size:header_size + payload_len].decode("utf-8")
    return json.loads(payload_json)


class GraffitiRegistry:
    def __init__(self) -> None:
        self._kv_prefix = "graffiti:"
        self.store = None
        self._data_cache = None
        default = {"posts": {}, "comments": {}, "payouts": {}, "proofs": {}}
        self.data = self._load(default)
        self.data.setdefault("proofs", {})


    def record_post(self, art_id: str, meta: Dict[str, Any], txid: str, block_height: int, pool_addr: str, amount_paid: int, *, block_hash: str | None = None) -> None:
        posts = self.data.setdefault("posts", {})
        existing = posts.get(art_id)
        if existing and existing.get("txid") == txid:
            return
        entry = dict(meta)
        entry.update({
            "art_id": art_id,
            "txid": txid,
            "block_height": int(block_height),
            "pool_address": pool_addr,
            "amount_paid": int(amount_paid),
            "block_hash": block_hash,
        })
        stats = entry.setdefault("stats", {})
        stats["pool_balance"] = int(stats.get("pool_balance", 0)) + int(amount_paid)
        stats.setdefault("creator_paid", 0)
        stats.setdefault("storage_paid", 0)
        stats.setdefault("comments", 0)
        posts[art_id] = entry
        self._flush()


    def get_post(self, art_id: str) -> Dict[str, Any] | None:
        return (self.data.get("posts") or {}).get(art_id)


    def record_comment(self, art_id: str, meta: Dict[str, Any], txid: str,
                       block_height: int, creator_paid: int, storage_paid: int) -> None:
        comments = self.data.setdefault("comments", {})
        thread = comments.setdefault(art_id, [])
        entry = {
            "txid": txid,
            "block_height": int(block_height),
            "comment": meta.get("comment"),
            "commenter": meta.get("commenter"),
            "amount": int(meta.get("amount") or 0),
            "tip": int(meta.get("tip") or 0),
            "creator_paid": int(creator_paid),
            "storage_paid": int(storage_paid),
            "ts": int(meta.get("ts") or time.time()),
        }
        existing_txids = {item.get("txid") for item in thread}
        if txid in existing_txids:
            return
        thread.append(entry)
        post = self.get_post(art_id)
        if post:
            stats = post.setdefault("stats", {})
            stats["creator_paid"] = int(stats.get("creator_paid", 0)) + int(creator_paid)
            stats["storage_paid"] = int(stats.get("storage_paid", 0)) + int(storage_paid)
            stats["pool_balance"] = int(stats.get("pool_balance", 0)) + int(storage_paid)
            stats["comments"] = int(stats.get("comments", 0)) + 1
        self._flush()


    def record_payout(self, art_id: str, recipients: Dict[str, int], txid: str, block_height: int, epoch: int | None = None, pool_balance: int | None = None) -> None:
        posts = self.data.setdefault("posts", {})
        post = posts.get(art_id)
        if not post:
            return
        stats = post.setdefault("stats", {})
        total = sum(int(v) for v in recipients.values())
        payouts = self.data.setdefault("payouts", {})
        art_payouts = payouts.setdefault(art_id, [])
        # Idempotent replay: skip if already recorded
        for existing in art_payouts:
            if existing.get("txid") == txid:
                if pool_balance is not None:
                    stats["pool_balance"] = max(0, int(pool_balance))
                return
        if pool_balance is not None:
            stats["pool_balance"] = max(0, int(pool_balance))
        else:
            stats["pool_balance"] = max(0, int(stats.get("pool_balance", 0)) - total)
        if epoch is not None:
            stats["last_paid_epoch"] = max(int(stats.get("last_paid_epoch", -1)), int(epoch))
        art_payouts.append({
            "txid": txid,
            "block_height": int(block_height),
            "recipients": {addr: int(val) for addr, val in recipients.items()},
            "amount": int(total),
            "epoch": None if epoch is None else int(epoch),
        })
        self._flush()


    def set_pool_balance(self, art_id: str, pool_balance: int) -> None:
        posts = self.data.setdefault("posts", {})
        post = posts.get(art_id)
        if not post:
            return
        stats = post.setdefault("stats", {})
        stats["pool_balance"] = max(0, int(pool_balance))
        self._flush()


    def record_proof(self, art_id: str, storer: str, epoch: int, offset: int, length: int,
                     proof_hash: str, height: int = 0, seed: str = "") -> None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower()
        if not art_id or not storer:
            return
        proofs = self.data.setdefault("proofs", {})
        art_proofs = proofs.setdefault(art_id, [])
        entry = {
            "storer": storer,
            "epoch": int(epoch),
            "offset": int(offset),
            "length": int(length),
            "hash": proof_hash,
            "height": int(height),
            "seed": seed,
            "ts": int(time.time()),
        }
        # Replace existing entry for same storer+epoch
        replaced = False
        for idx, item in enumerate(art_proofs):
            if item.get("storer") == storer and int(item.get("epoch", -1)) == int(epoch):
                art_proofs[idx] = entry
                replaced = True
                break
        if not replaced:
            art_proofs.append(entry)
        self.data["proofs"][art_id] = art_proofs
        self._flush()


    def get_proof(self, art_id: str, storer: str, epoch: int) -> Dict[str, Any] | None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower()
        if not art_id or not storer:
            return None
        proofs = (self.data.get("proofs") or {}).get(art_id, [])
        for item in proofs:
            if item.get("storer") == storer and int(item.get("epoch", -1)) == int(epoch):
                return dict(item)
        return None


    def get_latest_proof(self, art_id: str, storer: str | None = None) -> Dict[str, Any] | None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower() if storer else None
        proofs = (self.data.get("proofs") or {}).get(art_id, [])
        if not proofs:
            return None
        filtered = [dict(p) for p in proofs if (not storer or p.get("storer") == storer)]
        if not filtered:
            return None
        filtered.sort(key=lambda r: (int(r.get("epoch", -1)), int(r.get("ts", 0))), reverse=True)
        return filtered[0]


    def get_latest_proof_epoch(self, art_id: str, storer: str | None = None) -> int:
        proof = self.get_latest_proof(art_id, storer)
        if not proof:
            return -1
        return int(proof.get("epoch", -1))


    def list_payouts(self, art_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        art_id = (art_id or "").strip().lower()
        payouts = (self.data.get("payouts") or {}).get(art_id, [])
        items = [dict(entry) for entry in payouts]
        items.sort(key=lambda r: int(r.get("block_height") or 0), reverse=True)
        if isinstance(limit, int) and limit > 0:
            return items[:limit]
        return items


    def list_posts(self, limit: int = 50, offset: int = 0) -> list[Dict[str, Any]]:
        posts = self.data.get("posts") or {}
        items: list[Dict[str, Any]] = []
        for art_id, entry in posts.items():
            rec = dict(entry)
            rec["art_id"] = art_id
            stats = rec.get("stats") or {}
            rec["stats"] = stats
            items.append(rec)
        items.sort(key=lambda r: (int(r.get("block_height") or 0), int(r.get("ts") or 0)), reverse=True)
        off = max(0, int(offset or 0))
        if isinstance(limit, int) and limit > 0:
            return items[off:off + limit]
        return items[off:]


    def list_comments(self, art_id: str, limit: int = 50) -> list[Dict[str, Any]]:
        art_id = (art_id or "").strip().lower()
        if not art_id:
            return []
        comments = (self.data.get("comments") or {}).get(art_id, [])
        items = [dict(entry) for entry in comments]
        items.sort(key=lambda r: (int(r.get("block_height") or 0), int(r.get("ts") or 0)), reverse=True)
        if isinstance(limit, int) and limit > 0:
            return items[:limit]
        return items


    def _load(self, default: dict) -> dict:
        data = {"posts": {}, "comments": {}, "payouts": {}, "proofs": {}}
        for k, v in iter_prefix("graffiti", b""):
            try:
                if k.startswith(b"p:"):
                    art_id = k[2:].decode("utf-8")
                    data["posts"][art_id] = deserialize_post_binary(v, art_id)
                elif k.startswith(b"c:"):
                    parts = k[2:].decode("utf-8").split(":")
                    if len(parts) >= 2:
                        art_id = parts[0]
                        data["comments"].setdefault(art_id, []).append(deserialize_comment_binary(v))
                elif k.startswith(b"y:"):
                    parts = k[2:].decode("utf-8").split(":")
                    if len(parts) >= 2:
                        art_id = parts[0]
                        data["payouts"].setdefault(art_id, []).append(deserialize_payout_binary(v))
                elif k.startswith(b"r:"):
                    parts = k[2:].decode("utf-8").split(":")
                    if len(parts) >= 2:
                        art_id = parts[0]
                        data["proofs"].setdefault(art_id, []).append(deserialize_proof_binary(v))
            except Exception:
                log.exception("Error decoding graffiti key %s", k)
        return data or dict(default)


    def _flush(self) -> None:
        with batch("graffiti") as b:
            for art_id, post in (self.data.get("posts") or {}).items():
                b.put(f"p:{art_id}".encode("utf-8"), serialize_post_binary(post))
            for art_id, comments in (self.data.get("comments") or {}).items():
                for idx, c in enumerate(comments):
                    b.put(f"c:{art_id}:{idx:08d}".encode("utf-8"), serialize_comment_binary(c))
            for art_id, payouts in (self.data.get("payouts") or {}).items():
                for idx, y in enumerate(payouts):
                    b.put(f"y:{art_id}:{idx:08d}".encode("utf-8"), serialize_payout_binary(y))
            for art_id, proofs in (self.data.get("proofs") or {}).items():
                for idx, r in enumerate(proofs):
                    b.put(f"r:{art_id}:{idx:08d}".encode("utf-8"), serialize_proof_binary(r))


__all__ = ["GraffitiRegistry", "serialize_post_binary", "deserialize_post_binary", "serialize_comment_binary", "deserialize_comment_binary", "serialize_payout_binary", "deserialize_payout_binary", "serialize_proof_binary", "deserialize_proof_binary"]
