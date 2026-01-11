# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173

from __future__ import annotations
import json, re, time, hashlib, math, mimetypes, os
from typing import Any, Dict, Optional
from bech32 import bech32_decode, bech32_encode, convertbits

from ..utils.helpers import Script, OP_RETURN, hash160, compute_tx_weight_vsize
from ..utils import config as CFG
from ..core.tx import Tx, TxIn, TxOut

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.graffiti")

# -----------------------------
# Internal helpers / validation
# -----------------------------

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
ART_ID_RE = re.compile(rf"^({CFG.ART_ID_PREFIX}[0-9a-f]{{{CFG.ART_ID_BODY_LEN}}}|[0-9a-f]{{64}})$")
MIME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+/_-]{0,63}$")  # konservatif
_MIME_ALLOWED = tuple(m.lower() for m in CFG.GRAFFITI_ALLOWED_MIME)
_EXT_ALLOWED = tuple(e.lower() for e in CFG.GRAFFITI_ALLOWED_EXT)

def _is_valid_sha256_hex(x: str) -> bool:
    return bool(HEX64_RE.fullmatch(x.strip().lower()))

def _is_valid_mime(x: str) -> bool:
    if not isinstance(x, str):
        return False
    x = x.strip()
    if not x:
        return False
    if len(x) > 64:
        return False
    return bool(MIME_RE.fullmatch(x))

def _is_valid_tsar_address(addr: str) -> bool:
    hrp, data = bech32_decode(addr)
    if hrp is None or hrp != CFG.ADDRESS_PREFIX:
        return False
    prog = bytes(convertbits(data[1:], 5, 8, False))
    return len(prog) in (20, 32)

def _is_valid_art_id(art_id: str) -> bool:
    if not isinstance(art_id, str):
        return False
    return bool(ART_ID_RE.fullmatch(art_id.strip().lower()))

def _strip_art_prefix(art_id: str) -> str:
    aid = (art_id or "").strip().lower()
    if aid.startswith(CFG.ART_ID_PREFIX):
        return aid[CFG.ART_ID_PREFIX_LEN:]
    return aid

def _decorate_art_id(base_hex: str) -> str:
    base = (base_hex or "").strip().lower()
    if not HEX64_RE.fullmatch(base):
        raise ValueError("bad_art_id_hash")
    return CFG.ART_ID_PREFIX + base[:CFG.ART_ID_BODY_LEN]

def _normalize_art_id(art_id: str, *, prefer_prefix: bool = True) -> str:
    """
    Accept legacy 64-hex art_id or new prefixed form.
    If prefer_prefix=True and legacy is provided, return prefixed variant; otherwise preserve legacy.
    """
    if not isinstance(art_id, str):
        raise ValueError("bad_art_id")
    aid = art_id.strip().lower()
    if aid.startswith(CFG.ART_ID_PREFIX):
        body = aid[CFG.ART_ID_PREFIX_LEN:]
        if len(body) != CFG.ART_ID_BODY_LEN or not re.fullmatch(r"[0-9a-f]+", body):
            raise ValueError("bad_art_id")
        return aid
    if HEX64_RE.fullmatch(aid):
        return _decorate_art_id(aid) if prefer_prefix else aid
    raise ValueError("bad_art_id")


def validate_graffiti_file(size_bytes: int, mime: str | None = None, filename: str | None = None) -> str:
    """
    Validasi ukuran & tipe file graffiti sesuai kebijakan.
    Mengembalikan MIME ternormalisasi (lowercase) jika valid, atau raise ValueError jika melanggar.
    """
    try:
        size_int = int(size_bytes)
    except Exception:
        log.exception("[validate_graffiti_file] unexpected error")
        raise ValueError("bad_size_bytes") from None
    if size_int <= 0:
        raise ValueError("bad_size_bytes")
    if size_int > CFG.GRAFFITI_MAX_SIZE_BYTES:
        raise ValueError("graffiti_too_large")

    mime_norm = (mime or "").strip().lower()
    if not mime_norm and filename:
        guess, _ = mimetypes.guess_type(filename)
        mime_norm = (guess or "").strip().lower()

    ext = ""
    if filename:
        ext = os.path.splitext(filename)[1].lstrip(".").lower()
    log.info("mime=%s", mime_norm)
    if mime_norm and _is_valid_mime(mime_norm):
        if _MIME_ALLOWED and mime_norm not in _MIME_ALLOWED:
            raise ValueError("mime_not_allowed")
    elif ext:
        if _EXT_ALLOWED and ext not in _EXT_ALLOWED:
            raise ValueError("mime_not_allowed")
        if not mime_norm:
            if ext in ("jpg", "jpeg"):
                mime_norm = "image"
            elif ext == ("mp4", "mkv"):
                mime_norm = "video"
    else:
        raise ValueError("mime_not_allowed")

    if not mime_norm:
        raise ValueError("mime_not_allowed")
    return mime_norm

def _encode_comment(comment_text: str) -> str:
    if not isinstance(comment_text, str):
        raise ValueError("comment_text must be str")
    data = comment_text.encode("utf-8")
    if not data:
        raise ValueError("empty_comment")
    if len(data) > int(CFG.GRAFFITI_COMMENT_MAX_BYTES):
        raise ValueError("comment_too_large")
    return data.hex()

def _compact_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=CFG.CANONICAL_SEP, ensure_ascii=True).encode('ascii')

def _guard_payload_size(data: bytes) -> None:
    limit = CFG.MAX_GRAFFITI_OPRET
    if len(data) > limit:
        raise ValueError(f"graffiti_opreturn_too_large: {len(data)} > {limit}")


def _pool_redeem_script(art_id: str) -> bytes:
    """
    Deterministic redeem script for storage pool payouts (P2WSH).
    Script: <push art_digest> OP_EQUAL
    Witness must push matching art_digest to spend.
    """
    art_raw = _strip_art_prefix(_normalize_art_id(art_id, prefer_prefix=False))
    art_bytes = bytes.fromhex(art_raw)
    if len(art_bytes) > 75:
        art_bytes = hashlib.sha256(art_bytes).digest()
    push_len = len(art_bytes)
    return bytes([push_len]) + art_bytes + b"\x87"  # OP_EQUAL


def compute_proof_epoch(height: int) -> int:
    h = int(height)
    return max(0, h // int(CFG.GRAFFITI_PROOF_EPOCH_BLOCKS))


def calc_proof_challenge(art_id: str, size_bytes: int, height: int, *, chunk_bytes: int | None = None) -> Dict[str, int | str]:
    """
    Deterministic byte-range challenge for retention proof.
    Returns mapping with epoch, offset, length, and seed hash.
    """
    art_norm = _normalize_art_id(art_id, prefer_prefix=False)
    size = int(size_bytes)
    if size <= 0:
        raise ValueError("bad_size_bytes")
    epoch = compute_proof_epoch(height)
    seed = hashlib.sha256(b"|".join([
        CFG.GRAFFITI_MAGIC,
        b"PROOF",
        _strip_art_prefix(art_norm).encode("ascii"),
        str(epoch).encode("ascii"),
    ])).digest()
    if chunk_bytes is None:
        chunk_bytes = int(CFG.GRAFFITI_PROOF_CHUNK_BYTES)
    max_len = max(1, int(chunk_bytes))
    total_chunks = max(1, int(math.ceil(size / float(max_len))))
    idx = int.from_bytes(seed[:8], "big") % total_chunks
    offset = int(idx * max_len)
    length = min(max_len, size - offset)
    if length <= 0:
        length = min(max_len, size)
    return {
        "epoch": int(epoch),
        "offset": int(offset),
        "length": int(length),
        "seed": seed.hex(),
    }


def hash_proof_chunk(chunk: bytes) -> str:
    if not isinstance(chunk, (bytes, bytearray)):
        raise ValueError("chunk_must_be_bytes")
    if not chunk:
        raise ValueError("empty_chunk")
    return hashlib.sha256(bytes(chunk)).hexdigest()

# -----------------------------
# MERKLE (native)
# -----------------------------
try:
    from tsarcore_native import (
        graff_merkle_root_for_file as _native_graff_merkle_root_for_file, #wallet
        graff_merkle_path_for_bytes as _native_graff_merkle_path_for_bytes, #storage node
        graff_merkle_path_for_file as _native_graff_merkle_path_for_file, #storage node
        graff_merkle_verify as _native_graff_merkle_verify, #node
    )
except ImportError as exc:
    raise ImportError("tsarcore_native is required for graffiti merkle") from exc

def merkle_root_for_file(path: str, chunk_size: int) -> tuple[str, int]: #wallet
    root, count = _native_graff_merkle_root_for_file(path, int(chunk_size))
    return bytes(root).hex(), int(count)

def merkle_path_for_bytes(data: bytes, chunk_size: int, index: int) -> list[dict[str, str]]: #storage node
    return list(_native_graff_merkle_path_for_bytes(data, int(chunk_size), int(index)))

def merkle_path_for_file(path: str, chunk_size: int, index: int) -> list[dict[str, str]]: #storage node
    return list(_native_graff_merkle_path_for_file(path, int(chunk_size), int(index)))

def verify_merkle_path(root_hex: str, leaf_hash_hex: str, path: list[dict[str, str]]) -> bool: #node
    return bool(_native_graff_merkle_verify(root_hex, leaf_hash_hex, path or []))

# ---- END OF MERKLE ----

def derive_pool_address_p2wpkh(art_id_hex: str) -> str:
    """
    Legacy pool address derivation (P2WPKH) retained for backward compatibility.
    """
    art_hex = _strip_art_prefix(art_id_hex)
    art_bytes = bytes.fromhex(art_hex)
    seed = CFG.GRAFFITI_POOL_SALT + art_bytes
    pkh = hash160(seed)
    data = [0] + list(convertbits(pkh, 8, 5, True))
    return bech32_encode(CFG.ADDRESS_PREFIX, data)


def derive_pool_address_p2wsh(art_id_hex: str) -> str:
    """
    Deterministic P2WSH pool address for storage payouts.
    """
    redeem = _pool_redeem_script(art_id_hex)
    prog = hashlib.sha256(redeem).digest()
    data = [0] + list(convertbits(prog, 8, 5, True))
    return bech32_encode(CFG.ADDRESS_PREFIX, data)


def hash_pool_redeem_script(art_id_hex: str) -> str:
    """
    Return sha256(redeem_script) hex for the pool covenant.
    """
    return hashlib.sha256(_pool_redeem_script(art_id_hex)).hexdigest()


def _pool_spk_bytes(art_id_hex: str) -> bytes:
    redeem = _pool_redeem_script(art_id_hex)
    prog = hashlib.sha256(redeem).digest()
    return Script([0, prog]).serialize()


def find_pool_utxos(utxo_db, art_id: str) -> list[dict]:
    """
    Cari UTXO yang script_pubkey-nya sesuai pool P2WSH untuk art_id.
    utxo_db: instance UTXODB (punya .utxos dict).
    """
    spk_hex = _pool_spk_bytes(art_id).hex()
    out: list[dict] = []
    # Coba via index get() jika tersedia
    bucket = utxo_db.get(spk_hex) or {}
    if isinstance(bucket, dict):
        for key, entry in bucket.items():
            txid_hex, idx_str = key.split(":")
            amt = int(entry.get("amount", entry.get("tx_out", {}).get("amount", 0)))
            out.append({
                "txid": txid_hex,
                "vout": int(idx_str),
                "amount": amt,
                "script_pubkey": spk_hex,
            })

    # Fallback: scan utxo_db.utxos in-memory
    for key, entry in getattr(utxo_db, "utxos", {}).items():
        tx_out = entry.get("tx_out") if isinstance(entry, dict) else None
        if not isinstance(tx_out, dict):
            continue
        spk = tx_out.get("script_pubkey")
        if spk and str(spk).lower() == spk_hex:
            amt = int(tx_out.get("amount", 0))
            txid_hex, idx_str = key.split(":")
            out.append({
                "txid": txid_hex,
                "vout": int(idx_str),
                "amount": amt,
                "script_pubkey": spk_hex,
            })
    # dedup by outpoint
    uniq = {}
    for item in out:
        k = f"{item.get('txid')}:{item.get('vout')}"
        uniq[k] = item
    out = list(uniq.values())
    out.sort(key=lambda r: r.get("amount", 0))
    return out


def build_payout_tx(
    utxo_db,
    art_id: str,
    recipients: list[dict[str, Any]] | dict[str, int],
    *,
    fee_rate: int | None = None,
    epoch: int | None = None,
    proof: Optional[Dict[str, Any]] = None,
    dust_threshold: int | None = None,
) -> Tx:
    """
    Bangun transaksi payout dari UTXO pool P2WSH untuk art_id.
    - recipients: list dict {"addr","amount"} atau mapping addr->amount (sats)
    - fee_rate: sat/vbyte; default CFG.DEFAULT_FEE_RATE_SATVB
    """
    art_norm = _normalize_art_id(art_id, prefer_prefix=False)
    dust = int(CFG.DUST_THRESHOLD_SAT if dust_threshold is None else dust_threshold)
    rate = int(fee_rate if fee_rate is not None else CFG.DEFAULT_FEE_RATE_SATVB)
    utxo_db._load()

    rec_list: list[dict[str, Any]] = []
    if isinstance(recipients, dict):
        recipients = [{"addr": a, "amount": v} for a, v in recipients.items()]
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("recipients_empty")
    for item in recipients:
        addr = str(item.get("addr") or item.get("address") or "").strip().lower()
        amt = int(item.get("amount", 0))
        if not _is_valid_tsar_address(addr) or amt <= 0:
            raise ValueError("bad_recipient")
        rec_list.append({"addr": addr, "amount": amt})

    total_needed = sum(r["amount"] for r in rec_list)
    utxos = find_pool_utxos(utxo_db, art_norm)
    if not utxos:
        raise ValueError("no_pool_utxo")

    total_available = sum(int(u.get("amount", 0) or 0) for u in utxos)
    if total_needed > total_available:
        raise ValueError("insufficient_pool")

    redeem_script = _pool_redeem_script(art_norm)
    art_digest = bytes.fromhex(_strip_art_prefix(art_norm))
    if len(art_digest) > 75:
        art_digest = hashlib.sha256(art_digest).digest()

    pool_spk = Script.deserialize(_pool_spk_bytes(art_norm))

    def _build_inputs(selected_utxos: list[dict[str, Any]]) -> list[TxIn]:
        inputs: list[TxIn] = []
        for u in selected_utxos:
            inputs.append(
                TxIn(
                    bytes.fromhex(u["txid"]),
                    int(u["vout"]),
                    amount=int(u.get("amount", 0)),
                    script_sig=Script([]),
                    witness=[art_digest, redeem_script],
                )
            )
        return inputs

    def _build_opret(recipients_list: list[dict[str, Any]]) -> TxOut:
        meta = build_payout_metadata(
            art_norm,
            epoch if epoch is not None else 0,
            recipients_list,
            proof=proof,
        )
        return TxOut(0, build_script(meta))

    def _estimate_fee(selected_utxos: list[dict[str, Any]], include_change: bool, recipients_list: list[dict[str, Any]]) -> int:
        outs: list[TxOut] = []
        if include_change:
            outs.append(TxOut(max(1, dust), pool_spk))
        for rec in recipients_list:
            outs.append(TxOut(1, Script.p2wpkh_script(rec["addr"])))
        outs.append(_build_opret(recipients_list))
        tx_tmp = Tx(version=1, inputs=_build_inputs(selected_utxos), outputs=outs, locktime=0, auto_compute_txid=False)
        _weight, vsize, _base, _total = compute_tx_weight_vsize(tx_tmp)
        return int(rate * max(1, int(vsize)))

    is_max_claim = (len(rec_list) == 1 and total_needed == total_available)
    utxos_sorted = sorted(utxos, key=lambda u: u.get("amount", 0), reverse=True)

    if is_max_claim:
        selected_utxos = list(utxos_sorted)
        total_in = total_available
        for _ in range(2):
            fee_est = _estimate_fee(selected_utxos, False, rec_list)
            payout_amt = total_in - fee_est
            if payout_amt <= 0:
                raise ValueError("insufficient_pool")
            if payout_amt == rec_list[0]["amount"]:
                break
            rec_list[0]["amount"] = payout_amt
        outs: list[TxOut] = [TxOut(int(rec_list[0]["amount"]), Script.p2wpkh_script(rec_list[0]["addr"]))]
        outs.append(_build_opret(rec_list))
        tx_final = Tx(version=1, inputs=_build_inputs(selected_utxos), outputs=outs, locktime=0, auto_compute_txid=True)
        tx_final.fee = total_in - sum(int(getattr(o, "amount", 0) or 0) for o in outs)
        return tx_final

    selected_utxos: list[dict[str, Any]] = []
    acc = 0
    fee_final = None
    change_amt = 0
    for utxo in utxos_sorted:
        selected_utxos.append(utxo)
        acc += int(utxo.get("amount", 0))
        fee_with_change = _estimate_fee(selected_utxos, True, rec_list)
        change = acc - total_needed - fee_with_change
        if change >= dust:
            fee_final = fee_with_change
            change_amt = change
            break
        fee_no_change = _estimate_fee(selected_utxos, False, rec_list)
        change = acc - total_needed - fee_no_change
        if change >= 0:
            fee_final = fee_no_change
            change_amt = 0
            break

    if fee_final is None:
        raise ValueError("insufficient_pool")

    outs: list[TxOut] = []
    if change_amt >= dust:
        outs.append(TxOut(int(change_amt), pool_spk))
    for rec in rec_list:
        outs.append(TxOut(int(rec["amount"]), Script.p2wpkh_script(rec["addr"])))
    outs.append(_build_opret(rec_list))

    tx_final = Tx(version=1, inputs=_build_inputs(selected_utxos), outputs=outs, locktime=0, auto_compute_txid=True)
    tx_final.fee = acc - sum(int(getattr(o, "amount", 0) or 0) for o in outs)
    return tx_final


# -----------------------------
# Public API
# -----------------------------

def build_metadata(sha256_hex: str, size_bytes: int, mime: str,
                   storer_addr: str, receipt_id: str,
                   creator_addr: str,
                   ts: Optional[int] = None, height: Optional[int] = None,
                   merkle_root: Optional[str] = None,
                   merkle_chunk_bytes: Optional[int] = None,
                   merkle_chunks: Optional[int] = None,
                   extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    
    if not _is_valid_sha256_hex(sha256_hex):
        raise ValueError("bad_sha256_hex")
    if not isinstance(size_bytes, int) or size_bytes < 0:
        raise ValueError("bad_size_bytes")
    mime_norm = validate_graffiti_file(size_bytes, mime)
    if not _is_valid_tsar_address(storer_addr):
        raise ValueError("bad_storer_addr")
    if not isinstance(receipt_id, str) or not receipt_id.strip():
        raise ValueError("bad_receipt_id")
    if not _is_valid_tsar_address(creator_addr):
        raise ValueError("bad_creator_addr")

    art_id = compute_art_id(sha256_hex, creator_addr)
    meta: Dict[str, Any] = {
        "sha256": sha256_hex.strip().lower(),
        "art_id": art_id,
        "size": int(size_bytes),
        "mime": mime_norm,
        "storer": storer_addr.strip().lower(),
        "receipt": receipt_id.strip(),
        "event": "POST",
    }
    meta["creator"] = creator_addr.strip().lower()
    if merkle_root or merkle_chunk_bytes or merkle_chunks:
        mroot = str(merkle_root or "").strip().lower()
        if not _is_valid_sha256_hex(mroot):
            raise ValueError("bad_merkle_root")
        mchunk = int(merkle_chunk_bytes or 0)
        mcount = int(merkle_chunks or 0)
        if mchunk <= 0 or mcount <= 0:
            raise ValueError("bad_merkle_meta")
        expect = int(math.ceil(int(size_bytes) / float(mchunk)))
        if expect != mcount:
            raise ValueError("merkle_count_mismatch")
        meta["mroot"] = mroot
        meta["mchunk"] = mchunk
        meta["mcount"] = mcount
    # Anchor opsional
    if ts is None:
        ts = int(time.time())
    meta["ts"] = int(ts)
    if height is not None:
        meta["height"] = int(height)

    # Extra kecil (dibatasi agar payload tetap kecil)
    if extra:
        for k, v in extra.items():
            if k in meta:
                continue
            if isinstance(v, (str, bytes)) and len(str(v)) > 128:
                continue
            meta[k] = v
    return meta

def build_comment_metadata(
    art_id: str,
    comment_text: str,
    amount_sats: int,
    creator_addr: str,
    commenter_addr: str | None = None,
    tip_sats: int = 0,
    ts: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
    
    art_id_norm = _normalize_art_id(art_id, prefer_prefix=False)
    if not _is_valid_tsar_address(creator_addr):
        raise ValueError("bad_creator_addr")
    
    if commenter_addr and not _is_valid_tsar_address(commenter_addr):
        raise ValueError("bad_commenter_addr")
    
    base_amount = int(amount_sats)
    if base_amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
        raise ValueError("comment_fee_too_low")
    
    tip = int(tip_sats or 0)
    if tip < 0:
        raise ValueError("bad_tip")
    
    comment_hex = _encode_comment(comment_text)
    meta: Dict[str, Any] = {
        "event": "COMMENT",
        "art_id": art_id_norm,
        "comment": comment_hex,
        "amount": base_amount,
        "tip": tip,
        "creator": creator_addr.strip().lower(),
    }
    if commenter_addr:
        meta["commenter"] = commenter_addr.strip().lower()
    if ts is None:
        ts = int(time.time())
    meta["ts"] = int(ts)
    if extra:
        for k, v in extra.items():
            if k in meta:
                continue
            if isinstance(v, (str, bytes)) and len(str(v)) > 128:
                continue
            meta[k] = v
    return meta

def build_payout_metadata(
    art_id: str,
    epoch: int,
    recipients: list[dict[str, Any]] | dict[str, int],
    proof: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build on-chain metadata for storage pool payout (P2WSH pool).
    recipients: list of {"addr": str, "amount": int} or mapping addr->amount (sats).
    proof: optional {"offset","length","hash","seed","height"} for retention epoch.
    """
    art_id_norm = _normalize_art_id(art_id, prefer_prefix=False)
    ep = int(epoch)
    if ep < 0:
        raise ValueError("bad_epoch")

    rec_list: list[dict[str, Any]] = []
    if isinstance(recipients, dict):
        recipients = [{"addr": a, "amount": v} for a, v in recipients.items()]
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("bad_recipients")
    for item in recipients:
        addr = str(item.get("addr") or item.get("address") or "").strip().lower()
        amt = int(item.get("amount", 0))
        if not _is_valid_tsar_address(addr) or amt <= 0:
            raise ValueError("bad_recipients")
        rec_list.append({"addr": addr, "amount": amt})

    meta: Dict[str, Any] = {
        "event": "PAYOUT",
        "art_id": art_id_norm,
        "epoch": ep,
        "recipients": rec_list,
    }
    if proof and isinstance(proof, dict):
        for k in ("offset", "length", "hash", "seed", "height", "epoch", "storer"):
            if k in proof:
                meta[f"proof_{k}"] = proof.get(k)
    if extra:
        for k, v in extra.items():
            if k in meta:
                continue
            if isinstance(v, (str, bytes)) and len(str(v)) > 128:
                continue
            meta[k] = v
    return meta

def calc_comment_split(base_amount: int, tip: int = 0) -> Dict[str, int]:
    amt = int(base_amount)
    if amt < 0:
        raise ValueError("base_amount_negative")
    
    tip_amt = max(0, int(tip))
    denom = max(1, int(CFG.GRAFFITI_COMMENT_BP_DENOM))
    creator_bp = max(0, min(denom, int(CFG.GRAFFITI_COMMENT_CREATOR_BP)))
    storage_bp = max(0, min(denom, int(CFG.GRAFFITI_COMMENT_STORAGE_BP)))
    creator_share = (amt * creator_bp) // denom
    storage_share = (amt * storage_bp) // denom
    miner_share = max(0, amt - creator_share - storage_share)
    
    return {
        "creator_base": int(creator_share),
        "creator_total": int(creator_share + tip_amt),
        "storage": int(storage_share),
        "miner": int(miner_share),
        "tip": tip_amt,
    }

def encode_payload(meta: Dict[str, Any]) -> bytes:
    if not isinstance(meta, dict):
        raise ValueError("meta_must_be_dict")
    payload = CFG.GRAFFITI_MAGIC + _compact_json(meta)
    _guard_payload_size(payload)
    return payload

def build_script(meta: Dict[str, Any]) -> Script:
    payload = encode_payload(meta)
    return Script([OP_RETURN, payload])

def build_opret_hex(meta: Dict[str, Any]) -> str:
    return encode_payload(meta).hex()

def parse_payload(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        if not isinstance(data, (bytes, bytearray)):
            return None
        data = bytes(data)
        if not data.startswith(CFG.GRAFFITI_MAGIC):
            return None
        blob = data[len(CFG.GRAFFITI_MAGIC):]
        if not blob:
            return None
        obj = json.loads(blob.decode('ascii'))
        if not isinstance(obj, dict):
            return None
        
        event = str(obj.get("event", "POST")).strip().upper()
        if event == "POST":
            if not _is_valid_sha256_hex(obj.get("sha256", "")):
                return None
            if not isinstance(obj.get("size"), int) or obj["size"] < 0:
                return None
            if not _is_valid_mime(obj.get("mime", "")):
                return None
            if not _is_valid_tsar_address(obj.get("storer", "")):
                return None
            receipt = obj.get("receipt", "")
            if not isinstance(receipt, str) or not receipt.strip():
                return None
            creator_addr = obj.get("creator")
            if creator_addr and not _is_valid_tsar_address(creator_addr):
                return None
            art_id = obj.get("art_id")
            if art_id and not _is_valid_art_id(art_id):
                return None
            if creator_addr:
                base_hash = compute_art_id(obj.get("sha256", ""), creator_addr, decorate=False)
                decorated = _decorate_art_id(base_hash)
                if art_id is None:
                    obj["art_id"] = decorated
                else:
                    aid_norm = art_id.strip().lower()
                    if aid_norm not in (decorated, base_hash):
                        return None
                    obj["art_id"] = decorated if aid_norm == decorated else aid_norm
            mroot = obj.get("mroot") or obj.get("merkle_root")
            mchunk = obj.get("mchunk") or obj.get("merkle_chunk")
            mcount = obj.get("mcount") or obj.get("merkle_count")
            if mroot or mchunk or mcount:
                if not (mroot and mchunk and mcount):
                    return None
                if not _is_valid_sha256_hex(str(mroot)):
                    return None
                try:
                    mchunk_i = int(mchunk)
                    mcount_i = int(mcount)
                except Exception:
                    return None
                if mchunk_i <= 0 or mcount_i <= 0:
                    return None
                expect = int(math.ceil(int(obj.get("size", 0)) / float(mchunk_i)))
                if expect != mcount_i:
                    return None
                obj["mroot"] = str(mroot).strip().lower()
                obj["mchunk"] = mchunk_i
                obj["mcount"] = mcount_i
                    
        elif event == "COMMENT":
            art_id = obj.get("art_id", "")
            obj["art_id"] = _normalize_art_id(art_id, prefer_prefix=False)
            comment_hex = obj.get("comment", "")
            if not isinstance(comment_hex, str):
                return None
            comment_bytes = bytes.fromhex(comment_hex)
            if not comment_bytes or len(comment_bytes) > int(CFG.GRAFFITI_COMMENT_MAX_BYTES):
                return None
            amount = int(obj.get("amount", 0))
            if amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
                return None
            tip = int(obj.get("tip", 0))
            if tip < 0:
                return None
            creator_addr = obj.get("creator")
            if not _is_valid_tsar_address(creator_addr or ""):
                return None
            commenter = obj.get("commenter")
            if commenter and not _is_valid_tsar_address(commenter):
                return None
            obj["comment_len"] = len(comment_bytes)
            obj["comment_hex"] = comment_hex
            
        elif event == "PAYOUT":
            art_id = obj.get("art_id", "")
            obj["art_id"] = _normalize_art_id(art_id, prefer_prefix=False)
            epoch = int(obj.get("epoch", -1))
            if epoch < 0:
                return None
            recipients = obj.get("recipients") or []
            if not isinstance(recipients, list) or not recipients:
                return None
            parsed_rec: list[dict[str, Any]] = []
            for item in recipients:
                if not isinstance(item, dict):
                    return None
                addr = str(item.get("addr") or item.get("address") or "").strip().lower()
                amt = int(item.get("amount", 0))
                if amt <= 0 or not _is_valid_tsar_address(addr):
                    return None
                parsed_rec.append({"addr": addr, "amount": amt})
            obj["recipients"] = parsed_rec
            # optional proof hints
            for k in ("offset", "length", "hash", "seed", "height", "epoch", "storer"):
                plain_key = k
                pref_key = f"proof_{k}"
                use_key = pref_key if pref_key in obj else plain_key
                if use_key in obj:
                    val = obj[use_key]
                    if k in ("offset", "length", "height"):
                        obj[pref_key] = int(val)
                    elif k == "hash":
                        if not isinstance(val, str) or len(val) != 64:
                            return None
                        obj[pref_key] = val
                    elif k == "storer":
                        sval = str(val).strip().lower()
                        if not sval:
                            return None
                        obj[pref_key] = sval
                    else:
                        obj[pref_key] = str(val)
        else:
            return None
        obj["event"] = event
        return obj
    except Exception:
        log.exception("[parse_payload] unexpected error")
        return None


def parse_from_script(script: Script) -> Optional[Dict[str, Any]]:
    raw = script.serialize()
    if not raw or raw[0] != OP_RETURN:
        return None
    # Ambil push pertama setelah OP_RETURN
    i = 1
    if i >= len(raw):
        return None
    first = raw[i]; i += 1
    if 1 <= first <= 75:
        n = first
        end = i + n
        if end > len(raw): return None
        data = raw[i:end]
    elif first == 0x4c:  # OP_PUSHDATA1
        if i >= len(raw): return None
        n = raw[i]; i += 1
        end = i + n
        if end > len(raw): return None
        data = raw[i:end]
    elif first == 0x4d:  # OP_PUSHDATA2
        if i + 1 >= len(raw): return None
        n = int.from_bytes(raw[i:i+2], 'little'); i += 2
        end = i + n
        if end > len(raw): return None
        data = raw[i:end]
    else:
        return None
    return parse_payload(data)


def compute_art_id(sha256_hex: str, creator_addr: str, block_hash: str | None = None, *, decorate: bool = True) -> str:
    """
    Deterministic art identifier anchored to creator and file hash, with optional block_hash
    salt if caller already knows the confirmed block. The default (without block_hash) is
    used for block_id anchoring so it can be computed before mining.

    Returns prefixed art_id (64 chars) by default; use decorate=False for legacy raw digest.
    """
    if not _is_valid_sha256_hex(sha256_hex):
        raise ValueError("bad_sha256_hex")
    if not _is_valid_tsar_address(creator_addr):
        raise ValueError("bad_creator_addr")
    parts = [
        b"TSAR_GRAFFITI_ART",
        bytes.fromhex(sha256_hex.strip().lower()),
        creator_addr.strip().lower().encode("utf-8"),
    ]
    if block_hash:
        block_hash_bytes = bytes.fromhex(block_hash.strip())
        parts.append(block_hash_bytes)
    blob = b"|".join(parts)
    base_hex = hashlib.sha256(blob).hexdigest()
    if not decorate:
        return base_hex
    return _decorate_art_id(base_hex)

def derive_pool_address(art_id_hex: str) -> str:
    return derive_pool_address_p2wsh(art_id_hex)

def calc_upload_fee_sats(size_bytes: int) -> int:
    billable = max(int(size_bytes), int(CFG.GRAFFITI_MIN_BILLABLE_SIZE))
    chunks = max(1, math.ceil(billable / float(CFG.GRAFFITI_MIN_BILLABLE_SIZE)))
    return int(chunks * float(CFG.GRAFFITI_UPLOAD_FEE_PER_CHUNK))

__all__ = [
    "build_metadata",
    "build_comment_metadata",
    "build_payout_metadata",
    "build_payout_tx",
    "find_pool_utxos",
    "encode_payload",
    "build_script",
    "build_opret_hex",
    "parse_payload",
    "parse_from_script",
    "compute_art_id",
    "derive_pool_address",
    "derive_pool_address_p2wpkh",
    "derive_pool_address_p2wsh",
    "hash_pool_redeem_script",
    "calc_upload_fee_sats",
    "calc_comment_split",
    "compute_proof_epoch",
    "calc_proof_challenge",
    "hash_proof_chunk",
    "merkle_leaves_for_file",
    "merkle_leaves_from_bytes",
    "merkle_root_from_leaves",
    "merkle_root_for_bytes",
    "merkle_root_for_file",
    "merkle_path_from_leaves",
    "merkle_path_for_bytes",
    "merkle_path_for_file",
    "verify_merkle_path",
    "validate_graffiti_file",
]
