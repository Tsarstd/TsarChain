# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173

from __future__ import annotations
import json, re, time, hashlib, math
from typing import Any, Dict, Optional
from bech32 import bech32_decode, bech32_encode, convertbits

from ..utils.helpers import Script, OP_RETURN, hash160
from ..utils import config as CFG
from ..core.tx import Tx, TxIn, TxOut

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts(graffiti)")

# -----------------------------
# Internal helpers / validation
# -----------------------------

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
ART_ID_RE = re.compile(rf"^({CFG.ART_ID_PREFIX}[0-9a-f]{{{CFG.ART_ID_BODY_LEN}}}|[0-9a-f]{{64}})$")
MIME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+/_-]{0,63}$")  # konservatif

def _is_valid_sha256_hex(x: str) -> bool:
    try:
        return bool(HEX64_RE.fullmatch(x.strip().lower()))
    except Exception:
        return False

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
    try:
        hrp, data = bech32_decode(addr)
        if hrp is None or hrp != CFG.ADDRESS_PREFIX:
            return False
        prog = bytes(convertbits(data[1:], 5, 8, False))
        return len(prog) in (20, 32)
    except Exception:
        return False

def _is_valid_art_id(art_id: str) -> bool:
    if not isinstance(art_id, str):
        return False
    try:
        return bool(ART_ID_RE.fullmatch(art_id.strip().lower()))
    except Exception:
        return False

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
    log.info("OP_RETURN data: %s bytes, with limit %s bytes", len(data), limit)


def _pool_redeem_script(art_id: str) -> bytes:
    """
    Deterministic redeem script for storage pool payouts (P2WSH).
    Script: <push art_digest> OP_EQUAL
    Witness must push matching art_digest to spend.
    """
    art_raw = _strip_art_prefix(_normalize_art_id(art_id, prefer_prefix=False))
    try:
        art_bytes = bytes.fromhex(art_raw)
    except Exception:
        art_bytes = hashlib.sha256(art_raw.encode("ascii")).digest()
    if len(art_bytes) > 75:
        art_bytes = hashlib.sha256(art_bytes).digest()
    push_len = len(art_bytes)
    return bytes([push_len]) + art_bytes + b"\x87"  # OP_EQUAL


def compute_proof_epoch(height: int) -> int:
    try:
        h = int(height)
    except Exception:
        return 0
    return max(0, h // int(CFG.GRAFFITI_PROOF_EPOCH_BLOCKS))


def calc_proof_challenge(art_id: str, size_bytes: int, height: int) -> Dict[str, int | str]:
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
    offset = int.from_bytes(seed[:8], "big") % max(1, size)
    max_len = max(1, int(CFG.GRAFFITI_PROOF_CHUNK_BYTES))
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


def derive_pool_address_p2wpkh(art_id_hex: str) -> str:
    """
    Legacy pool address derivation (P2WPKH) retained for backward compatibility.
    """
    art_hex = _strip_art_prefix(art_id_hex)
    try:
        art_bytes = bytes.fromhex(art_hex)
    except Exception:
        raise ValueError("bad_art_id_hex")
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
    try:
        bucket = utxo_db.get(spk_hex) or {}
        if isinstance(bucket, dict):
            for key, entry in bucket.items():
                try:
                    txid_hex, idx_str = key.split(":")
                    amt = int(entry.get("amount", entry.get("tx_out", {}).get("amount", 0)))
                    out.append({
                        "txid": txid_hex,
                        "vout": int(idx_str),
                        "amount": amt,
                        "script_pubkey": spk_hex,
                    })
                except Exception:
                    continue
    except Exception:
        pass

    # Fallback: scan utxo_db.utxos in-memory
    for key, entry in getattr(utxo_db, "utxos", {}).items():
        try:
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
        except Exception:
            continue
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
    try:
        utxo_db._load()
    except Exception:
        pass

    rec_list: list[dict[str, Any]] = []
    if isinstance(recipients, dict):
        recipients = [{"addr": a, "amount": v} for a, v in recipients.items()]
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("recipients_empty")
    for item in recipients:
        addr = str(item.get("addr") or item.get("address") or "").strip().lower()
        try:
            amt = int(item.get("amount", 0))
        except Exception:
            amt = 0
        if not _is_valid_tsar_address(addr) or amt <= 0:
            raise ValueError("bad_recipient")
        rec_list.append({"addr": addr, "amount": amt})

    utxos = find_pool_utxos(utxo_db, art_norm)
    if not utxos:
        raise ValueError("no_pool_utxo")

    redeem_script = _pool_redeem_script(art_norm)
    art_digest = bytes.fromhex(_strip_art_prefix(art_norm))
    if len(art_digest) > 75:
        art_digest = hashlib.sha256(art_digest).digest()

    total_needed = sum(r["amount"] for r in rec_list)
    selected = None
    fee_final = None
    change_amt = 0
    outputs: list[TxOut] = []

    # Greedy: coba kombinasi satu UTXO besar dulu, jika kurang coba tambahkan utxo kecil sebagai input kedua.
    # Untuk kesederhanaan, saat ini pilih satu utxo terbesar yang cukup; jika tidak cukup, raise.
    utxos_sorted = sorted(utxos, key=lambda u: u.get("amount", 0), reverse=True)
    for utxo in utxos_sorted:
        amount_in = int(utxo.get("amount", 0))
        # Build outputs (recipients)
        outs = []
        for rec in rec_list:
            spk = Script.p2wpkh_script(rec["addr"])
            outs.append(TxOut(int(rec["amount"]), spk))
        # OP_RETURN payout metadata
        meta = build_payout_metadata(art_norm, epoch if epoch is not None else 0, rec_list)
        opret_spk = build_script(meta)
        outs.append(TxOut(0, opret_spk))

        # temp tx for fee estimate
        txin = TxIn(bytes.fromhex(utxo["txid"]), int(utxo["vout"]), amount=amount_in, script_sig=Script([]), witness=[art_digest, redeem_script])
        tx_tmp = Tx(version=1, inputs=[txin], outputs=list(outs), locktime=0, auto_compute_txid=False)
        try:
            raw = tx_tmp.serialize()
            raw_wit = tx_tmp.serialize(include_witness=True)
            vbytes = int((len(raw) * 3 + len(raw_wit)) / 4)
        except Exception:
            vbytes = 200
        fee_est = rate * max(1, vbytes)
        change = amount_in - total_needed - fee_est
        if change >= dust:
            outs.insert(0, TxOut(change, Script.deserialize(_pool_spk_bytes(art_norm))))
        elif change < 0:
            continue  # utxo kecil, coba berikutnya

        tx_final = Tx(version=1, inputs=[txin], outputs=outs, locktime=0, auto_compute_txid=True)
        selected = tx_final
        fee_final = fee_est
        change_amt = max(0, change)
        break

    if selected is None:
        raise ValueError("insufficient_pool")

    selected.fee = fee_final
    return selected


# -----------------------------
# Public API
# -----------------------------

def build_metadata(sha256_hex: str, size_bytes: int, mime: str,
                   storer_addr: str, receipt_id: str,
                   creator_addr: str,
                   ts: Optional[int] = None, height: Optional[int] = None,
                   extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    
    if not _is_valid_sha256_hex(sha256_hex):
        raise ValueError("bad_sha256_hex")
    if not isinstance(size_bytes, int) or size_bytes < 0:
        raise ValueError("bad_size_bytes")
    if not _is_valid_mime(mime):
        raise ValueError("bad_mime")
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
        "mime": mime.strip(),
        "storer": storer_addr.strip().lower(),
        "receipt": receipt_id.strip(),
        "event": "POST",
    }
    meta["creator"] = creator_addr.strip().lower()
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
    
    try:
        art_id_norm = _normalize_art_id(art_id, prefer_prefix=False)
    except Exception:
        raise ValueError("bad_art_id")
    
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
    try:
        ep = int(epoch)
    except Exception:
        raise ValueError("bad_epoch")
    if ep < 0:
        raise ValueError("bad_epoch")

    rec_list: list[dict[str, Any]] = []
    if isinstance(recipients, dict):
        recipients = [{"addr": a, "amount": v} for a, v in recipients.items()]
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("bad_recipients")
    for item in recipients:
        addr = str(item.get("addr") or item.get("address") or "").strip().lower()
        try:
            amt = int(item.get("amount", 0))
        except Exception:
            amt = 0
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
        for k in ("offset", "length", "hash", "seed", "height"):
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
                    
        elif event == "COMMENT":
            art_id = obj.get("art_id", "")
            try:
                obj["art_id"] = _normalize_art_id(art_id, prefer_prefix=False)
            except Exception:
                return None
            comment_hex = obj.get("comment", "")
            if not isinstance(comment_hex, str):
                return None
            try:
                comment_bytes = bytes.fromhex(comment_hex)
            except Exception:
                return None
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
            
        elif event == "PAYOUT":
            art_id = obj.get("art_id", "")
            try:
                obj["art_id"] = _normalize_art_id(art_id, prefer_prefix=False)
            except Exception:
                return None
            try:
                epoch = int(obj.get("epoch", -1))
            except Exception:
                epoch = -1
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
                try:
                    amt = int(item.get("amount", 0))
                except Exception:
                    return None
                if amt <= 0 or not _is_valid_tsar_address(addr):
                    return None
                parsed_rec.append({"addr": addr, "amount": amt})
            obj["recipients"] = parsed_rec
            # optional proof hints
            for k in ("offset", "length", "hash", "seed", "height"):
                plain_key = k
                pref_key = f"proof_{k}"
                use_key = pref_key if pref_key in obj else plain_key
                if use_key in obj:
                    try:
                        val = obj[use_key]
                        if k in ("offset", "length", "height"):
                            obj[pref_key] = int(val)
                        elif k == "hash":
                            if not isinstance(val, str) or len(val) != 64:
                                return None
                            obj[pref_key] = val
                        else:
                            obj[pref_key] = str(val)
                    except Exception:
                        return None
        else:
            return None
        obj["event"] = event
        return obj
    except Exception:
        return None


def parse_from_script(script: Script) -> Optional[Dict[str, Any]]:
    try:
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
    except Exception:
        return None


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
        try:
            block_hash_bytes = bytes.fromhex(block_hash.strip())
        except Exception:
            block_hash_bytes = block_hash.strip().encode("utf-8")
        parts.append(block_hash_bytes)
    blob = b"|".join(parts)
    base_hex = hashlib.sha256(blob).hexdigest()
    if not decorate:
        return base_hex
    return _decorate_art_id(base_hex)


def derive_pool_address(art_id_hex: str) -> str:
    """
    Default pool address derivation (P2WSH). Use derive_pool_address_p2wpkh for legacy.
    """
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
]
