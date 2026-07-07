# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
import hashlib
from unittest.mock import patch

from tsarchain.contracts import graffiti
from tsarchain.contracts.graffiti import (
    _is_valid_sha256_hex,
    _is_valid_mime,
    _is_valid_tsar_address,
    _is_valid_art_id,
    _strip_art_prefix,
    _decorate_art_id,
    _normalize_art_id,
    validate_graffiti_file,
    _encode_comment,
    _compact_json,
    _guard_payload_size,
    _pool_redeem_script,
    compute_proof_epoch,
    calc_proof_challenge,
    hash_proof_chunk,
    derive_pool_address_p2wpkh,
    derive_pool_address_p2wsh,
    hash_pool_redeem_script,
    _pool_spk_bytes,
    find_pool_utxos,
    build_payout_tx,
    build_metadata,
    build_comment_metadata,
    build_payout_metadata,
    calc_comment_split,
    encode_payload,
    build_script,
    parse_payload,
    parse_from_script,
    compute_art_id,
    derive_pool_address,
    calc_upload_fee_sats,
)
from tsarchain.utils.helpers import Script, OP_RETURN
from tsarchain.core.tx import Tx, TxIn, TxOut
from bech32 import bech32_encode, convertbits

# Mock data
VALID_SHA256 = "a" * 64
VALID_TSAR_ADDR = bech32_encode("tsar", [0] + list(convertbits(bytes.fromhex("b" * 40), 8, 5, True)))
VALID_CREATOR_ADDR = VALID_TSAR_ADDR
VALID_STORER_ADDR = bech32_encode("tsar", [0] + list(convertbits(bytes.fromhex("c" * 40), 8, 5, True)))
VALID_ART_ID = "art1" + ("a" * 60)
VALID_MIME = "image/png"


class MockCFG:
    ART_ID_PREFIX = "art1"
    ART_ID_PREFIX_LEN = 4
    ART_ID_BODY_LEN = 60
    GRAFFITI_ALLOWED_MIME = ["image/png", "image/jpeg", "video/mp4"]
    GRAFFITI_ALLOWED_EXT = ["png", "jpg", "jpeg", "mp4"]
    ADDRESS_PREFIX = "tsar"
    GRAFFITI_MAX_SIZE_BYTES = 10 * 1024 * 1024
    GRAFFITI_COMMENT_MAX_BYTES = 256
    CANONICAL_SEP = (",", ":")
    MAX_GRAFFITI_OPRET = 1024
    GRAFFITI_MAGIC = b"TSARGR"
    GRAFFITI_PROOF_EPOCH_BLOCKS = 1000
    GRAFFITI_PROOF_CHUNK_BYTES = 1024
    GRAFFITI_POOL_SALT = b"salt"
    DUST_THRESHOLD_SAT = 546
    DEFAULT_FEE_RATE_SATVB = 1
    GRAFFITI_COMMENT_MIN_FEE = 100
    GRAFFITI_COMMENT_BP_DENOM = 10000
    GRAFFITI_COMMENT_CREATOR_BP = 7000
    GRAFFITI_COMMENT_STORAGE_BP = 2000
    GRAFFITI_MIN_BILLABLE_SIZE = 1024
    GRAFFITI_UPLOAD_FEE_PER_CHUNK = 100


@pytest.fixture(autouse=True)
def mock_cfg(monkeypatch):
    monkeypatch.setattr("tsarchain.contracts.graffiti.CFG", MockCFG)
    monkeypatch.setattr("tsarchain.contracts.graffiti._MIME_ALLOWED", tuple(m.lower() for m in MockCFG.GRAFFITI_ALLOWED_MIME))
    monkeypatch.setattr("tsarchain.contracts.graffiti._EXT_ALLOWED", tuple(e.lower() for e in MockCFG.GRAFFITI_ALLOWED_EXT))
    import re
    monkeypatch.setattr("tsarchain.contracts.graffiti.ART_ID_RE", re.compile(rf"^({MockCFG.ART_ID_PREFIX}[0-9a-f]{{{MockCFG.ART_ID_BODY_LEN}}}|[0-9a-f]{{64}})$"))

def test_is_valid_sha256_hex():
    assert _is_valid_sha256_hex("a" * 64)
    assert not _is_valid_sha256_hex("a" * 63)
    assert not _is_valid_sha256_hex("z" * 64)
    assert not _is_valid_sha256_hex("")

def test_is_valid_mime():
    assert _is_valid_mime("image/png")
    assert _is_valid_mime("text/plain")
    assert not _is_valid_mime("image/png" * 10)  # > 64 chars
    assert not _is_valid_mime("")
    assert not _is_valid_mime(123)

def test_is_valid_tsar_address():
    assert _is_valid_tsar_address(VALID_TSAR_ADDR)
    assert not _is_valid_tsar_address("invalid_address")
    assert not _is_valid_tsar_address(bech32_encode("nottsar", [0] + list(convertbits(bytes.fromhex("b" * 40), 8, 5, True))))

def test_is_valid_art_id():
    assert _is_valid_art_id("art1" + "a" * 60)
    assert _is_valid_art_id("a" * 64)
    assert not _is_valid_art_id("art1" + "a" * 59)
    assert not _is_valid_art_id(123)

def test_strip_art_prefix():
    assert _strip_art_prefix("art1" + "a" * 60) == "a" * 60
    assert _strip_art_prefix("a" * 64) == "a" * 64

def test_decorate_art_id():
    assert _decorate_art_id("a" * 64) == "art1" + "a" * 60
    with pytest.raises(ValueError):
        _decorate_art_id("a" * 63)

def test_normalize_art_id():
    assert _normalize_art_id("art1" + "a" * 60) == "art1" + "a" * 60
    assert _normalize_art_id("a" * 64, prefer_prefix=True) == "art1" + "a" * 60
    assert _normalize_art_id("a" * 64, prefer_prefix=False) == "a" * 64
    with pytest.raises(ValueError):
        _normalize_art_id("invalid")
    with pytest.raises(ValueError):
        _normalize_art_id(123)

def test_validate_graffiti_file():
    assert validate_graffiti_file(100, mime="image/png") == "image/png"
    assert validate_graffiti_file(100, filename="test.png") == "image/png"
    with pytest.raises(ValueError, match="bad_size_bytes"):
        validate_graffiti_file(0, mime="image/png")
    with pytest.raises(ValueError, match="bad_size_bytes"):
        validate_graffiti_file(-1, mime="image/png")
    with pytest.raises(ValueError, match="bad_size_bytes"):
        validate_graffiti_file("invalid", mime="image/png")
    with pytest.raises(ValueError, match="graffiti_too_large"):
        validate_graffiti_file(MockCFG.GRAFFITI_MAX_SIZE_BYTES + 1, mime="image/png")
    with pytest.raises(ValueError, match="mime_not_allowed"):
        validate_graffiti_file(100, mime="text/plain")

def test_encode_comment():
    assert _encode_comment("hello") == b"hello".hex()
    with pytest.raises(ValueError, match="comment_text must be str"):
        _encode_comment(123)
    with pytest.raises(ValueError, match="empty_comment"):
        _encode_comment("")
    with pytest.raises(ValueError, match="comment_too_large"):
        _encode_comment("a" * (MockCFG.GRAFFITI_COMMENT_MAX_BYTES + 1))

def test_compact_json():
    assert _compact_json({"a": 1, "b": "c"}) == b'{"a":1,"b":"c"}'

def test_guard_payload_size():
    _guard_payload_size(b"a" * 10)
    with pytest.raises(ValueError, match="graffiti_opreturn_too_large"):
        _guard_payload_size(b"a" * (MockCFG.MAX_GRAFFITI_OPRET + 1))

def test_pool_redeem_script():
    script = _pool_redeem_script(VALID_ART_ID)
    assert script[-1] == 0x87  # OP_EQUAL
    assert len(script) > 1

def test_compute_proof_epoch():
    assert compute_proof_epoch(0) == 0
    assert compute_proof_epoch(MockCFG.GRAFFITI_PROOF_EPOCH_BLOCKS) == 1
    assert compute_proof_epoch(MockCFG.GRAFFITI_PROOF_EPOCH_BLOCKS - 1) == 0

def test_calc_proof_challenge():
    challenge = calc_proof_challenge(VALID_ART_ID, 2048, 1500)
    assert challenge["epoch"] == 1
    assert "offset" in challenge
    assert "length" in challenge
    assert "seed" in challenge
    
    with pytest.raises(ValueError, match="bad_size_bytes"):
        calc_proof_challenge(VALID_ART_ID, 0, 1500)

def test_hash_proof_chunk():
    chunk = b"testdata"
    assert hash_proof_chunk(chunk) == hashlib.sha256(chunk).hexdigest()
    with pytest.raises(ValueError, match="chunk_must_be_bytes"):
        hash_proof_chunk("string")
    with pytest.raises(ValueError, match="empty_chunk"):
        hash_proof_chunk(b"")

def test_derive_pool_address_p2wpkh():
    addr = derive_pool_address_p2wpkh(VALID_ART_ID)
    assert addr.startswith(MockCFG.ADDRESS_PREFIX)

def test_derive_pool_address_p2wsh():
    addr = derive_pool_address_p2wsh(VALID_ART_ID)
    assert addr.startswith(MockCFG.ADDRESS_PREFIX)

def test_hash_pool_redeem_script():
    h = hash_pool_redeem_script(VALID_ART_ID)
    assert len(h) == 64

def test_pool_spk_bytes():
    spk = _pool_spk_bytes(VALID_ART_ID)
    assert spk.startswith(b"\x00\x20")

class MockUTXODB:
    def __init__(self, utxos=None):
        self.utxos = utxos or {}

    def get(self, key):
        # mock index based get
        return None
        
    def _load(self):
        pass

def test_find_pool_utxos():
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    tx1 = "a" * 64
    tx2 = "b" * 64
    tx3 = "c" * 64
    db = MockUTXODB({
        f"{tx1}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 1000}},
        f"{tx2}:1": {"tx_out": {"script_pubkey": "other", "amount": 2000}},
        f"{tx3}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 500}},
    })
    utxos = find_pool_utxos(db, VALID_ART_ID)
    assert len(utxos) == 2
    # Should be sorted by amount
    assert utxos[0]["amount"] == 500
    assert utxos[1]["amount"] == 1000

def test_build_payout_tx():
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    tx1 = "a" * 64
    db = MockUTXODB({
        f"{tx1}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 5000}},
    })
    recipients = [{"addr": VALID_TSAR_ADDR, "amount": 4000}]
    
    tx = build_payout_tx(db, VALID_ART_ID, recipients)
    assert isinstance(tx, Tx)
    assert len(tx.inputs) == 1
    # output to recipient + output to op_return + (maybe change if dust limit allows)
    # 5000 in, 4000 out -> 1000 remainder - fee.
    # We just ensure it built successfully.
    
    # Test insufficient pool
    recipients_large = [{"addr": VALID_TSAR_ADDR, "amount": 10000}]
    with pytest.raises(ValueError, match="insufficient_pool"):
        build_payout_tx(db, VALID_ART_ID, recipients_large)

def test_build_metadata():
    meta = build_metadata(VALID_SHA256, 100, "image/png", VALID_STORER_ADDR, "receipt123", VALID_CREATOR_ADDR)
    assert meta["sha256"] == VALID_SHA256
    assert meta["size"] == 100
    assert meta["mime"] == "image/png"
    assert meta["storer"] == VALID_STORER_ADDR
    assert meta["receipt"] == "receipt123"
    assert meta["creator"] == VALID_CREATOR_ADDR
    assert meta["event"] == "POST"
    assert "ts" in meta
    assert "art_id" in meta

    with pytest.raises(ValueError):
        build_metadata("invalid", 100, "image/png", VALID_STORER_ADDR, "receipt123", VALID_CREATOR_ADDR)

def test_build_comment_metadata():
    meta = build_comment_metadata(VALID_ART_ID, "nice!", 1000, VALID_CREATOR_ADDR, tip_sats=50)
    assert meta["event"] == "COMMENT"
    assert meta["amount"] == 1000
    assert meta["tip"] == 50
    assert meta["creator"] == VALID_CREATOR_ADDR
    
    with pytest.raises(ValueError, match="comment_fee_too_low"):
        build_comment_metadata(VALID_ART_ID, "nice!", 10, VALID_CREATOR_ADDR)

def test_build_payout_metadata():
    recipients = [{"addr": VALID_TSAR_ADDR, "amount": 1000}]
    meta = build_payout_metadata(VALID_ART_ID, 1, recipients)
    assert meta["event"] == "PAYOUT"
    assert meta["epoch"] == 1
    assert len(meta["recipients"]) == 1

def test_calc_comment_split():
    split = calc_comment_split(10000, tip=1000)
    assert split["creator_base"] == 7000
    assert split["storage"] == 2000
    assert split["miner"] == 1000
    assert split["tip"] == 1000
    assert split["creator_total"] == 8000

def test_encode_payload_and_build_script():
    meta = {"event": "POST"}
    payload = encode_payload(meta)
    assert payload.startswith(MockCFG.GRAFFITI_MAGIC)
    
    script = build_script(meta)
    assert script.serialize()[0] == OP_RETURN

def test_parse_payload():
    meta = build_metadata(VALID_SHA256, 100, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR)
    payload = encode_payload(meta)
    parsed = parse_payload(payload)
    assert parsed is not None
    assert parsed["event"] == "POST"
    assert parsed["sha256"] == VALID_SHA256

    comment_meta = build_comment_metadata(VALID_ART_ID, "nice", 1000, VALID_CREATOR_ADDR)
    comment_payload = encode_payload(comment_meta)
    parsed_comment = parse_payload(comment_payload)
    assert parsed_comment is not None
    assert parsed_comment["event"] == "COMMENT"

    payout_meta = build_payout_metadata(VALID_ART_ID, 1, [{"addr": VALID_TSAR_ADDR, "amount": 1000}])
    payout_payload = encode_payload(payout_meta)
    parsed_payout = parse_payload(payout_payload)
    assert parsed_payout is not None
    assert parsed_payout["event"] == "PAYOUT"

def test_parse_from_script():
    meta = build_metadata(VALID_SHA256, 100, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR)
    script = build_script(meta)
    parsed = parse_from_script(script)
    assert parsed is not None
    assert parsed["event"] == "POST"

def test_compute_art_id():
    art_id = compute_art_id(VALID_SHA256, VALID_CREATOR_ADDR)
    assert art_id.startswith(MockCFG.ART_ID_PREFIX)
    assert len(art_id) == MockCFG.ART_ID_PREFIX_LEN + MockCFG.ART_ID_BODY_LEN
    
    art_id_raw = compute_art_id(VALID_SHA256, VALID_CREATOR_ADDR, decorate=False)
    assert len(art_id_raw) == 64

def test_derive_pool_address():
    addr = derive_pool_address(VALID_ART_ID)
    assert addr == derive_pool_address_p2wsh(VALID_ART_ID)

def test_calc_upload_fee_sats():
    fee = calc_upload_fee_sats(500)
    assert fee == MockCFG.GRAFFITI_UPLOAD_FEE_PER_CHUNK
    
    fee2 = calc_upload_fee_sats(1500)
    assert fee2 == 2 * MockCFG.GRAFFITI_UPLOAD_FEE_PER_CHUNK

# Test merkle functions using mocking since they rely on native core
@patch('tsarchain.contracts.graffiti._native_graff_merkle_root_for_file')
def test_merkle_root_for_file(mock_native):
    mock_native.return_value = (bytes.fromhex(VALID_SHA256), 10)
    root, count = graffiti.merkle_root_for_file("test.txt", 1024)
    assert root == VALID_SHA256
    assert count == 10

@patch('tsarchain.contracts.graffiti._native_graff_merkle_path_for_bytes')
def test_merkle_path_for_bytes(mock_native):
    mock_native.return_value = [{"hash": VALID_SHA256, "pos": "L"}]
    path = graffiti.merkle_path_for_bytes(b"data", 1024, 0)
    assert len(path) == 1

@patch('tsarchain.contracts.graffiti._native_graff_merkle_path_for_file')
def test_merkle_path_for_file(mock_native):
    mock_native.return_value = [{"hash": VALID_SHA256, "pos": "L"}]
    path = graffiti.merkle_path_for_file("test.txt", 1024, 0)
    assert len(path) == 1

@patch('tsarchain.contracts.graffiti._native_graff_merkle_verify')
def test_verify_merkle_path(mock_native):
    mock_native.return_value = True
    assert graffiti.verify_merkle_path(VALID_SHA256, VALID_SHA256, [])

def test_normalize_art_id_invalid_body():
    with pytest.raises(ValueError):
        _normalize_art_id(MockCFG.ART_ID_PREFIX + "z" * 60)

@patch("mimetypes.guess_type")
def test_validate_graffiti_file_ext(mock_guess):
    mock_guess.return_value = (None, None)
    assert validate_graffiti_file(100, filename="test.jpg") == "image"
    assert validate_graffiti_file(100, filename="test.mp4") == "video"
    with pytest.raises(ValueError):
        validate_graffiti_file(100, filename="test.unsupported")
    with pytest.raises(ValueError):
        validate_graffiti_file(100, mime="") # no filename, no mime

@patch("tsarchain.contracts.graffiti._normalize_art_id")
def test_pool_redeem_script_long(mock_norm):
    mock_norm.return_value = "a" * 160
    assert len(_pool_redeem_script("anything")) > 0 # Hits the length > 75 branch

def test_calc_proof_challenge_fallback():
    assert calc_proof_challenge(VALID_ART_ID, 100, 1500, chunk_bytes=200)["length"] == 100

def test_find_pool_utxos_fallback():
    # test fallback when bucket is not dict
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    db = MockUTXODB({
        f"tx5:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 999}},
    })
    # If get returns None, it falls back
    utxos = find_pool_utxos(db, VALID_ART_ID)
    assert len(utxos) == 1
    assert utxos[0]["amount"] == 999
    
def test_build_payout_tx_max_claim():
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    tx1 = "a" * 64
    db = MockUTXODB({
        f"{tx1}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 5000}},
    })
    recipients = [{"addr": VALID_TSAR_ADDR, "amount": 5000}]
    tx = build_payout_tx(db, VALID_ART_ID, recipients)
    assert len(tx.outputs) > 0 # successfully computed max claim minus fee

def test_build_payout_tx_dict_recipients():
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    tx1 = "a" * 64
    db = MockUTXODB({
        f"{tx1}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 5000}},
    })
    recipients = {VALID_TSAR_ADDR: 4000}
    tx = build_payout_tx(db, VALID_ART_ID, recipients)
    assert len(tx.outputs) > 0

def test_build_payout_tx_no_pool_utxos():
    db = MockUTXODB({})
    with pytest.raises(ValueError, match="no_pool_utxo"):
        build_payout_tx(db, VALID_ART_ID, [{"addr": VALID_TSAR_ADDR, "amount": 4000}])

def test_build_payout_tx_bad_recipients():
    db = MockUTXODB({})
    with pytest.raises(ValueError):
        build_payout_tx(db, VALID_ART_ID, [])
    with pytest.raises(ValueError):
        build_payout_tx(db, VALID_ART_ID, [{"addr": "invalid", "amount": 4000}])
    with pytest.raises(ValueError):
        build_payout_tx(db, VALID_ART_ID, [{"addr": VALID_TSAR_ADDR, "amount": -1}])

def test_build_metadata_merkle_and_extra():
    meta = build_metadata(VALID_SHA256, 1024, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR,
                          merkle_root=VALID_SHA256, merkle_chunk_bytes=512, merkle_chunks=2,
                          extra={"test_key": "test_val", "sha256": "ignored", "long": "a"*150})
    assert meta["mroot"] == VALID_SHA256
    assert meta["mchunk"] == 512
    assert meta["mcount"] == 2
    assert meta["test_key"] == "test_val"
    assert "long" not in meta

def test_build_metadata_bad_merkle():
    with pytest.raises(ValueError):
         build_metadata(VALID_SHA256, 1024, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR,
                        merkle_root="invalid")
    with pytest.raises(ValueError):
         build_metadata(VALID_SHA256, 1024, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR,
                        merkle_root=VALID_SHA256, merkle_chunk_bytes=0, merkle_chunks=2)
    with pytest.raises(ValueError):
         build_metadata(VALID_SHA256, 1024, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR,
                        merkle_root=VALID_SHA256, merkle_chunk_bytes=512, merkle_chunks=1) # count mismatch

def test_build_comment_metadata_extra_and_bad_params():
    with pytest.raises(ValueError):
        build_comment_metadata(VALID_ART_ID, "nice", 1000, "invalid")
    with pytest.raises(ValueError):
        build_comment_metadata(VALID_ART_ID, "nice", 1000, VALID_CREATOR_ADDR, commenter_addr="invalid")
    with pytest.raises(ValueError):
        build_comment_metadata(VALID_ART_ID, "nice", 1000, VALID_CREATOR_ADDR, tip_sats=-1)
    meta = build_comment_metadata(VALID_ART_ID, "nice", 1000, VALID_CREATOR_ADDR, extra={"foo": "bar", "long": "a"*150})
    assert meta["foo"] == "bar"
    assert "long" not in meta

def test_build_payout_metadata_bad_params():
    with pytest.raises(ValueError):
        build_payout_metadata(VALID_ART_ID, -1, [{"addr": VALID_TSAR_ADDR, "amount": 1000}])
    with pytest.raises(ValueError):
        build_payout_metadata(VALID_ART_ID, 1, [])
    with pytest.raises(ValueError):
        build_payout_metadata(VALID_ART_ID, 1, [{"invalid": 1000}])
    with pytest.raises(ValueError):
        build_payout_metadata(VALID_ART_ID, 1, [{"addr": "invalid", "amount": 1000}])
        
def test_build_payout_metadata_proof_and_extra():
    meta = build_payout_metadata(VALID_ART_ID, 1, {VALID_TSAR_ADDR: 1000},
                                 proof={"offset": 0, "length": 100, "hash": VALID_SHA256, "storer": VALID_STORER_ADDR, "ignored": "ignored"},
                                 extra={"foo": "bar", "long": "a"*150})
    assert meta["foo"] == "bar"
    assert "long" not in meta
    assert meta["proof_offset"] == 0
    assert meta["proof_hash"] == VALID_SHA256
    assert "proof_ignored" not in meta

def test_calc_comment_split_negative():
    with pytest.raises(ValueError):
        calc_comment_split(-1)

def test_encode_payload_bad():
    with pytest.raises(ValueError):
        encode_payload(123)

def test_parse_payload_more_branches():
    assert parse_payload(b"invalid_magic") is None
    assert parse_payload(MockCFG.GRAFFITI_MAGIC) is None
    assert parse_payload(MockCFG.GRAFFITI_MAGIC + b"not_json") is None
    assert parse_payload(MockCFG.GRAFFITI_MAGIC + b'"string"') is None
    
    # event POST invalid cases
    assert parse_payload(encode_payload({"event": "POST", "sha256": "invalid"})) is None
    assert parse_payload(encode_payload({"event": "POST", "sha256": VALID_SHA256, "size": -1})) is None
    assert parse_payload(encode_payload({"event": "POST", "sha256": VALID_SHA256, "size": 100, "mime": "invalid"})) is None
    assert parse_payload(encode_payload({"event": "POST", "sha256": VALID_SHA256, "size": 100, "mime": "image/png", "storer": "invalid"})) is None
    assert parse_payload(encode_payload({"event": "POST", "sha256": VALID_SHA256, "size": 100, "mime": "image/png", "storer": VALID_STORER_ADDR, "receipt": ""})) is None
    assert parse_payload(encode_payload({"event": "POST", "sha256": VALID_SHA256, "size": 100, "mime": "image/png", "storer": VALID_STORER_ADDR, "receipt": "r1", "creator": "invalid"})) is None
    
    # creator provided -> base_hash
    meta = {"event": "POST", "sha256": VALID_SHA256, "size": 100, "mime": "image/png", "storer": VALID_STORER_ADDR, "receipt": "r1", "creator": VALID_CREATOR_ADDR}
    assert parse_payload(encode_payload(meta))["art_id"].startswith("art1")
    
    # test mroot provided but missing others
    meta["mroot"] = VALID_SHA256
    assert parse_payload(encode_payload(meta)) is None
    
    # COMMENT invalid cases
    assert parse_payload(encode_payload({"event": "COMMENT", "comment": b"a".hex()})) is None # wait, parse_payload parses the hex string, I'll pass hex
    assert parse_payload(encode_payload({"event": "COMMENT", "comment": ""})) is None
    assert parse_payload(encode_payload({"event": "COMMENT", "comment": ("a" * (MockCFG.GRAFFITI_COMMENT_MAX_BYTES * 2 + 2))})) is None
    assert parse_payload(encode_payload({"event": "COMMENT", "comment": "aa", "amount": 10})) is None # < min_fee
    assert parse_payload(encode_payload({"event": "COMMENT", "comment": "aa", "amount": 1000, "tip": -1})) is None
    assert parse_payload(encode_payload({"event": "COMMENT", "comment": "aa", "amount": 1000, "tip": 0, "creator": "invalid"})) is None
    assert parse_payload(encode_payload({"event": "COMMENT", "comment": "aa", "amount": 1000, "tip": 0, "creator": VALID_CREATOR_ADDR, "commenter": "invalid"})) is None
    
    # PAYOUT invalid cases
    assert parse_payload(encode_payload({"event": "PAYOUT", "epoch": -1})) is None
    assert parse_payload(encode_payload({"event": "PAYOUT", "epoch": 1, "recipients": []})) is None
    assert parse_payload(encode_payload({"event": "PAYOUT", "epoch": 1, "recipients": ["invalid"]})) is None
    assert parse_payload(encode_payload({"event": "PAYOUT", "epoch": 1, "recipients": [{"addr": "invalid", "amount": 1000}]})) is None
    
    # unknown event
    assert parse_payload(encode_payload({"event": "UNKNOWN"})) is None

def test_parse_from_script_branches():
    assert parse_from_script(Script([])) is None
    # Empty OP_RETURN
    assert parse_from_script(Script([OP_RETURN])) is None
    
    meta_small = {"event": "UNKNOWN"}
    payload_small = encode_payload(meta_small)
    data_small = bytes([OP_RETURN, len(payload_small)]) + payload_small
    assert parse_from_script(Script.deserialize(data_small)) is None
    
    # OP_PUSHDATA1
    data1 = b"\x6a\x4c" + bytes([len(payload_small)]) + payload_small
    assert parse_from_script(Script.deserialize(data1)) is None
    
    meta_large = build_metadata(VALID_SHA256, 100, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR, extra={"long": "a"*200})
    payload_large = encode_payload(meta_large)
    data2 = b"\x6a\x4d" + len(payload_large).to_bytes(2, 'little') + payload_large
    assert parse_from_script(Script.deserialize(data2)) is not None
    
    data3 = b"\x6a\x4e\x00\x00\x00\x00" # OP_PUSHDATA4 -> not supported directly in the logic, returns None
    assert parse_from_script(Script.deserialize(data3)) is None

def test_compute_art_id_branches():
    with pytest.raises(ValueError):
        compute_art_id("invalid", VALID_CREATOR_ADDR)
    with pytest.raises(ValueError):
        compute_art_id(VALID_SHA256, "invalid")
        
    # with block hash
    art_id_b = compute_art_id(VALID_SHA256, VALID_CREATOR_ADDR, block_hash=VALID_SHA256)
    art_id_nb = compute_art_id(VALID_SHA256, VALID_CREATOR_ADDR)
    assert art_id_b != art_id_nb

def test_build_payout_tx_insufficient_max_claim():
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    tx1 = "a" * 64
    db = MockUTXODB({
        f"{tx1}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 10}}, # Too small to pay fee
    })
    recipients = [{"addr": VALID_TSAR_ADDR, "amount": 10}]
    with pytest.raises(ValueError, match="insufficient_pool"):
        build_payout_tx(db, VALID_ART_ID, recipients)

def test_build_payout_tx_change():
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    tx1 = "a" * 64
    tx2 = "b" * 64
    db = MockUTXODB({
        f"{tx1}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 6000}},
        f"{tx2}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 200}},
    })
    recipients = [{"addr": VALID_TSAR_ADDR, "amount": 4500}]
    tx = build_payout_tx(db, VALID_ART_ID, recipients) # fee should leave change >= dust
    assert len(tx.outputs) > 2 # output, op_return, change

def test_build_payout_tx_no_change():
    spk_hex = _pool_spk_bytes(VALID_ART_ID).hex()
    tx1 = "a" * 64
    db = MockUTXODB({
        f"{tx1}:0": {"tx_out": {"script_pubkey": spk_hex, "amount": 5000}},
    })
    recipients = [{"addr": VALID_TSAR_ADDR, "amount": 4500}]
    tx = build_payout_tx(db, VALID_ART_ID, recipients) # fee leaves change < dust, so no change
    assert len(tx.outputs) == 2 # output, op_return

def test_parse_payload_merkle():
    meta = build_metadata(VALID_SHA256, 1024, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR,
                          merkle_root=VALID_SHA256, merkle_chunk_bytes=512, merkle_chunks=2)
    payload = encode_payload(meta)
    assert parse_payload(payload)["mroot"] == VALID_SHA256
    
    meta_bad_mroot = build_metadata(VALID_SHA256, 1024, "image/png", VALID_STORER_ADDR, "r1", VALID_CREATOR_ADDR,
                          merkle_root=VALID_SHA256, merkle_chunk_bytes=512, merkle_chunks=2)
    meta_bad_mroot["mroot"] = "invalid"
    assert parse_payload(encode_payload(meta_bad_mroot)) is None
    
    meta_bad_mchunk = meta.copy()
    meta_bad_mchunk["mchunk"] = "invalid"
    assert parse_payload(encode_payload(meta_bad_mchunk)) is None
    
    meta_bad_mcount = meta.copy()
    meta_bad_mcount["mcount"] = -1
    assert parse_payload(encode_payload(meta_bad_mcount)) is None
    
    meta_mismatch = meta.copy()
    meta_mismatch["mcount"] = 5
    assert parse_payload(encode_payload(meta_mismatch)) is None
