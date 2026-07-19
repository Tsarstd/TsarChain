# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

from unittest.mock import patch

from kremlin.security.chat import chat_common

def test_build_aad_bytes():
    frm = "alice"
    to = "bob"
    mid = 123
    ts = 1000
    from_static_hex = "010203"
    from_pub_hex = "040506"
    
    res = chat_common.build_aad_bytes(frm, to, mid, ts, from_static_hex, from_pub_hex)
    assert b"TSAR-AAD1" in res
    assert b"alice" in res
    assert b"bob" in res
    
    res2 = chat_common.build_aad_bytes(frm, to, mid, ts, from_static_hex, from_pub_hex, 1, 2)
    assert b"1" in res2
    assert b"2" in res2

def test_pack_unpack():
    msg = "hello world"
    packed = chat_common.pack(msg)
    assert len(packed) >= 128
    
    unpacked = chat_common.unpack(packed)
    assert unpacked == msg
    
    assert chat_common.unpack(b"1") == ""

def test_hkdf():
    secret = b"secret"
    info = b"info"
    res = chat_common.hkdf(secret, info, 32)
    assert len(res) == 32

def test_hkdf_rk():
    rk = b"rootkey" * 4
    ss = b"sharedsecret" * 3
    a, b = chat_common.hkdf_rk(rk, ss)
    assert len(a) == 32
    assert len(b) == 32

def test_hkdf_ck():
    ck = b"chainkey" * 4
    a, b = chat_common.hkdf_ck(ck)
    assert len(a) == 32
    assert len(b) == 32

def test_serialize_deserialize_priv():
    from cryptography.hazmat.primitives.asymmetric import x25519
    priv = x25519.X25519PrivateKey.generate()
    hex_str = chat_common.serialize_priv(priv)
    assert len(hex_str) == 64
    
    priv_loaded = chat_common.deserialize_priv(hex_str)
    assert priv.private_bytes_raw() == priv_loaded.private_bytes_raw()

def test_canon():
    assert chat_common.canon(" ALice ") == "alice"
    assert chat_common.canon(None) == ""

@patch("kremlin.security.chat.chat_common.WALL")
def test_chat_dh_gen_keypair(mock_wall):
    sk, pk = chat_common.chat_dh_gen_keypair()
    assert len(sk) == 64
    assert len(pk) == 64

@patch("kremlin.security.chat.chat_common.WALL")
def test_load_or_create_chat_dh_key(mock_wall):
    addr = "alice"
    pwd_provider = lambda p: "password"
    
    mock_wall._secure_load.return_value = ({"sk_hex": "sk", "pk_hex": "pk"}, False)
    sk, pk = chat_common.load_or_create_chat_dh_key(addr, pwd_provider)
    assert sk == "sk"
    assert pk == "pk"
    
    mock_wall._secure_load.return_value = (None, False)
    sk2, pk2 = chat_common.load_or_create_chat_dh_key(addr, pwd_provider)
    assert len(sk2) == 64
    assert len(pk2) == 64

@patch("kremlin.security.chat.chat_common.WALL")
def test_ensure_signed_prekey(mock_wall):
    mock_wall._secure_load.return_value = (None, False)
    mock_wall.load_keystore.return_value = {"wallets": {"alice": {"payload": "payload"}}}
    mock_wall.decrypt_privkey.return_value = "01"*32
    mock_wall.pubkey_from_privhex.return_value = b"pub"
    pwd_provider = lambda p: "pwd"
    
    res = chat_common.ensure_signed_prekey("alice", pwd_provider)
    assert "spk" in res
    assert "spk_sk" in res
    assert "sig" in res

@patch("kremlin.security.chat.chat_common.ensure_signed_prekey")
@patch("kremlin.security.chat.chat_common.WALL")
def test_add_one_time_prekeys(mock_wall, mock_ensure):
    mock_ensure.return_value = {"spk": "spk"}
    pwd_provider = lambda p: "pwd"
    res = chat_common.add_one_time_prekeys("alice", 2, pwd_provider)
    assert len(res["opk_list"]) == 2
    assert len(res["opk_pairs"]) == 2

@patch("kremlin.security.chat.chat_common.WALL")
def test_get_prekey_inventory(mock_wall):
    mock_wall._secure_load.return_value = (None, False)
    res = chat_common.get_prekey_inventory("alice", lambda p: "pwd")
    assert res["opk_queue"] == 0
    assert res["opk_unused_pairs"] == 0

@patch("kremlin.security.chat.chat_common.WALL")
def test_rotate_signed_prekey(mock_wall):
    mock_wall.load_keystore.return_value = {"wallets": {"alice": {"payload": "payload"}}}
    mock_wall.decrypt_privkey.return_value = "01"*32
    mock_wall.pubkey_from_privhex.return_value = b"pub"
    mock_wall._secure_load.return_value = (None, False)
    
    res = chat_common.rotate_signed_prekey("alice", lambda p: "pwd")
    assert "spk" in res
    assert "spk_sk" in res

@patch("kremlin.security.chat.chat_common.load_or_create_chat_dh_key")
@patch("kremlin.security.chat.chat_common.ensure_signed_prekey")
@patch("kremlin.security.chat.chat_common.WALL")
def test_get_prekey_bundle_local(mock_wall, mock_ensure, mock_load):
    mock_load.return_value = ("sk", "ik")
    mock_ensure.return_value = {"spk": "spk", "sig": "sig", "opk_list": ["opk1", "opk2"]}
    
    res = chat_common.get_prekey_bundle_local("alice", lambda p: "pwd")
    assert res["ik"] == "ik"
    assert res["spk"] == "spk"
    assert res["sig"] == "sig"
    assert res["opk"] == "opk1"

@patch("kremlin.security.chat.chat_common.WALL")
def test_get_local_prekeys_for_recv(mock_wall):
    mock_wall._secure_load.return_value = ({"spk_sk": "sk", "spk": "pk", "opk_pairs": [{"pk": "opk"}]}, False)
    res = chat_common.get_local_prekeys_for_recv("alice", lambda p: "pwd")
    assert res["spk"] == "pk"

@patch("kremlin.security.chat.chat_common.WALL")
def test_consume_opk_priv(mock_wall):
    record = {"opk_pairs": [{"pk": "opk1", "sk": "sk1", "used": False}]}
    mock_wall._secure_load.return_value = (record, False)
    
    sk = chat_common.consume_opk_priv("alice", "opk1", lambda p: "pwd")
    assert sk == "sk1"
    assert record["opk_pairs"][0]["used"] == True
    
    sk = chat_common.consume_opk_priv("alice", "opk1", lambda p: "pwd")
    assert sk == None

@patch("kremlin.security.chat.chat_common.WALL")
def test_chat_session(mock_wall):
    mock_wall._secure_load.return_value = ({"test": 1}, False)
    res = chat_common.load_chat_session("alice", "bob", lambda p: "pwd")
    assert res["test"] == 1
    
    chat_common.store_chat_session("alice", "bob", {"test": 2}, lambda p: "pwd")
    mock_wall._secure_store.assert_called_once()
    
    chat_common.delete_chat_session("alice", "bob")
    mock_wall._secure_backend_delete.assert_called_once()
