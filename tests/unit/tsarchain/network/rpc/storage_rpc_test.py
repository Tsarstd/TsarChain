# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import pytest
import base64
from unittest.mock import MagicMock, patch

from tsarchain.network.rpc.storage_rpc import handle_storage_rpc


@pytest.fixture(autouse=True)
def mock_config():
    with patch("tsarchain.network.rpc.storage_rpc.CFG") as mock_cfg:
        mock_cfg.ADDRESS_PREFIX = "ts"
        mock_cfg.STORAGE_RPC_RL_IP_BURST = 10
        mock_cfg.STORAGE_RPC_RL_WINDOW_S = 60
        mock_cfg.STORAGE_RPC_RL_BACKOFF_S = 10
        mock_cfg.DEBUG_BENCHMARKS = False
        mock_cfg.REPLAY_WINDOW_SEC = 60
        mock_cfg.GRAFFITI_PROOF_EPOCH_DRIFT = 2
        mock_cfg.DEFAULT_FEE_RATE_SATVB = 1
        mock_cfg.ARCHIVIST_AUTO_PAYOUT_COOLDOWN_SEC = 10
        mock_cfg.ENABLE_DANDELION_PP = False
        yield mock_cfg

@pytest.fixture(autouse=True)
def mock_graffiti():
    with patch("tsarchain.network.rpc.storage_rpc.GRAFFITI") as mock_graf:
        mock_graf._is_valid_tsar_address.return_value = True
        mock_graf._normalize_art_id.side_effect = lambda x, prefer_prefix: x
        mock_graf._is_valid_sha256_hex.return_value = True
        mock_graf.compute_proof_epoch.return_value = 10
        mock_graf.calc_proof_challenge.return_value = {"offset": 0, "length": 1024, "seed": "seed"}
        mock_graf.hash_proof_chunk.return_value = "chunk_hash"
        mock_graf.verify_merkle_path.return_value = True
        
        tx_mock = MagicMock()
        tx_mock.outputs = []
        tx_mock.to_dict.return_value = {"txid": "test"}
        mock_graf.build_payout_tx.return_value = tx_mock
        
        yield mock_graf

@pytest.fixture
def network():
    net = MagicMock()
    net.rl_ip = {}
    net._tb_allow.return_value = True
    net._nonce_guard.return_value = True
    
    net.broadcast.blockchain.height = 1000
    
    reg_mock = MagicMock()
    reg_mock.get_post.return_value = {"size": 2048, "mroot": "0"*64, "mchunk": 1024, "mcount": 2}
    reg_mock.get_proof.return_value = None
    reg_mock.get_latest_proof.return_value = {"offset": 0, "length": 1024, "hash": "h", "seed": "s", "height": 10, "epoch": 10, "storer": "storer_addr"}
    
    net.broadcast.utxodb._graffiti_registry = reg_mock
    net.storage_peers = {
        ("127.0.0.1", 1234): {"node_id": "nid1", "pubkey": "pk1", "addr": "storer_addr"},
        ("127.0.0.1", 0): {"node_id": "nid2", "addr": "storer_addr2"},
        ("127.0.0.2", 1234): {"node_id": "nid3", "addr": "storer_addr3"}
    }
    
    class DummyLock:
        def __enter__(self): pass
        def __exit__(self, *args): pass
    net.lock = DummyLock()
    
    return net

def test_rate_limit(network):
    network._tb_allow.return_value = False
    res = handle_storage_rpc(network, {}, ("127.0.0.1", 1234), "ANY")
    assert res == {"error": "rate_limited"}

def test_unknown_mtype(network):
    res = handle_storage_rpc(network, {}, ("127.0.0.1", 1234), "UNKNOWN", src_node_id="nid1", src_pubkey="pk1")
    assert res is None

def test_auth_no_src_node_id(network):
    res = handle_storage_rpc(network, {}, ("127.0.0.1", 1234), "ANY")
    assert res == {"error": "forbidden: storage-only endpoint"}

def test_auth_mismatch(network):
    # node_id mismatch
    res = handle_storage_rpc(network, {}, ("127.0.0.1", 1234), "ANY", src_node_id="nid_unkn", src_pubkey="pk1")
    assert res == {"error": "forbidden: storage-only endpoint"}
    
    # pubkey mismatch logs warning and continues loop (eventually returning forbidden if no match)
    res2 = handle_storage_rpc(network, {}, ("127.0.0.1", 1234), "ANY", src_node_id="nid1", src_pubkey="pk2")
    assert res2 == {"error": "forbidden: storage-only endpoint"}

    # pubkey missing but required by meta
    res3 = handle_storage_rpc(network, {}, ("127.0.0.1", 1234), "ANY", src_node_id="nid1")
    assert res3 == {"error": "forbidden: storage-only endpoint"}

def test_auth_invalid_storer(network, mock_graffiti):
    mock_graffiti._is_valid_tsar_address.return_value = False
    res = handle_storage_rpc(network, {"port": 1234}, ("127.0.0.1", 1234), "ANY", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "storer_unregistered"}

def test_proof_submit_basic(network, mock_config):
    msg = {
        "port": 1234, "ts": 123, "nonce": "abc",
        "art_id": "art1", "epoch": 10, "offset": 0, "length": 1024,
        "hash": "chunk_hash", "storer": "storer_addr", "height": 1000, "seed": "seed",
        "chunk": base64.b64encode(b"A"*1024).decode("ascii"),
        "path": []
    }
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"status": "ok", "art_id": "art1", "epoch": 10}
    
    # Benchmarks
    mock_config.DEBUG_BENCHMARKS = True
    with patch("tsarchain.network.rpc.storage_rpc.time.perf_counter", side_effect=[1.0, 20.0]):
        res_bench = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
        assert res_bench == {"status": "ok", "art_id": "art1", "epoch": 10}
    mock_config.DEBUG_BENCHMARKS = False
        
    # Replay guard fail
    network._nonce_guard.return_value = False
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "replay_guard"}
    network._nonce_guard.return_value = True

def test_proof_submit_bad_fields(network, mock_graffiti):
    msg_base = {"port": 1234, "ts": 123, "nonce": "abc", "storer": "storer_addr"}
    
    # missing fields or bad values
    msg = {**msg_base, "epoch": -1}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "bad_fields"}
    
    mock_graffiti._is_valid_sha256_hex.return_value = False
    msg = {**msg_base, "epoch": 10, "offset": 0, "length": 100, "hash": "h"}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "bad_fields"}
    mock_graffiti._is_valid_sha256_hex.return_value = True

def test_proof_submit_storer_checks(network):
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "epoch": 10, "offset": 0, "length": 100, "hash": "h"}
    # missing storer
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "missing_storer"}
    # storer mismatch
    msg["storer"] = "other_storer"
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "storer_mismatch"}

def test_proof_submit_registry_checks(network):
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "epoch": 10, "offset": 0, "length": 1024, "hash": "h", "storer": "storer_addr"}
    # no registry
    network.broadcast.utxodb._graffiti_registry = None
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "registry_unavailable"}
    
    # unknown art_id
    reg = MagicMock()
    reg.get_post.return_value = None
    network.broadcast.utxodb._graffiti_registry = reg
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "unknown_art_id"}
    
    # out of range size
    reg.get_post.return_value = {"size": 500}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "out_of_range", "size": 500}

def test_proof_submit_merkle_meta(network, mock_graffiti):
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "epoch": 10, "offset": 0, "length": 1024, "hash": "h", "storer": "storer_addr"}
    reg = network.broadcast.utxodb._graffiti_registry
    
    # incomplete
    reg.get_post.return_value = {"size": 2048, "mroot": "r"}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_meta_incomplete"}
    
    # invalid types
    reg.get_post.return_value = {"size": 2048, "mroot": "r", "mchunk": "x", "mcount": 2}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_meta_invalid"}
    
    # zero chunk
    reg.get_post.return_value = {"size": 2048, "mroot": "r", "mchunk": "0", "mcount": "2"}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_meta_invalid"}

    # invalid mroot hash
    mock_graffiti._is_valid_sha256_hex.side_effect = lambda x: False if x == "invalid_hash" else True
    reg.get_post.return_value = {"size": 2048, "mroot": "invalid_hash", "mchunk": 1024, "mcount": 2}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_root_invalid"}
    mock_graffiti._is_valid_sha256_hex.side_effect = None
    mock_graffiti._is_valid_sha256_hex.return_value = True

def test_proof_submit_epoch_challenge(network, mock_graffiti):
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "epoch": 10, "offset": 0, "length": 1024, "hash": "h", "storer": "storer_addr", "height": -1}
    # epoch mismatch with height
    mock_graffiti.compute_proof_epoch.return_value = 11
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "epoch_mismatch"}
    
    # epoch out of range (window is tip_epoch +- drift)
    mock_graffiti.compute_proof_epoch.side_effect = lambda h: 100 if h == 1000 else 10
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "epoch_out_of_range", "tip_epoch": 100}
    mock_graffiti.compute_proof_epoch.side_effect = None
    mock_graffiti.compute_proof_epoch.return_value = 10

    # challenge mismatch
    mock_graffiti.calc_proof_challenge.return_value = {"offset": 1024, "length": 1024, "seed": "seed"}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "challenge_mismatch"}
    mock_graffiti.calc_proof_challenge.return_value = {"offset": 0, "length": 1024, "seed": "seed"}

    # seed mismatch
    msg["seed"] = "bad_seed"
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "seed_mismatch"}
    msg["seed"] = "seed"

def test_proof_submit_merkle_verification(network, mock_graffiti):
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "epoch": 10, "offset": 0, "length": 1024, "hash": "chunk_hash", "storer": "storer_addr", "seed": "seed"}
    # chunk missing
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_chunk_required"}
    
    # path missing
    msg["chunk"] = base64.b64encode(b"A"*1024).decode("ascii")
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_path_required"}
    msg["path"] = []
    
    # bad b64 chunk
    msg["chunk"] = "invalid_b64"
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_chunk_invalid"}
    msg["chunk"] = base64.b64encode(b"A"*1024).decode("ascii")
    
    # chunk len mismatch
    msg["chunk"] = base64.b64encode(b"A"*500).decode("ascii")
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_chunk_length"}
    msg["chunk"] = base64.b64encode(b"A"*1024).decode("ascii")
    
    # hash mismatch
    mock_graffiti.hash_proof_chunk.return_value = "bad_hash"
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_chunk_hash_mismatch"}
    mock_graffiti.hash_proof_chunk.return_value = "chunk_hash"
    
    # offset mismatch
    msg["offset"] = 500
    mock_graffiti.calc_proof_challenge.return_value = {"offset": 500, "length": 1024, "seed": "seed"}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_offset_mismatch"}
    msg["offset"] = 0
    mock_graffiti.calc_proof_challenge.return_value = {"offset": 0, "length": 1024, "seed": "seed"}

    # index out of range
    network.broadcast.utxodb._graffiti_registry.get_post.return_value = {"size": 4096, "mroot": "0"*64, "mchunk": 1024, "mcount": 2}
    msg["offset"] = 2048 # idx = 2, count = 2 -> out of range
    mock_graffiti.calc_proof_challenge.return_value = {"offset": 2048, "length": 1024, "seed": "seed"}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_index_out_of_range"}
    msg["offset"] = 0
    mock_graffiti.calc_proof_challenge.return_value = {"offset": 0, "length": 1024, "seed": "seed"}
    
    # path invalid
    mock_graffiti.verify_merkle_path.return_value = False
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "merkle_path_invalid"}
    mock_graffiti.verify_merkle_path.return_value = True

    # proof conflict
    reg = network.broadcast.utxodb._graffiti_registry
    reg.get_proof.return_value = {"hash": "different_hash"}
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_PROOF_SUBMIT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "proof_conflict"}
    reg.get_proof.return_value = None

def test_payout_basic(network, mock_config, mock_graffiti):
    msg = {
        "port": 1234, "ts": 123, "nonce": "abc",
        "art_id": "art1", "recipients": [{"addr": "storer_addr", "amount": 100}],
        "broadcast": True, "epoch": 10
    }
    mock_tx = MagicMock()
    mock_tx.outputs = [MagicMock(amount=100, script_pubkey=MagicMock())]
    mock_tx.outputs[0].script_pubkey.serialize.return_value = bytes.fromhex("0014" + "0"*40)
    mock_tx.to_dict.return_value = {"txid": "test_txid"}
    mock_graffiti.build_payout_tx.return_value = mock_tx
    network.broadcast.receive_tx.return_value = True
    
    # Enable Dandelion++
    mock_config.ENABLE_DANDELION_PP = True
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"status": "ok", "tx": {"txid": "test_txid"}}
    mock_config.ENABLE_DANDELION_PP = False
    
    # Broadcast failure
    network.broadcast.receive_tx.return_value = False
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "broadcast_failed"}

    # Benchmarks
    mock_config.DEBUG_BENCHMARKS = True
    network.broadcast.receive_tx.return_value = True
    with patch("tsarchain.network.rpc.storage_rpc.time.perf_counter", side_effect=[1.0, 20.0]):
        res_bench = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
        assert res_bench == {"status": "ok", "tx": {"txid": "test_txid"}}
    mock_config.DEBUG_BENCHMARKS = False

def test_payout_bad_recipients(network):
    msg_base = {"port": 1234, "ts": 123, "nonce": "abc", "art_id": "art1"}
    
    # Missing recipients
    res = handle_storage_rpc(network, msg_base, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "bad_recipients"}
    
    # Dict recipients conversion
    res = handle_storage_rpc(network, {**msg_base, "recipients": {"storer_addr": 100}}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res["status"] == "ok"
    
    # single recipient flattened
    res = handle_storage_rpc(network, {**msg_base, "recipient": "storer_addr", "amount": 100}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res["status"] == "ok"
    
    # Multiple recipients
    res = handle_storage_rpc(network, {**msg_base, "recipients": [{"addr": "storer_addr", "amount": 100}, {"addr": "other", "amount": 50}]}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "payout_requires_single_recipient"}
    
    # Bad recipient addr/amount
    res = handle_storage_rpc(network, {**msg_base, "recipients": [{"addr": "", "amount": 100}]}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "bad_recipients"}
    
    # Recipient mismatch
    res = handle_storage_rpc(network, {**msg_base, "recipients": [{"addr": "other_storer", "amount": 100}]}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "payout_recipient_mismatch"}

def test_payout_utxo_proof_checks(network, mock_graffiti):
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "art_id": "art1", "recipients": [{"addr": "storer_addr", "amount": 100}], "epoch": 10}
    
    # no utxo
    network.broadcast.utxodb = None
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "utxo_unavailable"}
    
def test_payout_epoch_logic(network, mock_graffiti):
    network.broadcast.utxodb._graffiti_registry.get_latest_proof.return_value = {"epoch": 9}
    mock_graffiti.compute_proof_epoch.return_value = 10
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "art_id": "art1", "recipients": [{"addr": "storer_addr", "amount": 100}]}
    
    # explicit epoch > tip
    res = handle_storage_rpc(network, {**msg, "epoch": 11}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "epoch_in_future", "tip_epoch": 10}

    # explicit epoch but missing proof
    network.broadcast.utxodb._graffiti_registry.get_latest_proof.return_value = None
    res = handle_storage_rpc(network, {**msg, "epoch": 9}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "missing_proof", "requested_epoch": 9}
    
    # explicit epoch mismatch
    network.broadcast.utxodb._graffiti_registry.get_latest_proof.return_value = {"epoch": 8}
    res = handle_storage_rpc(network, {**msg, "epoch": 9}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "proof_epoch_mismatch", "requested_epoch": 9, "have": 8}
    
    # implicit epoch (epoch=-1) > tip
    network.broadcast.utxodb._graffiti_registry.get_latest_proof.return_value = {"epoch": 11}
    res = handle_storage_rpc(network, {**msg, "epoch": -1}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "epoch_in_future", "tip_epoch": 10}
    
    # implicit epoch missing proof
    network.broadcast.utxodb._graffiti_registry.get_latest_proof.return_value = None
    res = handle_storage_rpc(network, {**msg, "epoch": -1}, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "missing_proof"}

def test_payout_replay_guard(network):
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "art_id": "art1", "recipients": [{"addr": "storer_addr", "amount": 100}]}
    network._nonce_guard.return_value = False
    res = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res == {"error": "replay_guard"}

@patch("tsarchain.network.rpc.storage_rpc.time.time")
def test_payout_cooldown(mock_time, network):
    mock_time.return_value = 1000
    network._payout_guard = None
    msg = {"port": 1234, "ts": 123, "nonce": "abc", "art_id": "art1", "recipients": [{"addr": "storer_addr", "amount": 100}]}
    
    # first call succeeds, sets guard
    res1 = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res1.get("status") == "ok"
    
    # immediate second call fails cooldown
    mock_time.return_value = 1005
    res2 = handle_storage_rpc(network, msg, ("127.0.0.1", 1234), "GRAFFITI_BUILD_PAYOUT", src_node_id="nid1", src_pubkey="pk1")
    assert res2.get("error") == "payout_cooldown"
    assert "retry_after" in res2

def test_resolve_storage_sender_scores(network):
    # Port 0 -> score 1
    # Auth will pass, and unknown mtype will return None
    res = handle_storage_rpc(network, {"port": 1234}, ("127.0.0.1", 0), "ANY", src_node_id="nid2")
    assert res is None
    
    # Port mismatch but both > 0 -> should skip
    res_mismatch = handle_storage_rpc(network, {"port": 1235}, ("127.0.0.1", 1234), "UNKNOWN", src_node_id="nid1", src_pubkey="pk1")
    assert res_mismatch == {"error": "forbidden: storage-only endpoint"}
    
    # mtype UNKNOWN will return None if auth passes
    res2 = handle_storage_rpc(network, {"port": 1234}, ("127.0.0.1", 1234), "UNKNOWN", src_node_id="nid1", src_pubkey="pk1")
    assert res2 is None
    
    # If no peers available (empty dict)
    network.storage_peers = None
    res3 = handle_storage_rpc(network, {"port": 1234}, ("127.0.0.1", 1234), "UNKNOWN", src_node_id="nid1", src_pubkey="pk1")
    assert res3 == {"error": "forbidden: storage-only endpoint"}
    
    # If network has storage_peers but we have wrong ip
    network.storage_peers = {("192.168.1.1", 1234): {"node_id": "nid1", "pubkey": "pk1"}}
    res4 = handle_storage_rpc(network, {"port": 1234}, ("127.0.0.1", 1234), "UNKNOWN", src_node_id="nid1", src_pubkey="pk1")
    assert res4 == {"error": "forbidden: storage-only endpoint"}
