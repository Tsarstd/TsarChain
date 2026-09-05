# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import pytest
import threading
import collections
from unittest.mock import Mock, patch

from tsarchain.network.rpc_helper.explorer import ExplorerHandler


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------

@pytest.fixture
def mixin():
    """Return an instance of ExplorerHandler with mocked dependencies."""
    m = ExplorerHandler(network=type('Dummy', (), {})())
    m.broadcast = Mock()
    m.broadcast.mempool = Mock()
    m.mempool = m.broadcast.mempool
    # Cache and lock for handle_get_block_hash
    m._block_hash_cache = collections.OrderedDict()
    m._block_hash_cache_lock = threading.RLock()
    # Mock helper methods that are called
    m.build_outpoint_map = Mock(return_value={})
    m.find_tx_and_meta = Mock(return_value=(None, None, None, None, None, None, None, None))
    m.is_coinbase_tx = Mock(return_value=False)
    m.txin_prevkey = Mock(return_value="txid:0")
    patcher = patch('tsarchain.network.rpc_helper.explorer.spkhex_to_address', return_value="address")
    m._spkhex_to_address = patcher.start()
    m.txout_to_address = Mock(return_value="address")
    yield m
    patcher.stop()


# ----------------------------------------------------------------------
# Tests for bhash_hex
# ----------------------------------------------------------------------

def test_bhash_hex_bytes(mixin):
    block = Mock()
    block.hash = b'abcdef123456'
    assert mixin.bhash_hex(block) == b'abcdef123456'.hex()


def test_bhash_hex_bytearray(mixin):
    block = Mock()
    block.hash = bytearray(b'abcdef123456')
    assert mixin.bhash_hex(block) == bytearray(b'abcdef123456').hex()


def test_bhash_hex_str(mixin):
    block = Mock()
    block.hash = 'a' * 64   # length >= 64
    assert mixin.bhash_hex(block) == 'a' * 64


def test_bhash_hex_callable(mixin):
    block = Mock()
    block.hash = Mock(return_value=b'abcdef123456')
    assert mixin.bhash_hex(block) == b'abcdef123456'.hex()


def test_bhash_hex_callable_str(mixin):
    block = Mock()
    block.hash = Mock(return_value='a' * 64)
    assert mixin.bhash_hex(block) == 'a' * 64


def test_bhash_hex_invalid(mixin):
    block = Mock()
    block.hash = 12345
    assert mixin.bhash_hex(block) == ''


# ----------------------------------------------------------------------
# Tests for _prevhash_hex
# ----------------------------------------------------------------------

def test_prevhash_hex_bytes(mixin):
    block = Mock()
    block.prev_block_hash = b'abcdef'
    assert mixin._prevhash_hex(block) == b'abcdef'.hex()


def test_prevhash_hex_bytearray(mixin):
    block = Mock()
    block.prev_block_hash = bytearray(b'abcdef')
    assert mixin._prevhash_hex(block) == bytearray(b'abcdef').hex()


def test_prevhash_hex_str(mixin):
    block = Mock()
    block.prev_block_hash = 'abcdef'
    assert mixin._prevhash_hex(block) == 'abcdef'


def test_prevhash_hex_invalid(mixin):
    block = Mock()
    block.prev_block_hash = 123
    assert mixin._prevhash_hex(block) == ''


# ----------------------------------------------------------------------
# Tests for extract_block_id_from_block
# ----------------------------------------------------------------------

def test_extract_block_id_from_block_no_txs(mixin):
    block = Mock()
    block.transactions = []
    assert mixin._extract_block_id_from_block(block) is None


def test_extract_block_id_from_block_coinbase_first(mixin):
    cb = Mock()
    cb.is_coinbase = True
    cb.block_id = 'block_id_123'
    block = Mock()
    block.transactions = [cb]
    assert mixin._extract_block_id_from_block(block) == 'block_id_123'


def test_extract_block_id_from_block_coinbase_not_first(mixin):
    tx1 = Mock()
    tx1.is_coinbase = False
    cb = Mock()
    cb.is_coinbase = True
    cb.block_id = 'block_id_456'
    block = Mock()
    block.transactions = [tx1, cb]
    assert mixin._extract_block_id_from_block(block) == 'block_id_456'


def test_extract_block_id_from_block_no_coinbase(mixin):
    tx1 = Mock()
    tx1.is_coinbase = False
    tx2 = Mock()
    tx2.is_coinbase = False
    block = Mock()
    block.transactions = [tx1, tx2]
    assert mixin._extract_block_id_from_block(block) is None


def test_extract_block_id_from_block_coinbase_no_block_id(mixin):
    cb = Mock()
    cb.is_coinbase = True
    cb.block_id = None
    block = Mock()
    block.transactions = [cb]
    assert mixin._extract_block_id_from_block(block) is None


def test_calculate_block_bonus(mixin):
    block = Mock()
    block.height = 5
    block.total_fee = 1500
    chain = [block]
    assert mixin._calculate_block_bonus(5, chain, {}) == 1500
    assert mixin._calculate_block_bonus(99, chain, {}) is None


# ----------------------------------------------------------------------
# Tests for handle_get_block_hash
# ----------------------------------------------------------------------

def test_handle_get_block_hash_cache_hit(mixin):
    height = 100
    hash_val = "abc123"
    mixin._block_hash_cache[height] = (hash_val, time.time())
    result = mixin.handle_get_block_hash(height)
    assert result["type"] == "BLOCK_HASH"
    assert result["height"] == height
    assert result["hash"] == hash_val
    assert result["cache_hit"] is True
    mixin.broadcast.blockchain.get_block_hash.assert_not_called()


def test_handle_get_block_hash_cache_expired(mixin):
    height = 100
    hash_val = "abc123"
    mixin._block_hash_cache[height] = (hash_val, time.time() - 10)
    mixin.broadcast.blockchain.get_block_hash.return_value = "newhash"
    result = mixin.handle_get_block_hash(height)
    assert result["type"] == "BLOCK_HASH"
    assert result["height"] == height
    assert result["hash"] == "newhash"
    assert result["cache_hit"] is False
    mixin.broadcast.blockchain.get_block_hash.assert_called_once_with(height)


def test_handle_get_block_hash_cache_miss(mixin):
    height = 200
    mixin.broadcast.blockchain.get_block_hash.return_value = "def456"
    result = mixin.handle_get_block_hash(height)
    assert result["hash"] == "def456"
    assert result["cache_hit"] is False
    mixin.broadcast.blockchain.get_block_hash.assert_called_once_with(height)
    assert mixin._block_hash_cache[height][0] == "def456"


def test_handle_get_block_hash_broadcast_exception(mixin):
    height = 300
    mixin.broadcast.blockchain.get_block_hash.side_effect = Exception("RPC error")
    result = mixin.handle_get_block_hash(height)
    assert result["type"] == "BLOCK_HASH"
    assert result["error"] == "height_out_of_range"
    assert result["cache_hit"] is False
    assert "hash" not in result


def test_handle_get_block_hash_cache_eviction(mixin):
    mixin.broadcast.blockchain.get_block_hash.side_effect = lambda h: f"hash{h}"
    with patch('tsarchain.network.rpc_helper.explorer.CFG') as mock_cfg:
        mock_cfg.HASH_CACHE_MAX = 2
        mixin.handle_get_block_hash(1)
        mixin.handle_get_block_hash(2)
        mixin.handle_get_block_hash(3)
        assert 1 not in mixin._block_hash_cache
        assert 2 in mixin._block_hash_cache
        assert 3 in mixin._block_hash_cache


def test_handle_get_block_hash_benchmark(mixin):
    with patch('tsarchain.network.rpc_helper.explorer.CFG') as mock_cfg:
        mock_cfg.DEBUG_BENCHMARKS = True
        mock_cfg.HASH_CACHE_MAX = 100
        mixin.broadcast.blockchain.get_block_hash.return_value = "hash"
        with patch('tsarchain.utils.benchmarks.log') as mock_log:
            with patch('tsarchain.utils.benchmarks.time') as mock_time:
                mock_time.perf_counter.side_effect = [0.0, 0.020]
                result = mixin.handle_get_block_hash(10)
                assert result["hash"] == "hash"
                mock_log.warning.assert_called_once()
                args, _ = mock_log.warning.call_args
                assert "GET_BLOCK_HASH" in args[1]


# ----------------------------------------------------------------------
# Tests for _serialize_tx_basic
# ----------------------------------------------------------------------

def test_serialize_tx_basic(mixin):
    tx = Mock()
    tx.txid = b'abcdef'
    tx.is_coinbase = False
    tx.fee = 500
    tx.inputs = [Mock(), Mock()]
    tx.outputs = [
        Mock(amount=100, script_pubkey=b'abc'),
        Mock(amount=200, script_pubkey=b'def')
    ]
    mixin.txout_to_address.side_effect = ['addr1', 'addr2']
    result = mixin._serialize_tx_basic(tx)
    assert result["txid"] == b'abcdef'.hex()
    assert result["is_coinbase"] is False
    assert result["fee"] == 500
    assert len(result["vin"]) == 2
    assert len(result["vout"]) == 2
    assert result["vout"][0]["index"] == 0
    assert result["vout"][0]["amount"] == 100
    assert result["vout"][0]["address"] == 'addr1'
    assert result["vout"][1]["amount"] == 200


def test_serialize_tx_basic_txid_str(mixin):
    tx = Mock()
    tx.txid = 'abcdef'
    tx.is_coinbase = True
    tx.reward = 25000000000
    tx.inputs = []
    tx.outputs = []
    result = mixin._serialize_tx_basic(tx)
    assert result["txid"] == 'abcdef'
    assert result["is_coinbase"] is True
    assert result["reward"] == 25000000000


def test_serialize_tx_basic_txid_none(mixin):
    tx = Mock()
    tx.txid = None
    tx.is_coinbase = False
    tx.fee = None
    tx.inputs = []
    tx.outputs = []
    result = mixin._serialize_tx_basic(tx)
    assert result["txid"] == ''
    assert result["is_coinbase"] is False


# ----------------------------------------------------------------------
# Tests for serialize_block
# ----------------------------------------------------------------------

def test_serialize_block_success(mixin):
    block = Mock()
    block.height = 100
    block.timestamp = 123456
    block.version = 1
    block.nonce = 42
    block.merkle_root = b'merkle'
    block.bits = 0x1d00ffff
    block.chainwork = b'chainwork'
    block.difficulty = 123.45
    block.total_fee = 5000

    tx1 = Mock()
    tx1.txid = b'txid1'
    tx1.inputs = []
    tx1.outputs = [Mock(amount=10, script_pubkey=b'abc')]

    tx2 = Mock()
    tx2.txid = b'txid2'
    tx2.inputs = []
    tx2.outputs = [Mock(amount=20, script_pubkey=b'def')]
    block.transactions = [tx1, tx2]

    mem_tx1 = Mock()
    mem_tx1.outputs = [Mock(script_pubkey=b'graffiti')]
    mem_tx2 = Mock()
    mem_tx2.outputs = [Mock(script_pubkey=b'plain')]
    mixin.mempool.get_all_txs.return_value = [mem_tx1, mem_tx2]

    with patch('tsarchain.network.rpc_helper.explorer.estimate_block_size_bytes') as mock_est_size, \
         patch('tsarchain.network.rpc_helper.explorer.GRAFF') as mock_graff, \
         patch.object(mixin, 'bhash_hex', return_value='blockhash'), \
         patch.object(mixin, '_prevhash_hex', return_value='prevhash'), \
         patch.object(mixin, '_extract_block_id_from_block', return_value='blockid'), \
         patch.object(mixin, '_serialize_tx_basic') as mock_serialize_tx:

        mock_est_size.return_value = 1024

        mock_graff.parse_from_script.side_effect = [
            None,  # tx1 output
            {'event': 'POST', 'sha256': 'sha', 'size': 100, 'mime': 'text', 'creator': 'alice'},
            {'event': 'POST'},
            None,
        ]
        mock_serialize_tx.side_effect = lambda tx: {
            'txid': tx.txid.hex() if isinstance(tx.txid, (bytes, bytearray)) else tx.txid,
            'vin': [],
            'vout': []
        }

        result = mixin.serialize_block(block)

        assert result["type"] == "BLOCK"
        assert result["block_id"] == "blockid"
        assert result["hash"] == "blockhash"
        assert result["prev_hash"] == "prevhash"
        assert result["height"] == 100
        assert result["time"] == 123456
        assert result["nonce"] == 42
        assert result["difficulty"] == 123.45
        assert result["version"] == 1
        assert result["bits"] == 0x1d00ffff
        assert result["chainwork"] == b'chainwork'
        assert result["size_bytes"] == 1024
        assert result["merkle_root"] == b'merkle'.hex()
        assert result["total_fee"] == 5000
        assert result["tx_count"] == 2
        assert len(result["tx"]) == 2
        assert len(result["graffiti"]) == 1
        assert result["graffiti"][0]["txid"] == b'txid2'.hex()
        assert result["graffiti"][0]["sha256"] == 'sha'
        assert result["graffiti_on_mempool"] == 1
        assert result["comments"] == []
        assert result["payouts"] == []
        assert result["payout_count"] == 0


def test_serialize_block_with_comments_and_payouts(mixin):
    block = Mock()
    block.height = 200
    block.timestamp = 789
    block.version = 2
    block.nonce = 99
    block.merkle_root = b'merkle2'
    block.bits = 0x1d00ffff
    block.chainwork = b'cw'
    block.difficulty = 456.78
    block.total_fee = 0
    block.transactions = []

    tx1 = Mock()
    tx1.txid = b'tx_comment'
    tx1.inputs = []
    tx1.outputs = [Mock(amount=0, script_pubkey=b'comment_script')]

    tx2 = Mock()
    tx2.txid = b'tx_payout'
    tx2.inputs = []
    tx2.outputs = [Mock(amount=0, script_pubkey=b'payout_script')]
    block.transactions = [tx1, tx2]

    mixin.mempool.get_all_txs.return_value = []

    with patch('tsarchain.network.rpc_helper.explorer.estimate_block_size_bytes') as mock_est_size, \
         patch('tsarchain.network.rpc_helper.explorer.GRAFF') as mock_graff, \
         patch.object(mixin, 'bhash_hex', return_value='h'), \
         patch.object(mixin, '_prevhash_hex', return_value='p'), \
         patch.object(mixin, '_extract_block_id_from_block', return_value='bid'), \
         patch.object(mixin, '_serialize_tx_basic', return_value={'txid': 'dummy', 'vin': [], 'vout': []}):

        mock_est_size.return_value = 512
        mock_graff.parse_from_script.side_effect = [
            {'event': 'COMMENT', 'art_id': 'art1', 'comment_len': 10, 'commenter': 'bob'},
            {'event': 'PAYOUT', 'art_id': 'art2', 'epoch': 5, 'recipients': ['addr1', 'addr2']}
        ]
        result = mixin.serialize_block(block)
        assert len(result["comments"]) == 1
        assert result["comments"][0]["txid"] == b'tx_comment'.hex()
        assert result["comments"][0]["art_id"] == 'art1'
        assert len(result["payouts"]) == 1
        assert result["payouts"][0]["txid"] == b'tx_payout'.hex()
        assert result["payouts"][0]["recipients"] == ['addr1', 'addr2']
        assert result["payout_count"] == 1
        assert result["graffiti"] == []
        assert result["graffiti_on_mempool"] == 0


def test_serialize_block_no_graffiti(mixin):
    block = Mock()
    block.height = 1
    block.timestamp = 0
    block.version = 1
    block.nonce = 0
    block.merkle_root = b'root'
    block.bits = 0
    block.chainwork = b''
    block.difficulty = 0
    block.total_fee = 0
    block.transactions = [Mock(txid=b'tx', inputs=[], outputs=[Mock(script_pubkey=b'plain')])]
    mixin.mempool.get_all_txs.return_value = []

    with patch('tsarchain.network.rpc_helper.explorer.estimate_block_size_bytes') as mock_est_size, \
         patch('tsarchain.network.rpc_helper.explorer.GRAFF') as mock_graff, \
         patch.object(mixin, 'bhash_hex', return_value=''), \
         patch.object(mixin, '_prevhash_hex', return_value=''), \
         patch.object(mixin, '_extract_block_id_from_block', return_value=None), \
         patch.object(mixin, '_serialize_tx_basic', return_value={'txid': 'tx', 'vin': [], 'vout': []}):

        mock_est_size.return_value = 0
        mock_graff.parse_from_script.return_value = None
        result = mixin.serialize_block(block)
        assert result["graffiti"] == []
        assert result["comments"] == []
        assert result["payouts"] == []
        assert result["payout_count"] == 0
        assert result["graffiti_on_mempool"] == 0


# ----------------------------------------------------------------------
# Tests for process_tx_lookup
# ----------------------------------------------------------------------

def test_get_tx_detail_tx_not_found(mixin):
    mixin.find_tx_and_meta.return_value = (None, None, None, None, None, None, None, None)
    result = mixin.process_tx_lookup("123")
    assert result["error"] == "tx not found"
    assert result["txid"] == "123"


def test_get_tx_detail_coinbase(mixin):
    tx = Mock()
    tx.inputs = []
    tx.outputs = [Mock(amount=50, script_pubkey=b'abc')]
    height = 100
    timestamp = 123456
    conf = 10
    tip_height = 110
    chain = []
    mem = None
    mixin.find_tx_and_meta.return_value = ("chain", tx, height, timestamp, conf, chain, mem, tip_height)
    mixin.is_coinbase_tx.return_value = True
    mixin.build_outpoint_map.return_value = {}
    mixin.txout_to_address.return_value = "miner_addr"
    with patch('tsarchain.network.rpc_helper.explorer.GRAFF') as mock_graff:
        mock_graff.parse_from_script.return_value = None
        result = mixin.process_tx_lookup("txid")
        assert result["type"] == "TX_DETAIL"
        assert result["txid"] == "txid"
        assert result["status"] == "confirmed"
        assert result["confirmations"] == conf
        assert result["height"] == height
        assert result["timestamp"] == timestamp
        assert result["is_coinbase"] is True
        assert result["inputs"] == []
        assert len(result["outputs"]) == 1
        assert result["total_in"] is None
        assert result["total_out"] == 50
        assert result["fee"] is None
        assert result["bonus"] is None


def test_get_tx_detail_non_coinbase_confirmed_with_bonus(mixin):
    tx = Mock()
    tx.inputs = [Mock()]
    tx.outputs = [Mock(amount=10, script_pubkey=b'out1'), Mock(amount=20, script_pubkey=b'out2')]
    height = 200
    timestamp = 789
    conf = 5
    tip_height = 205

    block = Mock()
    block.height = height
    block.total_fee = 95
    other_tx = Mock()
    other_tx.inputs = [Mock()]
    other_tx.outputs = [Mock(amount=5)]
    coinbase_tx = Mock()
    coinbase_tx.is_coinbase = True
    block.transactions = [coinbase_tx, tx, other_tx]
    chain = [block]
    mem = None

    mixin.find_tx_and_meta.return_value = ("chain", tx, height, timestamp, conf, chain, mem, tip_height)

    def is_coinbase_side_effect(t):
        return t is coinbase_tx
    mixin.is_coinbase_tx.side_effect = is_coinbase_side_effect

    opmap = {
        "prevtx:0": (100, "spk1"),
        "prevtx2:0": (30, "spk2")
    }
    mixin.build_outpoint_map.return_value = opmap
    # Urutan panggilan txin_prevkey:
    # 1. vin untuk tx utama -> "prevtx:0"
    # 2. bonus untuk tx utama -> "prevtx:0"
    # 3. bonus untuk other_tx -> "prevtx2:0"
    mixin.txin_prevkey.side_effect = ["prevtx:0", "prevtx:0", "prevtx2:0"]
    mixin._spkhex_to_address.return_value = "addr_input"
    mixin.txout_to_address.return_value = "addr_output"

    with patch('tsarchain.network.rpc_helper.explorer.GRAFF') as mock_graff:
        mock_graff.parse_from_script.return_value = None
        result = mixin.process_tx_lookup("txid")

        assert result["type"] == "TX_DETAIL"
        assert result["txid"] == "txid"
        assert result["status"] == "confirmed"
        assert result["height"] == height
        assert result["total_in"] == 100
        assert result["total_out"] == 30
        assert result["fee"] == 70
        assert result["bonus"] == 95

        assert len(result["inputs"]) == 1
        assert result["inputs"][0]["prev_txid"] == "prevtx"
        assert result["inputs"][0]["amount"] == 100
        assert result["outputs"][0]["amount"] == 10


def test_get_tx_detail_unconfirmed(mixin):
    tx = Mock()
    tx.inputs = [Mock()]
    tx.outputs = [Mock(amount=50, script_pubkey=b'out')]
    tip_height = 100
    mem = Mock()
    mixin.find_tx_and_meta.return_value = ("mempool", tx, None, None, 0, None, mem, tip_height)
    mixin.is_coinbase_tx.return_value = False
    mixin.build_outpoint_map.return_value = {"prev:0": (100, "spk")}
    mixin.txin_prevkey.return_value = "prev:0"
    mixin._spkhex_to_address.return_value = "addr"
    mixin.txout_to_address.return_value = "addr2"
    with patch('tsarchain.network.rpc_helper.explorer.GRAFF') as mock_graff:
        mock_graff.parse_from_script.return_value = None
        result = mixin.process_tx_lookup("txid")
        assert result["status"] == "unconfirmed"
        assert result["confirmations"] == 0
        assert result["height"] is None
        assert result["timestamp"] is None
        assert result["bonus"] is None
        assert result["fee"] == 50


def test_get_tx_detail_no_fee_if_input_less_than_output(mixin):
    tx = Mock()
    tx.inputs = [Mock()]
    tx.outputs = [Mock(amount=100, script_pubkey=b'out')]
    mixin.find_tx_and_meta.return_value = ("chain", tx, 1, 123, 1, [], None, 1)
    mixin.is_coinbase_tx.return_value = False
    mixin.build_outpoint_map.return_value = {"prev:0": (50, "spk")}
    mixin.txin_prevkey.return_value = "prev:0"
    mixin._spkhex_to_address.return_value = "addr"
    mixin.txout_to_address.return_value = "addr2"
    with patch('tsarchain.network.rpc_helper.explorer.GRAFF') as mock_graff:
        mock_graff.parse_from_script.return_value = None
        result = mixin.process_tx_lookup("txid")
        assert result["fee"] is None


def test_explorer_handler_init():
    dummy_net = type('Dummy', (), {})()
    handler = ExplorerHandler(dummy_net)
    assert handler._block_hash_cache is not None
    assert handler._block_hash_cache_lock is not None


def test_get_mempool_graffiti_count_no_broadcast(mixin):
    mixin.broadcast = None
    assert mixin._get_mempool_graffiti_count() == 0


def test_get_mempool_graffiti_count_no_mempool(mixin):
    mixin.broadcast.mempool = None
    assert mixin._get_mempool_graffiti_count() == 0


def test_explorer_handler_proxy_delegation():
    from tsarchain.network.node import Network
    from tsarchain.network.rpc_helper.history import HistoryHandler
    from tsarchain.core.tx import TxOut, Script

    net = Network.__new__(Network)
    hist = HistoryHandler(net)
    exp = ExplorerHandler(net)
    net.__dict__["_handlers"] = [hist, exp]

    # ExplorerHandler should resolve txout_to_address via NetworkProxy -> HistoryHandler
    assert callable(exp.txout_to_address)
    txout = TxOut(amount=1000, script_pubkey=Script(b"\x00\x14" + b"\x01" * 20))
    addr = exp.txout_to_address(txout)
    assert addr is not None
    assert addr.startswith("tsar1")

    # Non-existent attribute raises AttributeError
    with pytest.raises(AttributeError):
        _ = exp.non_existent_attribute
