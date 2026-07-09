# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

import time
import pytest
import threading
import collections
from unittest.mock import Mock, patch

from tsarchain.network.rpc_helper.history_mixin import HistoryMixin



class DummyScriptPubKey:
    def __init__(self, hex_str=None, bytes_data=None):
        self._hex = hex_str
        self._bytes = bytes_data

    def serialize(self):
        if self._bytes is not None:
            return self._bytes
        if self._hex is not None:
            return bytes.fromhex(self._hex)
        return b''

class DummyTxOut:
    def __init__(self, amount=0, script_pubkey=None):
        self.amount = amount
        self.script_pubkey = script_pubkey

class DummyTxIn:
    def __init__(self, txid=None, vout=0, prev_tx=b'', prev_index=None):
        self.txid = txid
        self.vout = vout if prev_index is None else prev_index
        self.prev_tx = prev_tx

class DummyTx:
    def __init__(self, txid=None, inputs=None, outputs=None):
        self.txid = txid
        self.inputs = inputs or []
        self.outputs = outputs or []

class DummyBlock:
    def __init__(self, height=0, timestamp=0, transactions=None):
        self.height = height
        self.timestamp = timestamp
        self.transactions = transactions or []


@pytest.fixture
def mixin():
    """Create a HistoryMixin instance with mocked dependencies."""
    class TestMixin(HistoryMixin):
        def _bhash_hex(self, block):
            h = getattr(block, "hash", None)
            if h is None:
                h = getattr(block, "block_hash", None)
            if h is None:
                return ""
            if isinstance(h, (bytes, bytearray)):
                return h.hex()
            return str(h)
        
        def _addr_to_spk(self):
            class _Spk:
                def __init__(self, data):
                    self._data = data
                def serialize(self):
                    return self._data
            return _Spk(b'\x00\x14' + b'a' * 20)

    obj = TestMixin()
    obj.broadcast = Mock()
    obj.broadcast.lock = threading.RLock()
    obj.broadcast.blockchain = Mock()
    obj.broadcast.blockchain.chain = []
    obj.broadcast.blockchain.height = 0
    obj.broadcast.mempool = Mock()
    obj.broadcast.mempool.get_all_txs = Mock(return_value=[])
    obj.broadcast.mempool.change_seq = 0

    # Clear cache for each test
    obj._tx_history_cache = collections.OrderedDict()
    obj._tx_history_cache_lock = threading.RLock()

    return obj


@pytest.fixture
def patch_config():
    """Patch CFG constants."""
    with patch('tsarchain.network.rpc_helper.history_mixin.CFG') as mock_cfg:
        mock_cfg.ADDRESS_PREFIX = 'tsar'
        mock_cfg.MAX_UTXO_ADDR_LEN = 100
        mock_cfg.MAX_HISTORY_LIMIT = 50
        yield mock_cfg


# ----------------------------------------------------------------------
# Tests for _txin_prevkey
# ----------------------------------------------------------------------
def test_txin_prevkey_with_txid_bytes(mixin):
    tin = DummyTxIn(txid=b'abc' * 8 + b'def' * 8, vout=5)  # 32 bytes
    result = mixin._txin_prevkey(tin)
    expected = tin.txid.hex() + ':5'
    assert result == expected

def test_txin_prevkey_with_txid_str(mixin):
    txid_hex = 'a' * 64
    tin = DummyTxIn(txid=txid_hex, vout=3)
    result = mixin._txin_prevkey(tin)
    assert result == f'{txid_hex}:3'

def test_txin_prevkey_with_prev_tx(mixin):
    prev_tx = b'foo' * 10  # not 32 bytes, but it's okay
    tin = DummyTxIn(prev_tx=prev_tx, prev_index=7)
    result = mixin._txin_prevkey(tin)
    assert result == f'{prev_tx.hex()}:7'

def test_txin_prevkey_fallback(mixin):
    tin = Mock()
    tin.txid = None
    tin.vout = 9
    tin.prev_tx = None
    result = mixin._txin_prevkey(tin)
    assert result == ':9'  # str(None) -> 'None'? actually '' if p0 is None -> ''


# ----------------------------------------------------------------------
# Tests for _is_coinbase_tx
# ----------------------------------------------------------------------
def test_is_coinbase_tx_no_inputs(mixin):
    tx = DummyTx(inputs=[])
    assert mixin._is_coinbase_tx(tx) is True

def test_is_coinbase_tx_with_zero_txid_bytes(mixin):
    tin = DummyTxIn(txid=b'\x00' * 32)
    tx = DummyTx(inputs=[tin])
    assert mixin._is_coinbase_tx(tx) is True

def test_is_coinbase_tx_with_zero_txid_hex(mixin):
    txid_hex = '00' * 32
    tin = DummyTxIn(txid=txid_hex)
    tx = DummyTx(inputs=[tin])
    assert mixin._is_coinbase_tx(tx) is True

def test_is_coinbase_tx_with_prev_tx_zero(mixin):
    tin = DummyTxIn(prev_tx=b'\x00' * 32)
    tx = DummyTx(inputs=[tin])
    assert mixin._is_coinbase_tx(tx) is True

def test_is_coinbase_tx_non_coinbase(mixin):
    tin = DummyTxIn(txid=b'not' + b'\x00' * 29)  # random
    tx = DummyTx(inputs=[tin])
    assert mixin._is_coinbase_tx(tx) is False




# ----------------------------------------------------------------------
# Tests for _txout_to_spk_hex
# ----------------------------------------------------------------------
def test_txout_to_spk_hex_with_serialize(mixin):
    spk = DummyScriptPubKey(hex_str='0014' + 'a' * 40)
    txout = DummyTxOut(script_pubkey=spk)
    result = mixin._txout_to_spk_hex(txout)
    assert result == '0014' + 'a' * 40

def test_txout_to_spk_hex_with_bytes(mixin):
    spk_bytes = b'\x00\x14' + b'a' * 20
    txout = DummyTxOut(script_pubkey=spk_bytes)
    result = mixin._txout_to_spk_hex(txout)
    assert result == spk_bytes.hex()

def test_txout_to_spk_hex_with_str(mixin):
    spk_hex = '0014' + 'a' * 40
    txout = DummyTxOut(script_pubkey=spk_hex)
    result = mixin._txout_to_spk_hex(txout)
    assert result == spk_hex.lower()

def test_txout_to_spk_hex_none(mixin):
    txout = DummyTxOut(script_pubkey=None)
    result = mixin._txout_to_spk_hex(txout)
    assert result is None


# ----------------------------------------------------------------------
# Tests for _txout_to_address
# ----------------------------------------------------------------------
def test_txout_to_address(mixin):
    spk_hex = '0014' + 'a' * 40
    txout = DummyTxOut(script_pubkey=spk_hex)
    with patch('tsarchain.network.rpc_helper.history_mixin.spkhex_to_address', return_value='tsar1abc') as mock_spk:
        result = mixin._txout_to_address(txout)
        assert result == 'tsar1abc'
        mock_spk.assert_called_once_with(spk_hex)

def test_txout_to_address_no_spk(mixin):
    txout = DummyTxOut(script_pubkey=None)
    result = mixin._txout_to_address(txout)
    assert result is None


# ----------------------------------------------------------------------
# Tests for _normalize_spk_hex
# ----------------------------------------------------------------------
def test_normalize_spk_hex_bech32(mixin):
    addr = 'tsar1q...'  # dummy
    with patch.object(mixin, '_addr_to_spk') as mock_addr_to_spk:
        mock_spk = Mock()
        mock_spk.serialize.return_value = b'\x00\x14' + b'\xaa' * 20
        mock_addr_to_spk.return_value = mock_spk
        result = mixin._normalize_spk_hex(addr)
        assert result == ('0014' + 'aa' * 20)

def test_normalize_spk_hex_already_p2wpkh(mixin):
    spk_hex = '0014' + 'a' * 40
    result = mixin._normalize_spk_hex(spk_hex)
    assert result == spk_hex

def test_normalize_spk_hex_already_p2wsh(mixin):
    spk_hex = '0020' + 'b' * 64
    result = mixin._normalize_spk_hex(spk_hex)
    assert result == spk_hex

def test_normalize_spk_hex_old_p2pkh(mixin):
    # '00' + 20 bytes (40 hex) -> total 42
    addr = '00' + 'a' * 40
    result = mixin._normalize_spk_hex(addr)
    assert result == '0014' + 'a' * 40

def test_normalize_spk_hex_old_p2wsh(mixin):
    addr = '00' + 'b' * 64  # 2 + 64 = 66
    result = mixin._normalize_spk_hex(addr)
    assert result == '0020' + 'b' * 64

def test_normalize_spk_hex_invalid(mixin):
    assert mixin._normalize_spk_hex('invalid') is None
    assert mixin._normalize_spk_hex('0014' + 'a'*39) is None  # wrong length
    assert mixin._normalize_spk_hex('0020' + 'b'*63) is None


# ----------------------------------------------------------------------
# Tests for _build_outpoint_map
# ----------------------------------------------------------------------
def test_build_outpoint_map_chain_only(mixin):
    spk_hex_a = '0014' + 'aa' * 20
    spk_hex_b = '0014' + 'bb' * 20
    spk_hex_c = '0014' + 'cc' * 20
    tx1 = DummyTx(txid=b'a'*32, outputs=[
        DummyTxOut(amount=100, script_pubkey=bytes.fromhex(spk_hex_a)),
        DummyTxOut(amount=200, script_pubkey=bytes.fromhex(spk_hex_b)),
    ])
    tx2 = DummyTx(txid=b'b'*32, outputs=[DummyTxOut(amount=50, script_pubkey=bytes.fromhex(spk_hex_c))])
    block = DummyBlock(transactions=[tx1, tx2])
    chain = [block]
    result = mixin._build_outpoint_map(chain)
    assert len(result) == 3
    key1 = tx1.txid.hex() + ':0'
    key2 = tx1.txid.hex() + ':1'
    key3 = tx2.txid.hex() + ':0'
    assert result[key1] == (100, spk_hex_a)
    assert result[key2] == (200, spk_hex_b)
    assert result[key3] == (50, spk_hex_c)

def test_build_outpoint_map_with_mem(mixin):
    chain_tx = DummyTx(txid=b'c'*32, outputs=[DummyTxOut(amount=10, script_pubkey=bytes.fromhex('0014' + 'dd'*20))])
    block = DummyBlock(transactions=[chain_tx])
    chain = [block]

    mem_tx = DummyTx(txid=b'm'*32, outputs=[DummyTxOut(amount=5, script_pubkey=bytes.fromhex('0014' + 'ee'*20))])
    mem = [mem_tx]

    chain_map, mem_map = mixin._build_outpoint_map(chain, mem)
    assert len(chain_map) == 1
    assert len(mem_map) == 1
    assert chain_map[chain_tx.txid.hex() + ':0'] == (10, '0014' + 'dd'*20)
    assert mem_map[mem_tx.txid.hex() + ':0'] == (5, '0014' + 'ee'*20)


# ----------------------------------------------------------------------
# Tests for _find_tx_and_meta
# ----------------------------------------------------------------------
def test_find_tx_and_meta_in_mempool(mixin):
    txid_hex = 'a' * 64
    tx = DummyTx(txid=bytes.fromhex(txid_hex))
    mixin.broadcast.mempool.get_all_txs.return_value = [tx]
    mixin.broadcast.blockchain.chain = []
    mixin.broadcast.blockchain.height = 0

    result = mixin._find_tx_and_meta(txid_hex)
    where, found_tx, height, timestamp, conf, chain, mem, tip = result
    assert where == 'mempool'
    assert found_tx is tx
    assert height is None
    assert timestamp == 0
    assert conf is None
    assert chain == []
    assert mem == [tx]
    assert tip == 0

def test_find_tx_and_meta_in_chain(mixin):
    txid_hex = 'b' * 64
    tx = DummyTx(txid=bytes.fromhex(txid_hex))
    block = DummyBlock(height=100, timestamp=1234567890, transactions=[tx])
    mixin.broadcast.blockchain.chain = [block]
    mixin.broadcast.blockchain.height = 120
    mixin.broadcast.mempool.get_all_txs.return_value = []

    result = mixin._find_tx_and_meta(txid_hex)
    where, found_tx, height, timestamp, conf, chain, mem, tip = result
    assert where == 'chain'
    assert found_tx is tx
    assert height == 100
    assert timestamp == 1234567890
    assert conf == 120 - 100 + 1  # 21
    assert chain == [block]
    assert mem == []
    assert tip == 120

def test_find_tx_and_meta_not_found(mixin):
    mixin.broadcast.mempool.get_all_txs.return_value = []
    mixin.broadcast.blockchain.chain = [DummyBlock(transactions=[])]
    mixin.broadcast.blockchain.height = 0

    result = mixin._find_tx_and_meta('deadbeef')
    assert result[0] is None
    assert result[1] is None
    assert result[2] is None


# ----------------------------------------------------------------------
# Tests for _get_tx_history (integration)
# ----------------------------------------------------------------------
def test_get_tx_history_invalid_address(mixin):
    result = mixin._get_tx_history('')
    assert result == {'items': [], 'total': 0, 'limit': 50, 'offset': 0}
    result = mixin._get_tx_history(None)
    assert result == {'items': [], 'total': 0, 'limit': 50, 'offset': 0}

def test_get_tx_history_address_too_long(mixin, patch_config):
    patch_config.MAX_UTXO_ADDR_LEN = 5
    result = mixin._get_tx_history('a'*10)
    assert 'error' in result
    assert result['error'] == 'address too long'

def test_get_tx_history_invalid_address_format(mixin):
    with patch.object(mixin, '_normalize_spk_hex', return_value=None):
        result = mixin._get_tx_history('invalid')
        assert 'error' in result
        assert result['error'] == 'invalid address'

def test_get_tx_history_cache_hit(mixin):
    target_spk = '0014' + 'a'*40
    cache = mixin._tx_history_cache
    cache[target_spk] = {
        'ts': time.time(),
        'tip_height': 100,
        'tip_hash': 'abc',
        'mem_seq': 5,
        'items': [{'txid': 'fake', 'direction': 'in', 'amount': 10, 'status': 'confirmed'}]
    }
    # Set up matching tip and mem_seq
    mixin.broadcast.blockchain.height = 100
    mixin.broadcast.blockchain.chain = [Mock()]
    mixin.broadcast.mempool.change_seq = 5
    with patch.object(mixin, '_bhash_hex', return_value='abc'):
        with patch.object(mixin, '_build_outpoint_map') as mock_build:
            result = mixin._get_tx_history('0014' + 'a'*40)
            assert len(result['items']) == 1
            assert result['total'] == 1
            mock_build.assert_not_called()  # cache hit, no rebuild

def test_get_tx_history_cache_miss(mixin):
    target_spk = '0014' + 'a'*40
    mixin._tx_history_cache.clear()

    with patch.object(mixin, '_normalize_spk_hex', return_value=target_spk):
        txid_hex = 'f' * 64
        tx = DummyTx(
            txid=bytes.fromhex(txid_hex),
            inputs=[DummyTxIn(txid=b'p'*32, vout=0)],
            outputs=[DummyTxOut(amount=50, script_pubkey=b'\x00\x14' + b'b'*20)]
        )
        block = DummyBlock(height=10, timestamp=12345, transactions=[tx])
        mixin.broadcast.blockchain.chain = [block]
        mixin.broadcast.blockchain.height = 15
        mixin.broadcast.mempool.get_all_txs.return_value = []
        mixin.broadcast.mempool.change_seq = 0

        prev_key = (b'p'*32).hex() + ':0'
        prev_spk_hex = target_spk
        opmap_chain = {prev_key: (100, prev_spk_hex)}
        opmap_mem = {}
        with patch.object(mixin, '_build_outpoint_map', return_value=(opmap_chain, opmap_mem)):
            with patch('tsarchain.network.rpc_helper.history_mixin.spkhex_to_address', return_value='tsar1other'):
                result = mixin._get_tx_history(target_spk)
                assert len(result['items']) == 1
                item = result['items'][0]
                assert item['direction'] == 'out'
                assert item['amount'] == 100
                assert item['status'] == 'confirmed'
                assert item['confirmations'] == 15 - 10 + 1  # 6


# ----------------------------------------------------------------------
# Additional tests for edge cases in _get_tx_history
# ----------------------------------------------------------------------
def test_get_tx_history_coinbase_incoming(mixin):
    target_spk = '0014' + 'a'*40
    tx = DummyTx(txid=b'c'*32, inputs=[], outputs=[DummyTxOut(amount=50, script_pubkey=bytes.fromhex(target_spk))])
    block = DummyBlock(height=5, timestamp=999, transactions=[tx])
    mixin.broadcast.blockchain.chain = [block]
    mixin.broadcast.blockchain.height = 10
    mixin.broadcast.mempool.get_all_txs.return_value = []

    with patch.object(mixin, '_normalize_spk_hex', return_value=target_spk):
        with patch.object(mixin, '_build_outpoint_map', return_value=({}, {})):
            with patch('tsarchain.network.rpc_helper.history_mixin.spkhex_to_address', return_value='tsar1coinbase'):
                result = mixin._get_tx_history(target_spk)
                assert len(result['items']) == 1
                item = result['items'][0]
                assert item['direction'] == 'in'
                assert item['amount'] == 50
                assert item['from'] == 'coinbase'

def test_get_tx_history_deduplication(mixin):
    txid_hex = 'd'*64
    tx = DummyTx(
        txid=bytes.fromhex(txid_hex),
        inputs=[DummyTxIn(txid=b'p'*32, vout=0)],
        outputs=[DummyTxOut(amount=10, script_pubkey=b'\x00\x14' + b'a'*20)]
    )
    block = DummyBlock(height=100, timestamp=123, transactions=[tx])
    mixin.broadcast.blockchain.chain = [block]
    mixin.broadcast.blockchain.height = 100
    mixin.broadcast.mempool.get_all_txs.return_value = [tx]  # same tx in mempool

    target_spk = '0014' + 'a'*40
    with patch.object(mixin, '_normalize_spk_hex', return_value=target_spk):
        prev_key = (b'p'*32).hex() + ':0'
        opmap_chain = {prev_key: (100, target_spk)}
        opmap_mem = {}
        with patch.object(mixin, '_build_outpoint_map', return_value=(opmap_chain, opmap_mem)):
            with patch('tsarchain.network.rpc_helper.history_mixin.spkhex_to_address', return_value='tsar1other'):
                result = mixin._get_tx_history(target_spk)
                assert len(result['items']) == 1
                item = result['items'][0]
                assert item['status'] == 'confirmed'
                assert item['height'] == 100