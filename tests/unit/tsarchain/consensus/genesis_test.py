# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import Mock, patch
from tsarchain.consensus.genesis import _resolve_genesis_hash, GenesisManager

# -------------------- Fixtures for Config and Logging --------------------

@pytest.fixture(autouse=True)
def mock_config_and_logger(monkeypatch):
    """Mock the config module and logger to avoid external dependencies."""
    # Mock CFG
    mock_cfg = Mock()
    mock_cfg.GENESIS_HASH_HEX = ""
    mock_cfg.ZERO_HASH = b"\x00" * 32
    mock_cfg.INITIAL_BITS = 0x1e0ffff0
    mock_cfg.GENESIS_BLOCK_ID_DEFAULT = "genesis_block"
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG", mock_cfg)

    # Mock logger
    mock_logger = Mock()
    monkeypatch.setattr("tsarchain.consensus.genesis.log", mock_logger)


# -------------------- Tests for _resolve_genesis_hash --------------------

def test_resolve_genesis_hash_valid_no_prefix(monkeypatch):
    """GENESIS_HASH_HEX is a valid 64-char hex without 0x prefix."""
    hex_str = "a" * 64
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.GENESIS_HASH_HEX", hex_str)
    result = _resolve_genesis_hash()
    assert result == bytes.fromhex(hex_str)


def test_resolve_genesis_hash_valid_with_prefix(monkeypatch):
    """GENESIS_HASH_HEX includes '0x' prefix."""
    hex_str = "0x" + "b" * 64
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.GENESIS_HASH_HEX", hex_str)
    result = _resolve_genesis_hash()
    assert result == bytes.fromhex("b" * 64)


def test_resolve_genesis_hash_empty(monkeypatch):
    """GENESIS_HASH_HEX is empty string -> returns None."""
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.GENESIS_HASH_HEX", "")
    assert _resolve_genesis_hash() is None


def test_resolve_genesis_hash_none(monkeypatch):
    """GENESIS_HASH_HEX is None -> returns None."""
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.GENESIS_HASH_HEX", None)
    assert _resolve_genesis_hash() is None


def test_resolve_genesis_hash_invalid_length(monkeypatch):
    """GENESIS_HASH_HEX has wrong length -> raises ValueError."""
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.GENESIS_HASH_HEX", "abc")
    with pytest.raises(ValueError, match="Invalid Genesis Hash!!"):
        _resolve_genesis_hash()


def test_resolve_genesis_hash_invalid_chars(monkeypatch):
    """GENESIS_HASH_HEX contains non-hex chars -> raises ValueError."""
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.GENESIS_HASH_HEX", "g" * 64)
    with pytest.raises(ValueError, match="Invalid Genesis Hash!!"):
        _resolve_genesis_hash()


# -------------------- Dummy Blockchain class for mixin testing --------------------

class DummyBlockchain:
    """Minimal implementation of the required interface for testing."""
    def __init__(self, chain=None):
        self.chain = chain if chain is not None else []
        self.total_supply = 0
        self._saved = False
        self._state_saved = False
        self._chain_dirty = False
        self._utxo_dirty = False
        self.genesis_manager = GenesisManager(self)

    def _persist_empty_state_if_needed(self):
        return self.genesis_manager._persist_empty_state_if_needed()

    def _enforce_genesis_lock(self):
        return self.genesis_manager._enforce_genesis_lock()

    def create_genesis_with_lock(self, miner_address: str, use_cores: int | None=None):
        return self.genesis_manager.create_genesis_with_lock(miner_address, use_cores)

    def ensure_genesis(self, miner_address: str, use_cores: int | None = None) -> bool:
        return self.genesis_manager.ensure_genesis(miner_address, use_cores)

    # def create_genesis_block(self, miner_address, use_cores: int | None = None):
    #     return self.genesis_manager._create_genesis_block(miner_address, use_cores)

    def save_state(self):
        self._state_saved = True

    def save_chain(self, force_full=False):
        self._saved = True

    def get_block_reward(self, height):
        return 50  # arbitrary

    def validate_block(self, block):
        return True  # default success

    def _mark_chain_dirty(self, height):
        self._chain_dirty = True

    def ensure_utxodb(self):
        return Mock()  # return a mock store

    def mark_utxo_dirty(self):
        self._utxo_dirty = True

    def maybe_flush_utxo(self, force=False):
        pass

    def calculate_total_supply(self):
        return 0


# -------------------- Tests for GenesisManager methods --------------------

def test_persist_empty_state_if_needed():
    """_persist_empty_state_if_needed calls save_state."""
    bc = DummyBlockchain()
    bc._persist_empty_state_if_needed()
    assert bc._state_saved is True


def test_enforce_genesis_lock_no_genesis_hash(monkeypatch):
    """If GENESIS_HASH is None, function verifies height=0 & prev_hash=ZERO_HASH and returns."""
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", None)
    block = Mock()
    block.height = 0
    block.prev_block_hash = b"\x00" * 32
    bc = DummyBlockchain(chain=[block])
    bc._enforce_genesis_lock()  # should not raise


def test_enforce_genesis_lock_empty_chain(monkeypatch):
    """If chain is empty, returns without checking."""
    # Set a dummy GENESIS_HASH
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", b"a" * 32)
    bc = DummyBlockchain(chain=[])
    bc._enforce_genesis_lock()  # no exception


def test_enforce_genesis_lock_height_not_zero(monkeypatch):
    """Raises ValueError if genesis block height != 0."""
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", b"a" * 32)
    block = Mock()
    block.height = 1
    block.prev_block_hash = b"\x00" * 32
    bc = DummyBlockchain(chain=[block])
    with pytest.raises(ValueError, match="Genesis must have height=0"):
        bc._enforce_genesis_lock()


def test_enforce_genesis_lock_prev_hash_not_zero(monkeypatch):
    """Raises ValueError if genesis prev_block_hash != ZERO_HASH."""
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", b"a" * 32)
    block = Mock()
    block.height = 0
    block.prev_block_hash = b"not_zero"
    bc = DummyBlockchain(chain=[block])
    with pytest.raises(ValueError, match="prev_block_hash must be ZERO_HASH"):
        bc._enforce_genesis_lock()


def test_enforce_genesis_lock_hash_mismatch(monkeypatch):
    """Raises ValueError if genesis hash != GENESIS_HASH."""
    expected = b"a" * 32
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", expected)
    block = Mock()
    block.height = 0
    block.prev_block_hash = b"\x00" * 32
    # Mock hash() to return different bytes
    block.hash = Mock(return_value=b"b" * 32)
    bc = DummyBlockchain(chain=[block])
    with pytest.raises(ValueError, match="Genesis mismatch"):
        bc._enforce_genesis_lock()


def test_enforce_genesis_lock_success(monkeypatch):
    """No exception when conditions are satisfied."""
    expected = b"a" * 32
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", expected)
    block = Mock()
    block.height = 0
    block.prev_block_hash = b"\x00" * 32
    block.hash = Mock(return_value=expected)
    bc = DummyBlockchain(chain=[block])
    bc._enforce_genesis_lock()  # should not raise


def test_create_genesis_with_lock_success(monkeypatch):
    """create_genesis_with_lock calls _create_genesis_block and saves if needed."""
    # Set GENESIS_HASH to match created block's hash
    expected = b"a" * 32
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", expected)

    bc = DummyBlockchain()
    # Override _create_genesis_block on genesis_manager
    def fake_create_genesis(self_manager, miner, use_cores):
        block = Mock()
        block.hash = Mock(return_value=expected)
        self_manager.blockchain.chain.append(block)
    bc.genesis_manager._create_genesis_block = fake_create_genesis.__get__(bc.genesis_manager)

    bc.create_genesis_with_lock("miner", use_cores=4)

    # Check that save_chain and save_state were called
    assert bc._saved is True
    assert bc._state_saved is True
    # Chain should have one block
    assert len(bc.chain) == 1


def test_create_genesis_with_lock_hash_mismatch(monkeypatch):
    """Raises ValueError if created genesis hash does not match GENESIS_HASH."""
    expected = b"a" * 32
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", expected)

    bc = DummyBlockchain()
    def fake_create_genesis(self_manager, miner, use_cores):
        block = Mock()
        block.hash = Mock(return_value=b"b" * 32)
        self_manager.blockchain.chain.append(block)
    bc.genesis_manager._create_genesis_block = fake_create_genesis.__get__(bc.genesis_manager)

    with pytest.raises(ValueError, match="does not match TSAR_GENESIS_HASH"):
        bc.create_genesis_with_lock("miner", use_cores=4)





def test_ensure_genesis_chain_not_empty():
    """If chain non-empty, ensure_genesis returns False and does not create."""
    bc = DummyBlockchain(chain=[Mock()])
    result = bc.ensure_genesis("miner")
    assert result is False


def test_ensure_genesis_init_genesis_false():
    """If init_genesis is False, returns False."""
    bc = DummyBlockchain(chain=[])
    with patch.object(bc.genesis_manager, "create_genesis_with_lock") as mock_create:
        result = bc.genesis_manager.ensure_genesis("miner", init_genesis=False)
        assert result is False
        mock_create.assert_not_called()


def test_ensure_genesis_success():
    """If chain empty and init_genesis=True, create genesis and return True."""
    bc = DummyBlockchain(chain=[])
    with patch.object(bc.genesis_manager, "create_genesis_with_lock") as mock_create:
        result = bc.genesis_manager.ensure_genesis("miner", use_cores=2, init_genesis=True)
        assert result is True
        mock_create.assert_called_once_with("miner", 2)


@patch("tsarchain.consensus.genesis.Block")
@patch("tsarchain.consensus.genesis.CoinbaseTx")
def test_create_genesis_block_success(mock_coinbase_cls, mock_block_cls, monkeypatch):
    """Test full creation of genesis block with mining and validation."""
    # Set up mocks
    mock_coinbase = Mock()
    mock_coinbase_cls.return_value = mock_coinbase
    mock_block = Mock()
    mock_block.hash.return_value = b"a" * 32
    mock_block_cls.return_value = mock_block

    # Set GENESIS_HASH to match
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", b"a" * 32)
    # Set config values
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.ZERO_HASH", b"\x00" * 32)
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.INITIAL_BITS", 0x12345678)
    monkeypatch.setattr("tsarchain.consensus.genesis.CFG.GENESIS_BLOCK_ID_DEFAULT", "test_genesis")

    bc = DummyBlockchain()
    # Mock validate_block to return True
    bc.validate_block = Mock(return_value=True)

    # Mock store update and flush
    mock_store = Mock()
    bc.ensure_utxodb = Mock(return_value=mock_store)

    result = bc.create_genesis_with_lock("miner_address", use_cores=4)

    # Assertions
    mock_coinbase_cls.assert_called_once_with(
        to_address="miner_address",
        reward=bc.get_block_reward(0),
        block_id="test_genesis",
        height=0
    )
    mock_coinbase.compute_txid.assert_called_once()
    mock_block_cls.assert_called_once_with(
        height=0,
        prev_block_hash=b"\x00" * 32,
        transactions=[mock_coinbase]
    )
    assert mock_block.bits == 0x12345678
    mock_block.mine.assert_called_once_with(use_cores=4)
    bc.validate_block.assert_called_once_with(mock_block)
    assert len(bc.chain) == 1
    assert bc.chain[0] is mock_block
    # Check dirty flags and saves
    assert bc._chain_dirty is True
    assert bc._saved is True  # save_chain called
    mock_store.update.assert_called_once_with(
        mock_block.transactions, block_height=0, autosave=False
    )
    assert bc._utxo_dirty is True
    bc.maybe_flush_utxo = Mock()
    with patch.object(bc, "maybe_flush_utxo") as mock_flush:
        pass

    # We'll just test the internal calls directly in a separate test case.
    # For this test, we can at least verify that the block is added and saves called.
    assert result is None


def test_create_genesis_block_validation_fails():
    """If validate_block returns False, raise ValueError."""
    bc = DummyBlockchain()
    bc.validate_block = Mock(return_value=False)
    with patch("tsarchain.consensus.genesis.Block") as mock_block_cls, patch("tsarchain.consensus.genesis.CoinbaseTx"):
        block = Mock()
        block.hash.return_value = b"a" * 32
        mock_block_cls.return_value = block
        with pytest.raises(ValueError, match="Genesis block validation failed"):
            bc.create_genesis_with_lock("miner")


def test_create_genesis_block_hash_mismatch(monkeypatch):
    """Raise ValueError if new genesis hash doesn't match GENESIS_HASH."""
    monkeypatch.setattr("tsarchain.consensus.genesis.GENESIS_HASH", b"a" * 32)
    bc = DummyBlockchain()
    bc.validate_block = Mock(return_value=True)
    with patch("tsarchain.consensus.genesis.Block") as mock_block_cls, patch("tsarchain.consensus.genesis.CoinbaseTx"):
        block = Mock()
        block.hash.return_value = b"b" * 32  # different
        mock_block_cls.return_value = block
        with pytest.raises(ValueError, match="does not match TSAR_GENESIS_HASH"):
            bc.create_genesis_with_lock("miner")

