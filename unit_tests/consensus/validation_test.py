import time
import pytest
import threading
from unittest.mock import Mock, patch

from tsarchain.consensus.validation import ValidationMixin

# -------------------------------------------------------------------
# Fixtures for mock objects
# -------------------------------------------------------------------

@pytest.fixture
def mock_block():
    """Return a minimal mock Block object."""
    block = Mock()
    block.height = 1
    block.prev_block_hash = b"prevhash"
    block.transactions = []
    block.bits = 0x1d00ffff
    block.merkle_root = b"merkle"
    block.timestamp = int(time.time())
    block.hash = Mock(return_value=b"blockhash")
    block.header = Mock(return_value=b"header")
    return block

@pytest.fixture(autouse=True)
def mock_randomx(monkeypatch):
    from tsarchain.consensus.validation import CFG
    if CFG.POW_ALGO == "randomx":
        monkeypatch.setattr(
            "tsarchain.utils.helpers.pow_hash_verify_light",
            lambda *args, **kwargs: None
        )
        monkeypatch.setattr(
            "tsarchain.utils.helpers.pow_key_for_height",
            lambda h: b"dummy_key"
        )
        monkeypatch.setattr(
            "tsarchain.utils.helpers.pow_hash_verify_light",
            lambda *args, **kwargs: b"dummy_hash"
        )

@pytest.fixture
def mock_tx():
    """Return a minimal mock Transaction object."""
    tx = Mock()
    tx.is_coinbase = False
    tx.inputs = []
    tx.outputs = []
    tx.txid = None
    tx.txid_hex = None
    tx.fee = 0
    def compute_txid():
        tx.txid = b"txid"
        tx.txid_hex = "txid"
    tx.compute_txid = compute_txid
    return tx

@pytest.fixture
def mock_coinbase_tx():
    tx = Mock()
    tx.is_coinbase = True
    tx.inputs = []
    tx.outputs = []
    tx.txid = b"coinbase_txid"
    tx.txid_hex = "coinbase_txid"
    return tx

# -------------------------------------------------------------------
# Test class
# -------------------------------------------------------------------

class TestValidationMixin:

    # Helper to create a concrete instance of the mixin with required attributes
    def create_instance(self):
        class DummyConsensus(ValidationMixin):
            def __init__(self):
                self.lock = threading.Lock()
                self.chain = []
                self.height = -1
                self._last_block_validation_error = None
                self._cumulative_supply_until = Mock(return_value=0)
                self._scheduled_reward = Mock(return_value=50)
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
                self._ensure_utxodb = Mock(return_value=None)
                self._chain_state_token_locked = Mock(return_value=(0, b"token"))
                self._validate_chain_context_locked = Mock(return_value=True)
                self._check_sigops_budget = Mock(return_value=True)
                self._validate_merkle = Mock(return_value=True)
                self._ensure_unique_txids = Mock(return_value=True)
                self._check_block_limits = Mock(return_value=True)
                self._validate_pow = Mock(return_value=True)
                self._serialize_tx_cached = Mock(return_value=b"serialized")
                self._compute_txids_for_block = Mock(return_value=True)
        return DummyConsensus()

    # -------------------------------------------------------------------
    # Tests for _ensure_warm
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_not_randomx(self, mock_cfg):
        instance = self.create_instance()
        mock_cfg.POW_ALGO = "sha256"
        with patch("tsarchain.consensus.validation.H") as mock_H:
            instance._ensure_warm(100)
            mock_H.pow_hash_verify_light.assert_not_called()

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_epoch_already_warmed(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance.__class__._pow_epoch_warmed = set([0])
        with patch("tsarchain.consensus.validation.H") as mock_H:
            instance._ensure_warm(50)
            mock_H.pow_hash_verify_light.assert_not_called()
        instance.__class__._pow_epoch_warmed = set()

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_calls_pow_hash(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance.__class__._pow_epoch_warmed = set()
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.pow_key_for_height = Mock(return_value=b"key")
            mock_H.pow_hash_verify_light = Mock()
            instance._ensure_warm(150)
            mock_H.pow_hash_verify_light.assert_called_once_with(b"\x00"*80, key_hint=b"key")
            assert 1 in instance.__class__._pow_epoch_warmed
        instance.__class__._pow_epoch_warmed = set()

    # -------------------------------------------------------------------
    # Tests for _warm_pow_context
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.threading.Thread")
    def test_warm_pow_context_not_randomx(self, mock_thread, mock_cfg):
        mock_cfg.POW_ALGO = "sha256"
        instance = self.create_instance()
        instance._warm_pow_context(100)
        mock_thread.assert_not_called()

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.threading.Thread")
    def test_warm_pow_context_already_scheduled(self, mock_thread, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance._pow_warm_next_epoch = 2
        instance._warm_pow_context(150)
        mock_thread.assert_not_called()

    # -------------------------------------------------------------------
    # Tests for validate_block
    # -------------------------------------------------------------------

    def test_validate_block_missing_fields(self):
        instance = self.create_instance()
        block = Mock()
        block.height = None
        block.prev_block_hash = b"hash"
        block.transactions = []   # empty, triggers missing_fields
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "block_missing_fields"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_success(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]   # non‑empty to pass initial check
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        result = instance.validate_block(block)
        assert result is True
        assert instance._last_block_validation_error is None

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_pow_invalid(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_pow.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "pow_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_compute_txids_fails(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._compute_txids_for_block.return_value = False
        instance._last_block_validation_error = "tx_serialize_failed"  # pre‑set
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_serialize_failed"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_merkle_mismatch(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_merkle.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "merkle_mismatch"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_duplicate_txid(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._ensure_unique_txids.return_value = False
        instance._last_block_validation_error = "duplicate_or_missing_txid"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "duplicate_or_missing_txid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_block_limits_exceeded(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._check_block_limits.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "block_limits_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_chain_context_invalid(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_chain_context_locked.return_value = False
        instance._last_block_validation_error = "chain_context_invalid"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "chain_context_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_sigops_limit_exceeded(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._check_sigops_budget.return_value = False
        instance._last_block_validation_error = "sigops_limit_exceeded"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "sigops_limit_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_transactions_fail(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 1  # > 0, so _validate_transactions is called
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        def fake_validate(*args, **kwargs):
            instance._last_block_validation_error = "tx_validation_failed"
            return False

        instance._validate_transactions = Mock(side_effect=fake_validate)
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_validation_failed"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_state_changed(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        call_count = 0
        def fake_token():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (0, b"token1")
            else:
                return (1, b"token2")

        instance._chain_state_token_locked = Mock(side_effect=fake_token)
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "chain_state_changed_during_validation"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_unexpected_exception(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        instance._validate_pow = Mock(side_effect=Exception("pow error"))
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "unexpected_validation_error"

    # -------------------------------------------------------------------
    # Tests for _validate_transactions
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_empty_txs(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        block = Mock()
        block.transactions = []
        instance._ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "empty_block_transactions"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_missing_coinbase(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        tx = Mock()
        tx.is_coinbase = False
        block = Mock()
        block.transactions = [tx]
        instance._ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "missing_coinbase"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_duplicate_coinbase(self, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        cb = Mock()
        cb.is_coinbase = True
        cb2 = Mock()
        cb2.is_coinbase = True
        block = Mock()
        block.transactions = [cb, cb2]
        instance._ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "duplicate_coinbase"

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.H")
    def test_validate_transactions_serialize_fails(self, mock_H, mock_cfg):
        mock_cfg.POW_ALGO = "randomx"
        instance = self.create_instance()
        cb = Mock()
        cb.is_coinbase = True
        tx = Mock()
        tx.is_coinbase = False
        block = Mock()
        block.transactions = [cb, tx]
        block.height = 1
        instance._ensure_utxodb = Mock(return_value=None)
        instance._serialize_tx_cached = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_serialize_failed"