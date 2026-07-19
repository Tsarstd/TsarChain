# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock

from tsarchain.network.rpc.user_rpc.category import graff_activities


@pytest.fixture
def mock_self():
    """Membuat objek self tiruan untuk dipakai sebagai argumen fungsi."""
    self_obj = MagicMock()
    # Atribut yang digunakan: rl_ip, broadcast
    self_obj.rl_ip = {}
    # broadcast.utxodb._graffiti_registry akan di-set di setiap test
    self_obj.broadcast = MagicMock()
    return self_obj


@pytest.fixture
def mock_registry():
    """Registry tiruan dengan method yang bisa di-override."""
    reg = MagicMock()
    reg.list_posts.return_value = [{"art_id": "graf123", "title": "Test"}]
    reg.list_comments.return_value = [{"comment": "Nice", "commenter": "addr1"}]
    reg.get_post.return_value = {"art_id": "graf123", "title": "Test", "stats": {}}
    reg.list_payouts.return_value = [{"txid": "tx1", "amount": 100}]
    return reg


@pytest.fixture(autouse=True)
def patch_config(monkeypatch):
    """Set konfigurasi dasar agar test stabil."""
    monkeypatch.setattr(graff_activities.CFG, "GRAFFITI_RL_IP_BURST", 10)
    monkeypatch.setattr(graff_activities.CFG, "GRAFFITI_RL_WINDOW_S", 30)
    monkeypatch.setattr(graff_activities.CFG, "GRAFFITI_RL_BACKOFF_S", 3)
    monkeypatch.setattr(graff_activities.CFG, "RPC_POW_DIFFICULTY_READ", 12)
    monkeypatch.setattr(graff_activities.CFG, "DEBUG_BENCHMARKS", False)  # matikan log benchmark


@pytest.fixture
def mock_allow_rpc_success(monkeypatch):
    """Mock allow_rpc_with_pow selalu return (True, None)."""
    def _success(*args, **kwargs):
        return True, None
    monkeypatch.setattr(graff_activities.CM, "allow_rpc_with_pow", _success)


@pytest.fixture
def mock_allow_rpc_failure(monkeypatch):
    """Mock allow_rpc_with_pow return (False, dict error)."""
    def _failure(*args, **kwargs):
        return False, {"error": "pow_required", "pow_challenge": "challenge"}
    monkeypatch.setattr(graff_activities.CM, "allow_rpc_with_pow", _failure)


# ==================== Test get_posts ====================

def test_get_posts_success(mock_self, mock_registry, mock_allow_rpc_success):
    """get_posts: sukses, registry tersedia."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"limit": 10, "offset": 5}
    result = graff_activities.get_posts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_POSTS"
    assert result["posts"] == mock_registry.list_posts.return_value
    # Verifikasi pemanggilan list_posts dengan limit dan offset yang benar
    mock_registry.list_posts.assert_called_once_with(10, 5)


def test_get_posts_default_limit_offset(mock_self, mock_registry, mock_allow_rpc_success):
    """get_posts: limit dan offset default."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {}  # tidak ada limit/offset
    result = graff_activities.get_posts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_POSTS"
    mock_registry.list_posts.assert_called_once_with(50, 0)


def test_get_posts_limit_clamp(mock_self, mock_registry, mock_allow_rpc_success):
    """get_posts: limit di-clamp antara 1 dan 500."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"limit": 1000, "offset": -5}
    result = graff_activities.get_posts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    # limit menjadi 500, offset menjadi 0
    mock_registry.list_posts.assert_called_once_with(500, 0)


def test_get_posts_no_registry(mock_self, mock_allow_rpc_success):
    """get_posts: registry None, return empty list."""
    mock_self.broadcast.utxodb._graffiti_registry = None
    message = {}
    result = graff_activities.get_posts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_POSTS"
    assert result["posts"] == []


def test_get_posts_pow_failure(mock_self, mock_allow_rpc_failure):
    """get_posts: PoW gagal, return pow_resp."""
    message = {}
    mock_self.broadcast.utxodb = None
    result = graff_activities.get_posts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result == {"error": "pow_required", "pow_challenge": "challenge"}


# ==================== Test get_comments ====================

def test_get_comments_success(mock_self, mock_registry, mock_allow_rpc_success):
    """get_comments: sukses dengan art_id."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"art_id": "graf123", "limit": 20}
    result = graff_activities.get_comments(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_COMMENTS"
    assert result["art_id"] == "graf123"
    assert result["comments"] == mock_registry.list_comments.return_value
    mock_registry.list_comments.assert_called_once_with("graf123", 20)


def test_get_comments_no_art_id(mock_self, mock_allow_rpc_success):
    """get_comments: art_id kosong, return empty comments."""
    mock_self.broadcast.utxodb._graffiti_registry = MagicMock()
    message = {"art_id": ""}  # atau tidak ada
    result = graff_activities.get_comments(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_COMMENTS"
    assert result["comments"] == []
    # Pastikan registry tidak dipanggil
    mock_self.broadcast.utxodb._graffiti_registry.list_comments.assert_not_called()


def test_get_comments_default_limit(mock_self, mock_registry, mock_allow_rpc_success):
    """get_comments: limit default 100."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"art_id": "graf123"}
    result = graff_activities.get_comments(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    mock_registry.list_comments.assert_called_once_with("graf123", 100)


def test_get_comments_limit_clamp(mock_self, mock_registry, mock_allow_rpc_success):
    """get_comments: limit di-clamp 1-500."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"art_id": "graf123", "limit": 600}
    result = graff_activities.get_comments(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    mock_registry.list_comments.assert_called_once_with("graf123", 500)


def test_get_comments_no_registry(mock_self, mock_allow_rpc_success):
    """get_comments: registry None, return empty list."""
    mock_self.broadcast.utxodb._graffiti_registry = None
    message = {"art_id": "graf123"}
    result = graff_activities.get_comments(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_COMMENTS"
    assert result["comments"] == []


def test_get_comments_pow_failure(mock_self, mock_allow_rpc_failure):
    """get_comments: PoW gagal, return pow_resp."""
    message = {"art_id": "graf123"}
    result = graff_activities.get_comments(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result == {"error": "pow_required", "pow_challenge": "challenge"}


# ==================== Test get_art ====================

def test_get_art_success(mock_self, mock_registry, mock_allow_rpc_success, monkeypatch):
    """get_art: sukses, post ditemukan."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    # Mock _normalize_art_id agar mengembalikan art_id yang sudah dinormalisasi
    def mock_normalize(aid, prefer_prefix=False):
        return aid.strip().lower()
    monkeypatch.setattr(graff_activities.GRAFFITI, "_normalize_art_id", mock_normalize)

    message = {"art_id": "graf123"}
    result = graff_activities.get_art(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_ART"
    assert result["art_id"] == "graf123"
    assert result["post"] == mock_registry.get_post.return_value
    mock_registry.get_post.assert_called_once_with("graf123")


def test_get_art_missing_art_id(mock_self, mock_allow_rpc_success):
    """get_art: art_id kosong, return error."""
    mock_self.broadcast.utxodb._graffiti_registry = MagicMock()
    message = {"art_id": ""}
    result = graff_activities.get_art(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_ART"
    assert result["error"] == "missing_art_id"
    # Pastikan registry tidak dipanggil
    mock_self.broadcast.utxodb._graffiti_registry.get_post.assert_not_called()


def test_get_art_not_found(mock_self, mock_registry, mock_allow_rpc_success, monkeypatch):
    """get_art: post tidak ditemukan, return error not_found."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    mock_registry.get_post.return_value = None  # tidak ditemukan
    def mock_normalize(aid, prefer_prefix=False):
        return aid.strip().lower()
    monkeypatch.setattr(graff_activities.GRAFFITI, "_normalize_art_id", mock_normalize)

    message = {"art_id": "graf999"}
    result = graff_activities.get_art(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_ART"
    assert result["art_id"] == "graf999"
    assert result["error"] == "not_found"


def test_get_art_no_registry(mock_self, mock_allow_rpc_success, monkeypatch):
    """get_art: registry None, return not_found."""
    mock_self.broadcast.utxodb._graffiti_registry = None
    def mock_normalize(aid, prefer_prefix=False):
        return aid.strip().lower()
    monkeypatch.setattr(graff_activities.GRAFFITI, "_normalize_art_id", mock_normalize)

    message = {"art_id": "graf123"}
    result = graff_activities.get_art(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_ART"
    assert result["art_id"] == "graf123"
    assert result["error"] == "not_found"


def test_get_art_pow_failure(mock_self, mock_allow_rpc_failure):
    """get_art: PoW gagal, return pow_resp."""
    message = {"art_id": "graf123"}
    result = graff_activities.get_art(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result == {"error": "pow_required", "pow_challenge": "challenge"}


# ==================== Test get_payouts ====================

def test_get_payouts_success(mock_self, mock_registry, mock_allow_rpc_success):
    """get_payouts: sukses dengan art_id."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"art_id": "graf123", "limit": 30}
    result = graff_activities.get_payouts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_PAYOUTS"
    assert result["art_id"] == "graf123"
    assert result["payouts"] == mock_registry.list_payouts.return_value
    mock_registry.list_payouts.assert_called_once_with("graf123", 30)


def test_get_payouts_no_art_id(mock_self, mock_allow_rpc_success):
    """get_payouts: art_id kosong, return empty payouts."""
    mock_self.broadcast.utxodb._graffiti_registry = MagicMock()
    message = {"art_id": ""}
    result = graff_activities.get_payouts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_PAYOUTS"
    assert result["payouts"] == []
    mock_self.broadcast.utxodb._graffiti_registry.list_payouts.assert_not_called()


def test_get_payouts_default_limit(mock_self, mock_registry, mock_allow_rpc_success):
    """get_payouts: limit default 100."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"art_id": "graf123"}
    result = graff_activities.get_payouts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    mock_registry.list_payouts.assert_called_once_with("graf123", 100)


def test_get_payouts_limit_clamp(mock_self, mock_registry, mock_allow_rpc_success):
    """get_payouts: limit 0 -> or 100 -> 100, clamp tetap 100."""
    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"art_id": "graf123", "limit": 0}
    result = graff_activities.get_payouts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    mock_registry.list_payouts.assert_called_once_with("graf123", 100)


def test_get_payouts_no_registry(mock_self, mock_allow_rpc_success):
    """get_payouts: registry None, return empty list."""
    mock_self.broadcast.utxodb._graffiti_registry = None
    message = {"art_id": "graf123"}
    result = graff_activities.get_payouts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result["type"] == "GRAFFITI_GET_PAYOUTS"
    assert result["payouts"] == []


def test_get_payouts_pow_failure(mock_self, mock_allow_rpc_failure):
    """get_payouts: PoW gagal, return pow_resp."""
    message = {"art_id": "graf123"}
    result = graff_activities.get_payouts(
        mock_self, message, pow_obj=None, base_identity="id",
        client_ip="127.0.0.1"
    )
    assert result == {"error": "pow_required", "pow_challenge": "challenge"}


# ==================== Test benchmark logging (optional) ====================

def test_get_comments_benchmark(mock_self, mock_registry, mock_allow_rpc_success, monkeypatch, caplog):
    """get_comments: benchmark diaktifkan dan melewati threshold."""
    monkeypatch.setattr(graff_activities.CFG, "DEBUG_BENCHMARKS", True)
    # Mock time.perf_counter agar durasi > 15ms
    mock_time = MagicMock()
    mock_time.perf_counter.side_effect = [0.0, 0.020]  # 20ms
    monkeypatch.setattr("tsarchain.utils.benchmarks.time", mock_time)

    mock_self.broadcast.utxodb._graffiti_registry = mock_registry
    message = {"art_id": "graf123", "rpc_source": "test"}
    with caplog.at_level("DEBUG", logger="tsarchain.utils.benchmarks"):
        result = graff_activities.get_comments(
            mock_self, message, pow_obj=None, base_identity="id",
            client_ip="127.0.0.1"
        )
    assert result["type"] == "GRAFFITI_GET_COMMENTS"
    assert "Benchmark" in caplog.text
    assert "20.000" in caplog.text or "20.0" in caplog.text