# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest
from tsarchain.utils import config as CFG


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "no_storage_isolation: mark test to skip automatic storage directory isolation"
    )


@pytest.fixture(autouse=True)
def isolate_unit_test_storage(request, tmp_path, monkeypatch):
    """
    Automatically isolates storage, database, and cache paths for all unit tests
    so that unit tests operate in a temporary directory and NEVER touch or overwrite
    the real development 'data/' directory.
    """
    if request.node.get_closest_marker("no_storage_isolation"):
        yield
        return

    mock_data = tmp_path / "mock_test_data"
    mock_data.mkdir(parents=True, exist_ok=True)

    # 1. Patch tsarchain/node database paths
    monkeypatch.setattr(CFG, "NODE_DATA_DIR", str(mock_data / "node"))
    monkeypatch.setattr(CFG, "LMDB_KEYS_DIR", str(mock_data / "keys"))
    monkeypatch.setattr(CFG, "LMDB_CHAIN_DIR", str(mock_data / "node/chain"))
    monkeypatch.setattr(CFG, "LMDB_UTXO_DIR", str(mock_data / "node/utxo"))
    monkeypatch.setattr(CFG, "LMDB_STATE_DIR", str(mock_data / "node/state"))
    monkeypatch.setattr(CFG, "LMDB_GRAFFITI_DIR", str(mock_data / "node/graffiti"))
    monkeypatch.setattr(CFG, "LMDB_MEMPOOL_DIR", str(mock_data / "node/mempool"))

    # 2. Patch web database and cache paths
    monkeypatch.setattr(CFG, "WEB_DATABASE_PATH", str(mock_data / "web"))
    monkeypatch.setattr(CFG, "WEB_MEDIA_CACHE_DIR", str(mock_data / "web/graffiti_cache"))
    monkeypatch.setattr(CFG, "WEB_RECEIPTS_DIR", str(mock_data / "web/receipts"))
    monkeypatch.setattr(CFG, "WEB_HISTORY_BOOKS_DIR", str(mock_data / "web/history_books"))

    # 3. Patch snapshot and archivist paths
    monkeypatch.setattr(CFG, "SNAPSHOT_META_PATH", str(mock_data / "node/snapshot.meta.json"))
    monkeypatch.setattr(CFG, "SNAPSHOT_BACKUP_DIR", str(mock_data / "snapshot"))
    monkeypatch.setattr(CFG, "ARCHIVIST_INDEX_DB_PATH", str(mock_data / "archivist/storage/index_db"))
    monkeypatch.setattr(CFG, "ARCHIVIST_KEY_PATH", str(mock_data / "keys/archivist_key"))
    monkeypatch.setattr(CFG, "ARCHIVIST_PAYOUT_GUARD_DB_PATH", str(mock_data / "archivist/storage/payout_guard"))
    monkeypatch.setattr(CFG, "STORAGE_DIR", str(mock_data / "archivist/storage"))

    # 4. Patch centralized key identifiers and paths
    monkeypatch.setattr(CFG, "NODE_KEY_PATH", str(mock_data / "keys/node_key"))
    monkeypatch.setattr(CFG, "PEER_KEYS_PATH", str(mock_data / "keys/peer_keys"))
    monkeypatch.setattr(CFG, "USER_KEY_PATH", str(mock_data / "keys/user_key"))
    monkeypatch.setattr(CFG, "REGISTRY_PATH", str(mock_data / "keys/wallet_registry"))
    monkeypatch.setattr(CFG, "CHAT_STATE", str(mock_data / "keys/chat_config"))
    monkeypatch.setattr(CFG, "CHAT_KEYS_DIR", str(mock_data / "keys/chat_keys"))
    monkeypatch.setattr(CFG, "PREKEY_DIR", str(mock_data / "keys/chat_prekeys"))
    monkeypatch.setattr(CFG, "CHAT_SESSION_DIR", str(mock_data / "keys/chat_sessions"))

    # 6. Clear singleton storage caches before test
    try:
        from tsarchain.storage import kv
        kv._native_stores.clear()
        kv._native_store = None
    except Exception:
        pass

    try:
        from web.Backend.src.python.logic_web import db_cache
        db_cache._store = None
    except Exception:
        pass

    yield

    # Clear singleton storage caches after test
    try:
        from tsarchain.storage import kv
        kv._native_stores.clear()
        kv._native_store = None
    except Exception:
        pass

    try:
        from web.Backend.src.python.logic_web import db_cache
        db_cache._store = None
    except Exception:
        pass
