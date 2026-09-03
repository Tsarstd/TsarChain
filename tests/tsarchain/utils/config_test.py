# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest

from tsarchain.utils import config as CFG


@pytest.mark.no_storage_isolation
def test_clean_relative_paths():
    assert CFG.NODE_DATA_DIR == "data/node"
    assert CFG.LMDB_CHAIN_DIR == "data/node/chain"
    assert CFG.LMDB_UTXO_DIR == "data/node/utxo"
    assert CFG.LMDB_STATE_DIR == "data/node/state"
    assert CFG.LMDB_CHAT_PREKEYS == "data/node/chat_prekeys"
    assert CFG.LMDB_KEYS_DIR == "data/keys"
    assert CFG.STORAGE_DIR == "data/archivist/storage"
    assert CFG.WEB_SERVER_HOST == "0.0.0.0"
    assert CFG.WEB_SERVER_PORT == 4000
    assert CFG.WEB_NODE_HOST == "127.0.0.1"
    assert CFG.WEB_NODE_PORT == 38169


@pytest.mark.no_storage_isolation
def test_node_public_ip_urls():
    assert CFG.WEB_EXPLORER_URL == f"http://{CFG.NODE_PUBLIC_IP}/?search="
    assert CFG.SNAPSHOT_FILE_URL == f"http://{CFG.NODE_PUBLIC_IP}:8121/tsarchain.tar.gz"
