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
    assert CFG.LMDB_KEYS_DIR == "data/keys"
    assert CFG.NODE_KEY_PATH == "data/keys/node_key"
    assert CFG.ARCHIVIST_KEY_PATH == "data/keys/archivist_key"
    assert CFG.USER_KEY_PATH == "data/keys/user_key"
    assert CFG.STORAGE_DIR == "data/archivist/storage"
