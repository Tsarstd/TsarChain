# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import sys
from pathlib import Path
from unittest.mock import patch

from tsarchain.utils import config as CFG


def test_project_root_type():
    assert isinstance(CFG.PROJECT_ROOT, Path)
    assert CFG.PROJECT_ROOT.exists()


def test_get_base_dir_normal():
    base_dir = CFG.get_base_dir()
    assert isinstance(base_dir, Path)
    assert (base_dir / "src").exists() or (base_dir / "apps").exists()


def test_get_base_dir_frozen(tmp_path):
    mock_exe = tmp_path / "mock_app.exe"
    mock_exe.touch()
    
    with patch.object(sys, "frozen", True, create=True), \
         patch.object(sys, "executable", str(mock_exe)):
        base_dir = CFG.get_base_dir()
        assert base_dir == tmp_path.resolve()


def test_lmdb_paths_anchored_to_project_root():
    assert str(CFG.PROJECT_ROOT) in CFG.LMDB_CHAIN_DIR
    assert str(CFG.PROJECT_ROOT) in CFG.LMDB_UTXO_DIR
    assert str(CFG.PROJECT_ROOT) in CFG.LMDB_STATE_DIR
    assert str(CFG.PROJECT_ROOT) in CFG.KEYS_DATA_DIR
