# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import os
from unittest.mock import patch
from tsarchain.storage.db import AtomicJSONFile

def test_atomic_json_file_init_defaults():
    # Test initialization with default values
    with patch.dict(os.environ, {}, clear=True):
        db_file = AtomicJSONFile("dummy_db.json")
        assert db_file.keep_backups == 3
        assert db_file.backup_interval_sec == 900
        assert db_file.dedup_backups is True

def test_atomic_json_file_init_explicit_args():
    # Test initialization with explicit constructor arguments
    with patch.dict(os.environ, {}, clear=True):
        db_file = AtomicJSONFile(
            "dummy_db.json",
            keep_backups=5,
            backup_interval_sec=1200,
            dedup_backups=False
        )
        assert db_file.keep_backups == 5
        assert db_file.backup_interval_sec == 1200
        assert db_file.dedup_backups is False

def test_atomic_json_file_init_env_vars():
    # Test initialization using environment variables
    env_vars = {
        "TSAR_BACKUP_KEEP": "10",
        "TSAR_BACKUP_INTERVAL_SEC": "3600",
        "TSAR_BACKUP_DEDUP": "false"
    }
    with patch.dict(os.environ, env_vars):
        db_file = AtomicJSONFile("dummy_db.json")
        assert db_file.keep_backups == 10
        assert db_file.backup_interval_sec == 3600
        assert db_file.dedup_backups is False

def test_atomic_json_file_init_negative_values():
    # Test negative constructor arguments, which should result in max(0, val)
    with patch.dict(os.environ, {}, clear=True):
        db_file = AtomicJSONFile(
            "dummy_db.json",
            keep_backups=-5,
            backup_interval_sec=-10
        )
        assert db_file.keep_backups == 0
        assert db_file.backup_interval_sec == 0
