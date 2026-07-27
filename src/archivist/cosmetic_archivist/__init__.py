# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

"""
Cosmetic module for TsarChain CLI Archivist UI/UX.
Provides rich terminal graphics, banners, system snapshot, and live TUI dashboard.
"""

from .interface import (
    print_banner,
    print_system_snapshot,
    get_user_input,
    _enable_windows_vt100,
    format_files_table,
    format_pool_table,
)
from .tui import ArchivistTUI, create_tui_logger

__all__ = [
    "print_banner",
    "print_system_snapshot",
    "get_user_input",
    "_enable_windows_vt100",
    "format_files_table",
    "format_pool_table",
    "ArchivistTUI",
    "create_tui_logger",
]
