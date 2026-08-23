# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain - see LICENSE

import queue
import logging
from unittest.mock import patch, MagicMock

from kremlin.dialogs.log_viewer import (
    TkLogHandler, TsarLogViewer, open_log_toplevel,
    export_log_bundle, start_log_gui, launch_gui_in_thread,
)


def test_tk_log_handler():
    q = queue.Queue()
    h = TkLogHandler(q)
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "msg", (), None)
    h.emit(record)
    assert q.qsize() == 1


def test_tsar_log_viewer_lifecycle_and_features():
    with patch("kremlin.dialogs.log_viewer.tk") as mock_tk, \
         patch("kremlin.dialogs.log_viewer.ttk"), \
         patch("kremlin.dialogs.log_viewer.filedialog"), \
         patch("kremlin.dialogs.log_viewer.messagebox"):
        
        mock_tk.BooleanVar = MagicMock()
        mock_tk.StringVar = MagicMock()
        master = MagicMock()
        q = queue.Queue()
        
        # Initialize viewer
        viewer = TsarLogViewer(
            master,
            queue_=q,
            attach_to_root=True,
            filter_queue=queue.Queue()
        )
        
        # Test line parsing
        msg, lvl, mod = viewer._decode_line("[INFO] tsarchain.network: Hello")
        assert lvl == "Info"
        assert mod == "network"

        msg2, lvl2, mod2 = viewer._decode_line('{"lvl": "DEBUG", "logger": "tsarchain.core", "msg": "json test"}')
        assert lvl2 == "Debug"
        assert mod2 == "core"

        # Test log appending & record ingestion
        viewer._append_line("test log line", level_hint="INFO", module_hint="core")
        record = logging.LogRecord("tsarchain.consensus", logging.WARNING, "test.py", 1, "warn log", (), None)
        viewer._append_record(record)

        # Test filter switching
        viewer._current_module_filter = "core"
        viewer._render_from_buffer()

        # Test pump handlers
        viewer._pollqueue()
        viewer._poll_tail()
        viewer._poll_filter_updates()

        # Test actions (Clear All, Open Folder, Export)
        viewer.clear_all()
        viewer.open_log_folder()
        viewer.choose_file()
        viewer.export_logs()

        # Close
        viewer._on_close()


def test_open_log_toplevel_and_gui_launchers():
    with patch("kremlin.dialogs.log_viewer.tk") as mock_tk, \
         patch("kremlin.dialogs.log_viewer.TsarLogViewer"):
        
        mock_tk.Tk.return_value = MagicMock()
        mock_tk.Toplevel.return_value = MagicMock()

        # 1) Open log toplevel
        win = open_log_toplevel(MagicMock(), log_file="test.log")
        assert win is not None

        # 2) Start log GUI
        start_log_gui(log_file="test.log")

        # 3) Launch GUI in thread
        th = launch_gui_in_thread(log_file="test.log")
        th.join(0.1)


def test_export_log_bundle():
    with patch("kremlin.dialogs.log_viewer.zipfile.ZipFile"), \
         patch("kremlin.dialogs.log_viewer.Path.mkdir"):
        path = export_log_bundle("test_bundle.zip")
        assert path.name == "test_bundle.zip"

