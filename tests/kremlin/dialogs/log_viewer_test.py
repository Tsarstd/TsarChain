# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain - see LICENSE

import queue
import logging
import pytest
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


def test_tsar_log_viewer_lifecycle_and_features(tmp_path):
    dummy_log = tmp_path / "dummy.log"
    dummy_log.write_text("[INFO] test log line\n", encoding="utf-8")
    dummy_zip = tmp_path / "dummy.zip"

    with patch("kremlin.dialogs.log_viewer.tk") as mock_tk, \
         patch("kremlin.dialogs.log_viewer.ttk"), \
         patch("kremlin.dialogs.log_viewer.filedialog") as mock_filedialog, \
         patch("kremlin.dialogs.log_viewer.messagebox"), \
         patch("kremlin.dialogs.log_viewer.os.system") as mock_os_system, \
         patch("kremlin.dialogs.log_viewer.os.startfile", create=True) as mock_startfile, \
         patch("kremlin.dialogs.log_viewer.threading.Thread") as mock_thread, \
         patch("kremlin.dialogs.log_viewer.export_log_bundle") as mock_export_bundle:

        mock_tk.BooleanVar = MagicMock()
        mock_tk.StringVar = MagicMock()
        mock_filedialog.askopenfilename.return_value = str(dummy_log)
        mock_filedialog.asksaveasfilename.return_value = str(dummy_zip)
        mock_export_bundle.return_value = dummy_zip

        master = MagicMock()
        q = queue.Queue()

        # Initialize viewer
        viewer = TsarLogViewer(
            master,
            queue_=q,
            attach_to_root=False,
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
        assert mock_os_system.called or mock_startfile.called

        viewer.choose_file()
        assert viewer.tail_path is not None

        viewer.export_logs()
        assert mock_thread.called

        # Test export worker execution synchronously
        viewer._export_worker(str(dummy_zip))
        assert mock_export_bundle.called

        # Test export worker error handling
        mock_export_bundle.side_effect = RuntimeError("Disk full")
        viewer._export_worker(str(dummy_zip))

        # Close and verify cleanup
        viewer._on_close()
        assert viewer._stop_event.is_set()


def test_open_log_toplevel_and_gui_launchers():
    with patch("kremlin.dialogs.log_viewer.tk") as mock_tk, \
         patch("kremlin.dialogs.log_viewer.TsarLogViewer") as mock_viewer:

        mock_tk.Tk.return_value = MagicMock()
        mock_tk.Toplevel.return_value = MagicMock()

        # 1) Open log toplevel
        win = open_log_toplevel(MagicMock(), log_file="test.log")
        assert win is not None
        assert mock_viewer.called

        # 2) Start log GUI
        mock_root = MagicMock()
        mock_tk.Tk.return_value = mock_root
        start_log_gui(log_file="test.log", title="Custom Title")
        mock_root.title.assert_called_with("Custom Title")
        mock_root.mainloop.assert_called_once()

    # 3) Launch GUI in thread (start_log_gui mocked to prevent GUI spawn and mainloop lock)
    with patch("kremlin.dialogs.log_viewer.start_log_gui") as mock_start_gui:
        th = launch_gui_in_thread(log_file="test.log")
        th.join(timeout=2.0)
        assert not th.is_alive()
        mock_start_gui.assert_called_once_with(log_file="test.log")


def test_open_log_toplevel_and_start_gui_no_tk():
    with patch("kremlin.dialogs.log_viewer.tk", None):
        with pytest.raises(RuntimeError, match="Tkinter is not"):
            open_log_toplevel(MagicMock())

        with pytest.raises(RuntimeError, match="Tkinter is not"):
            start_log_gui()

        with pytest.raises(RuntimeError, match="Tkinter is not"):
            TsarLogViewer(MagicMock())


def test_export_log_bundle(tmp_path):
    bundle_path = tmp_path / "test_bundle.zip"
    mock_root = MagicMock()
    mock_root.handlers = []
    with patch("kremlin.dialogs.log_viewer.zipfile.ZipFile"), \
         patch("kremlin.dialogs.log_viewer.logging.getLogger", return_value=mock_root), \
         patch("kremlin.dialogs.log_viewer.Path.mkdir"):
        path = export_log_bundle(str(bundle_path))
        assert path.name == "test_bundle.zip"
