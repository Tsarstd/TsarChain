# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import queue
import logging
from unittest.mock import patch, MagicMock

from tsarchain.utils.tsar_logging import (
    RedactFilter, RateLimitFilter, JsonFormatter, SafeFormatter,
    TRACE, TkLogHandler, TsarLogViewer,
    setup_logging, export_log_bundle,
    get_logger, get_ctx_logger, _module_from_logger_name,
    start_log_gui, launch_gui_in_thread, open_log_toplevel,
    _parse_argv
)


def test_module_from_logger_name():
    assert _module_from_logger_name("tsarchain.network.peer") == "network"
    assert _module_from_logger_name("tsarchain.wallet") == "wallet"
    assert _module_from_logger_name("tsarchain.core.mempool (1)") == "core"
    assert _module_from_logger_name("other_module") is None
    assert _module_from_logger_name(None) is None

def test_get_logger():
    logger = get_logger("tsarchain.test")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "tsarchain.test"
    
    default_logger = get_logger()
    assert default_logger.name == "tsarchain"

def test_get_ctx_logger():
    ctx_logger = get_ctx_logger("tsarchain.test_ctx", peer="127.0.0.1")
    assert ctx_logger.logger.name == "tsarchain.test_ctx"
    assert ctx_logger.extra["peer"] == "127.0.0.1"
    ctx_logger.trace("Trace log")

def test_trace_level():
    assert logging.getLevelName(TRACE) == "TRACE"
    logger = get_logger("tsarchain.trace_test")
    assert hasattr(logger, "trace")
    logger.trace("Trace string")

def test_redact_filter():
    f = RedactFilter()
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "test seed: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", (), None)
    f.filter(record)
    assert "[REDACTED_MNEMONIC]" in record.msg
    
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, 'ik: "0123456789abcdef0123456789abcdef"', (), None)
    f.filter(record)
    assert "[REDACTED_HEX]" in record.msg

def test_rate_limit_filter():
    f = RateLimitFilter(min_interval=0.1)
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "msg", (), None)
    assert f.filter(record) is True
    assert f.filter(record) is False # second time should be filtered

def test_json_formatter():
    f = JsonFormatter()
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "msg", (), None)
    record.processName = "MainProcess"
    record.height = 100
    record.block = "abcd"
    try:
        raise ValueError("test")
    except ValueError:
        import sys
        record.exc_info = sys.exc_info()
    formatted = f.format(record)
    data = json.loads(formatted)
    assert data["msg"] == "msg"
    assert data["lvl"] == "INFO"
    assert data["logger"] == "test"
    assert data["height"] == 100
    assert "exc" in data

def test_safe_formatter():
    f = SafeFormatter("%(message)s", "%Y-%m-%d %H:%M:%S")
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "msg", (), None)
    assert f.format(record) == "msg"
    assert hasattr(record, "height")
    assert getattr(record, "height") == "-"

def test_setup_logging():
    with patch("tsarchain.utils.tsar_logging.RotatingFileHandler"):
        with patch("tsarchain.utils.tsar_logging.logging.basicConfig"):
            logger = setup_logging(log_file="test.log", to_console=True, force=True, level="DEBUG")
            assert logger.name == "tsarchain"

def test_tk_log_handler():
    q = queue.Queue()
    h = TkLogHandler(q)
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "msg", (), None)
    h.emit(record)
    assert q.qsize() == 1

def test_tsar_log_viewer_full():
    with patch("tsarchain.utils.tsar_logging.tk") as mock_tk, \
         patch("tsarchain.utils.tsar_logging.ttk"), \
         patch("tsarchain.utils.tsar_logging.filedialog"), \
         patch("tsarchain.utils.tsar_logging.messagebox"):
        mock_tk.BooleanVar = MagicMock()
        mock_tk.StringVar = MagicMock()
        master = MagicMock()
        q = queue.Queue()
        viewer = TsarLogViewer(master, queue_=q, attach_to_root=True, filter_queue=queue.Queue())
        
        # Call UI logic
        viewer.clear_all()
        viewer.open_log_folder()
        viewer.choose_file()
        viewer.export_logs()
        
        # Test line parsing
        msg, lvl, mod = viewer._decode_line("[INFO] tsarchain.network: Hello")
        msg2, lvl2, mod2 = viewer._decode_line('{"lvl": "INFO", "logger": "tsarchain.core", "msg": "json"}')
        
        # Test appending logic
        viewer._append_line("hello", level_hint="INFO", module_hint="core")
        
        # Simulate filter
        viewer._current_module_filter = "core"
        viewer._render_from_buffer()
        
        viewer._pollqueue()
        viewer._poll_tail()
        viewer._poll_filter_updates()
        
        viewer._on_close()

def test_export_log_bundle():
    with patch("tsarchain.utils.tsar_logging.zipfile.ZipFile"):
        with patch("tsarchain.utils.tsar_logging.Path.mkdir"):
            path = export_log_bundle("test.zip")
            assert path.name == "test.zip"

def test_start_gui_functions():
    with patch("tsarchain.utils.tsar_logging.tk") as mock_tk:
        with patch("tsarchain.utils.tsar_logging.TsarLogViewer"):
            # Mock tk.Tk
            mock_tk.Tk.return_value = MagicMock()
            mock_tk.Toplevel.return_value = MagicMock()
            
            # Since start_log_gui calls mainloop, we mock mainloop
            mock_tk.Tk.return_value.mainloop = MagicMock()
            start_log_gui()
            
            th = launch_gui_in_thread()
            th.join(0.1)
            
            open_log_toplevel(MagicMock())

def test_parse_argv():
    res = _parse_argv(["--file", "out.log", "--console", "--level", "INFO"])
    assert res["file"] == "out.log"
    assert res["console"] is True
    assert res["level"] == "INFO"

def test_extra_ui_and_parsers():
    with patch("tsarchain.utils.tsar_logging.tk") as mock_tk, \
         patch("tsarchain.utils.tsar_logging.ttk"):
        mock_tk.BooleanVar = MagicMock()
        mock_tk.StringVar = MagicMock()
        master = MagicMock()
        viewer = TsarLogViewer(master, queue_=queue.Queue(), attach_to_root=False, filter_queue=None)
        
        viewer.tail_path = "dummy.log"
        viewer._truncate_log_files(delete_backups=True)
        viewer._set_status("test msg")
        try:
            viewer._update_tab_title("All")
        except Exception:
            pass
            
        msg, lvl, mod = viewer._decode_line("plain text here [ERROR]")
        assert lvl == "Error"
        
        msg, lvl, mod = viewer._decode_line('{"lvl": "DEBUG", "logger": "tsarchain.utils", "msg": "test"}')
        assert lvl == "Debug"
        assert mod == "utils"
        
        record = logging.LogRecord("tsarchain.core", logging.CRITICAL, "t.py", 1, "crit", (), None)
        viewer._append_record(record)
        
        # Test __main__ block loosely
        with patch("tsarchain.utils.tsar_logging.sys.argv", ["test.py", "--file", "dummy.log", "--no-attach"]), \
             patch("tsarchain.utils.tsar_logging.setup_logging"), \
             patch("tsarchain.utils.tsar_logging.start_log_gui"):
            import tsarchain.utils.tsar_logging
