# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import os
import sys
import json
import queue
import logging
import zipfile
import platform
import threading

from pathlib import Path
from typing import Optional, Any
from collections import deque
from logging.handlers import RotatingFileHandler

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    tk = None  # type: ignore
    ttk = None  # type: ignore
    filedialog = None  # type: ignore
    messagebox = None  # type: ignore

from tsarchain.utils import config as CFG
from tsarchain.utils.tsar_logging import (
    TRACE, _DEFAULT_FMT, _DEFAULT_DATEFMT,
    _module_from_logger_name,
)

TITLE = "Tsar Logging — Minimal GUI"
ZIP_BUNDLE = "tsar_logs_bundle.zip"
MODULES = ("consensus", "contracts", "core", "mempool", "network", "storage", "utils", "wallet", "native", "archivist", "miner", "apps")


def _ensure_log_file(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch()
    except Exception:
        pass


class TkLogHandler(logging.Handler):
    """Logging handler that queues LogRecords for asynchronous GUI rendering."""
    def __init__(self, q: queue.Queue[logging.LogRecord],
                 fmt: str = _DEFAULT_FMT, datefmt: str = _DEFAULT_DATEFMT):
        super().__init__()
        self.q = q
        self.setFormatter(logging.Formatter(fmt, datefmt))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.q.put(record, block=False)
        except Exception:
            pass


class TsarLogViewer:
    """Tkinter-based log viewer dashboard with live tailing, filtering, and tabbed levels."""
    LEVELS = [
        ("All",       -1),
        ("Trace",     TRACE),
        ("Info",      logging.INFO),
        ("Debug",     logging.DEBUG),
        ("Warning",   logging.WARNING),
        ("Error",     logging.ERROR),
        ("Critical",  logging.CRITICAL),
    ]

    def __init__(
        self,
        master: Any,
        *,
        queue_: "queue.Queue[logging.LogRecord] | None" = None,
        log_file: Optional[str | os.PathLike] = None,
        attach_to_root: bool = True,
        filter_queue: "queue.Queue[str] | None" = None
    ):
        if tk is None:
            raise RuntimeError("Tkinter is not installed or available in this environment.")

        self.master = master
        self.master.title(TITLE)
        self.master.geometry("980x560")
        self.queue: "queue.Queue[logging.LogRecord]" = queue_ if queue_ is not None else queue.Queue()
        self.filter_queue = filter_queue

        # State
        self.autoscroll = tk.BooleanVar(value=True)
        self.mode_tail = False
        self.tail_path: Optional[Path] = Path(log_file) if log_file else None
        self._tail_fp = None
        self._tail_last_size = 0
        self._stop_event = threading.Event()
        self._counts = dict.fromkeys([name for name, _ in self.LEVELS], 0)

        self._buf: deque[tuple[str, str, Optional[str]]] = deque(maxlen=10000)
        self._current_module_filter = "All"

        # UI Layout
        container = ttk.Frame(self.master, padding=(8, 6, 8, 6))
        container.pack(fill=tk.BOTH, expand=True)

        topbar = ttk.Frame(container)
        topbar.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(topbar, text="Autoscroll").pack(side=tk.LEFT)
        ttk.Checkbutton(topbar, variable=self.autoscroll).pack(side=tk.LEFT, padx=(6, 16))

        ttk.Button(topbar, text="Clear All", command=self.clear_all).pack(side=tk.LEFT)
        ttk.Button(topbar, text="Open Log Folder", command=self.open_log_folder).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(topbar, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=(6, 0))

        # --- Format Mode & Pretty JSON ---
        ttk.Label(topbar, text="Format").pack(side=tk.LEFT, padx=(16, 4))
        self.format_mode = tk.StringVar(value="Auto")
        ttk.Combobox(
            topbar, textvariable=self.format_mode,
            values=["Auto", "Plain", "JSON"], state="readonly", width=7
        ).pack(side=tk.LEFT)

        self.pretty_json = tk.BooleanVar(value=False)
        ttk.Checkbutton(topbar, text="Pretty JSON", variable=self.pretty_json).pack(side=tk.LEFT, padx=(6, 0))

        # --- Module filter ---
        ttk.Label(topbar, text="Module").pack(side=tk.LEFT, padx=(16, 4))
        self.module_filter = tk.StringVar(value="All")
        ttk.Combobox(
            topbar,
            textvariable=self.module_filter,
            values=["All", *MODULES],
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT)
        self.module_filter.trace_add("write", lambda *_: self._on_module_change())

        ttk.Button(topbar, text="Open File…", command=self.choose_file).pack(side=tk.RIGHT)

        self.nb = ttk.Notebook(container)
        self.nb.pack(fill=tk.BOTH, expand=True)

        self.text_widgets: dict[str, Any] = {}
        for (name, _) in self.LEVELS:
            frame = ttk.Frame(self.nb)
            self.nb.add(frame, text=f"{name} (0)")
            text = tk.Text(frame, wrap="none", font=("Consolas", 10), undo=False)
            self._install_readonly(text)
            yscroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            xscroll = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
            text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            text.grid(row=0, column=0, sticky="nsew")
            yscroll.grid(row=0, column=1, sticky="ns")
            xscroll.grid(row=1, column=0, sticky="ew")

            text.tag_configure("DEBUG",    foreground="#A674B9")
            text.tag_configure("TRACE",    foreground="#b5c2b0")
            text.tag_configure("INFO",     foreground="#77c769")
            text.tag_configure("WARNING",  foreground="#f59e0b")
            text.tag_configure("ERROR",    foreground="#d84747")
            text.tag_configure("CRITICAL", foreground="#da69a3")

            text.configure(bg="#1a1a1a", fg="#e5e7eb", insertbackground="#ebe8e5")
            self.text_widgets[name] = text

        self.status = ttk.Label(container, text="Ready", anchor="w")
        self.status.pack(fill=tk.X, pady=(6, 0))

        self.tk_handler: Optional[TkLogHandler] = None

        if log_file:
            self.start_tail(log_file, load_history=True)

        if attach_to_root:
            self.attach_gui_handler()

        if self.filter_queue:
            self.master.after(100, self._poll_filter_updates)

        self.master.after(120, self._pollqueue)
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- Filter logic ----------

    def _poll_filter_updates(self):
        try:
            while True:
                new_filter = self.filter_queue.get_nowait()
                self._current_module_filter = new_filter
                self._on_module_change()
        except queue.Empty:
            pass
        if not self._stop_event.is_set():
            self.master.after(100, self._poll_filter_updates)

    def _category_match(self, module_hint: str | None) -> bool:
        if self._current_module_filter == "All":
            return True
        return module_hint == self._current_module_filter

    def _render_from_buffer(self):
        self._clear_ui_only()
        mapping = {
            "TRACE": "Trace", "DEBUG": "Debug", "INFO": "Info",
            "WARNING": "Warning", "ERROR": "Error", "CRITICAL": "Critical",
        }
        for msg, level_up, module in self._buf:
            if self._category_match(module):
                self._append("All", msg, tag=level_up)
                self._append(mapping.get(level_up, "Info"), msg, tag=level_up)

    def _on_module_change(self):
        try:
            self._current_module_filter = self.module_filter.get()
        except Exception:
            self._current_module_filter = "All"

        self._render_from_buffer()
        if not self._buf and self.tail_path and self.tail_path.exists():
            try:
                with self.tail_path.open("r", encoding="utf-8", errors="replace") as fp:
                    self._preload_tail_history(fp, max_bytes=512_000)
                self._render_from_buffer()
            except Exception:
                pass

    def _clear_ui_only(self):
        for name, _ in self.LEVELS:
            try:
                self.text_widgets[name].delete("1.0", tk.END)
            except Exception:
                pass
            self._counts[name] = 0
            self._update_tab_title(name)

    # ---------- Public controls ----------

    def attach_gui_handler(self):
        if self.tk_handler is None:
            self.tk_handler = TkLogHandler(self.queue)
            self.tk_handler.setLevel(logging.NOTSET)

            root = logging.getLogger()
            for handler in root.handlers[:]:
                if isinstance(handler, TkLogHandler):
                    root.removeHandler(handler)
            root.addHandler(self.tk_handler)

            try:
                for name, lg in logging.root.manager.loggerDict.items():
                    if isinstance(lg, logging.Logger) and name.startswith(("tsarchain", "apps")):
                        lg.propagate = True
                        for handler in lg.handlers[:]:
                            if isinstance(handler, TkLogHandler):
                                lg.removeHandler(handler)
            except Exception:
                pass

            self._set_status("GUI handler attached (live logging)")

    def start_tail(self, file_path: str | os.PathLike, *,
                   load_history: bool = True, history_bytes: int = 512_000):
        try:
            p = Path(file_path)
            _ensure_log_file(p)
            self._tail_fp = p.open("r", encoding="utf-8", errors="replace")
            self.tail_path = p
            self.mode_tail = True

            if load_history:
                try:
                    self._preload_tail_history(self._tail_fp, max_bytes=int(history_bytes))
                except Exception:
                    pass

            self._tail_fp.seek(0, 2)
            self._tail_last_size = self._tail_fp.tell()

            self._set_status(f"Tailing {p}")
            self.master.after(300, self._poll_tail)
        except Exception as e:
            self._set_status(f"Tail failed: {e}")
            self.mode_tail = False

    def _preload_tail_history(self, fp, *, max_bytes: int = 512_000):
        try:
            fp.seek(0, 2)
            size = fp.tell()
            start = max(0, size - int(max_bytes))
            fp.seek(start, 0)
            if start > 0:
                fp.readline()

            line = fp.readline()
            while line:
                text, level, module = self._decode_line(line)
                self._append_line(text, level_hint=level, module_hint=module)
                line = fp.readline()
        except Exception:
            pass

    # ---------- UI helpers ----------

    def clear_all(self):
        self._buf.clear()
        self._clear_ui_only()

        if self.tail_path and self.tail_path.exists():
            try:
                self._truncate_log_files(delete_backups=True)
                self._set_status("Cleared UI and erased log file")
            except Exception as e:
                if messagebox:
                    messagebox.showerror("Clear Logs", f"Failed to erase log file: {e}")
                else:
                    self._set_status(f"Clear UI only (file erase failed: {e})")
        else:
            self._set_status("Cleared UI")

    def _install_readonly(self, text: Any):
        def _block(_): return "break"

        for seq in ("<<Cut>>", "<<Paste>>", "<<Clear>>"):
            text.bind(seq, _block)

        for seq in ("<BackSpace>", "<Delete>", "<Return>", "<KP_Enter>", "<Tab>"):
            text.bind(seq, _block)

        text.bind("<Control-v>", _block)
        text.bind("<Control-x>", _block)
        text.bind("<Shift-Insert>", _block)
        text.bind("<Button-2>", _block)

        def _block_printable(e):
            if e.char and e.char.isprintable():
                return "break"
        text.bind("<Key>", _block_printable, add="+")

    def _get_target_handlers(self, p: Path) -> list:
        target_handlers = []
        for h in logging.getLogger().handlers[:]:
            try:
                if isinstance(h, RotatingFileHandler):
                    base = getattr(h, "baseFilename", None)
                    if base and Path(base) == p.resolve():
                        target_handlers.append(h)
            except Exception:
                pass
        return target_handlers

    def _truncate_handler(self, h) -> None:
        h.acquire()
        try:
            stream = getattr(h, "stream", None)
            if stream:
                stream.seek(0)
                stream.truncate(0)
                stream.flush()
            else:
                open(h.baseFilename, "w", encoding=getattr(h, "encoding", "utf-8")).close()
        finally:
            h.release()

    def _delete_backup_files(self, p: Path) -> None:
        for n in range(1, 100):
            bp = p.with_name(p.name + f".{n}")
            if not bp.exists():
                break
            try:
                bp.unlink()
            except Exception:
                pass

    def _truncate_log_files(self, delete_backups: bool = True) -> None:
        if not self.tail_path:
            return

        p = Path(self.tail_path)
        target_handlers = self._get_target_handlers(p)

        if target_handlers:
            for h in target_handlers:
                self._truncate_handler(h)
        else:
            open(p, "w", encoding="utf-8").close()

        self._tail_last_size = 0
        if self._tail_fp:
            try:
                self._tail_fp.seek(0)
                self._tail_fp.truncate(0)
            except Exception:
                pass

        if delete_backups:
            self._delete_backup_files(p)

    def open_log_folder(self):
        try:
            if self.tail_path and self.tail_path.exists():
                base = self.tail_path.parent
            else:
                base = Path("logging")
                base.mkdir(parents=True, exist_ok=True)

            if sys.platform.startswith("win"):
                os.startfile(str(base))
            elif sys.platform == "darwin":
                os.system(f'open "{base}"')
            else:
                os.system(f'xdg-open "{base}"')
        except Exception as e:
            if messagebox:
                messagebox.showerror("Open Folder", f"Failed: {e}")

    def choose_file(self):
        if not tk or not filedialog:
            return
        fp = filedialog.askopenfilename(
            title="Open log file",
            filetypes=[("Log files", "*.log *.jsonl"), ("All files", "*.*")]
        )
        if fp:
            self.clear_all()
            self.start_tail(fp)

    def export_logs(self):
        if filedialog:
            default = Path.home() / ZIP_BUNDLE
            out_path = filedialog.asksaveasfilename(
                title="Save Log Bundle",
                initialfile=default.name,
                defaultextension=".zip",
                filetypes=[("ZIP", "*.zip")],
            )
            if not out_path:
                return
        else:
            out_path = str(Path.cwd() / ZIP_BUNDLE)

        threading.Thread(
            target=self._export_worker, args=(out_path,), daemon=True
        ).start()

    def _export_worker(self, out_path: str):
        try:
            out = export_log_bundle(path=out_path)
            self.master.after(0, lambda: (
                messagebox and messagebox.showinfo("Export", f"Saved:\n{out}"),
                self._set_status(f"Exported bundle → {out}")
            ))
        except Exception as e:
            self.master.after(0, lambda: (
                messagebox and messagebox.showerror("Export", f"Failed: {e}"),
                self._set_status(f"Export failed: {e}")
            ))

    # ---------- Internal pumps ----------

    def _pollqueue(self):
        try:
            current_filter = self.module_filter.get()
            if current_filter != self._current_module_filter:
                self._current_module_filter = current_filter

            batch_count = 0
            while batch_count < 200:
                record = self.queue.get_nowait()
                self._append_record(record)
                batch_count += 1
        except queue.Empty:
            pass
        if not self._stop_event.is_set():
            self.master.after(120, self._pollqueue)

    def _poll_tail(self):
        if not self.mode_tail or not self._tail_fp:
            return
        try:
            current_filter = self.module_filter.get()
            if current_filter != self._current_module_filter:
                self._current_module_filter = current_filter

            lines_read = 0
            line = self._tail_fp.readline()
            while line and lines_read < 200:
                text, level, module = self._decode_line(line)
                self._append_line(text, level_hint=level, module_hint=module)
                lines_read += 1
                line = self._tail_fp.readline()
        except Exception:
            pass

        if not self._stop_event.is_set():
            self.master.after(250, self._poll_tail)

    def _append_record(self, record: logging.LogRecord):
        module = _module_from_logger_name(getattr(record, "name", None))

        try:
            msg = self.tk_handler.format(record) if self.tk_handler else logging.Formatter(_DEFAULT_FMT, _DEFAULT_DATEFMT).format(record)
            level_up = record.levelname.upper()
        except Exception:
            msg, level_up = record.getMessage(), "INFO"

        self._buf.append((msg, level_up, module))

        if not self._category_match(module):
            return
        mapping = {
            "TRACE": "Trace", "DEBUG": "Debug", "INFO": "Info",
            "WARNING": "Warning", "ERROR": "Error", "CRITICAL": "Critical",
        }
        self._append("All", msg, tag=level_up)
        self._append(mapping.get(level_up, "Info"), msg, tag=level_up)

    def _decode_line(self, line: str) -> tuple[str, Optional[str], Optional[str]]:
        mode = self.format_mode.get() if tk else "Auto"
        txt = line.rstrip("\n")

        def detect_level_from_text(s: str) -> Optional[str]:
            up = s.upper()
            for name, _ in self.LEVELS[1:]:
                token = f"[{name.upper()}]"
                if token in up:
                    return name
            return None

        def extract_module_from_plain(s: str) -> Optional[str]:
            bracket_pos = s.find(']')
            if bracket_pos == -1:
                return None
            after = s[bracket_pos+1:].strip()
            tokens = after.split(maxsplit=3)
            for token in tokens:
                clean_tok = token.rstrip(":")
                mod = _module_from_logger_name(clean_tok)
                if mod:
                    return mod
            return None

        if mode == "Plain":
            level = detect_level_from_text(txt)
            module = extract_module_from_plain(txt)
            return txt, level, module

        try:
            obj = json.loads(txt)
            lvl = str(obj.get("lvl", obj.get("level", ""))).upper()
            level = lvl.title() if lvl in {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"} else None
            logger_name = obj.get("logger", "")
            module = _module_from_logger_name(str(logger_name))
            text = (json.dumps(obj, ensure_ascii=False, indent=2)
                    if self.pretty_json.get()
                    else json.dumps(obj, ensure_ascii=False))
            return text, level, module
        except Exception:
            level = detect_level_from_text(txt)
            module = extract_module_from_plain(txt)
            return txt, level, module

    def _append_line(self, line: str, *, level_hint: Optional[str] = None, module_hint: Optional[str] = None):
        tag = (level_hint or "Info").upper()
        self._buf.append((line, tag, module_hint))
        if not self._category_match(module_hint):
            return
        self._append("All", line, tag=tag)
        self._append(level_hint or "Info", line, tag=tag)

    def _append(self, tab_name: str, text: str, tag: Optional[str] = None):
        valid_tabs = ["All", "Trace", "Info", "Debug", "Warning", "Error", "Critical"]
        if tab_name not in valid_tabs:
            return

        w = self.text_widgets.get(tab_name)
        if not w:
            return
        try:
            w.insert(tk.END, text + "\n", (tag or "INFO",))
            self._counts[tab_name] += 1
            self._update_tab_title(tab_name)
            if self.autoscroll and self.autoscroll.get():
                w.see(tk.END)
        except Exception:
            pass

    def _update_tab_title(self, tab_name: str):
        try:
            idx = [name for (name, _) in self.LEVELS].index(tab_name)
            self.nb.tab(idx, text=f"{tab_name} ({self._counts[tab_name]})")
        except Exception:
            pass

    def _set_status(self, msg: str):
        try:
            self.status.configure(text=msg)
        except Exception:
            pass

    def _on_close(self):
        try:
            self._stop_event.set()
            if self.tk_handler:
                root = logging.getLogger()
                try:
                    root.removeHandler(self.tk_handler)
                except Exception:
                    pass
            if self._tail_fp:
                self._tail_fp.close()
        except Exception:
            pass
        try:
            self.master.destroy()
        except Exception:
            pass


# =========================
# Public Helper Functions
# =========================

def open_log_toplevel(master, log_file: Optional[str | os.PathLike] = None, attach_to_root: bool = False):
    """Open a Toplevel window with TsarLogViewer."""
    if tk is None:
        raise RuntimeError("Tkinter is not available in this environment.")
    win = tk.Toplevel(master)
    win.title(TITLE)
    TsarLogViewer(win, queue_=queue.Queue(), log_file=log_file, attach_to_root=attach_to_root)
    return win


def export_log_bundle(path: str = ZIP_BUNDLE) -> Path:
    """Export log files and system context into a zipped bundle."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    files_abs: dict[Path, Path] = {}
    def _add(p: Path):
        try:
            if p.exists():
                rp = p.resolve()
                files_abs.setdefault(rp, p)
        except Exception:
            pass

    root = logging.getLogger()
    for h in root.handlers[:]:
        try:
            try:
                h.flush()
            except Exception:
                pass
            if isinstance(h, RotatingFileHandler):
                p = Path(getattr(h, "baseFilename"))
                _add(p)
                for bp in p.parent.glob(p.name + ".*"):
                    if bp.is_file():
                        _add(bp)
        except Exception:
            pass

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("log_info.txt", "\n".join([
            f"Python Version : {platform.python_version()}",
            f"Operation System : {platform.platform()}",
            f"Mode : {'DEV' if CFG.IS_DEV else 'PROD'}",
            f"Log Level : {CFG.LOG_LEVEL}",
            f"Log Format : {CFG.LOG_FORMAT}",
            f"Log Rate Limit/sec : {CFG.LOG_RATE_LIMIT_SECONDS}",
        ]))
        for rp, p in sorted(files_abs.items(), key=lambda kv: (kv[1].stem, kv[1].suffix)):
            try:
                z.write(rp, p.name)
            except Exception:
                pass
    return out.resolve()


def start_log_gui(log_file: Optional[str | os.PathLike] = None, title: Optional[str] = None) -> None:
    """Start standalone TsarLogViewer application."""
    if tk is None:
        raise RuntimeError("Tkinter is not available in this environment.")
    root = tk.Tk()
    if title:
        root.title(title)
    TsarLogViewer(root, queue_=queue.Queue(), log_file=log_file, attach_to_root=True)
    root.mainloop()


def launch_gui_in_thread(log_file: Optional[str | os.PathLike] = None) -> threading.Thread:
    """Launch GUI log viewer in a background thread."""
    def gui_wrapper():
        start_log_gui(log_file=log_file)

    t = threading.Thread(target=gui_wrapper, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    start_log_gui()

