# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
'''
HOW TO USE logging in your code:

self.log.trace("very technical details, like : PING , mining detail, etc. usually unnecessary")
self.log.info("normal event / milestone")
self.log.debug("technical details for diagnosis")
self.log.warning("a non-fatal condition that needs attention")
self.log.error("handled error")
self.log.critical("fatal condition")
self.log.exception("context message when an exception occurs") >automatically include traceback
'''

from __future__ import annotations

import os, sys, logging, threading, queue, re, json, time, hashlib, platform, zipfile
import tkinter as tk
from collections import deque
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

from tsarchain.utils import config as CFG

# ===== TRACE level (di bawah DEBUG) =====
TRACE = 9
logging.addLevelName(TRACE, "TRACE")
def _trace(self, msg, *a, **k):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, a, **k)
logging.Logger.trace = _trace

# --- Module filter helpers ---
MODULES = ("consensus", "contracts", "core", "mempool", "network", "storage", "utils", "wallet")
_RE_LOG_PLAIN = re.compile(r"\]\s+[^\s]+\s+([^:]+):\s")

def _module_from_logger_name(name: str | None) -> str | None:
    if not name:
        return None
    base = name.split("(", 1)[0]
    parts = base.split(".")
    try:
        i = parts.index("tsarchain")
    except ValueError:
        return None
    if i + 1 < len(parts):
        mod = parts[i + 1].strip().lower()
        return mod
    return None

# =========================
# 0) Defaults & helpers
# =========================

def _ensure_log_file(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch()
    except Exception:
        pass

# =========================
# 1) Core logging setup
# =========================

if CFG.LOG_SHOW_PROCESS:
    _DEFAULT_FMT = "%(asctime)s [%(levelname)s] %(processName)s %(name)s: %(message)s"
else:
    _DEFAULT_FMT = f"%(asctime)s [%(levelname)s] {CFG.LOG_PROC_PLACEHOLDER} %(name)s: %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


class RedactFilter(logging.Filter):
    RE_SEED = re.compile(r"\b([a-z]{3,}\s){11,23}[a-z]{3,}\b", re.I)
    RE_WIF  = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
    def filter(self, record):
        msg = record.getMessage()
        msg = self.RE_SEED.sub("[REDACTED_MNEMONIC]", msg)
        msg = self.RE_WIF.sub("[REDACTED_WIF]", msg)
        record.msg, record.args = msg, None
        return True

class RateLimitFilter(logging.Filter):
    def __init__(self, min_interval: float = 2.0):
        super().__init__()
        self.min_interval = float(min_interval)
        self._last: dict[str, float] = {}
    def filter(self, record):
        base = f"{record.name}|{record.levelno}|{record.msg}"
        key = hashlib.blake2b(base.encode(), digest_size=8).hexdigest()
        now = time.monotonic()
        last = self._last.get(key, 0.0)
        if (now - last) < self.min_interval:
            return False
        self._last[key] = now
        return True

class JsonFormatter(logging.Formatter):
    def format(self, record):
        d = {
            "ts": self.formatTime(record, _DEFAULT_DATEFMT),
            "lvl": record.levelname,
            "logger": record.name,
            "proc": (record.processName if CFG.LOG_SHOW_PROCESS else CFG.LOG_PROC_PLACEHOLDER),
            "msg": record.getMessage(),
        }
        for k in ("height", "block", "peer"):
            v = getattr(record, k, None)
            if v not in (None, "-"):
                d[k] = v
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, ensure_ascii=False)

class SafeFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "height"): record.height = "-"
        if not hasattr(record, "block"):  record.block  = "-"
        if not hasattr(record, "peer"):   record.peer   = "-"
        return super().format(record)

class ContextAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("height", "-")
        extra.setdefault("block", "-")
        extra.setdefault("peer", "-")
        return msg, kwargs
    
    def isEnabledFor(self, level: int) -> bool:
        return self.logger.isEnabledFor(level)

    def trace(self, msg, *args, **kwargs):
        if self.logger.isEnabledFor(TRACE):
            self.log(TRACE, msg, *args, **kwargs)


def get_ctx_logger(name: str = "tsarchain", **ctx) -> ContextAdapter:
    return ContextAdapter(get_logger(name), ctx)

def setup_logging(
    log_file: str | os.PathLike | None = None,
    level: int | str | None = None,
    to_console: bool | None = None,
    rotate_max_bytes: int | None = None,
    backup_count: int | None = None,
    force: bool = False,
    fmt: str = _DEFAULT_FMT,
    datefmt: str = _DEFAULT_DATEFMT,) -> logging.Logger:

    if level is None:
        level = CFG.LOG_LEVEL
    if log_file is None:
        log_file = CFG.LOG_PATH

    # Get preference from CFG when argument is None
    if to_console is None:
        to_console = bool(getattr(CFG, "LOG_TO_CONSOLE", True))
    if rotate_max_bytes is None:
        rotate_max_bytes = int(getattr(CFG, "LOG_ROTATE_MAX_BYTES", 5_000_000))
    if backup_count is None:
        backup_count = int(getattr(CFG, "LOG_BACKUP_COUNT", 3))

    log_path = Path(log_file)
    if log_path.parent and not log_path.parent.exists():
        log_path.parent.mkdir(parents=True, exist_ok=True)

    handlers: list[logging.Handler] = []
    as_json = str(CFG.LOG_FORMAT).lower() == "json"
    rate_seconds_console = float(getattr(CFG, "LOG_RATE_LIMIT_SECONDS", 0.0))
    rate_seconds_file    = float(getattr(CFG, "LOG_FILE_RATE_LIMIT_SECONDS", 0.0))

    # --- File handler ---
    fh = RotatingFileHandler(
        log_path, maxBytes=int(rotate_max_bytes), backupCount=int(backup_count),
        encoding="utf-8", delay=True
    )
    file_fmt = JsonFormatter() if as_json else SafeFormatter(fmt, datefmt)
    fh.setFormatter(file_fmt)
    fh.addFilter(RedactFilter())
    if rate_seconds_file > 0.0:
        fh.addFilter(RateLimitFilter(rate_seconds_file))
    handlers.append(fh)

    # --- Console handler (optional) ---
    if to_console:
        console_fmt = JsonFormatter() if as_json else SafeFormatter(fmt, datefmt)
        sh = logging.StreamHandler()
        sh.setFormatter(console_fmt)
        sh.addFilter(RedactFilter())
        if rate_seconds_console > 0.0:
            sh.addFilter(RateLimitFilter(rate_seconds_console))
        handlers.append(sh)

    # Level
    lvl = level
    if isinstance(lvl, str):
        try:
            lvl = logging._nameToLevel.get(lvl.upper(), lvl)
        except Exception:
            pass

    logging.basicConfig(level=lvl, handlers=handlers, force=force)
    _name = logging.getLevelName(lvl) if isinstance(lvl, int) else str(level)
    logging.getLogger("tsarchain").trace(
        "Logging configured: level=%s file=%s format=%s console=%s rotate=%s backup=%s",
        _name, str(log_path), ("json" if as_json else "plain"),
        to_console, rotate_max_bytes, backup_count
    )
    return logging.getLogger("tsarchain")


def get_logger(name: Optional[str] = None) -> logging.Logger:
    base = "tsarchain" if not name else name
    return logging.getLogger(base)


# =========================
# 2) Tkinter GUI Handler
# =========================

class TkLogHandler(logging.Handler):
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


# =========================
# 3) GUI — TsarLogViewer
# =========================

class TsarLogViewer:
    LEVELS = [
        ("All",       -1),
        ("Trace",     TRACE),
        ("Info",      logging.INFO),
        ("Debug",     logging.DEBUG),
        ("Warning",   logging.WARNING),
        ("Error",     logging.ERROR),
        ("Critical",  logging.CRITICAL),
    ]

    def __init__(self, master: "tk.Tk", *, queue_: "queue.Queue[logging.LogRecord] | None", 
                log_file: Optional[str] = None, attach_to_root: bool = True,
                filter_queue: "queue.Queue[str] | None" = None):
        self.master = master
        self.master.title("Tsar Logging — Minimal GUI")
        self.master.geometry("980x560")
        self.queue: "queue.Queue[logging.LogRecord]" = queue_ or queue.Queue()
        self.filter_queue = filter_queue

        # Status
        self.autoscroll = tk.BooleanVar(value=True) if tk else None
        self.mode_tail = False
        self.tail_path: Optional[Path] = None
        self._tail_fp = None
        self._tail_last_size = 0
        self._stop_event = threading.Event()
        self._counts = {name: 0 for (name, _) in self.LEVELS}
        
        self._buf = deque(maxlen=10000)
        self._current_module_filter = "All"

        # UI
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

        self.text_widgets: dict[str, "tk.Text"] = {}
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
        if not log_file:
            log_file = CFG.LOG_PATH
        self.start_tail(log_file, load_history=True)
        if attach_to_root:
            self.attach_gui_handler()
            if self._tail_fp:
                try:
                    self._tail_fp.close()
                except Exception:
                    pass
                self._tail_fp = None
            self.mode_tail = False
            self.tail_path = None

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
        result = (self._current_module_filter == "All") or (module_hint == self._current_module_filter)
        if self._current_module_filter != "All":
            return result
        return True
    
    def _render_from_buffer(self):
        self._clear_ui_only()
        mapping = {
            "TRACE": "Trace", "DEBUG": "Debug", "INFO": "Info",
            "WARNING": "Warning", "ERROR": "Error", "CRITICAL": "Critical",
        }
        for msg, level_up, module in list(self._buf):
            if self._category_match(module):
                self._append("All", msg, tag=level_up)
                self._append(mapping.get(level_up, "Info"), msg, tag=level_up)

    def _on_module_change(self):
        try:
            self._current_module_filter = self.module_filter.get()
        except Exception:
            self._current_module_filter = "All"
        
        self._render_from_buffer()
        if not self._buf and self.tail_path:
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
                    if isinstance(lg, logging.Logger) and name.startswith("tsarchain"):
                        lg.propagate = True
                        for handler in lg.handlers[:]:
                            if isinstance(handler, TkLogHandler):
                                lg.removeHandler(handler)
            except Exception:
                pass

            self._set_status("GUI handler attached (live + tail mode)")


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
        for name, _ in self.LEVELS:
            self.text_widgets[name].delete("1.0", tk.END)
            self._counts[name] = 0
            self._update_tab_title(name)

        try:
            self._truncate_log_files(delete_backups=True)
            self._set_status("Cleared UI and erased log file")
        except Exception as e:
            if messagebox:
                messagebox.showerror("Clear Logs", f"Failed to erase log file: {e}")
            else:
                self._set_status(f"Clear UI only (file erase failed: {e})")
                
    def _install_readonly(self, text: tk.Text):
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

    def _truncate_log_files(self, delete_backups: bool = True) -> None:
        p = Path(self.tail_path) if self.tail_path else Path(CFG.LOG_PATH).resolve()
        root = logging.getLogger()
        target_handlers = []
        for h in list(root.handlers):
            try:
                from logging.handlers import RotatingFileHandler
                if isinstance(h, RotatingFileHandler):
                    base = getattr(h, "baseFilename", None)
                    if base and Path(base) == p:
                        target_handlers.append(h)
            except Exception:
                pass

        if target_handlers:
            for h in target_handlers:
                h.acquire()
                try:
                    stream = getattr(h, "stream", None)
                    if stream:
                        stream.seek(0)
                        stream.truncate(0)
                        stream.flush()
                    else:
                        with open(h.baseFilename, "w", encoding=getattr(h, "encoding", "utf-8")):
                            pass
                finally:
                    h.release()
        else:
            with open(p, "w", encoding="utf-8"):
                pass

        self._tail_last_size = 0
        if self._tail_fp:
            try:
                self._tail_fp.seek(0)
                self._tail_fp.truncate(0)
            except Exception:
                pass

        if delete_backups:
            base = p
            for n in range(1, 100):
                bp = base.with_name(base.name + f".{n}")
                if not bp.exists():
                    break
                try:
                    bp.unlink()
                except Exception:
                    pass

    def open_log_folder(self):
        try:
            base = self.tail_path.parent if self.tail_path else Path(CFG.LOG_PATH).resolve().parent
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
            default = Path.home() / "tsar_logs_bundle.zip"
            out_path = filedialog.asksaveasfilename(
                title="Save Log Bundle",
                initialfile=default.name,
                defaultextension=".zip",
                filetypes=[("ZIP", "*.zip")],
            )
            if not out_path:
                return
        else:
            out_path = str(Path.cwd() / "tsar_logs_bundle.zip")

        threading.Thread(
            target=self._export_worker, args=(out_path,), daemon=True
        ).start()

    def _export_worker(self, out_path: str):
        try:
            out = export_log_bundle(path=out_path)
            self.master.after(0, lambda: (
                messagebox and messagebox.showinfo("Export Logs", f"Saved:\n{out}"),
                self._set_status(f"Exported bundle → {out}")
            ))
        except Exception as e:
            self.master.after(0, lambda: (
                messagebox and messagebox.showerror("Export Logs", f"Failed: {e}"),
                self._set_status(f"Export failed: {e}")
            ))

    # ---------- Internal pumps ----------

    def _pollqueue(self):
        try:
            current_filter = self.module_filter.get()
            if current_filter != self._current_module_filter:
                self._current_module_filter = current_filter
                
            while True:
                record = self.queue.get_nowait()
                self._append_record(record)
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
                
            line = self._tail_fp.readline()
            while line:
                text, level, module = self._decode_line(line)
                self._append_line(text, level_hint=level, module_hint=module)
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
        level = None

        def _from_plain(s: str):
            nonlocal level
            up = s.upper()
            for name, _lvl in self.LEVELS[1:]:
                token = f"[{name.upper()}]"
                if token in up:
                    level = name
                    break
            m = _RE_LOG_PLAIN.search(s)
            logger_name = m.group(1) if m else None
            module = _module_from_logger_name(logger_name)
            return s, module

        def _from_json(s: str):
            nonlocal level
            try:
                obj = json.loads(s)
                lvl = str(obj.get("lvl", obj.get("level", ""))).upper()
                if lvl in {"TRACE","DEBUG","INFO","WARNING","ERROR","CRITICAL"}:
                    level = lvl.title()
                logger_name = obj.get("logger", "")
                module = _module_from_logger_name(str(logger_name))
                if self.pretty_json.get():
                    return json.dumps(obj, ensure_ascii=False, indent=2), module
                return json.dumps(obj, ensure_ascii=False), module
            except Exception:
                text, module = _from_plain(s)
                return text, module

        if mode == "Plain":
            text, module = _from_plain(txt)
            return text, level, module
        elif mode == "JSON":
            text, module = _from_json(txt)
            return text, level, module
        else:  # Auto
            try:
                text, module = _from_json(txt)
                return text, level, module
            except Exception:
                text, module = _from_plain(txt)
                return text, level, module

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
            
        w = self.text_widgets[tab_name]
        try:
            w.insert(tk.END, text + "\n", (tag or "INFO",))
            self._counts[tab_name] += 1
            self._update_tab_title(tab_name)
            if self.autoscroll and self.autoscroll.get():
                w.see(tk.END)
        except Exception:
            pass

    def _update_tab_title(self, tab_name: str):
        idx = [name for (name, _) in self.LEVELS].index(tab_name)
        self.nb.tab(idx, text=f"{tab_name} ({self._counts[tab_name]})")

    def _set_status(self, msg: str):
        try:
            self.status.configure(text=msg)
        except Exception:
            pass

    def _on_close(self):
        try:
            self._stop_event.set()
            if hasattr(self, '_attached_loggers'):
                for lg, handler in self._attached_loggers:
                    try: 
                        lg.removeHandler(handler)
                    except Exception:
                        pass
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
        self.master.destroy()

# =========================
# 4) Convenience APIs
# =========================

def start_log_gui(
    log_file: Optional[str] = None,
    attach_to_root: bool = True,
    title: Optional[str] = None,) -> None:
    
    if tk is None:
        raise RuntimeError("Tkinter is not available in this environment.")
    root = tk.Tk()
    if title:
        root.title(title)
    log_path = log_file or CFG.LOG_PATH
    viewer = TsarLogViewer(root, queue_=queue.Queue(), log_file=log_path, attach_to_root=attach_to_root)
    root.mainloop()

def launch_gui_in_thread(log_file: Optional[str] = None, attach_to_root: bool = True) -> threading.Thread:
    def gui_wrapper():
        root = tk.Tk()
        root.title("Tsar Logging — Minimal GUI")
        
        log_queue = queue.Queue()
        filter_queue = queue.Queue()
        viewer = TsarLogViewer(root, queue_=log_queue, log_file=log_file, attach_to_root=attach_to_root, filter_queue=filter_queue)
        root.mainloop()
    
    t = threading.Thread(target=gui_wrapper, daemon=True)
    t.start()
    return t

def open_log_toplevel(master, log_file: Optional[str] = None, attach_to_root: bool = False):
    win = tk.Toplevel(master)
    win.title("Tsar Logging — Minimal GUI")
    log_path = log_file or CFG.LOG_PATH
    TsarLogViewer(win, queue_=queue.Queue(), log_file=log_path, attach_to_root=attach_to_root)
    return win

def export_log_bundle(path: str = "tsar_logs_bundle.zip") -> Path:
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
    for h in list(root.handlers):
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

    try:
        base = Path(CFG.LOG_PATH)
    except Exception:
        base = Path(str(CFG.LOG_PATH))
    try:
        base.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    _add(base)
    for bp in base.parent.glob(base.name + ".*"):
        if bp.is_file():
            _add(bp)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("log_info.txt", "\n".join([
            f"Python Version : {platform.python_version()}",
            f"Operation System : {platform.platform()}",
            f"Mode : {CFG.MODE}",
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


# =========================
# 5) CLI entry
# =========================

def _parse_argv(argv: list[str]) -> dict:
    import argparse
    p = argparse.ArgumentParser(description="Tsar Logging GUI")
    p.add_argument("--file", "-f", default=CFG.LOG_PATH,
                   help="Path file log untuk ditail (default: data/logging/tsarchain.log).")
    p.add_argument("--no-attach", action="store_true", help="Jangan attach handler GUI ke root logger (tail only).")
    p.add_argument("--level", "-l", default=CFG.LOG_LEVEL,
                   help="Log level during setup (when run standalone).")
    p.add_argument("--console", action="store_true", help="Tampilkan juga ke console.")
    p.add_argument("--no-file", action="store_true", help="Do not write to a file when running standalone.")
    args = p.parse_args(argv)
    return {
        "file": None if args.no_file else args.file,
        "attach": not args.no_attach,
        "level": args.level,
        "console": args.console,
    }

if __name__ == "__main__":
    args = _parse_argv(sys.argv[1:])
    if args["file"]:
        _ensure_log_file(Path(args["file"]))

    try:
        if args["attach"]:
            setup_logging(
                log_file=args["file"] or CFG.LOG_PATH,
                level=args["level"],
                to_console=bool(args["console"]),
                force=False,
            )
    except Exception:
        pass

    start_log_gui(log_file=args["file"] or CFG.LOG_PATH, attach_to_root=bool(args["attach"]))
