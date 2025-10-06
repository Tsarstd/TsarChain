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
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

from ..utils import config as CFG

# ===== TRACE level (di bawah DEBUG) =====
TRACE = 9
logging.addLevelName(TRACE, "TRACE")
def _trace(self, msg, *a, **k):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, a, **k)
logging.Logger.trace = _trace

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

_DEFAULT_FMT = "%(asctime)s [%(levelname)s] %(processName)s %(name)s: %(message)s"
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
            "proc": record.processName,
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
    to_console: bool = True,
    rotate_max_bytes: int = 5_000_000,
    backup_count: int = 3,
    force: bool = False,
    fmt: str = _DEFAULT_FMT,
    datefmt: str = _DEFAULT_DATEFMT,) -> logging.Logger:
    
    if level is None:
        level = CFG.LOG_LEVEL
    if log_file is None:
        log_file = CFG.LOG_PATH

    log_path = Path(log_file)
    if log_path.parent and not log_path.parent.exists():
        log_path.parent.mkdir(parents=True, exist_ok=True)

    handlers: list[logging.Handler] = []
    as_json = str(CFG.LOG_FORMAT).lower() == "json"
    rate_seconds = CFG.LOG_RATE_LIMIT_SECONDS

    fh = RotatingFileHandler(
        log_path, maxBytes=int(rotate_max_bytes), backupCount=int(backup_count),
        encoding="utf-8", delay=True
    )
    file_fmt = JsonFormatter() if as_json else SafeFormatter(fmt, datefmt)
    fh.setFormatter(file_fmt)
    fh.addFilter(RedactFilter())
    handlers.append(fh)

    if to_console:
        console_fmt = JsonFormatter() if as_json else SafeFormatter(fmt, datefmt)
        sh = logging.StreamHandler()
        sh.setFormatter(console_fmt)
        sh.addFilter(RedactFilter())
        if rate_seconds > 0:
            sh.addFilter(RateLimitFilter(rate_seconds))
        handlers.append(sh)

    lvl = level
    if isinstance(lvl, str):
        try:
            lvl = logging._nameToLevel.get(lvl.upper(), lvl)
        except Exception:
            pass
    logging.basicConfig(level=lvl, handlers=handlers, force=force)
    _name = logging.getLevelName(lvl) if isinstance(lvl, int) else str(level)
    logging.getLogger("tsarchain").trace(
        "Logging configured: level=%s file=%s", _name, str(log_path))
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

    def __init__(self, master: "tk.Tk", *, queue_: "queue.Queue[logging.LogRecord] | None", log_file: Optional[str] = None, attach_to_root: bool = True):
        self.master = master
        self.master.title("Tsar Logging — Minimal GUI")
        self.master.geometry("980x560")
        self.queue: "queue.Queue[logging.LogRecord]" = queue_ or queue.Queue()

        # Status
        self.autoscroll = tk.BooleanVar(value=True) if tk else None
        self.mode_tail = False
        self.tail_path: Optional[Path] = None
        self._tail_fp = None  # type: ignore
        self._tail_last_size = 0
        self._stop_event = threading.Event()
        self._counts = {name: 0 for (name, _) in self.LEVELS}

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

        ttk.Button(topbar, text="Open File…", command=self.choose_file).pack(side=tk.RIGHT)

        self.nb = ttk.Notebook(container)
        self.nb.pack(fill=tk.BOTH, expand=True)

        self.text_widgets: dict[str, "tk.Text"] = {}
        for (name, _) in self.LEVELS:
            frame = ttk.Frame(self.nb)
            self.nb.add(frame, text=f"{name} (0)")
            text = tk.Text(frame, wrap="none", font=("Consolas", 10), undo=False)
            yscroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            xscroll = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
            text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

            text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            yscroll.pack(side=tk.RIGHT, fill=tk.Y)
            xscroll.pack(side=tk.BOTTOM, fill=tk.X)

            text.tag_configure("DEBUG",    foreground="#835496")
            text.tag_configure("TRACE",    foreground="#b5c2b0")
            text.tag_configure("INFO",     foreground="#6bd359")
            text.tag_configure("WARNING",  foreground="#f59e0b")
            text.tag_configure("ERROR",    foreground="#ef4444")
            text.tag_configure("CRITICAL", foreground="#f472b6")

            text.configure(bg="#0b0f14", fg="#e5e7eb", insertbackground="#e5e7eb")
            self.text_widgets[name] = text

        self.status = ttk.Label(container, text="Ready", anchor="w")
        self.status.pack(fill=tk.X, pady=(6, 0))

        self.tk_handler: Optional[TkLogHandler] = None
        if not log_file:
            log_file = CFG.LOG_PATH
        self.start_tail(log_file, load_history=True)
        if attach_to_root:
            self.attach_gui_handler()
            self.mode_tail = False
            if self._tail_fp:
                try: self._tail_fp.close()
                except Exception: pass
                self._tail_fp = None

        self.master.after(100, self._pollqueue)

        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- Public controls ----------

    def attach_gui_handler(self):
        if self.tk_handler is None:
            self.tk_handler = TkLogHandler(self.queue)
            root = logging.getLogger()
            root.addHandler(self.tk_handler)
            self._set_status("GUI handler attached")

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
                level = None
                up = line.upper()
                for name, _lvl in self.LEVELS[1:]:
                    token = f"[{name.upper()}]"
                    if token in up:
                        level = name
                        break
                if level is None:
                    try:
                        obj = json.loads(line)
                        lvl = str(obj.get("lvl", "")).upper()
                        if lvl in ("TRACE","DEBUG","INFO","WARNING","ERROR","CRITICAL"):
                            level = lvl.title()
                    except Exception:
                        pass
                    
                self._append_line(line.rstrip("\n"), level_hint=level)
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
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
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
            line = self._tail_fp.readline()
            while line:
                level = None
                text = line.rstrip("\n")
                try:
                    obj = json.loads(text)
                    lvl = (obj.get("lvl") or obj.get("level") or "").upper()
                    if lvl in {"TRACE","DEBUG","INFO","WARNING","ERROR","CRITICAL"}:
                        level = lvl.title()
                        text = json.dumps(obj, ensure_ascii=False)
                except Exception:
                    pass
                if not level:
                    for name, _lvl in self.LEVELS[1:]:
                        token = f"[{name.upper()}]"
                        if token in text.upper():
                            level = name
                            break
                self._append_line(text, level_hint=level)
                line = self._tail_fp.readline()
        except Exception:
            pass
        if not self._stop_event.is_set():
            self.master.after(250, self._poll_tail)

    def _append_record(self, record: logging.LogRecord):
        try:
            msg = self.tk_handler.format(record) if self.tk_handler else logging.Formatter(_DEFAULT_FMT, _DEFAULT_DATEFMT).format(record)
            levelname = record.levelname.upper()
        except Exception:
            msg = f"{record.getMessage()}"
            levelname = "INFO"

        self._append("All", msg, tag=levelname)
        mapping = {
            "TRACE": "Trace",
            "INFO": "Info",
            "DEBUG": "Debug",
            "WARNING": "Warning",
            "ERROR": "Error",
            "CRITICAL": "Critical",
        }
        tab = mapping.get(levelname, "Info")
        self._append(tab, msg, tag=levelname)

    def _append_line(self, line: str, *, level_hint: Optional[str] = None):
        tag = (level_hint or "Info").upper()
        self._append("All", line, tag=tag)
        self._append(level_hint or "Info", line, tag=tag)

    def _append(self, tab_name: str, text: str, tag: Optional[str] = None):
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
            if self.tk_handler:
                logging.getLogger().removeHandler(self.tk_handler)
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
    t = threading.Thread(target=start_log_gui, args=(log_file or CFG.LOG_PATH, attach_to_root, "Tsar Logging — Minimal GUI"), daemon=True)
    t.start()
    return t

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
        z.writestr("env.txt", "\n".join([
            f"python={platform.python_version()}",
            f"os={platform.platform()}",
            f"tsar_log_level={CFG.LOG_LEVEL}",
            f"tsar_log_format={CFG.LOG_FORMAT}",
            f"tsar_log_rate_limit_seconds={CFG.LOG_RATE_LIMIT_SECONDS}",
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
