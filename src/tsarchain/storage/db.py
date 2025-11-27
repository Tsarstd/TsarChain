# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os
import io
import json
import time
import hashlib
from typing import Any, Optional, Callable

from tsarcore_native import json_read_file as _native_json_read_file, json_write_file as _native_json_write_file

from ..utils import config as CFG

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.storage.db')


try:
    import fcntl  # POSIX
    _HAS_FCNTL = True
except Exception:
    _HAS_FCNTL = False

try:
    import msvcrt  # Windows
    _HAS_MSVCRT = True
except Exception:
    _HAS_MSVCRT = False


class _FileLock:
    def __init__(self, lock_path: str, shared: bool = False):
        self.lock_path = lock_path
        self.shared = shared
        self._fh: Optional[io.TextIOBase] = None

    def acquire(self, timeout: float = 10.0) -> None:
        os.makedirs(os.path.dirname(self.lock_path) or ".", exist_ok=True)
        start = time.time()
        self._fh = open(self.lock_path, "a+")
        while True:
            try:
                if _HAS_FCNTL:
                    import fcntl
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_SH if self.shared else fcntl.LOCK_EX)
                    return
                elif _HAS_MSVCRT:
                    import msvcrt
                    try:
                        msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                        return
                    except OSError:
                        pass
                else:
                    return
            except Exception:
                pass
            if time.time() - start > timeout:
                raise TimeoutError(f"Timeout acquiring lock: {self.lock_path}")
            time.sleep(0.05)

    def release(self) -> None:
        if not self._fh:
            return
        try:
            if _HAS_FCNTL:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            elif _HAS_MSVCRT:
                import msvcrt
                try:
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        finally:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()


class AtomicJSONFile:
    def __init__(self, path: str,*, pretty: bool = True, keep_backups: int | None = None, checksum: bool = True, backup_interval_sec: int | None = None, dedup_backups: bool = True,):
        self.path = os.path.abspath(path)
        self.dir = os.path.dirname(self.path) or "."
        self.pretty = pretty
        env_keep = os.getenv("TSAR_BACKUP_KEEP")
        env_ivl  = os.getenv("TSAR_BACKUP_INTERVAL_SEC")
        env_ded  = os.getenv("TSAR_BACKUP_DEDUP")

        default_keep = 3
        default_ivl  = 900

        self.keep_backups = max(0, int(keep_backups if keep_backups is not None else (int(env_keep) if env_keep else default_keep)))
        self.backup_interval_sec = max(0, int(backup_interval_sec if backup_interval_sec is not None else (int(env_ivl) if env_ivl else default_ivl)))
        self.dedup_backups = (str(env_ded).strip().lower() in {"1","true","yes","on"}) if env_ded is not None else bool(dedup_backups)

        self.checksum = checksum
        self.lock_path = self.path + ".lock"
        self.sha_path = self.path + ".sha256"
        self.journal_path = self.path + ".journal"
        os.makedirs(self.dir, exist_ok=True)

    def _serialize(self, obj: Any) -> bytes:
        if self.pretty:
            return (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        return json.dumps(obj, ensure_ascii=False, separators=CFG.CANONICAL_SEP).encode("utf-8")

    def _list_backups(self) -> list[str]:
        base = os.path.basename(self.path) + ".bak-"
        files = []
        for f in os.listdir(self.dir):
            if f.startswith(base):
                p = os.path.join(self.dir, f)
                if os.path.isfile(p):
                    files.append(f)
        files.sort(key=lambda f: os.path.getmtime(os.path.join(self.dir, f)), reverse=True)
        return files

    def _latest_backup_info(self):
        baks = self._list_backups()
        if not baks:
            return None, None, None, None
        p = os.path.join(self.dir, baks[0])
        try:
            with open(p, "rb") as fh:
                raw = fh.read()
            chk = hashlib.sha256(raw).hexdigest()
        except Exception:
            chk = None
        return baks[0], p, os.path.getmtime(p), chk

    def _prune_old_backups(self):
        if self.keep_backups <= 0:
            for f in self._list_backups():
                try: os.remove(os.path.join(self.dir, f))
                except Exception: pass
            return
        baks = self._list_backups()
        for f in baks[self.keep_backups:]:
            try: os.remove(os.path.join(self.dir, f))
            except Exception: pass

    def _write_bytes_atomic(self, data: bytes) -> None:
        # Require native JSON writer; no Python I/O fallback.
        data_text = data.decode("utf-8", errors="ignore")

        make_backup = os.path.exists(self.path) and self.keep_backups > 0
        if make_backup:
            now = time.time()
            old_txt = _native_json_read_file(self.path)
            old_chk = hashlib.sha256(old_txt.encode("utf-8")).hexdigest() if old_txt is not None else None

            _, _, last_mtime, last_chk = self._latest_backup_info()
            if last_mtime is not None and self.backup_interval_sec > 0:
                if (now - float(last_mtime)) < float(self.backup_interval_sec):
                    make_backup = False
            if make_backup and self.dedup_backups and last_chk is not None and old_chk is not None:
                if last_chk == old_chk:
                    make_backup = False
            if make_backup:
                ts = time.strftime("%Y%m%d-%H%M%S")
                bak_path = f"{self.path}.bak-{ts}"
                try:
                    os.replace(self.path, bak_path)
                except Exception:
                    try:
                        with open(self.path, "rb") as rf, open(bak_path, "wb") as wf:
                            wf.write(rf.read()); wf.flush(); os.fsync(wf.fileno())
                    except Exception:
                        pass

        _native_json_write_file(self.path, data_text, pretty=self.pretty)

        if self.checksum:
            try:
                written_txt = _native_json_read_file(self.path)
                if written_txt is not None:
                    chk = hashlib.sha256(written_txt.encode("utf-8")).hexdigest()
                    os.makedirs(os.path.dirname(self.sha_path) or ".", exist_ok=True)
                    with open(self.sha_path, "w", encoding="utf-8") as cf:
                        cf.write(chk + "\n"); cf.flush(); os.fsync(cf.fileno())
            except Exception:
                log.debug("[DB] checksum write failed", exc_info=True)

        self._prune_old_backups()

    def _cleanup_journal(self) -> None:
        try:
            if os.path.exists(self.journal_path):
                with open(self.journal_path, "r", encoding="utf-8") as jf:
                    j = json.load(jf)
                tmp = j.get("tmp")
                if tmp and os.path.exists(tmp):
                    try: os.remove(tmp)
                    except Exception: pass
                try: os.remove(self.journal_path)
                except Exception: pass
        except Exception:
            try: os.remove(self.journal_path)
            except Exception: pass

    def load(self, default: Any = None, *, validate: Optional[Callable[[Any], bool]] = None) -> Any:
        self._cleanup_journal()
        with _FileLock(self.lock_path, shared=True):
            try:
                raw_txt = _native_json_read_file(self.path)
                if raw_txt is None:
                    return default

                data = json.loads(raw_txt)
                if validate is not None:
                    ok = False
                    try: ok = bool(validate(data))
                    except Exception: ok = False
                    if not ok:
                        raise ValueError("Validation failed")
                return data
            except Exception:
                # Fallback only to existing backups, still via native reader.
                for b in self._list_backups():
                    try:
                        backup_path = os.path.join(self.dir, b)
                        raw_txt = _native_json_read_file(backup_path)
                        if raw_txt is None:
                            continue
                        return json.loads(raw_txt)
                    except Exception:
                        continue
                return default

    def save(self, obj: Any) -> None:
        data = self._serialize(obj)
        with _FileLock(self.lock_path, shared=False):
            self._write_bytes_atomic(data)

class BaseDatabase:
    def __init__(self, folder: str = "data"):
        self.folder = os.path.abspath(folder)
        os.makedirs(self.folder, exist_ok=True)

    def _resolve_json_path(self, name_or_path: str) -> str:
        if os.path.dirname(name_or_path) or str(name_or_path).lower().endswith(".json"):
            return os.path.abspath(name_or_path)
        return os.path.join(self.folder, f"{name_or_path}.json")

    def save_json(self, name_or_path: str, obj: Any, *, keep_backups: int = 2) -> None:
        path = self._resolve_json_path(name_or_path)
        AtomicJSONFile(path, keep_backups=keep_backups).save(obj)

    def load_json(self, name_or_path: str, default: Any = None) -> Any:
        path = self._resolve_json_path(name_or_path)
        return AtomicJSONFile(path).load(default)
