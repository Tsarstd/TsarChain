# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import os
import time
import base64
import threading

from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import clean_remove_file
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.Backend.src.core.logic_web.db_files")

_receipt_timers = {}
_history_timers = {}
_timers_lock = threading.Lock()


def get_receipt_file_path(txid: str) -> str:
    safe_txid = _sanitize_key(txid)
    if not safe_txid:
        return ""
    os.makedirs(CFG.WEB_RECEIPTS_DIR, exist_ok=True)
    return os.path.join(CFG.WEB_RECEIPTS_DIR, f"{safe_txid[:64]}.jpg")


def is_receipt_fresh(file_path: str, max_age_seconds: int) -> bool:
    return _is_file_fresh(file_path, max_age_seconds)


def read_receipt_file_as_dict(file_path: str, txid: str) -> dict:
    safe_txid = _sanitize_key(txid)
    return _read_file_as_dict(file_path, f"{safe_txid[:64]}.jpg", "image/jpeg", "Receipt")


def schedule_receipt_deletion(txid: str, delay_seconds: int):
    _schedule_deletion(_receipt_timers, txid, get_receipt_file_path, delay_seconds)


def cleanup_receipt_files(max_age_seconds: int):
    _cleanup_dir_files(CFG.WEB_RECEIPTS_DIR, ".jpg", max_age_seconds)


def get_history_book_file_path(address: str) -> str:
    safe_addr = _sanitize_key(address)
    if not safe_addr:
        return ""
    os.makedirs(CFG.WEB_HISTORY_BOOKS_DIR, exist_ok=True)
    return os.path.join(CFG.WEB_HISTORY_BOOKS_DIR, f"history_{safe_addr}.pdf")


def is_history_book_fresh(file_path: str, max_age_seconds: int) -> bool:
    return _is_file_fresh(file_path, max_age_seconds)


def read_history_book_file_as_dict(file_path: str, address: str) -> dict:
    safe_addr = _sanitize_key(address)
    return _read_file_as_dict(file_path, f"history_{safe_addr}.pdf", "application/pdf", "History Book")


def schedule_history_book_deletion(address: str, delay_seconds: int):
    _schedule_deletion(_history_timers, address, get_history_book_file_path, delay_seconds)


def cleanup_history_book_files(max_age_seconds: int):
    _cleanup_dir_files(CFG.WEB_HISTORY_BOOKS_DIR, ".pdf", max_age_seconds)


# =============================================================================
# INTERNAL METHOD
# =============================================================================

def _sanitize_key(key: str) -> str:
    norm = str(key or "").strip().lower()
    return os.path.basename(norm).replace("..", "").replace("/", "").replace("\\", "")


def _is_file_fresh(file_path: str, max_age_seconds: int) -> bool:
    if not os.path.exists(file_path):
        return False
    try:
        return (time.time() - os.path.getmtime(file_path)) <= max_age_seconds
    except Exception:
        return False


def _read_file_as_dict(file_path: str, filename: str, mime: str, title: str) -> dict:
    with open(file_path, "rb") as f:
        data = f.read()
    b64_str = base64.b64encode(data).decode('utf-8')
    return {
        "status": "success",
        "message": f"{title} generated successfully (from cache)",
        "data_url": f"data:{mime};base64,{b64_str}",
        "filename": filename,
        "size_bytes": len(data)
    }


def _schedule_deletion(timers_map: dict, key: str, get_path_fn, delay_seconds: int):
    norm_key = _sanitize_key(key)
    if not norm_key:
        return

    def delete_file():
        file_path = get_path_fn(norm_key)
        if file_path and os.path.exists(file_path):
            clean_remove_file(file_path)
            log.debug("Auto-deleted cached file after %ds: %s", delay_seconds, file_path)
        with _timers_lock:
            timers_map.pop(norm_key, None)

    with _timers_lock:
        old_timer = timers_map.pop(norm_key, None)
        if old_timer is not None:
            old_timer.cancel()

        timer = threading.Timer(delay_seconds, delete_file)
        timer.daemon = True
        timers_map[norm_key] = timer
        timer.start()


def _cleanup_dir_files(dir_path: str, ext: str, max_age_seconds: int):
    if not os.path.exists(dir_path):
        return
    now = time.time()
    for filename in os.listdir(dir_path):
        if filename.endswith(ext):
            file_path = os.path.join(dir_path, filename)
            try:
                if (now - os.path.getmtime(file_path)) > max_age_seconds:
                    clean_remove_file(file_path)
            except Exception:
                pass
