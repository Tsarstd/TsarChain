# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import os
import time
import base64
import threading

from tsarchain.utils import config as CFG
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.logic_web.db_files")


# ============= RECEIPT CACHE HELPER ==============

def get_receipt_file_path(txid: str) -> str:
    txid_norm = str(txid or "").strip().lower()
    txid_safe = os.path.basename(txid_norm).replace("..", "").replace("/", "").replace("\\", "")
    if not txid_safe:
        return ""
    output_dir = CFG.WEB_RECEIPTS_DIR
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, f"{txid_safe[:64]}.jpg")


def is_receipt_fresh(file_path: str, max_age_seconds: int) -> bool:
    if not os.path.exists(file_path):
        return False
    
    try:
        file_age = time.time() - os.path.getmtime(file_path)
        return file_age <= max_age_seconds
    except Exception:
        return False


def read_receipt_file_as_dict(file_path: str, txid: str) -> dict:
    with open(file_path, "rb") as f:
        image_bytes = f.read()
    
    base64_image = base64.b64encode(image_bytes).decode('utf-8')
    return {
        "status": "success",
        "message": "Receipt generated successfully (from cache)",
        "data_url": f"data:image/jpeg;base64,{base64_image}",
        "filename": f"{txid[:64]}.jpg",
        "size_bytes": len(image_bytes)
    }


_receipt_timers = {}
_history_timers = {}
_timers_lock = threading.Lock()


def schedule_receipt_deletion(txid: str, delay_seconds: int):
    txid_norm = str(txid or "").strip().lower()
    
    def delete_file():
        file_path = get_receipt_file_path(txid_norm)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                log.debug(f"Auto-deleted receipt file after {delay_seconds}s: {file_path}")
            except Exception:
                pass
        with _timers_lock:
            _receipt_timers.pop(txid_norm, None)
    
    with _timers_lock:
        old_timer = _receipt_timers.pop(txid_norm, None)
        if old_timer is not None:
            old_timer.cancel()
        
        timer = threading.Timer(delay_seconds, delete_file)
        timer.daemon = True
        _receipt_timers[txid_norm] = timer
        timer.start()


def cleanup_receipt_files(max_age_seconds: int):
    output_dir = CFG.WEB_RECEIPTS_DIR
    if not os.path.exists(output_dir):
        return
    
    current_time = time.time()
    for filename in os.listdir(output_dir):
        if filename.endswith('.jpg'):
            file_path = os.path.join(output_dir, filename)
            try:
                file_age = current_time - os.path.getmtime(file_path)
                if file_age > max_age_seconds:
                    os.remove(file_path)
                    log.debug(f"Cleaned up stale receipt file: {filename} (age: {file_age:.1f}s)")
            except Exception:
                pass


# ============= HISTORY BOOK CACHE HELPER ==============

def get_history_book_file_path(address: str) -> str:
    addr_norm = str(address or "").strip().lower()
    addr_safe = os.path.basename(addr_norm).replace("..", "").replace("/", "").replace("\\", "")
    if not addr_safe:
        return ""
    output_dir = CFG.WEB_HISTORY_BOOKS_DIR
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, f"history_{addr_safe[:16]}.pdf")


def is_history_book_fresh(file_path: str, max_age_seconds: int) -> bool:
    if not os.path.exists(file_path):
        return False
    
    try:
        file_age = time.time() - os.path.getmtime(file_path)
        return file_age <= max_age_seconds
    except Exception:
        return False


def read_history_book_file_as_dict(file_path: str, address: str) -> dict:
    with open(file_path, "rb") as f:
        pdf_bytes = f.read()
    
    base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
    return {
        "status": "success",
        "message": "History Book generated successfully (from cache)",
        "data_url": f"data:application/pdf;base64,{base64_pdf}",
        "filename": f"history_{address}.pdf",
        "size_bytes": len(pdf_bytes)
    }


def schedule_history_book_deletion(address: str, delay_seconds: int):
    addr_norm = str(address or "").strip().lower()

    def delete_file():
        file_path = get_history_book_file_path(addr_norm)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                log.debug(f"Auto-deleted history book file after {delay_seconds}s: {file_path}")
            except Exception:
                pass
        with _timers_lock:
            _history_timers.pop(addr_norm, None)
    
    with _timers_lock:
        old_timer = _history_timers.pop(addr_norm, None)
        if old_timer is not None:
            old_timer.cancel()
        
        timer = threading.Timer(delay_seconds, delete_file)
        timer.daemon = True
        _history_timers[addr_norm] = timer
        timer.start()


def cleanup_history_book_files(max_age_seconds: int):
    output_dir = CFG.WEB_HISTORY_BOOKS_DIR
    if not os.path.exists(output_dir):
        return
    
    current_time = time.time()
    for filename in os.listdir(output_dir):
        if filename.endswith('.pdf'):
            file_path = os.path.join(output_dir, filename)
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > max_age_seconds:
                os.remove(file_path)
                log.debug(f"Cleaned up stale history book file: {filename} (age: {file_age:.1f}s)")
