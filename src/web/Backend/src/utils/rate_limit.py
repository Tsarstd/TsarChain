# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import time
import math
import threading
from typing import Dict, Any, Tuple


class RateLimiter:
    def __init__(self, window_ms: int = 60000, max_requests: int = 60):
        self.window_sec = max(0.001, float(window_ms) / 1000.0)
        self.max_requests = max(1, int(max_requests))
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._last_sweep = 0.0
        self._sweep_interval = 60.0

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        expired = [k for k, v in self._store.items() if v["reset_at"] <= now]
        for k in expired:
            self._store.pop(k, None)

    def check(self, key: str) -> Tuple[bool, Dict[str, str], int]:
        now = time.time()
        with self._lock:
            self._sweep(now)
            
            entry = self._store.get(key)
            if entry is None or entry["reset_at"] <= now:
                entry = {
                    "count": 0,
                    "reset_at": now + self.window_sec
                }
                self._store[key] = entry
                
            reset_at = entry["reset_at"]
            reset_epoch = int(math.ceil(reset_at))
            
            if entry["count"] >= self.max_requests:
                retry_after = max(1, int(math.ceil(reset_at - now)))
                headers = {
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_epoch),
                    "Retry-After": str(retry_after),
                }
                return False, headers, retry_after
                
            entry["count"] += 1
            remaining = max(0, self.max_requests - entry["count"])
            headers = {
                "X-RateLimit-Limit": str(self.max_requests),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_epoch),
            }
            return True, headers, 0
