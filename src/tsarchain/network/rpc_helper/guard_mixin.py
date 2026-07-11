# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import time
import threading
from typing import Union

from ...utils import config as CFG

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc_helper.guard_mixin")

class GuardMixin:
    _init_lock = threading.RLock()

    def _tb_now(self):
        return time.time()

    def _tb_allow(self, table, key, rate_per_window, window_s, burst, backoff_key=None):
        now = self._tb_now()
        if not hasattr(self, "backoff_until"):
            self.backoff_until = {}
        tokens, last = table.get(key, (burst, now))
        # refill
        if now > last:
            refill = (now - last) * (rate_per_window / float(window_s))
            tokens = min(burst, tokens + refill)
        # backoff?
        if backoff_key and self.backoff_until.get(backoff_key, 0) > now:
            log.warning("[ratelimit] backoff active key=%s until=%.3f now=%.3f", backoff_key, self.backoff_until.get(backoff_key, 0), now)
            return False
        if tokens >= 1.0:
            table[key] = (tokens - 1.0, now)
            return True
        log.warning("[ratelimit] denied key=%s rate=%s/%ss burst=%s", backoff_key or key, rate_per_window, window_s, burst)
        return False

    def _backoff(self, key, secs):
        self.backoff_until[key] = max(self._tb_now() + secs, self.backoff_until.get(key, 0))
        log.warning("[ratelimit] backoff set key=%s for %.2fs", key, secs)

    def _ensure_nonce_guard_initialized(self):
        if (hasattr(self, "_nonce_guard_lock") and self._nonce_guard_lock is not None and
            hasattr(self, "_nonce_guard_table") and self._nonce_guard_table is not None):
            return

        with GuardMixin._init_lock:
            if not hasattr(self, "_nonce_guard_lock") or self._nonce_guard_lock is None:
                self._nonce_guard_lock = threading.RLock()
            if not hasattr(self, "_nonce_guard_table") or self._nonce_guard_table is None:
                self._nonce_guard_table = {}

    def _nonce_guard(self, scope: str, sender_key: str, nonce: str, ts: Union[int, float], window: int) -> bool:
        
        if not (scope and sender_key and nonce and isinstance(ts, (int, float))):
            return False

        now = self._tb_now()
        if abs(now - ts) > window:
            log.warning("[nonce_guard] ts window violation scope=%s sender=%s",
                        scope, sender_key)
            return False

        max_entries = max(1, int(CFG.NONCE_PER_SENDER_MAX))
        bucket_key = f"{scope}:{sender_key}"
        self._ensure_nonce_guard_initialized()

        with self._nonce_guard_lock:
            bucket = self._nonce_guard_table.setdefault(bucket_key, {})
            # prune expired
            keys_to_remove = []
            for n, t in bucket.items():
                if now - t > window:
                    keys_to_remove.append(n)
            for n in keys_to_remove:
                bucket.pop(n, None)
            if nonce in bucket:
                log.warning("[nonce_guard] replay scope=%s sender=%s nonce=%s",
                            scope, sender_key, nonce[:16])
                return False
            bucket[nonce] = now
            # enforce size
            if len(bucket) > max_entries:
                for n, _t in sorted(bucket.items(), key=lambda it: it[1])[:len(bucket) - max_entries]:
                    bucket.pop(n, None)
        return True