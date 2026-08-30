# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import time
from web.Backend.src.utils.rate_limit import RateLimiter


def test_rate_limiter_allow():
    limiter = RateLimiter(window_ms=1000, max_requests=5)
    
    for i in range(5):
        allowed, hdrs, retry_after = limiter.check("127.0.0.1")
        assert allowed is True
        assert hdrs["X-RateLimit-Limit"] == "5"
        assert int(hdrs["X-RateLimit-Remaining"]) == 4 - i
        assert retry_after == 0


def test_rate_limiter_block():
    limiter = RateLimiter(window_ms=1000, max_requests=2)
    
    # 2 requests allowed
    ok1, _, _ = limiter.check("1.2.3.4")
    ok2, _, _ = limiter.check("1.2.3.4")
    assert ok1 is True
    assert ok2 is True

    # 3rd request blocked
    ok3, hdrs3, retry_after3 = limiter.check("1.2.3.4")
    assert ok3 is False
    assert hdrs3["X-RateLimit-Remaining"] == "0"
    assert hdrs3["Retry-After"] != "0"
    assert retry_after3 >= 1

    # Different IP is not affected
    ok_other, _, _ = limiter.check("5.6.7.8")
    assert ok_other is True


def test_rate_limiter_reset_and_sweep():
    limiter = RateLimiter(window_ms=10, max_requests=1)
    limiter._sweep_interval = 0.001  # accelerate sweep for test

    ok1, _, _ = limiter.check("1.1.1.1")
    assert ok1 is True

    ok2, _, _ = limiter.check("1.1.1.1")
    assert ok2 is False

    # Wait for window to expire
    time.sleep(0.02)

    ok3, _, _ = limiter.check("1.1.1.1")
    assert ok3 is True
