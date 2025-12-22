"use strict";

const DEFAULT_SWEEP_MS = 60 * 1000;

const normalizeIp = (req) => {
  const raw = req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || "unknown";
  return String(raw).replace(/^::ffff:/, "");
};

const createRateLimiter = (options = {}) => {
  const windowMs = Number(options.windowMs) > 0 ? Number(options.windowMs) : 60 * 1000;
  const max = Number(options.max) > 0 ? Number(options.max) : 60;
  const keyGenerator = options.keyGenerator || ((req) => normalizeIp(req));

  const store = new Map();
  let lastSweep = 0;

  const sweep = (now) => {
    if (now - lastSweep < DEFAULT_SWEEP_MS) return;
    lastSweep = now;
    for (const [key, entry] of store.entries()) {
      if (!entry || entry.resetAt <= now) {
        store.delete(key);
      }
    }
  };

  return function rateLimiter(req, res, next) {
    const now = Date.now();
    sweep(now);

    const key = keyGenerator(req);
    let entry = store.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      store.set(key, entry);
    }

    if (entry.count >= max) {
      const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
      res.setHeader("X-RateLimit-Limit", String(max));
      res.setHeader("X-RateLimit-Remaining", "0");
      res.setHeader("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({ error: "rate_limited", retry_after: retryAfter });
    }

    entry.count += 1;
    const remaining = Math.max(0, max - entry.count);
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(remaining));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));
    return next();
  };
};

module.exports = { createRateLimiter };
