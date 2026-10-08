'use strict';
/**
 * Fixed-window rate limiting per client IP (OWASP A07 — brute force, credential stuffing).
 * Sends IETF RateLimit headers and Retry-After. Logs the first hit per window only,
 * so an attacker can't flood the audit log either.
 */
const config = require('../config');
const { audit } = require('../audit');

function createLimiter({ name, windowMs, limit, message }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
  }, windowMs).unref();

  return (req, res, next) => {
    const now = Date.now();
    let entry = hits.get(req.ip);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(req.ip, entry);
    }
    entry.count += 1;
    const reset = Math.ceil((entry.resetAt - now) / 1000);
    res.set('RateLimit-Policy', `${limit};w=${windowMs / 1000}`);
    res.set('RateLimit', `limit=${limit}, remaining=${Math.max(0, limit - entry.count)}, reset=${reset}`);
    if (entry.count > limit) {
      if (entry.count === limit + 1) audit(req, 'rate_limit.hit', { detail: `${name}: ${req.method} ${req.path}` });
      res.set('Retry-After', String(reset));
      return res.status(429).json({ error: message });
    }
    return next();
  };
}

const authLimiter = createLimiter({
  name: 'auth',
  windowMs: 15 * 60 * 1000,
  limit: config.AUTH_RATE_LIMIT,
  message: 'Too many attempts from your network. Wait a few minutes and try again.',
});

const apiLimiter = createLimiter({
  name: 'api',
  windowMs: 15 * 60 * 1000,
  limit: config.API_RATE_LIMIT,
  message: 'Too many requests. Slow down and try again shortly.',
});

module.exports = { createLimiter, authLimiter, apiLimiter };
