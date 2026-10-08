'use strict';
/**
 * CSRF defence in depth (OWASP A01):
 *  1. SameSite=Strict session cookie (set in app.js)
 *  2. Fetch Metadata: reject state-changing requests marked cross-site by the browser
 *  3. Origin check: if an Origin header is present it must match our host
 *  4. Synchronizer token: per-session random token sent in the X-CSRF-Token header,
 *     compared in constant time
 */
const crypto = require('crypto');
const { audit } = require('../audit');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function issueCsrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('base64url');
  return req.session.csrfToken;
}

function sameOrigin(req) {
  const origin = req.get('origin');
  if (!origin) return true; // non-browser clients; the token check below still applies
  try {
    return new URL(origin).host === req.get('host');
  } catch {
    return false; // includes the opaque "null" origin
  }
}

function reject(req, res, reason) {
  audit(req, 'csrf.reject', { detail: `${reason} on ${req.method} ${req.originalUrl}` });
  return res.status(403).json({ error: 'Invalid or missing CSRF token. Refresh the page and try again.' });
}

function csrfProtection(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  if (req.get('sec-fetch-site') === 'cross-site') return reject(req, res, 'cross-site fetch');
  if (!sameOrigin(req)) return reject(req, res, `foreign origin ${String(req.get('origin')).slice(0, 80)}`);

  const sent = Buffer.from(String(req.get('x-csrf-token') || ''));
  const expected = Buffer.from(String(req.session?.csrfToken || ''));
  if (!expected.length || sent.length !== expected.length || !crypto.timingSafeEqual(sent, expected)) {
    return reject(req, res, 'bad token');
  }
  return next();
}

module.exports = { issueCsrfToken, csrfProtection };
