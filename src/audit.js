'use strict';
/**
 * Security audit log (OWASP A09: Security Logging & Monitoring).
 * Records who/what/when/where for security-relevant events. Never logs passwords,
 * codes, tokens or note contents. Values are stored as JSON data and rendered with
 * textContent in the UI, so log entries can't inject markup.
 */
const db = require('./db');

const WARN = new Set([
  'auth.login.fail', 'auth.login.locked', 'auth.account.locked', 'auth.mfa.fail', 'auth.mfa.exhausted',
  'csrf.reject', 'authz.denied', 'authz.idor_attempt', 'rate_limit.hit', 'account.password.fail',
  'account.mfa.disable.fail',
]);

function audit(req, type, { userId, username, detail } = {}) {
  db.audit.add({
    type,
    level: WARN.has(type) ? 'warn' : 'info',
    userId: userId ?? req.session?.userId ?? null,
    username: username ? String(username).slice(0, 64) : null,
    ip: req.ip,
    ua: String(req.get('user-agent') || '').slice(0, 160),
    detail: detail ? String(detail).slice(0, 200) : null,
  });
}

module.exports = { audit };
