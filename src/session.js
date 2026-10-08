'use strict';
/**
 * Session helpers + authentication / authorization middleware.
 * - Session ID is regenerated at every privilege change (prevents session fixation).
 * - Each user has a sessionVersion; bumping it instantly invalidates every other session
 *   (used by "sign out everywhere", password change and admin MFA reset).
 * - Idle timeout: rolling cookie/store expiry. Absolute timeout: enforced here.
 */
const db = require('./db');
const config = require('./config');
const { SessionStore } = require('./lib/sessions');
const { issueCsrfToken } = require('./security/csrf');
const { audit } = require('./audit');

const sessions = new SessionStore({
  cookieName: config.SESSION_COOKIE,
  secret: config.secrets.sessionSecret,
  idleMs: config.SESSION_IDLE_MS,
  secure: config.isProd,
});

function clearAuth(session) {
  delete session.userId;
  delete session.sv;
  delete session.loginAt;
}

/** Returns the signed-in user, or null (and clears an invalid/expired session). */
function getSessionUser(req) {
  const s = req.session;
  if (!s || !s.userId) return null;
  if (Date.now() - s.loginAt > config.SESSION_ABSOLUTE_MS) {
    clearAuth(s);
    return null;
  }
  const user = db.users.findById(s.userId);
  if (!user || user.sessionVersion !== s.sv) {
    clearAuth(s);
    return null;
  }
  return user;
}

/** Fully authenticate: brand-new session ID and CSRF token. Returns the token. */
function establishSession(req, user) {
  sessions.regenerate(req);
  req.session.userId = user.id;
  req.session.sv = user.sessionVersion;
  req.session.loginAt = Date.now();
  db.users.update(user.id, { previousLoginAt: user.lastLoginAt || null, lastLoginAt: new Date().toISOString() });
  return issueCsrfToken(req);
}

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    mfaEnabled: Boolean(u.mfaEnabled),
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt || null,
    previousLoginAt: u.previousLoginAt || null,
  };
}

// ---- API middleware ---------------------------------------------------------
function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  req.user = user;
  return next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user?.role !== role) {
      audit(req, 'authz.denied', { userId: req.user?.id, username: req.user?.username, detail: `${req.method} ${req.path}` });
      return res.status(403).json({ error: 'You do not have permission to do that.' });
    }
    return next();
  };
}

// ---- Page middleware (redirects instead of JSON) --------------------------------
function pageAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.redirect('/login');
  req.user = user;
  return next();
}
function pageAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    audit(req, 'authz.denied', { userId: req.user.id, username: req.user.username, detail: 'GET /admin page' });
    return res.redirect('/dashboard');
  }
  return next();
}
function guestOnly(req, res, next) {
  if (getSessionUser(req)) return res.redirect('/dashboard');
  return next();
}

module.exports = {
  sessions, getSessionUser, establishSession, publicUser,
  requireAuth, requireRole, pageAuth, pageAdmin, guestOnly,
};
