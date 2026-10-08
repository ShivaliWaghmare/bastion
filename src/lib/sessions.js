'use strict';
/**
 * Server-side session store (in memory).
 * - Session ID: 256 bits from the OS CSPRNG, never derived from user data.
 * - Cookie value is "<id>.<HMAC-SHA256>" — tampered cookies are rejected in constant time.
 * - Cookie flags: HttpOnly, SameSite=Strict, Secure (production), Path=/.
 * - Rolling idle expiry; capped store size so anonymous traffic can't exhaust memory.
 * Note: sessions live in memory, so restarting the server signs everyone out.
 */
const crypto = require('crypto');
const { parseCookies } = require('./web');

const MAX_SESSIONS = 50_000;

class SessionStore {
  constructor({ cookieName, secret, idleMs, secure }) {
    this.cookieName = cookieName;
    this.secret = secret;
    this.idleMs = idleMs;
    this.secure = secure;
    this.map = new Map();
    setInterval(() => this.sweep(), 60_000).unref();
  }

  mac(id) {
    return crypto.createHmac('sha256', this.secret).update(id).digest('base64url');
  }

  unsign(value) {
    const i = value.lastIndexOf('.');
    if (i < 1) return null;
    const id = value.slice(0, i);
    const given = Buffer.from(value.slice(i + 1));
    const expected = Buffer.from(this.mac(id));
    return given.length === expected.length && crypto.timingSafeEqual(given, expected) ? id : null;
  }

  sweep() {
    const now = Date.now();
    for (const [id, entry] of this.map) if (entry.expires <= now) this.map.delete(id);
  }

  middleware() {
    return (req, res, next) => {
      const raw = parseCookies(req.get('cookie'))[this.cookieName];
      const id = raw ? this.unsign(raw) : null;
      const entry = id ? this.map.get(id) : null;
      if (entry && entry.expires > Date.now()) {
        req.sessionId = id;
        req.session = entry.data;
      } else {
        if (entry) this.map.delete(id);
        req.sessionId = null;
        req.session = {};
      }
      req.hadSessionCookie = Boolean(raw);
      res.locals.beforeSend.push(() => this.commit(req, res));
      next();
    };
  }

  cookieOptions() {
    return { httpOnly: true, sameSite: 'Strict', secure: this.secure, path: '/', maxAge: this.idleMs };
  }

  /** New session ID, empty data. Call on every privilege change (anti session-fixation). */
  regenerate(req) {
    if (req.sessionId) this.map.delete(req.sessionId);
    req.sessionId = null;
    req.session = {};
  }

  destroy(req) {
    this.regenerate(req);
  }

  commit(req, res) {
    const hasData = Object.keys(req.session || {}).length > 0;
    if (!hasData) {
      if (req.sessionId) this.map.delete(req.sessionId);
      if (req.hadSessionCookie) res.clearCookie(this.cookieName, { path: '/', httpOnly: true, sameSite: 'Strict', secure: this.secure });
      return;
    }
    if (!req.sessionId) {
      if (this.map.size >= MAX_SESSIONS) this.map.delete(this.map.keys().next().value); // evict oldest
      req.sessionId = crypto.randomBytes(32).toString('base64url');
    }
    this.map.delete(req.sessionId); // re-insert → keeps Map ordered by recent activity
    this.map.set(req.sessionId, { data: req.session, expires: Date.now() + this.idleMs });
    res.cookie(this.cookieName, `${req.sessionId}.${this.mac(req.sessionId)}`, this.cookieOptions()); // rolling expiry
  }
}

module.exports = { SessionStore };
