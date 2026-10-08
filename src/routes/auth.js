'use strict';
const db = require('../db');
const config = require('../config');
const { audit } = require('../audit');
const { schemas, validate } = require('../validation');
const { hashPassword, verifyPassword, dummyHash, passwordPolicyErrors } = require('../security/password');
const { verifyTotp } = require('../security/totp');
const { decrypt } = require('../security/encryption');
const { issueCsrfToken } = require('../security/csrf');
const { authLimiter } = require('../security/rateLimit');
const { sessions, establishSession, requireAuth, publicUser, getSessionUser } = require('../session');

// One message for every failure mode → no username enumeration (OWASP A07).
const GENERIC_LOGIN_ERROR = 'Incorrect username or password. Repeated failures temporarily lock the account.';

module.exports = function registerAuthRoutes(app) {
  app.get('/api/auth/csrf', (req, res) => res.json({ csrfToken: issueCsrfToken(req) }));

  app.post('/api/auth/register', authLimiter, validate(schemas.register), async (req, res) => {
    const { username, password } = req.body;
    const problems = passwordPolicyErrors(password, username);
    if (problems.length) return res.status(400).json({ error: problems.join(' ') });

    if (db.users.findByUsername(username)) {
      audit(req, 'auth.register.duplicate', { username });
      return res.status(409).json({ error: 'That username is not available.' });
    }
    const passwordHash = await hashPassword(password);
    if (db.users.findByUsername(username)) return res.status(409).json({ error: 'That username is not available.' });

    // The very first account becomes admin — no hard-coded default credentials.
    const role = db.users.count() === 0 ? 'admin' : 'user';
    const user = db.users.create({
      username, passwordHash, role,
      failedLogins: 0, lockUntil: 0, sessionVersion: 1,
      mfaEnabled: false, mfaSecretEnc: null, lastTotpStep: -1,
      lastLoginAt: null, previousLoginAt: null,
    });
    audit(req, 'auth.register', { userId: user.id, username, detail: role === 'admin' ? 'first account — granted admin role' : null });
    return res.status(201).json({ ok: true, role });
  });

  app.post('/api/auth/login', authLimiter, validate(schemas.login), async (req, res) => {
    const { username, password } = req.body;
    const user = db.users.findByUsername(username);

    if (!user) {
      await verifyPassword(password, await dummyHash()); // equalise timing
      audit(req, 'auth.login.fail', { username, detail: 'unknown username' });
      return res.status(401).json({ error: GENERIC_LOGIN_ERROR });
    }
    if (user.lockUntil > Date.now()) {
      await verifyPassword(password, await dummyHash());
      audit(req, 'auth.login.locked', { userId: user.id, username: user.username, detail: 'attempt while locked' });
      return res.status(401).json({ error: GENERIC_LOGIN_ERROR });
    }

    if (!(await verifyPassword(password, user.passwordHash))) {
      const failed = (user.failedLogins || 0) + 1;
      if (failed >= config.MAX_FAILED_LOGINS) {
        db.users.update(user.id, { failedLogins: 0, lockUntil: Date.now() + config.LOCKOUT_MS });
        audit(req, 'auth.account.locked', { userId: user.id, username: user.username, detail: `${failed} consecutive failures — locked 15 min` });
      } else {
        db.users.update(user.id, { failedLogins: failed });
      }
      audit(req, 'auth.login.fail', { userId: user.id, username: user.username, detail: `wrong password (${failed}/${config.MAX_FAILED_LOGINS})` });
      return res.status(401).json({ error: GENERIC_LOGIN_ERROR });
    }

    db.users.update(user.id, { failedLogins: 0, lockUntil: 0 });

    if (user.mfaEnabled) {
      // Password OK but NOT authenticated yet: park a short-lived "pending MFA" marker.
      sessions.regenerate(req);
      req.session.mfaPending = { userId: user.id, exp: Date.now() + config.MFA_PENDING_MS, attempts: 0 };
      const csrfToken = issueCsrfToken(req);
      audit(req, 'auth.login.mfa_challenge', { userId: user.id, username: user.username });
      return res.json({ mfaRequired: true, csrfToken });
    }

    const csrfToken = establishSession(req, user);
    audit(req, 'auth.login.success', { userId: user.id, username: user.username });
    return res.json({ ok: true, csrfToken, redirect: '/dashboard' });
  });

  app.post('/api/auth/mfa', authLimiter, validate(schemas.mfa), (req, res) => {
    const pending = req.session.mfaPending;
    if (!pending || pending.exp < Date.now()) {
      delete req.session.mfaPending;
      return res.status(401).json({ error: 'Your sign-in attempt expired. Start again.', restart: true });
    }
    pending.attempts += 1;
    const user = db.users.findById(pending.userId);
    if (!user || !user.mfaEnabled) {
      delete req.session.mfaPending;
      return res.status(401).json({ error: 'Sign-in failed. Start again.', restart: true });
    }
    if (pending.attempts > 5) {
      delete req.session.mfaPending;
      audit(req, 'auth.mfa.exhausted', { userId: user.id, username: user.username });
      return res.status(401).json({ error: 'Too many invalid codes. Start again.', restart: true });
    }

    const secret = decrypt(user.mfaSecretEnc, `mfa:${user.id}`);
    const step = verifyTotp(secret, req.body.code, user.lastTotpStep ?? -1);
    if (step === null) {
      audit(req, 'auth.mfa.fail', { userId: user.id, username: user.username, detail: `invalid code (${pending.attempts}/5)` });
      return res.status(401).json({ error: 'That code is not valid. Wait for a new one and try again.' });
    }

    db.users.update(user.id, { lastTotpStep: step });
    const csrfToken = establishSession(req, db.users.findById(user.id));
    audit(req, 'auth.login.success', { userId: user.id, username: user.username, detail: 'password + TOTP' });
    return res.json({ ok: true, csrfToken, redirect: '/dashboard' });
  });

  app.post('/api/auth/logout', (req, res) => {
    if (req.session.userId) audit(req, 'auth.logout');
    sessions.destroy(req);
    return res.json({ ok: true });
  });

  // Lightweight check for public pages: reveals only whether *this* browser is signed in.
  app.get('/api/auth/status', (req, res) => res.json({ authenticated: Boolean(getSessionUser(req)) }));

  app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({
      user: publicUser(req.user),
      session: {
        loginAt: new Date(req.session.loginAt).toISOString(),
        idleTimeoutMinutes: config.SESSION_IDLE_MS / 60000,
        absoluteExpiresAt: new Date(req.session.loginAt + config.SESSION_ABSOLUTE_MS).toISOString(),
      },
    });
  });
};
