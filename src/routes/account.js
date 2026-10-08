'use strict';
const db = require('../db');
const { audit } = require('../audit');
const { schemas, validate } = require('../validation');
const { hashPassword, verifyPassword, passwordPolicyErrors } = require('../security/password');
const { generateSecret, verifyTotp, otpauthUrl } = require('../security/totp');
const { encrypt, decrypt } = require('../security/encryption');
const { authLimiter } = require('../security/rateLimit');
const qrcode = require('../lib/qrcode');
const { sessions, requireAuth, establishSession } = require('../session');

module.exports = function registerAccountRoutes(app) {
  app.use('/api/account', requireAuth);

  // ---- Change password (re-authentication required) ------------------------
  app.post('/api/account/password', authLimiter, validate(schemas.changePassword), async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!(await verifyPassword(currentPassword, req.user.passwordHash))) {
      audit(req, 'account.password.fail', { userId: req.user.id, username: req.user.username });
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }
    const problems = passwordPolicyErrors(newPassword, req.user.username);
    if (currentPassword === newPassword) problems.push('New password must be different from the current one.');
    if (problems.length) return res.status(400).json({ error: problems.join(' ') });

    db.users.update(req.user.id, {
      passwordHash: await hashPassword(newPassword),
      sessionVersion: req.user.sessionVersion + 1, // kills every other session
    });
    const csrfToken = establishSession(req, db.users.findById(req.user.id));
    audit(req, 'account.password.changed', { userId: req.user.id, username: req.user.username, detail: 'other sessions revoked' });
    return res.json({ ok: true, csrfToken });
  });

  // ---- Sign out everywhere ----------------------------------------------------
  app.post('/api/account/sessions/revoke-all', (req, res) => {
    db.users.update(req.user.id, { sessionVersion: req.user.sessionVersion + 1 });
    audit(req, 'account.sessions.revoked', { userId: req.user.id, username: req.user.username });
    sessions.destroy(req);
    return res.json({ ok: true });
  });

  // ---- Two-factor authentication (TOTP) ---------------------------------------
  app.post('/api/account/mfa/setup', (req, res) => {
    if (req.user.mfaEnabled) return res.status(400).json({ error: 'Two-factor authentication is already enabled.' });
    const secret = generateSecret();
    // Held only in the server-side session until the user proves they saved it.
    req.session.mfaSetup = { secret, exp: Date.now() + 10 * 60 * 1000 };
    const url = otpauthUrl(secret, req.user.username);
    return res.json({ secret, otpauthUrl: url, qrDataUrl: qrcode.toDataUrl(url) });
  });

  app.post('/api/account/mfa/enable', authLimiter, validate(schemas.mfa), (req, res) => {
    const setup = req.session.mfaSetup;
    if (!setup || setup.exp < Date.now()) {
      delete req.session.mfaSetup;
      return res.status(400).json({ error: 'Setup expired. Start again.' });
    }
    const step = verifyTotp(setup.secret, req.body.code, -1);
    if (step === null) return res.status(400).json({ error: 'That code is not valid. Check your device clock and try again.' });

    db.users.update(req.user.id, {
      mfaEnabled: true,
      mfaSecretEnc: encrypt(setup.secret, `mfa:${req.user.id}`), // encrypted at rest
      lastTotpStep: step,
    });
    delete req.session.mfaSetup;
    audit(req, 'account.mfa.enabled', { userId: req.user.id, username: req.user.username });
    return res.json({ ok: true });
  });

  app.post('/api/account/mfa/disable', authLimiter, validate(schemas.mfaDisable), async (req, res) => {
    const user = req.user;
    if (!user.mfaEnabled) return res.status(400).json({ error: 'Two-factor authentication is not enabled.' });
    const passwordOk = await verifyPassword(req.body.password, user.passwordHash);
    const step = passwordOk ? verifyTotp(decrypt(user.mfaSecretEnc, `mfa:${user.id}`), req.body.code, user.lastTotpStep ?? -1) : null;
    if (!passwordOk || step === null) {
      audit(req, 'account.mfa.disable.fail', { userId: user.id, username: user.username });
      return res.status(400).json({ error: 'Password or code is incorrect.' });
    }
    db.users.update(user.id, { mfaEnabled: false, mfaSecretEnc: null, lastTotpStep: step });
    audit(req, 'account.mfa.disabled', { userId: user.id, username: user.username });
    return res.json({ ok: true });
  });

  // ---- Own security activity ---------------------------------------------------
  app.get('/api/account/activity', (req, res) => {
    const events = db.audit
      .list({ userId: req.user.id, limit: 25 })
      .map(({ at, type, level, ip, detail }) => ({ at, type, level, ip, detail }));
    res.json({ events });
  });
};
