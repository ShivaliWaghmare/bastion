'use strict';
/** Admin-only API — role-based access control enforced server-side on every route. */
const db = require('../db');
const { audit } = require('../audit');
const { isUuid } = require('../validation');
const { requireAuth, requireRole } = require('../session');

function loadTarget(req, res, next) {
  const target = isUuid(req.params.id) ? db.users.findById(req.params.id) : null;
  if (!target) return res.status(404).json({ error: 'User not found.' });
  req.target = target;
  return next();
}

module.exports = function registerAdminRoutes(app) {
  app.use('/api/admin', requireAuth, requireRole('admin'));

  app.get('/api/admin/stats', (req, res) => {
    const since = Date.now() - 24 * 60 * 60 * 1000;
    const users = db.users.list();
    res.json({
      users: users.length,
      notes: db.notes.count(),
      events24h: db.audit.countSince(since),
      warnings24h: db.audit.countSince(since, (e) => e.level === 'warn'),
      lockedAccounts: users.filter((u) => u.lockUntil > Date.now()).length,
      mfaUsers: users.filter((u) => u.mfaEnabled).length,
    });
  });

  app.get('/api/admin/users', (req, res) => {
    const users = db.users.list().map((u) => ({
      id: u.id,
      username: u.username,
      role: u.role,
      mfaEnabled: Boolean(u.mfaEnabled),
      failedLogins: u.failedLogins || 0,
      locked: u.lockUntil > Date.now(),
      lockUntil: u.lockUntil > Date.now() ? new Date(u.lockUntil).toISOString() : null,
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt || null,
      notes: db.notes.countByOwner(u.id),
    }));
    res.json({ users }); // never includes hashes or secrets
  });

  app.get('/api/admin/audit', (req, res) => {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 300, 1), 1000);
    res.json({ events: db.audit.list({ limit }) });
  });

  app.post('/api/admin/users/:id/unlock', loadTarget, (req, res) => {
    db.users.update(req.target.id, { failedLogins: 0, lockUntil: 0 });
    audit(req, 'admin.user.unlocked', { userId: req.user.id, username: req.user.username, detail: `target: ${req.target.username}` });
    res.json({ ok: true });
  });

  app.post('/api/admin/users/:id/reset-mfa', loadTarget, (req, res) => {
    db.users.update(req.target.id, {
      mfaEnabled: false,
      mfaSecretEnc: null,
      sessionVersion: req.target.sessionVersion + 1, // force the user to sign in again
    });
    audit(req, 'admin.user.mfa_reset', { userId: req.user.id, username: req.user.username, detail: `target: ${req.target.username}` });
    res.json({ ok: true });
  });
};
