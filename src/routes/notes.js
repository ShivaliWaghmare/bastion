'use strict';
/**
 * Encrypted notes API.
 * Broken access control / IDOR (OWASP A01) is prevented by scoping every lookup to
 * the signed-in owner. A note that exists but belongs to someone else returns the
 * same 404 as a missing one (no information leak) and is logged as an IDOR attempt.
 */
const crypto = require('crypto');
const db = require('../db');
const config = require('../config');
const { audit } = require('../audit');
const { schemas, validate, isUuid } = require('../validation');
const { encrypt, decrypt } = require('../security/encryption');
const { requireAuth } = require('../session');

const aad = (id, ownerId) => `note:${id}:${ownerId}`;

function view(note, withBody) {
  const ctx = aad(note.id, note.ownerId);
  const out = { id: note.id, title: decrypt(note.titleEnc, ctx), createdAt: note.createdAt, updatedAt: note.updatedAt };
  if (withBody) out.body = decrypt(note.bodyEnc, ctx);
  return out;
}

const notFound = (res) => res.status(404).json({ error: 'Note not found.' });

function loadOwned(req, res, next) {
  if (!isUuid(req.params.id)) return notFound(res);
  const note = db.notes.findOwned(req.params.id, req.user.id);
  if (!note) {
    if (db.notes.exists(req.params.id)) {
      audit(req, 'authz.idor_attempt', { userId: req.user.id, username: req.user.username, detail: `${req.method} note ${req.params.id}` });
    }
    return notFound(res);
  }
  req.note = note;
  return next();
}

module.exports = function registerNoteRoutes(app) {
  app.use('/api/notes', requireAuth);

  app.get('/api/notes', (req, res) => {
    const notes = db.notes
      .listByOwner(req.user.id)
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
      .map((n) => view(n, false));
    res.json({ notes });
  });

  app.get('/api/notes/:id', loadOwned, (req, res) => res.json({ note: view(req.note, true) }));

  app.post('/api/notes', validate(schemas.note), (req, res) => {
    if (db.notes.countByOwner(req.user.id) >= config.MAX_NOTES_PER_USER) {
      return res.status(400).json({ error: `You can store at most ${config.MAX_NOTES_PER_USER} notes.` });
    }
    const id = crypto.randomUUID(); // unguessable IDs (defence in depth, not a substitute for authz)
    const at = new Date().toISOString();
    const note = db.notes.insert({
      id,
      ownerId: req.user.id,
      titleEnc: encrypt(req.body.title, aad(id, req.user.id)),
      bodyEnc: encrypt(req.body.body, aad(id, req.user.id)),
      createdAt: at,
      updatedAt: at,
    });
    audit(req, 'note.create', { userId: req.user.id, username: req.user.username });
    res.status(201).json({ note: view(note, true) });
  });

  app.put('/api/notes/:id', loadOwned, validate(schemas.note), (req, res) => {
    const ctx = aad(req.note.id, req.user.id);
    const note = db.notes.updateOwned(req.note.id, req.user.id, {
      titleEnc: encrypt(req.body.title, ctx),
      bodyEnc: encrypt(req.body.body, ctx),
      updatedAt: new Date().toISOString(),
    });
    res.json({ note: view(note, true) });
  });

  app.delete('/api/notes/:id', loadOwned, (req, res) => {
    db.notes.removeOwned(req.note.id, req.user.id);
    audit(req, 'note.delete', { userId: req.user.id, username: req.user.username });
    res.json({ ok: true });
  });
};
