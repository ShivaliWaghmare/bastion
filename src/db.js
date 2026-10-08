'use strict';
/**
 * Tiny JSON-file data store (no native modules, works everywhere).
 * - Writes are atomic: write to a temp file, then rename over the original.
 * - The file is created with mode 0600 (owner read/write only).
 * - Callers always get copies, never live references to stored objects.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DATA_DIR } = require('./config');

const DB_FILE = path.join(DATA_DIR, 'db.json');
const MAX_AUDIT = 2000;

let state = { users: [], notes: [], audit: [] };
if (fs.existsSync(DB_FILE)) {
  const raw = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  state = { users: raw.users || [], notes: raw.notes || [], audit: raw.audit || [] };
}

function persist() {
  const tmp = `${DB_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}

const copy = (o) => (o ? structuredClone(o) : null);
const now = () => new Date().toISOString();

const users = {
  count: () => state.users.length,
  list: () => state.users.map(copy),
  findById: (id) => copy(state.users.find((u) => u.id === id)),
  findByUsername: (name) => {
    const key = String(name).toLowerCase();
    return copy(state.users.find((u) => u.usernameLower === key));
  },
  create(data) {
    const user = { id: crypto.randomUUID(), createdAt: now(), ...data, usernameLower: data.username.toLowerCase() };
    state.users.push(user);
    persist();
    return copy(user);
  },
  update(id, patch) {
    const user = state.users.find((u) => u.id === id);
    if (!user) return null;
    Object.assign(user, patch);
    persist();
    return copy(user);
  },
};

const notes = {
  listByOwner: (ownerId) => state.notes.filter((n) => n.ownerId === ownerId).map(copy),
  countByOwner: (ownerId) => state.notes.filter((n) => n.ownerId === ownerId).length,
  count: () => state.notes.length,
  exists: (id) => state.notes.some((n) => n.id === id),
  // Ownership is part of the lookup itself — there is no "find by id" for notes.
  findOwned: (id, ownerId) => copy(state.notes.find((n) => n.id === id && n.ownerId === ownerId)),
  insert(note) {
    state.notes.push(note);
    persist();
    return copy(note);
  },
  updateOwned(id, ownerId, patch) {
    const note = state.notes.find((n) => n.id === id && n.ownerId === ownerId);
    if (!note) return null;
    Object.assign(note, patch);
    persist();
    return copy(note);
  },
  removeOwned(id, ownerId) {
    const i = state.notes.findIndex((n) => n.id === id && n.ownerId === ownerId);
    if (i === -1) return false;
    state.notes.splice(i, 1);
    persist();
    return true;
  },
};

const audit = {
  add(entry) {
    state.audit.push({ id: crypto.randomUUID(), at: now(), ...entry });
    if (state.audit.length > MAX_AUDIT) state.audit.splice(0, state.audit.length - MAX_AUDIT);
    persist();
  },
  list({ userId, limit = 200 } = {}) {
    const rows = userId ? state.audit.filter((e) => e.userId === userId) : state.audit;
    return rows.slice(-limit).reverse().map(copy);
  },
  countSince(sinceMs, predicate = () => true) {
    return state.audit.filter((e) => Date.parse(e.at) >= sinceMs && predicate(e)).length;
  },
};

module.exports = { users, notes, audit, DB_FILE };
