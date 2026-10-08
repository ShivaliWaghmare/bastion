'use strict';
/**
 * End-to-end security tests. Run with:  npm test
 * Spins up the real app on a random port with a throwaway data directory.
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'bastion-test-'));
process.env.AUTH_RATE_LIMIT = '1000';

const { createApp } = require('../src/app');
const { hotp, base32Decode, currentStep, verifyTotp } = require('../src/security/totp');
const { DB_FILE } = require('../src/db');

let server;
let base;

before(async () => {
  server = http.createServer(createApp().handler());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.close();
  fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
});

/** Minimal browser-like client: keeps its cookie and CSRF token. */
class Client {
  constructor() {
    this.cookie = '';
    this.csrf = null;
  }
  async req(method, url, body, { csrf = true, headers = {}, raw } = {}) {
    if (method !== 'GET' && csrf && !this.csrf) await this.refreshCsrf();
    const h = { Accept: 'application/json', ...headers };
    if (this.cookie) h.Cookie = this.cookie;
    if (method !== 'GET' && csrf) h['X-CSRF-Token'] = this.csrf;
    let payload;
    if (raw !== undefined) {
      payload = raw;
      h['Content-Type'] = 'application/json';
    } else if (body !== undefined) {
      payload = JSON.stringify(body);
      h['Content-Type'] = 'application/json';
    }
    const res = await fetch(base + url, { method, headers: h, body: payload, redirect: 'manual' });
    const setCookie = res.headers.getSetCookie?.() || [];
    for (const c of setCookie) {
      const [pair] = c.split(';');
      this.cookie = pair.endsWith('=') ? '' : pair;
    }
    let data = {};
    try {
      data = await res.json();
    } catch { /* non-JSON */ }
    if (data.csrfToken) this.csrf = data.csrfToken;
    return { status: res.status, data, headers: res.headers };
  }
  async refreshCsrf() {
    const r = await this.req('GET', '/api/auth/csrf');
    this.csrf = r.data.csrfToken;
  }
  get(u, o) { return this.req('GET', u, undefined, o); }
  post(u, b, o) { return this.req('POST', u, b, o); }
  put(u, b, o) { return this.req('PUT', u, b, o); }
  del(u, o) { return this.req('DELETE', u, undefined, o); }
}

const PW = 'calm-river-stone-42';
async function signup(name, password = PW) {
  const c = new Client();
  const r = await c.post('/api/auth/register', { username: name, password });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  const l = await c.post('/api/auth/login', { username: name, password });
  assert.equal(l.status, 200, JSON.stringify(l.data));
  return { c, role: r.data.role };
}

let admin;
let alice;
let bob;

test('first registered user becomes admin; later users do not', async () => {
  admin = await signup('admin_user');
  assert.equal(admin.role, 'admin');
  alice = await signup('alice');
  assert.equal(alice.role, 'user');
  bob = await signup('bob');
});

test('security headers: strict CSP, anti-framing, nosniff, no fingerprinting', async () => {
  const res = await fetch(`${base}/`);
  const csp = res.headers.get('content-security-policy');
  assert.match(csp, /script-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('session cookie is HttpOnly + SameSite=Strict, and the ID is rotated on login (anti-fixation)', async () => {
  const c = new Client();
  await c.refreshCsrf();
  const before = c.cookie;
  const raw = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: c.cookie, 'X-CSRF-Token': c.csrf },
    body: JSON.stringify({ username: 'alice', password: PW }),
  });
  const setCookie = raw.headers.getSetCookie().join(' ');
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.notEqual(setCookie.split(';')[0], before, 'session ID must change after login');
});

test('tampered session cookie is rejected', async () => {
  const c = new Client();
  c.cookie = alice.c.cookie.slice(0, -2) + (alice.c.cookie.endsWith('AA') ? 'BB' : 'AA');
  const r = await c.get('/api/auth/me');
  assert.equal(r.status, 401);
});

test('weak, common and username-containing passwords are rejected', async () => {
  const c = new Client();
  for (const password of ['short', 'password1234', 'carol_is_my_password!']) {
    const r = await c.post('/api/auth/register', { username: 'carol', password });
    assert.equal(r.status, 400, password);
  }
});

test('login errors are identical for unknown user and wrong password (no enumeration)', async () => {
  const c = new Client();
  const a = await c.post('/api/auth/login', { username: 'nobody_here', password: 'whatever-123456' });
  const b = await c.post('/api/auth/login', { username: 'bob', password: 'wrong-password-123' });
  assert.equal(a.status, 401);
  assert.equal(b.status, 401);
  assert.equal(a.data.error, b.data.error);
});

test('CSRF: state-changing requests need a valid token and same origin', async () => {
  const noToken = await alice.c.post('/api/notes', { title: 'x', body: '' }, { csrf: false });
  assert.equal(noToken.status, 403);
  const wrongToken = await alice.c.post('/api/notes', { title: 'x', body: '' }, { csrf: false, headers: { 'X-CSRF-Token': 'forged' } });
  assert.equal(wrongToken.status, 403);
  const crossSite = await alice.c.post('/api/notes', { title: 'x', body: '' }, { headers: { Origin: 'https://evil.example' } });
  assert.equal(crossSite.status, 403);
  const fetchMeta = await alice.c.post('/api/notes', { title: 'x', body: '' }, { headers: { 'Sec-Fetch-Site': 'cross-site' } });
  assert.equal(fetchMeta.status, 403);
});

let aliceNoteId;
test('notes are encrypted at rest (AES-256-GCM) and readable by their owner', async () => {
  const secret = 'my-launch-codes-0000';
  const r = await alice.c.post('/api/notes', { title: 'Private plan', body: secret });
  assert.equal(r.status, 201);
  aliceNoteId = r.data.note.id;
  const db = fs.readFileSync(DB_FILE, 'utf8');
  assert.ok(!db.includes(secret), 'plaintext must not appear on disk');
  assert.ok(!db.includes('Private plan'));
  const got = await alice.c.get(`/api/notes/${aliceNoteId}`);
  assert.equal(got.data.note.body, secret);
});

test('IDOR: another user cannot read, edit or delete the note (same 404 as missing)', async () => {
  const read = await bob.c.get(`/api/notes/${aliceNoteId}`);
  const edit = await bob.c.put(`/api/notes/${aliceNoteId}`, { title: 'pwned', body: '' });
  const del = await bob.c.del(`/api/notes/${aliceNoteId}`);
  const missing = await bob.c.get('/api/notes/00000000-0000-4000-8000-000000000000');
  for (const r of [read, edit, del]) assert.equal(r.status, 404);
  assert.equal(read.data.error, missing.data.error);
  const still = await alice.c.get(`/api/notes/${aliceNoteId}`);
  assert.equal(still.data.note.title, 'Private plan');
});

test('RBAC: admin API is forbidden to users, allowed to admin, never leaks hashes', async () => {
  assert.equal((await bob.c.get('/api/admin/users')).status, 403);
  assert.equal((await new Client().get('/api/admin/users')).status, 401);
  const r = await admin.c.get('/api/admin/users');
  assert.equal(r.status, 200);
  const blob = JSON.stringify(r.data);
  assert.ok(!blob.includes('scrypt$') && !blob.includes('passwordHash'));
});

test('admin page redirects non-admins server-side', async () => {
  const res = await fetch(`${base}/admin`, { headers: { Cookie: bob.c.cookie }, redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/dashboard');
});

test('input validation: unknown fields, prototype keys, wrong types, bad JSON, oversize', async () => {
  assert.equal((await alice.c.post('/api/notes', { title: 't', body: '', isAdmin: true })).status, 400);
  assert.equal((await alice.c.post('/api/notes', undefined, { raw: '{"__proto__":{"x":1},"title":"t","body":""}' })).status, 400);
  assert.equal((await alice.c.post('/api/notes', { title: ['array'], body: '' })).status, 400);
  assert.equal((await alice.c.post('/api/notes', undefined, { raw: '{not json' })).status, 400);
  assert.equal((await alice.c.post('/api/notes', { title: 't', body: 'x'.repeat(40000) })).status, 413);
});

test('stored XSS payloads are kept as inert data (rendered with textContent client-side)', async () => {
  const payload = '<img src=x onerror=alert(1)>';
  const r = await alice.c.post('/api/notes', { title: payload, body: payload });
  assert.equal(r.status, 201);
  assert.equal(r.data.note.title, payload); // exact data back, JSON-encoded
});

test('path traversal on static files is blocked', async () => {
  for (const p of ['/static/../server.js', '/static/..%2f..%2fserver.js', '/static/%2e%2e/%2e%2e/data/secrets.json', '/static/..%5cserver.js']) {
    const res = await fetch(base + p);
    const text = await res.text();
    assert.ok(!text.includes('createServer') && !text.includes('sessionSecret'), p);
  }
});

test('account lockout after 5 failed logins blocks even the correct password', async () => {
  await signup('dave');
  const c = new Client();
  for (let i = 0; i < 5; i++) await c.post('/api/auth/login', { username: 'dave', password: 'nope-nope-nope-1' });
  const r = await c.post('/api/auth/login', { username: 'dave', password: PW });
  assert.equal(r.status, 401);
  const users = await admin.c.get('/api/admin/users');
  const dave = users.data.users.find((u) => u.username === 'dave');
  assert.equal(dave.locked, true);
  assert.equal((await admin.c.post(`/api/admin/users/${dave.id}/unlock`)).status, 200);
  assert.equal((await c.post('/api/auth/login', { username: 'dave', password: PW })).status, 200);
});

test('TOTP matches RFC 6238 test vector', () => {
  const key = Buffer.from('12345678901234567890');
  assert.equal(hotp(key, Math.floor(59 / 30), 8), '94287082');
  assert.equal(hotp(key, Math.floor(1111111109 / 30), 8), '07081804');
});

test('2FA: enrol, sign in with code, replayed code rejected', async () => {
  const { c } = await signup('erin');
  const setup = await c.post('/api/account/mfa/setup');
  assert.match(setup.data.qrDataUrl, /^data:image\/svg\+xml;base64,/);
  const key = base32Decode(setup.data.secret);
  const step = currentStep();
  assert.equal((await c.post('/api/account/mfa/enable', { code: hotp(key, step) })).status, 200);
  await c.post('/api/auth/logout');

  const c2 = new Client();
  const login = await c2.post('/api/auth/login', { username: 'erin', password: PW });
  assert.equal(login.data.mfaRequired, true);
  assert.equal((await c2.get('/api/notes')).status, 401, 'not authenticated before 2nd factor');
  const code = hotp(key, step + 1);
  assert.equal((await c2.post('/api/auth/mfa', { code })).status, 200);
  assert.equal((await c2.get('/api/notes')).status, 200);

  const c3 = new Client();
  await c3.post('/api/auth/login', { username: 'erin', password: PW });
  const replay = await c3.post('/api/auth/mfa', { code });
  assert.equal(replay.status, 401, 'same code must not work twice');
  assert.equal(verifyTotp(setup.data.secret, '000000', step + 5), null);
});

test('password change and "sign out everywhere" revoke other sessions', async () => {
  const { c: laptop } = await signup('frank');
  const phone = new Client();
  await phone.post('/api/auth/login', { username: 'frank', password: PW });
  assert.equal((await phone.get('/api/auth/me')).status, 200);

  const change = await laptop.post('/api/account/password', { currentPassword: PW, newPassword: 'quiet-forest-path-77' });
  assert.equal(change.status, 200);
  assert.equal((await phone.get('/api/auth/me')).status, 401, 'other device signed out');
  assert.equal((await laptop.get('/api/auth/me')).status, 200, 'current device stays signed in');

  await laptop.post('/api/account/sessions/revoke-all');
  assert.equal((await laptop.get('/api/auth/me')).status, 401);
});

test('security events land in the audit log', async () => {
  const r = await admin.c.get('/api/admin/audit');
  const types = new Set(r.data.events.map((e) => e.type));
  for (const t of ['auth.login.fail', 'csrf.reject', 'authz.idor_attempt', 'authz.denied', 'auth.account.locked']) {
    assert.ok(types.has(t), `missing ${t}`);
  }
  assert.ok(!JSON.stringify(r.data).includes(PW), 'passwords never logged');
});
