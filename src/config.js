'use strict';
/**
 * Central configuration.
 * Secrets are generated automatically on first run and stored in data/secrets.json
 * (file mode 0600). Nothing to configure by hand — and no secrets live in source control.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const isProd = process.env.NODE_ENV === 'production';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true });

const SECRETS_FILE = path.join(DATA_DIR, 'secrets.json');

function loadOrCreateSecrets() {
  if (fs.existsSync(SECRETS_FILE)) {
    const s = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf8'));
    if (typeof s.sessionSecret === 'string' && /^[0-9a-f]{64}$/.test(s.encryptionKey)) return s;
    throw new Error('data/secrets.json is malformed. Run "npm run reset" to start fresh.');
  }
  const s = {
    sessionSecret: crypto.randomBytes(48).toString('hex'), // signs the session cookie
    encryptionKey: crypto.randomBytes(32).toString('hex'), // AES-256-GCM key for data at rest
    createdAt: new Date().toISOString(),
  };
  fs.writeFileSync(SECRETS_FILE, JSON.stringify(s, null, 2), { mode: 0o600 });
  return s;
}

module.exports = Object.freeze({
  isProd,
  DATA_DIR,
  PORT: Number(process.env.PORT) || 3000,
  // Bind to loopback only by default: the app is not exposed to your network.
  HOST: process.env.HOST || '127.0.0.1',
  secrets: loadOrCreateSecrets(),

  // __Host- prefix forces Secure + Path=/ + no Domain (only usable over HTTPS).
  SESSION_COOKIE: isProd ? '__Host-bastion.sid' : 'bastion.sid',
  SESSION_IDLE_MS: 30 * 60 * 1000, // 30 min inactivity
  SESSION_ABSOLUTE_MS: 8 * 60 * 60 * 1000, // 8 h hard limit

  MAX_FAILED_LOGINS: 5,
  LOCKOUT_MS: 15 * 60 * 1000,
  AUTH_RATE_LIMIT: Number(process.env.AUTH_RATE_LIMIT) || 20, // per IP / 15 min
  API_RATE_LIMIT: Number(process.env.API_RATE_LIMIT) || 600, // per IP / 15 min
  MFA_PENDING_MS: 5 * 60 * 1000,
  MAX_NOTES_PER_USER: 200,
});
