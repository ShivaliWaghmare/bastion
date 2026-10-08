'use strict';
/**
 * Password hashing with scrypt (memory-hard KDF, built into Node — no native addons).
 * Stored format:  scrypt$N$r$p$<salt b64>$<hash b64>
 * Parameters are stored with the hash, so they can be raised later without breaking old hashes.
 *
 * Policy follows NIST SP 800-63B: length over composition rules, plus a blocklist.
 */
const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);
const PARAMS = { N: 2 ** 15, r: 8, p: 1 }; // ~32 MiB memory per hash
const KEYLEN = 64;
const MAXMEM = 64 * 1024 * 1024;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16); // unique per password → no rainbow tables
  const key = await scrypt(password.normalize('NFKC'), salt, KEYLEN, { ...PARAMS, maxmem: MAXMEM });
  return ['scrypt', PARAMS.N, PARAMS.r, PARAMS.p, salt.toString('base64'), key.toString('base64')].join('$');
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, keyB64] = parts;
  const expected = Buffer.from(keyB64, 'base64');
  const actual = await scrypt(String(password).normalize('NFKC'), Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: MAXMEM,
  });
  return crypto.timingSafeEqual(actual, expected); // constant-time comparison
}

/**
 * When a username doesn't exist we still verify against this throwaway hash,
 * so the response time doesn't reveal which usernames are registered.
 */
let dummy;
function dummyHash() {
  dummy ||= hashPassword(crypto.randomBytes(16).toString('hex'));
  return dummy;
}

const COMMON = new Set([
  'password', 'password1', 'password12', 'password123', 'password1234', 'passw0rd', 'p@ssw0rd', 'p@ssword123',
  '123456789012', '1234567890', '12345678', '123456789', 'qwertyuiop', 'qwerty123456', 'qwertyuiop12',
  'iloveyou1234', 'letmein12345', 'welcome12345', 'welcome@123', 'admin1234567', 'administrator',
  'changeme1234', 'football1234', 'baseball1234', 'superman1234', 'trustno1trustno1', 'monkey123456',
  'dragon123456', 'sunshine1234', 'princess1234', 'abc123456789', 'aaaaaaaaaaaa', 'correcthorsebatterystaple',
  'india@123456', 'password@123', 'hello@123456', 'qwerty@12345', 'asdfghjkl123', 'zxcvbnm12345',
]);

/** Returns a list of human-readable problems (empty = OK). */
function passwordPolicyErrors(password, username = '') {
  const errors = [];
  const lower = password.toLowerCase();
  if (password.length < 12) errors.push('Password must be at least 12 characters.');
  if (password.length > 128) errors.push('Password must be at most 128 characters.');
  if (username && lower.includes(username.toLowerCase())) errors.push('Password must not contain your username.');
  if (COMMON.has(lower) || /^(.)\1+$/.test(password) || /^(?:0123456789|1234567890|abcdefghijkl)/i.test(password)) {
    errors.push('That password is too common — choose something less predictable.');
  }
  return errors;
}

module.exports = { hashPassword, verifyPassword, dummyHash, passwordPolicyErrors };
