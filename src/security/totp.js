'use strict';
/**
 * Time-based One-Time Passwords (RFC 6238 / RFC 4226), implemented with node:crypto.
 * Works with Google Authenticator, Microsoft Authenticator, Authy, 1Password, etc.
 * - ±1 step (30 s) tolerance for clock drift.
 * - Replay protection: a code's time-step must be newer than the last one accepted.
 */
const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/\s+/g, '').replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 character');
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(key, counter, digits = DIGITS) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 10 ** digits).padStart(digits, '0');
}

const currentStep = (nowMs = Date.now()) => Math.floor(nowMs / 1000 / STEP_SECONDS);

/** Returns the matched time-step (number) or null. */
function verifyTotp(secretB32, token, lastUsedStep = -1, nowMs = Date.now()) {
  if (!/^\d{6}$/.test(String(token))) return null;
  const key = base32Decode(secretB32);
  const step = currentStep(nowMs);
  for (let i = -1; i <= 1; i++) {
    const s = step + i;
    if (s <= lastUsedStep) continue; // already used → replay
    const candidate = Buffer.from(hotp(key, s));
    if (crypto.timingSafeEqual(candidate, Buffer.from(String(token)))) return s;
  }
  return null;
}

const generateSecret = () => base32Encode(crypto.randomBytes(20)); // 160-bit, per RFC 4226

function otpauthUrl(secret, account, issuer = 'Bastion') {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${params}`;
}

module.exports = { generateSecret, verifyTotp, otpauthUrl, hotp, base32Encode, base32Decode, currentStep };
