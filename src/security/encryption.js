'use strict';
/**
 * Field-level encryption at rest with AES-256-GCM (authenticated encryption).
 * - Random 96-bit IV per encryption (never reused with the same key).
 * - Additional Authenticated Data (AAD) binds each ciphertext to its record,
 *   e.g. "note:<id>:<owner>". Copying a ciphertext into another record makes
 *   decryption fail instead of silently leaking data.
 * Format:  v1.<iv>.<tag>.<ciphertext>   (base64url parts)
 */
const crypto = require('crypto');
const { secrets } = require('../config');

const KEY = Buffer.from(secrets.encryptionKey, 'hex');

function encrypt(plaintext, context) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  cipher.setAAD(Buffer.from(context, 'utf8'));
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ['v1', iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join('.');
}

function decrypt(payload, context) {
  const [version, iv, tag, ct] = String(payload).split('.');
  if (version !== 'v1') throw new Error('Unsupported ciphertext version');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(context, 'utf8'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
