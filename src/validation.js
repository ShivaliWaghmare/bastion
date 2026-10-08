'use strict';
/**
 * Input validation (OWASP A03). Every request body is checked against a strict
 * allow-list schema: unknown keys (including "__proto__"), wrong types and oversized
 * values are rejected before route logic runs. Output is a fresh object containing
 * only the allowed keys — this also blocks prototype-pollution and mass-assignment.
 */
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function str({ trim = false, min = 0, max = Infinity, pattern, required, tooShort, tooLong, invalid }) {
  return (v) => {
    if (typeof v !== 'string') return { error: required };
    const s = trim ? v.trim() : v;
    if (s.length < min) return { error: tooShort || required };
    if (s.length > max) return { error: tooLong || invalid };
    if (pattern && !pattern.test(s)) return { error: invalid };
    return { value: s };
  };
}

function object(shape) {
  return (input) => {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: 'Request body must be a JSON object.' };
    for (const key of Object.keys(input)) {
      if (!hasOwn(shape, key)) return { error: `Unexpected field "${key.slice(0, 40)}".` };
    }
    const value = {};
    for (const [key, rule] of Object.entries(shape)) {
      const r = rule(hasOwn(input, key) ? input[key] : undefined);
      if (r.error) return r;
      value[key] = r.value;
    }
    return { value };
  };
}

const USERNAME_MSG = 'Username must be 3–32 characters: letters, numbers or underscore.';
const username = str({ trim: true, pattern: /^[A-Za-z0-9_]{3,32}$/, required: 'Username is required.', invalid: USERNAME_MSG });
const password = str({ min: 1, max: 128, required: 'Password is required.', tooLong: 'Password is too long.' });
const code = str({ trim: true, pattern: /^\d{6}$/, required: 'Enter the 6-digit code.', invalid: 'Enter the 6-digit code from your authenticator app.' });

const schemas = {
  register: object({ username, password }),
  login: object({
    username: str({ trim: true, min: 1, max: 64, required: 'Username is required.', invalid: 'Username is too long.' }),
    password,
  }),
  mfa: object({ code }),
  note: object({
    title: str({ trim: true, min: 1, max: 120, required: 'Title is required.', tooLong: 'Title must be at most 120 characters.' }),
    body: str({ max: 20000, required: 'Note body must be text.', tooLong: 'Note must be at most 20,000 characters.' }),
  }),
  changePassword: object({ currentPassword: password, newPassword: password }),
  mfaDisable: object({ password, code }),
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

function validate(schema) {
  return (req, res, next) => {
    const r = schema(req.body ?? {});
    if (r.error) return res.status(400).json({ error: r.error });
    req.body = r.value;
    return next();
  };
}

module.exports = { schemas, validate, isUuid };
