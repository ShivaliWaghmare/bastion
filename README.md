# 🛡 Bastion — Secure Notes Vault

An encrypted notes app built to **practise web application security**. Every OWASP Top 10 defence it uses is written by hand in this repo — no frameworks, **zero npm dependencies** — so you can read exactly how each control works, then try to break it.

GitHub-dark UI · scrypt · AES-256-GCM · TOTP 2FA · CSRF tokens · strict CSP · RBAC · audit log · 19 security tests

---

## Run it (2 commands)

**Requirement:** Node.js **18.18 or newer** (20 or 22 LTS recommended). Check with `node -v`. If missing, install the LTS from <https://nodejs.org>.

1. Open the `bastion` folder in VS Code.
2. Open the terminal: **Ctrl + `** (backtick).
3. Run:

```bash
npm start
```

4. Open **http://localhost:3000** in your browser.

That's it. There is nothing to install or configure — secrets are generated automatically on first start (into `data/`). **The first account you register becomes the admin.**

> If port 3000 is busy, the server automatically tries 3001, 3002… — the terminal shows the URL.

### Other commands

| Command | What it does |
|---|---|
| `npm start` | Start the server |
| `npm test` | Run the 19 end-to-end security tests |
| `npm run dev` | Start with auto-restart when you edit code |
| `npm run reset` | Delete all data (users, notes, logs, secrets) and start fresh |

Stop the server with **Ctrl + C**.

---

## What to explore

| Page | What's there |
|---|---|
| `/` | Overview of all 12 security controls and the file that implements each |
| `/dashboard` | Your encrypted notes vault |
| `/security` | Enable 2FA (scan the QR with Google/Microsoft Authenticator), change password, sign out everywhere, your security log, live response-header inspector |
| `/admin` | (admin only) users, lockouts, unlock / reset 2FA, full audit log |

---

## Security controls → where to read them

| Control | OWASP | File |
|---|---|---|
| Password hashing — scrypt, per-user salt, constant-time compare, NIST 800-63B policy | A02, A07 | `src/security/password.js` |
| Encryption at rest — AES-256-GCM with record-bound associated data | A02 | `src/security/encryption.js` |
| TOTP 2FA (RFC 6238) — drift window, replay protection, encrypted secret | A07 | `src/security/totp.js` |
| QR code encoder (for 2FA) — written from the ISO spec | — | `src/lib/qrcode.js` |
| Sessions — 256-bit IDs, HMAC-signed HttpOnly/SameSite=Strict cookie, rotation on login, idle + absolute timeout, "sign out everywhere" | A07 | `src/lib/sessions.js`, `src/session.js` |
| CSRF — synchronizer token + Origin check + Fetch-Metadata | A01 | `src/security/csrf.js` |
| Security headers — strict CSP (no inline JS/CSS), anti-framing, nosniff, COOP/CORP, Permissions-Policy, HSTS in prod | A05 | `src/security/headers.js` |
| Access control — owner-scoped queries (no IDOR), server-side RBAC on API **and** pages | A01 | `src/routes/notes.js`, `src/routes/admin.js` |
| Brute force — per-IP rate limit + per-account lockout (5 tries → 15 min) | A07 | `src/security/rateLimit.js`, `src/routes/auth.js` |
| No user enumeration — same error + equalised timing for unknown users | A07 | `src/routes/auth.js` |
| Input validation — strict allow-list schemas, prototype-pollution safe, 32 KB body cap | A03, A08 | `src/validation.js`, `src/lib/web.js` |
| XSS-safe UI — DOM built with `textContent`, never `innerHTML` | A03 | `public/static/js/common.js` |
| Path traversal protection on static files | A01 | `src/lib/web.js` (`serveStatic`) |
| Audit logging — security events, never secrets or content | A09 | `src/audit.js` |
| Safe errors — generic messages to clients, details only in the server console | A05 | `src/app.js` |
| Network exposure — binds to `127.0.0.1` only by default | A05 | `src/config.js` |

---

## Try to break it (exercises)

1. **Stored XSS** — create a note titled `<img src=x onerror=alert(1)>`. It renders as plain text. Then open DevTools → Console and try `document.body.innerHTML += '<script>alert(1)</script>'` — CSP blocks it.
2. **Data at rest** — open `data/db.json`. Your notes are ciphertext (`v1.<iv>.<tag>.<data>`). Change one character of a ciphertext and reload the note: GCM authentication fails.
3. **Brute force** — enter a wrong password 5 times; the account locks. Watch `auth.account.locked` appear in **Admin → Audit log**, then unlock it from the Users table.
4. **IDOR** — create a second account in a private window, copy a note ID from the first account (DevTools → Network), and request `/api/notes/<id>` as the second user. You get a 404 and an `authz.idor_attempt` warning is logged.
5. **CSRF** — in DevTools, run:
   `fetch('/api/notes', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{"title":"x","body":""}'})` → **403** (no token).
6. **Session hijack resistance** — `document.cookie` in the console shows nothing: the session cookie is HttpOnly.
7. **Session revocation** — sign in from two browsers, change your password in one, and the other is signed out instantly.
8. **Clickjacking** — try embedding `http://localhost:3000` in an `<iframe>` on any page: `frame-ancestors 'none'` refuses it.
9. **Path traversal** — visit `http://localhost:3000/static/..%2f..%2fdata%2fsecrets.json` → not served.
10. **2FA replay** — enable 2FA, sign in with a code, sign out, and immediately try the same code again → rejected.

Run `npm test` any time to verify every control still holds after you change code.

---

## Project structure

```
bastion/
├── server.js                 # entry point (port fallback, timeouts, graceful shutdown)
├── src/
│   ├── app.js                # middleware pipeline + page routes
│   ├── config.js             # settings + auto-generated secrets
│   ├── db.js                 # JSON store with atomic writes (data/db.json)
│   ├── audit.js              # security event log
│   ├── session.js            # auth / RBAC middleware
│   ├── validation.js         # allow-list request schemas
│   ├── lib/
│   │   ├── web.js            # tiny HTTP framework, body parser, static server
│   │   ├── sessions.js       # signed server-side sessions
│   │   └── qrcode.js         # QR encoder for 2FA
│   ├── security/             # password, encryption, totp, csrf, headers, rateLimit
│   └── routes/               # auth, account, notes, admin
├── public/                   # HTML pages + static/css, static/js
├── test/security.test.js     # 19 end-to-end security tests
└── data/                     # created at runtime — git-ignored, never commit it
```

---

## Going to production (what you would change)

This is a learning lab tuned for running locally. For a real deployment:

- Serve over **HTTPS** behind a reverse proxy and set `NODE_ENV=production` — this enables `Secure` + `__Host-` cookies, HSTS and `upgrade-insecure-requests`.
- Move secrets out of `data/secrets.json` into a secret manager / KMS, and plan key rotation.
- Replace the JSON file store with a real database and the in-memory session store with Redis (sessions currently reset on restart).
- Ship the audit log to a SIEM and alert on `warn` events.
- Consider recovery codes for 2FA, WebAuthn/passkeys, and breached-password checks (HIBP k-anonymity API).
- Per-account lockout can be abused to lock out a victim (DoS) — production systems often prefer progressive delays + CAPTCHA.

Environment variables (all optional): `PORT`, `HOST`, `NODE_ENV`, `DATA_DIR`, `AUTH_RATE_LIMIT`, `API_RATE_LIMIT`.
