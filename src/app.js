'use strict';
const path = require('path');
const config = require('./config');
const { App, jsonBody, serveStatic } = require('./lib/web');
const { securityHeaders } = require('./security/headers');
const { csrfProtection } = require('./security/csrf');
const { apiLimiter } = require('./security/rateLimit');
const { sessions, pageAuth, pageAdmin, guestOnly } = require('./session');

const PUBLIC = path.join(__dirname, '..', 'public');

function createApp() {
  const app = new App();

  // 1. Security headers on every response (incl. errors and static files)
  app.use(securityHeaders({ isProd: config.isProd }));

  // 2. Static assets — before sessions, so CSS/JS never touch cookies
  app.use('/static', serveStatic('/static', path.join(PUBLIC, 'static'), { maxAgeSeconds: config.isProd ? 3600 : 0 }));

  // 3. Sessions
  app.use(sessions.middleware());

  // 4. Pages (server-side access checks; the JS on each page can't bypass these)
  const page = (name) => (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.sendFile(path.join(PUBLIC, `${name}.html`));
  };
  app.get('/', page('index'));
  app.get('/login', guestOnly, page('login'));
  app.get('/register', guestOnly, page('register'));
  app.get('/dashboard', pageAuth, page('dashboard'));
  app.get('/security', pageAuth, page('security'));
  app.get('/admin', pageAuth, pageAdmin, page('admin'));

  // 5. API pipeline: no-cache → rate limit → body (32 KB cap) → CSRF → routes
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store'); // never cache personal data
    next();
  });
  app.use('/api', apiLimiter);
  app.use('/api', jsonBody({ limit: 32 * 1024 }));
  app.use('/api', csrfProtection);
  require('./routes/auth')(app);
  require('./routes/account')(app);
  require('./routes/notes')(app);
  require('./routes/admin')(app);

  // 6. 404s
  app.notFound((req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found.' });
    res.status(404);
    return res.sendFile(path.join(PUBLIC, '404.html'));
  });

  // 7. Errors: generic message to the client, details only in the server console
  app.onError((err, req, res) => {
    if (err.expose && err.status) {
      if (err.status === 413) res.set('Connection', 'close');
      return res.status(err.status).json({ error: err.message });
    }
    console.error(`[error] ${req.method} ${req.originalUrl}:`, err);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  });

  return app;
}

module.exports = { createApp };
