'use strict';
/**
 * A deliberately small web framework (≈ Express-shaped) built on node:http.
 * Keeping it in-repo means there is no hidden behaviour: every byte the server
 * sends is decided by code you can read.
 */
const fs = require('fs');
const path = require('path');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
};

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  err.expose = true; // safe to show to the client
  return err;
}

function compile(pattern) {
  const keys = [];
  const source = pattern
    .split('/')
    .map((seg) => {
      if (seg.startsWith(':')) {
        keys.push(seg.slice(1));
        return '([^/]+)';
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { regex: new RegExp(`^${source}/?$`), keys };
}

const prefixMatches = (prefix, p) => prefix === '/' || p === prefix || p.startsWith(`${prefix}/`);

function serializeCookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${opts.path || '/'}`];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(opts.maxAge / 1000)}`);
  if (opts.expires) parts.push(`Expires=${opts.expires.toUTCString()}`);
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.secure) parts.push('Secure');
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  return parts.join('; ');
}

function parseCookies(header = '') {
  const out = Object.create(null);
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const key = part.slice(0, i).trim();
    let val = part.slice(i + 1).trim();
    try {
      val = decodeURIComponent(val);
    } catch {
      continue;
    }
    if (!(key in out)) out[key] = val;
  }
  return out;
}

function enhance(req, res) {
  const url = new URL(req.url, 'http://internal');
  req.path = url.pathname;
  req.query = Object.fromEntries(url.searchParams);
  req.originalUrl = req.url.slice(0, 300);
  req.params = {};
  req.body = {};
  const ra = req.socket.remoteAddress || '';
  req.ip = ra.startsWith('::ffff:') ? ra.slice(7) : ra;
  req.get = (name) => {
    const v = req.headers[name.toLowerCase()];
    return Array.isArray(v) ? v[0] : v;
  };

  res.locals = { beforeSend: [] };
  const commit = () => {
    for (const fn of res.locals.beforeSend.splice(0)) fn();
  };
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.set = (key, value) => {
    res.setHeader(key, value);
    return res;
  };
  res.cookie = (name, value, opts) => {
    const prev = res.getHeader('Set-Cookie');
    const list = prev ? [].concat(prev).filter((c) => !c.startsWith(`${name}=`)) : [];
    list.push(serializeCookie(name, value, opts));
    res.setHeader('Set-Cookie', list);
    return res;
  };
  res.clearCookie = (name, opts = {}) => res.cookie(name, '', { ...opts, maxAge: 0, expires: new Date(0) });
  res.send = (body, type = 'text/plain; charset=utf-8') => {
    if (res.writableEnded) return res;
    commit();
    if (!res.getHeader('Content-Type')) res.setHeader('Content-Type', type);
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
    res.setHeader('Content-Length', buf.length);
    res.end(buf);
    return res;
  };
  res.json = (obj) => res.send(JSON.stringify(obj), 'application/json; charset=utf-8');
  res.redirect = (location) => {
    commit();
    res.statusCode = 302;
    res.setHeader('Location', location);
    res.end();
  };
  res.sendFile = (file) => {
    fs.readFile(file, (err, data) => {
      if (err) {
        res.statusCode = 404;
        return res.send('Not found');
      }
      return res.send(data, MIME[path.extname(file).toLowerCase()] || 'application/octet-stream');
    });
  };
}

class App {
  constructor() {
    this.layers = [];
    this.notFoundHandler = (req, res) => res.status(404).send('Not found');
    this.errorHandler = (err, req, res) => res.status(500).send('Internal error');
  }

  use(prefix, ...fns) {
    if (typeof prefix === 'function') {
      fns.unshift(prefix);
      prefix = '/';
    }
    this.layers.push({ prefix, fns });
    return this;
  }

  route(method, pattern, ...fns) {
    const { regex, keys } = compile(pattern);
    this.layers.push({ method, regex, keys, fns });
    return this;
  }

  get(p, ...f) { return this.route('GET', p, ...f); }
  post(p, ...f) { return this.route('POST', p, ...f); }
  put(p, ...f) { return this.route('PUT', p, ...f); }
  delete(p, ...f) { return this.route('DELETE', p, ...f); }

  notFound(fn) { this.notFoundHandler = fn; }
  onError(fn) { this.errorHandler = fn; }

  handler() {
    return (req, res) => {
      try {
        enhance(req, res);
      } catch {
        res.statusCode = 400;
        return res.end('Bad request');
      }
      const method = req.method === 'HEAD' ? 'GET' : req.method;
      const chain = [];
      for (const layer of this.layers) {
        if (layer.method) {
          if (layer.method !== method) continue;
          const m = layer.regex.exec(req.path);
          if (!m) continue;
          const params = {};
          layer.keys.forEach((k, i) => {
            try {
              params[k] = decodeURIComponent(m[i + 1]);
            } catch {
              params[k] = m[i + 1];
            }
          });
          for (const fn of layer.fns) chain.push({ fn, params });
        } else if (prefixMatches(layer.prefix, req.path)) {
          for (const fn of layer.fns) chain.push({ fn, params: null });
        }
      }

      let i = 0;
      const fail = (err) => {
        if (res.headersSent) return res.end();
        try {
          return this.errorHandler(err, req, res);
        } catch {
          res.statusCode = 500;
          return res.end();
        }
      };
      const next = (err) => {
        if (err) return fail(err);
        if (res.headersSent) return undefined;
        const item = chain[i++];
        if (!item) return this.notFoundHandler(req, res);
        if (item.params) req.params = item.params;
        try {
          const ret = item.fn(req, res, next);
          if (ret && typeof ret.then === 'function') ret.catch(fail);
        } catch (e) {
          fail(e);
        }
        return undefined;
      };
      return next();
    };
  }
}

/** JSON body parser with a hard size cap and strict content-type. */
function jsonBody({ limit }) {
  return (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    if (Number(req.get('content-length')) > limit) return next(httpError(413, 'Request body is too large.'));
    const type = String(req.get('content-type') || '').split(';')[0].trim().toLowerCase();
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > limit) {
        done = true;
        next(httpError(413, 'Request body is too large.'));
      } else chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      if (size === 0) return next();
      if (type !== 'application/json') return next(httpError(415, 'Content-Type must be application/json.'));
      try {
        req.body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        return next(httpError(400, 'Malformed JSON body.'));
      }
      return next();
    });
    req.on('error', (e) => {
      if (!done) {
        done = true;
        next(e);
      }
    });
  };
}

/**
 * Static file server with path-traversal protection:
 * decode → reject NUL/backslash → normalise → resolve → must stay inside root.
 */
function serveStatic(mount, root, { maxAgeSeconds = 0 } = {}) {
  const base = path.resolve(root);
  return (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    let rel;
    try {
      rel = decodeURIComponent(req.path.slice(mount.length));
    } catch {
      return res.status(400).send('Bad request');
    }
    if (rel.includes('\0') || rel.includes('\\')) return res.status(400).send('Bad request');
    const file = path.resolve(base, `.${path.posix.normalize(`/${rel}`)}`);
    if (!file.startsWith(base + path.sep)) return res.status(403).send('Forbidden');
    return fs.stat(file, (err, st) => {
      if (err || !st.isFile()) return next();
      res.set('Cache-Control', maxAgeSeconds ? `public, max-age=${maxAgeSeconds}` : 'no-cache');
      return res.sendFile(file);
    });
  };
}

module.exports = { App, jsonBody, serveStatic, httpError, parseCookies, serializeCookie };
