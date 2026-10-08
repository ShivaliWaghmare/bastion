/**
 * Shared client code.
 * XSS rule for this codebase: never use innerHTML / insertAdjacentHTML / document.write
 * with data. All DOM is built with createElement + textContent via h() below.
 */
(() => {
  'use strict';

  let csrfToken = null;
  const idle = { limitMs: 30 * 60 * 1000, last: Date.now(), timer: null };

  // ---- API client (same-origin, CSRF header on every state-changing request) ----
  async function fetchCsrf() {
    const res = await fetch('/api/auth/csrf', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    csrfToken = (await res.json()).csrfToken;
    return csrfToken;
  }

  async function request(method, url, body, retried = false) {
    const headers = { Accept: 'application/json' };
    const opts = { method, headers, credentials: 'same-origin' };
    if (method !== 'GET') {
      headers['X-CSRF-Token'] = csrfToken || (await fetchCsrf());
      if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
    }
    const res = await fetch(url, opts);
    let data = {};
    try {
      data = await res.json();
    } catch {
      /* empty body */
    }
    // Stale token (e.g. server restarted) → fetch a fresh one and retry once.
    if (res.status === 403 && method !== 'GET' && !retried && /CSRF/i.test(data.error || '')) {
      csrfToken = null;
      return request(method, url, body, true);
    }
    if (typeof data.csrfToken === 'string') csrfToken = data.csrfToken;
    if (res.ok) idle.last = Date.now();
    if (!res.ok) {
      if (res.status === 401 && document.body.dataset.auth === 'required') location.assign('/login?expired=1');
      const err = new Error(data.error || `Request failed (${res.status})`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  const api = {
    get: (u) => request('GET', u),
    post: (u, b) => request('POST', u, b),
    put: (u, b) => request('PUT', u, b),
    del: (u) => request('DELETE', u),
  };

  // ---- Safe DOM builder -------------------------------------------------------
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if ((k === 'href' || k === 'src') && /^\s*javascript:/i.test(String(v))) continue; // block JS URLs
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const clear = (el) => {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  };
  const $ = (sel, root = document) => root.querySelector(sel);

  // ---- Feedback -----------------------------------------------------------------
  function toast(message, kind = 'info') {
    let host = $('.toasts');
    if (!host) {
      host = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
      document.body.append(host);
    }
    const t = h('div', { class: `toast toast-${kind}` }, message);
    host.append(t);
    setTimeout(() => {
      t.classList.add('out');
      setTimeout(() => t.remove(), 250);
    }, 3600);
  }

  function flash(el, kind, message) {
    if (!el) return;
    if (!message) {
      el.hidden = true;
      return;
    }
    el.className = `flash flash-${kind}`;
    el.textContent = message;
    el.hidden = false;
  }

  // ---- Formatting -------------------------------------------------------------------
  function timeAgo(iso) {
    if (!iso) return 'never';
    const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (s < 45) return 'just now';
    const units = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60]];
    for (const [name, sec] of units) {
      const n = Math.floor(s / sec);
      if (n >= 1) return `${n} ${name}${n > 1 ? 's' : ''} ago`;
    }
    return 'just now';
  }
  const formatDate = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');

  /** Rough entropy estimate for the strength meter (the server enforces the real policy). */
  function strength(pw) {
    if (!pw) return { score: null, label: '' };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/\d/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    const effective = Math.min(pw.length, new Set(pw).size * 2);
    const bits = effective * Math.log2(pool || 1);
    const score = bits < 30 ? 0 : bits < 50 ? 1 : bits < 65 ? 2 : bits < 85 ? 3 : 4;
    return { score, bits: Math.round(bits), label: ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'][score] };
  }

  function bindStrength(input, bar, label) {
    const update = () => {
      const s = strength(input.value);
      if (s.score === null) bar.removeAttribute('data-score');
      else bar.dataset.score = String(s.score);
      label.textContent = s.label ? `${s.label} · ~${s.bits} bits` : '';
    };
    input.addEventListener('input', update);
    update();
  }

  // ---- Idle session countdown -------------------------------------------------------
  function startIdleTimer() {
    const pill = $('#session-timer');
    if (!pill) return;
    const tick = () => {
      const left = idle.limitMs - (Date.now() - idle.last);
      if (left <= 0) {
        clearInterval(idle.timer);
        location.assign('/login?expired=1');
        return;
      }
      const m = Math.floor(left / 60000);
      const s = Math.floor((left % 60000) / 1000);
      pill.textContent = `session ${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
      pill.classList.toggle('warn', left < 2 * 60 * 1000);
      pill.title = 'Idle timeout — any action resets it';
    };
    tick();
    idle.timer = setInterval(tick, 1000);
  }

  // ---- Page shell -----------------------------------------------------------------------
  async function initShell() {
    const page = document.body.dataset.page;
    document.querySelectorAll('[data-nav]').forEach((a) => {
      if (a.dataset.nav === page) a.setAttribute('aria-current', 'page');
    });
    const logout = $('#logout-btn');
    if (logout) {
      logout.addEventListener('click', async () => {
        logout.disabled = true;
        try {
          await api.post('/api/auth/logout');
        } catch {
          /* ignore */
        }
        location.assign('/login?signedout=1');
      });
    }
    if (document.body.dataset.auth !== 'required') return null;

    const { user, session } = await api.get('/api/auth/me');
    const name = $('#user-name');
    const avatar = $('#user-avatar');
    if (name) name.textContent = user.username;
    if (avatar) avatar.textContent = user.username.slice(0, 1).toUpperCase();
    if (user.role === 'admin') document.querySelectorAll('[data-admin-only]').forEach((e) => { e.hidden = false; });
    idle.limitMs = session.idleTimeoutMinutes * 60000;
    idle.last = Date.now();
    startIdleTimer();
    return user;
  }

  window.App = {
    api, h, clear, $, toast, flash, timeAgo, formatDate, strength, bindStrength,
    ready: initShell().catch((err) => {
      console.error(err);
      return null;
    }),
  };
})();
