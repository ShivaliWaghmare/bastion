(() => {
  'use strict';
  const { api, h, clear, $, toast, timeAgo, formatDate, bindStrength } = App;

  let me = null;

  // ---- Overview -----------------------------------------------------------------
  function renderOverview() {
    $('#ov-username').textContent = me.username;
    clear($('#ov-role')).append(h('span', { class: `label ${me.role === 'admin' ? 'label-done' : ''}` }, me.role));
    clear($('#ov-mfa')).append(me.mfaEnabled
      ? h('span', { class: 'label label-success' }, 'Enabled')
      : h('span', { class: 'label label-warn' }, 'Not enabled'));
    $('#ov-created').textContent = formatDate(me.createdAt);
    $('#ov-prev').textContent = me.previousLoginAt ? `${formatDate(me.previousLoginAt)} (${timeAgo(me.previousLoginAt)})` : 'This is your first sign-in';
  }

  async function reloadMe() {
    me = (await api.get('/api/auth/me')).user;
    renderOverview();
    renderMfa();
  }

  // ---- 2FA ------------------------------------------------------------------------
  function renderMfa(mode) {
    const state = mode || (me.mfaEnabled ? 'on' : 'off');
    $('#mfa-off').hidden = state !== 'off';
    $('#mfa-setup').hidden = state !== 'setup';
    $('#mfa-on').hidden = state !== 'on';
    clear($('#mfa-status')).append(me.mfaEnabled
      ? h('span', { class: 'label label-success' }, 'Enabled')
      : h('span', { class: 'label' }, 'Disabled'));
  }

  $('#mfa-start').addEventListener('click', async () => {
    try {
      const s = await api.post('/api/account/mfa/setup');
      $('#mfa-qr').src = s.qrDataUrl; // data:image/svg+xml — allowed by CSP img-src
      $('#mfa-secret').textContent = s.secret.replace(/(.{4})/g, '$1 ').trim();
      renderMfa('setup');
      $('#mfa-code').focus();
    } catch (err) {
      toast(err.message, 'danger');
    }
  });
  $('#mfa-cancel').addEventListener('click', () => renderMfa());

  const digitsOnly = (el) => el.addEventListener('input', () => { el.value = el.value.replace(/\D/g, '').slice(0, 6); });
  digitsOnly($('#mfa-code'));
  digitsOnly($('#mfa-off-code'));

  $('#mfa-enable-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api.post('/api/account/mfa/enable', { code: $('#mfa-code').value });
      $('#mfa-code').value = '';
      toast('Two-factor authentication enabled.', 'success');
      await reloadMe();
      loadActivity();
    } catch (err) {
      toast(err.message, 'danger');
    }
  });

  $('#mfa-disable-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api.post('/api/account/mfa/disable', { password: $('#mfa-off-pw').value, code: $('#mfa-off-code').value });
      $('#mfa-off-pw').value = '';
      $('#mfa-off-code').value = '';
      toast('Two-factor authentication disabled.', 'success');
      await reloadMe();
      loadActivity();
    } catch (err) {
      toast(err.message, 'danger');
    }
  });

  // ---- Password -------------------------------------------------------------------
  bindStrength($('#pw-new'), $('#pw-meter'), $('#pw-meter-label'));
  $('#password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPassword = $('#pw-current').value;
    const newPassword = $('#pw-new').value;
    if (newPassword !== $('#pw-confirm').value) return toast('New passwords do not match.', 'danger');
    if (newPassword.length < 12) return toast('New password must be at least 12 characters.', 'danger');
    try {
      await api.post('/api/account/password', { currentPassword, newPassword });
      e.target.reset();
      $('#pw-new').dispatchEvent(new Event('input'));
      toast('Password updated. Other sessions were signed out.', 'success');
      loadActivity();
    } catch (err) {
      toast(err.message, 'danger');
    }
    return undefined;
  });

  // ---- Sessions ---------------------------------------------------------------------
  $('#revoke-all').addEventListener('click', async () => {
    if (!window.confirm('Sign out of every session, including this one?')) return;
    try {
      await api.post('/api/account/sessions/revoke-all');
    } catch {
      /* already signed out */
    }
    location.assign('/login?signedout=1');
  });

  // ---- Activity -----------------------------------------------------------------------
  async function loadActivity() {
    const body = $('#activity-body');
    try {
      const { events } = await api.get('/api/account/activity');
      clear(body);
      if (!events.length) body.append(h('tr', null, h('td', { colspan: '4', class: 'muted' }, 'No events yet.')));
      for (const ev of events) {
        body.append(h('tr', null,
          h('td', null, h('span', { class: `lvl lvl-${ev.level}` }), h('span', { class: 'event-type' }, ev.type)),
          h('td', { class: 'muted' }, ev.detail || '—'),
          h('td', { class: 'mono' }, ev.ip || '—'),
          h('td', { class: 'muted', title: formatDate(ev.at) }, timeAgo(ev.at))));
      }
    } catch (err) {
      toast(err.message, 'danger');
    }
  }
  $('#activity-refresh').addEventListener('click', loadActivity);

  // ---- Header inspector ----------------------------------------------------------------
  const HEADERS = [
    ['content-security-policy', 'Blocks inline/injected scripts (XSS) and framing.'],
    ['x-content-type-options', 'Stops MIME sniffing.'],
    ['x-frame-options', 'Legacy clickjacking protection.'],
    ['referrer-policy', 'No URLs leak to other sites.'],
    ['cross-origin-opener-policy', 'Isolates the browsing context.'],
    ['cross-origin-resource-policy', 'Other origins cannot embed responses.'],
    ['permissions-policy', 'Camera, mic, geolocation… disabled.'],
    ['cache-control', 'Personal data is never cached.'],
    ['ratelimit', 'Remaining request budget (IETF draft).'],
    ['strict-transport-security', 'HTTPS-only — sent in production mode only.'],
  ];

  async function loadHeaders() {
    const host = clear($('#headers-body'));
    const res = await fetch('/api/auth/me', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    const rows = HEADERS.map(([name, why]) => {
      const value = res.headers.get(name);
      return h('div', { class: 'box-row header-check' },
        h('span', { class: `state ${value ? 'ok' : 'no'}` }, value ? '✓' : '–'),
        h('div', null,
          h('div', { class: 'name' }, name),
          h('div', { class: 'small muted' }, why),
          h('div', { class: 'val' }, value || 'not present')));
    });
    const powered = res.headers.get('x-powered-by');
    rows.push(h('div', { class: 'box-row header-check' },
      h('span', { class: `state ${powered ? 'no' : 'ok'}` }, powered ? '!' : '✓'),
      h('div', null,
        h('div', { class: 'name' }, 'x-powered-by'),
        h('div', { class: 'small muted' }, 'Should be absent — no server fingerprinting.'),
        h('div', { class: 'val' }, powered || 'absent'))));
    host.append(...rows);
  }
  $('#headers-refresh').addEventListener('click', loadHeaders);

  App.ready.then((user) => {
    if (!user) return;
    me = user;
    renderOverview();
    renderMfa();
    loadActivity();
    loadHeaders();
  });
})();
