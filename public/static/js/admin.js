(() => {
  'use strict';
  const { api, h, clear, $, toast, timeAgo, formatDate } = App;

  let events = [];
  let me = null;

  function stat(label, value, warn) {
    return h('div', { class: 'stat' }, h('div', { class: 'k' }, label), h('div', { class: `v${warn && value > 0 ? ' warn' : ''}` }, String(value)));
  }

  async function loadStats() {
    const s = await api.get('/api/admin/stats');
    clear($('#stats')).append(
      stat('Users', s.users),
      stat('Encrypted notes', s.notes),
      stat('Events (24h)', s.events24h),
      stat('Warnings (24h)', s.warnings24h, true),
      stat('Locked accounts', s.lockedAccounts, true),
      stat('2FA enabled', `${s.mfaUsers}/${s.users}`),
    );
  }

  async function act(url, okMsg) {
    try {
      await api.post(url);
      toast(okMsg, 'success');
      await refresh();
    } catch (err) {
      toast(err.message, 'danger');
    }
  }

  async function loadUsers() {
    const { users } = await api.get('/api/admin/users');
    $('#user-count').textContent = String(users.length);
    const body = clear($('#users-body'));
    for (const u of users) {
      const status = u.locked
        ? h('span', { class: 'label label-danger', title: `Until ${formatDate(u.lockUntil)}` }, 'Locked')
        : u.failedLogins > 0
          ? h('span', { class: 'label label-warn' }, `${u.failedLogins} failed`)
          : h('span', { class: 'label label-success' }, 'Active');
      const actions = h('div', { class: 'cell-actions' });
      if (u.locked) actions.append(h('button', { class: 'btn btn-sm', type: 'button', onclick: () => act(`/api/admin/users/${u.id}/unlock`, `Unlocked ${u.username}.`) }, 'Unlock'));
      if (u.mfaEnabled && u.id !== me.id) {
        actions.append(h('button', {
          class: 'btn btn-sm btn-danger',
          type: 'button',
          onclick: () => window.confirm(`Reset 2FA for ${u.username}? They will be signed out.`) && act(`/api/admin/users/${u.id}/reset-mfa`, `2FA reset for ${u.username}.`),
        }, 'Reset 2FA'));
      }
      body.append(h('tr', null,
        h('td', null, h('strong', null, u.username), u.id === me.id ? h('span', { class: 'small muted' }, ' (you)') : null),
        h('td', null, h('span', { class: `label ${u.role === 'admin' ? 'label-done' : ''}` }, u.role)),
        h('td', null, u.mfaEnabled ? h('span', { class: 'label label-success' }, 'On') : h('span', { class: 'label' }, 'Off')),
        h('td', null, status),
        h('td', { class: 'mono' }, String(u.notes)),
        h('td', { class: 'muted', title: formatDate(u.lastLoginAt) }, timeAgo(u.lastLoginAt)),
        h('td', null, actions)));
    }
  }

  function renderAudit() {
    const level = $('#audit-level').value;
    const q = $('#audit-search').value.trim().toLowerCase();
    const rows = events.filter((e) => (!level || e.level === level)
      && (!q || [e.type, e.username, e.ip, e.detail].some((v) => v && String(v).toLowerCase().includes(q))));
    const body = clear($('#audit-body'));
    if (!rows.length) body.append(h('tr', null, h('td', { colspan: '5', class: 'muted' }, 'No matching events.')));
    for (const e of rows.slice(0, 300)) {
      body.append(h('tr', null,
        h('td', null, h('span', { class: `lvl lvl-${e.level}` }), h('span', { class: 'event-type' }, e.type)),
        h('td', null, e.username || '—'),
        h('td', { class: 'muted' }, e.detail || '—'),
        h('td', { class: 'mono', title: e.ua || '' }, e.ip || '—'),
        h('td', { class: 'muted', title: formatDate(e.at) }, timeAgo(e.at))));
    }
  }

  async function loadAudit() {
    events = (await api.get('/api/admin/audit?limit=500')).events;
    renderAudit();
  }

  async function refresh() {
    try {
      await Promise.all([loadStats(), loadUsers(), loadAudit()]);
    } catch (err) {
      toast(err.message, 'danger');
    }
  }

  $('#refresh').addEventListener('click', refresh);
  $('#audit-level').addEventListener('change', renderAudit);
  $('#audit-search').addEventListener('input', renderAudit);

  App.ready.then((user) => {
    if (!user) return;
    me = user;
    refresh();
  });
})();
