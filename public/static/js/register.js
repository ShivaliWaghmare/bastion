(() => {
  'use strict';
  const { api, $, flash, bindStrength } = App;

  const user = $('#username');
  const pw = $('#password');
  const confirm = $('#confirm');
  const banner = $('#flash');
  const btn = $('#register-btn');

  bindStrength(pw, $('#meter-bar'), $('#meter-label'));

  const rules = {
    length: () => pw.value.length >= 12,
    username: () => pw.value.length > 0 && (!user.value.trim() || !pw.value.toLowerCase().includes(user.value.trim().toLowerCase())),
    match: () => pw.value.length > 0 && pw.value === confirm.value,
  };
  function refresh() {
    document.querySelectorAll('#checklist li').forEach((li) => li.classList.toggle('ok', rules[li.dataset.rule]()));
    $('#pw-len').textContent = `${pw.value.length} / 128`;
  }
  [user, pw, confirm].forEach((el) => el.addEventListener('input', refresh));
  refresh();

  $('#register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = user.value.trim();
    if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) return flash(banner, 'danger', 'Username must be 3–32 characters: letters, numbers or underscore.');
    const failed = Object.entries(rules).find(([, ok]) => !ok());
    if (failed) {
      const msg = { length: 'Password must be at least 12 characters.', username: 'Password must not contain your username.', match: 'Passwords do not match.' };
      return flash(banner, 'danger', msg[failed[0]]);
    }
    btn.disabled = true;
    btn.textContent = 'Creating account…';
    try {
      const res = await api.post('/api/auth/register', { username, password: pw.value });
      location.assign(`/login?registered=1${res.role === 'admin' ? '&admin=1' : ''}`);
    } catch (err) {
      flash(banner, 'danger', err.message);
      btn.disabled = false;
      btn.textContent = 'Create account';
    }
    return undefined;
  });
})();
