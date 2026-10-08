(() => {
  'use strict';
  const { api, $, flash } = App;

  const params = new URLSearchParams(location.search);
  const banner = $('#flash');
  if (params.has('expired')) flash(banner, 'warn', 'Your session ended. Sign in again to continue.');
  else if (params.has('signedout')) flash(banner, 'info', 'You have been signed out.');
  else if (params.has('registered')) {
    flash(banner, 'success', params.get('admin') === '1'
      ? 'Account created. As the first user, you have the admin role. Sign in to continue.'
      : 'Account created. Sign in to continue.');
  }
  // Drop the query string so a refresh doesn't replay the message.
  if (location.search) history.replaceState(null, '', '/login');

  const form = $('#login-form');
  const btn = $('#login-btn');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('#username').value.trim();
    const password = $('#password').value;
    if (!username || !password) return flash(banner, 'danger', 'Enter your username and password.');
    btn.disabled = true;
    btn.textContent = 'Signing in…';
    try {
      const res = await api.post('/api/auth/login', { username, password });
      if (res.mfaRequired) {
        $('#step-password').hidden = true;
        $('#step-mfa').hidden = false;
        $('#code').focus();
        return undefined;
      }
      location.assign(res.redirect || '/dashboard');
    } catch (err) {
      flash(banner, 'danger', err.message);
      $('#password').value = '';
      $('#password').focus();
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
    return undefined;
  });

  const mfaForm = $('#mfa-form');
  const mfaBtn = $('#mfa-btn');
  const code = $('#code');
  code.addEventListener('input', () => {
    code.value = code.value.replace(/\D/g, '').slice(0, 6);
    if (code.value.length === 6) mfaForm.requestSubmit();
  });
  mfaForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!/^\d{6}$/.test(code.value)) return flash($('#mfa-flash'), 'danger', 'Enter the 6-digit code.');
    mfaBtn.disabled = true;
    try {
      const res = await api.post('/api/auth/mfa', { code: code.value });
      location.assign(res.redirect || '/dashboard');
    } catch (err) {
      if (err.data && err.data.restart) {
        location.assign('/login?expired=1');
        return undefined;
      }
      flash($('#mfa-flash'), 'danger', err.message);
      code.value = '';
      code.focus();
    } finally {
      mfaBtn.disabled = false;
    }
    return undefined;
  });
})();
