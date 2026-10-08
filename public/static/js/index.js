(() => {
  'use strict';
  // Landing page: if already signed in, swap guest buttons for "Open vault".
  fetch('/api/auth/status', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
    .then((res) => res.json())
    .then(({ authenticated }) => {
      if (!authenticated) return;
      document.querySelectorAll('[data-guest]').forEach((e) => { e.hidden = true; });
      document.querySelectorAll('[data-member]').forEach((e) => { e.hidden = false; });
    })
    .catch(() => {});
})();
