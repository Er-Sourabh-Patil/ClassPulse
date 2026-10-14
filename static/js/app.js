// Keep each browser tab on its own ClassPulse identity. Never put credentials in the token;
// it is only an opaque key to a server-side session record.
(function isolateTabSession() {
  let token = '';
  try { token = sessionStorage.getItem('classpulse_tab_session') || ''; } catch (_) {}
  const current = new URL(window.location.href);
  const fromUrl = current.searchParams.get('tab_session');
  if (fromUrl && /^[A-Za-z0-9_-]{32,100}$/.test(fromUrl)) token = fromUrl;
  if (!token) {
    const field = document.querySelector('input[name="tab_session"]');
    token = field ? field.value : '';
  }
  if (token) {
    try { sessionStorage.setItem('classpulse_tab_session', token); } catch (_) {}
    document.querySelectorAll('a[href]').forEach(link => {
      try {
        const u = new URL(link.href, window.location.origin);
        if (u.origin === window.location.origin && !u.pathname.startsWith('/static/')) {
          u.searchParams.set('tab_session', token); link.href = u.toString();
        }
      } catch (_) {}
    });
    document.querySelectorAll('form').forEach(form => {
      let field = form.querySelector('input[name="tab_session"]');
      if (!field) { field = document.createElement('input'); field.type = 'hidden'; field.name = 'tab_session'; form.appendChild(field); }
      field.value = token;
      // Do not read form.action: an input named "action" shadows that DOM property
      // and turns the submission URL into "[object HTMLInputElement]".
      try {
        const declaredAction = form.getAttribute('action');
        const actionUrl = declaredAction
          ? new URL(declaredAction, window.location.origin)
          : new URL(window.location.pathname + window.location.search, window.location.origin);
        if (actionUrl.origin === window.location.origin) {
          actionUrl.searchParams.set('tab_session', token);
          form.setAttribute('action', actionUrl.pathname + actionUrl.search + actionUrl.hash);
        }
      } catch (_) {}
    });
  }
})();

document.addEventListener('DOMContentLoaded', () => {
  const menu = document.getElementById('menuToggle');
  const sidebar = document.getElementById('sidebar');
  if (menu && sidebar) menu.addEventListener('click', () => sidebar.classList.toggle('open'));
  const toggle = document.getElementById('togglePassword');
  const password = document.getElementById('password');
  if (toggle && password) toggle.addEventListener('click', () => {
    const show = password.type === 'password'; password.type = show ? 'text' : 'password';
    toggle.innerHTML = show ? '<i class="bi bi-eye-slash"></i>' : '<i class="bi bi-eye"></i>';
    toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    const value = button.getAttribute('data-copy');
    try { await navigator.clipboard.writeText(value); button.innerHTML = '<i class="bi bi-check2"></i>'; }
    catch (_) { window.prompt('Copy this value:', value); }
  }));
  const search = document.getElementById('tableSearch');
  if (search) search.addEventListener('input', () => {
    const q = search.value.toLowerCase();
    document.querySelectorAll('.data-table tbody tr').forEach(row => { row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none'; });
  });
  document.querySelectorAll('[data-bs-toggle="popover"]').forEach(el => new bootstrap.Popover(el));
  document.querySelectorAll('form[onsubmit]').forEach(form => form.addEventListener('submit', event => {
    if (form.getAttribute('onsubmit') === 'return confirm(\'Change this account status?\')' || form.getAttribute('onsubmit') === 'return confirm(\'Change this activity status?\')') {
      if (!window.confirm(form.getAttribute('onsubmit').includes('account') ? 'Change this account status?' : 'Change this activity status?')) event.preventDefault();
    }
  }));
});
