
document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss toasts
  document.querySelectorAll('.toast').forEach((t, i) => {
    setTimeout(() => {
      t.style.transition = 'opacity .4s ease, transform .4s ease';
      t.style.opacity = '0';
      t.style.transform = 'translateX(20px)';
      setTimeout(() => t.remove(), 450);
    }, 4200 + i * 350);
  });

  // Password visibility toggle
  document.querySelectorAll('[data-toggle="password"]').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = document.querySelector(btn.dataset.target);
      if (!target) return;
      const type = target.getAttribute('type') === 'password' ? 'text' : 'password';
      target.setAttribute('type', type);
      btn.textContent = type === 'password' ? 'Show' : 'Hide';
    });
  });

  // Lightweight validation
  const forms = document.querySelectorAll('form[data-validate]');
  forms.forEach(form => {
    const email = form.querySelector('input[name="email"]');
    const password = form.querySelector('input[name="password"]');
    const username = form.querySelector('input[name="username"]');
    const confirm = form.querySelector('#confirm_password'); // signup only
    const submit = form.querySelector('button[type="submit"]');

    const errs = {
      email: form.querySelector('[data-error="email"]'),
      password: form.querySelector('[data-error="password"]'),
      username: form.querySelector('[data-error="username"]'),
      confirm: form.querySelector('[data-error="confirm"]'),
    };

    const touched = new Set();
    let submitAttempted = false;

    function markTouched(el){
      if (!el) return;
      el.dataset.dirty = '1';
      touched.add(el.name || el.id);
    }
    ['input','change','blur'].forEach(evt => {
      form.addEventListener(evt, (e) => {
        if (e.target.matches('input')) markTouched(e.target);
        validate();
      }, true);
    });
    form.addEventListener('submit', () => { submitAttempted = true; });

    function validEmail(v){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v || ''); }
    function show(field){ return submitAttempted || touched.has(field); }
    function validate() {
      let ok = true;
      if (email) {
        const good = validEmail(email.value);
        ok &&= good;
        errs.email.textContent = (!good && show('email')) ? 'Enter a valid email address.' : '';
      }
      if (password) {
        const good = (password.value || '').length >= 8;
        ok &&= good;
        errs.password.textContent = (!good && show('password')) ? 'Password must be at least 8 characters.' : '';
      }
      if (username) {
        const good = (username.value || '').trim().length >= 3;
        ok &&= good;
        errs.username.textContent = (!good && show('username')) ? 'Username must be at least 3 characters.' : '';
      }
      if (confirm) {
        const good = confirm.value === (password?.value || '');
        ok &&= good;
        errs.confirm.textContent = (!good && show('confirm_password')) ? 'Passwords do not match.' : '';
      }
      if (submit) submit.disabled = !ok;
    }
    validate();
  });
  // Show signup-success modal if redirected with ?registered=1
  const params = new URLSearchParams(location.search);
  if (params.get('registered') === '1') {
    const modal = document.getElementById('modal');
    if (modal) {
      modal.classList.add('open');
      const close = () => {
        modal.classList.remove('open');
        // clean up the ?registered=1
        history.replaceState({}, '', location.pathname);
      };
      // close on primary button
      modal.querySelectorAll('[data-close]').forEach(btn =>
        btn.addEventListener('click', close)
      );
      // close on backdrop click
      modal.querySelector('.modal-backdrop')?.addEventListener('click', close);
      // close on Escape
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') close();
      }, { once: true });
    }
  }
 // ---------- Back/Forward cache hardening for auth pages ----------
  // If user navigates Back to /login or /signup while already authenticated,
  // browsers may show a cached copy of the form. We (a) wipe fields fast,
  // (b) check auth state, and (c) reload to get the signed-in gate.
  function isAuthPage() {
    const p = location.pathname;
    return p.endsWith('/login') || p.endsWith('/signup');
  }
  function clearAuthInputsVisibleOnly() {
    if (!isAuthPage()) return;
    const form = document.querySelector('form');
    if (!form) return;
    // Only clear visible credential fields – do NOT touch hidden inputs like csrf_token
    form.querySelectorAll('input[type="password"], input[type="text"], input[type="email"]').forEach(i => {
      try { i.value = ''; } catch(_) {}
    });
  }
  window.addEventListener('pageshow', (e) => {
    if (!isAuthPage()) return;
    // Only clear on BFCache restores, so we don't wipe fresh page tokens
    if (e.persisted) {
      clearAuthInputsVisibleOnly();
      fetch('/auth/state', { credentials: 'same-origin' })
        .then(r => r.ok ? r.json() : { authenticated: false })
        .then(s => {
          if (s.authenticated) {
            // Reload the current URL so the server can render the signed-in gate
            location.replace(location.pathname);
          }
        })
        .catch(() => {/* ignore */});
    }
  });
});
