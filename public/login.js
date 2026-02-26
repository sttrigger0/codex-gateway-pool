function q(id) { return document.getElementById(id); }

function setStatus(text, kind = '') {
  const el = q('status');
  if (!el) return;
  el.textContent = String(text || '');
  el.classList.remove('ok', 'error');
  if (kind) el.classList.add(kind);
}

async function login() {
  const username = String(q('username') && q('username').value || '').trim();
  const password = String(q('password') && q('password').value || '');
  setStatus('Logging in...');

  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body && body.error ? body.error : `HTTP ${res.status}`);

  setStatus('Login successful.', 'ok');
  window.location.href = '/';
}

q('loginBtn').addEventListener('click', () => {
  login().catch((err) => setStatus(`Error: ${err.message}`, 'error'));
});

q('password').addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') {
    login().catch((err) => setStatus(`Error: ${err.message}`, 'error'));
  }
});
