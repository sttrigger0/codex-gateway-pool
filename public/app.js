function q(id) { return document.getElementById(id); }

function escapeHtml(raw) {
  return String(raw || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function fmtInt(v) {
  return Number(v || 0).toLocaleString();
}

function fmtDate(ms) {
  const n = Number(ms || 0);
  if (!n) return '-';
  return new Date(n).toLocaleString();
}

function fmtAgo(ms) {
  const n = Number(ms || 0);
  if (!n) return '-';
  const diff = Date.now() - n;
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function setStatus(text, kind = '') {
  const el = q('status');
  if (!el) return;
  el.textContent = String(text || '');
  el.classList.remove('ok', 'error');
  if (kind) el.classList.add(kind);
}

async function apiJson(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) {
      window.location.href = '/login';
      throw new Error('Session expired');
    }
    throw new Error(body && body.error ? body.error : `HTTP ${res.status}`);
  }
  return body;
}

function confirmAction(message) {
  return new Promise((resolve) => {
    let overlay = document.getElementById('confirmOverlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'confirmOverlay';
      overlay.innerHTML = `
        <div class="confirm-box">
          <p class="confirm-msg"></p>
          <div class="confirm-actions">
            <button class="btn confirm-cancel">Cancel</button>
            <button class="btn danger confirm-yes">Confirm</button>
          </div>
        </div>
      `;
      document.body.appendChild(overlay);
    }

    overlay.querySelector('.confirm-msg').textContent = message;
    overlay.classList.add('confirm-visible');

    const cleanup = (result) => {
      overlay.classList.remove('confirm-visible');
      overlay.querySelector('.confirm-cancel').removeEventListener('click', onCancel);
      overlay.querySelector('.confirm-yes').removeEventListener('click', onConfirm);
      overlay.removeEventListener('click', onOverlay);
      document.removeEventListener('keydown', onEsc);
      resolve(result);
    };

    const onCancel = () => cleanup(false);
    const onConfirm = () => cleanup(true);
    const onOverlay = (ev) => { if (ev.target === overlay) cleanup(false); };
    const onEsc = (ev) => { if (ev.key === 'Escape') cleanup(false); };

    overlay.querySelector('.confirm-cancel').addEventListener('click', onCancel);
    overlay.querySelector('.confirm-yes').addEventListener('click', onConfirm);
    overlay.addEventListener('click', onOverlay);
    document.addEventListener('keydown', onEsc);
  });
}

const state = {
  rows: [],
  totals: {},
  master: {},
};

function renderCards() {
  const host = q('summaryCards');
  if (!host) return;
  const t = state.totals || {};
  host.innerHTML = `
    <article class="card"><div class="label">Portal Users</div><div class="value">${fmtInt(t.users || 0)}</div><div class="sub">Registered users</div></article>
    <article class="card"><div class="label">API Keys Set</div><div class="value">${fmtInt(t.withApiKey || 0)}</div><div class="sub">Users with endpoint keys</div></article>
    <article class="card"><div class="label">Portal Online</div><div class="value">${fmtInt(t.portalOnline || 0)}</div><div class="sub">Users with active sessions</div></article>
    <article class="card"><div class="label">Codex Linked</div><div class="value">${fmtInt(t.codexConnected || 0)}</div><div class="sub">Users with auth.json</div></article>
    <article class="card"><div class="label">Device Auth Running</div><div class="value">${fmtInt(t.deviceAuthRunning || 0)}</div><div class="sub">Live login flows</div></article>
  `;
}

function renderMaster() {
  const m = state.master || {};
  q('masterMask').textContent = m.configured ? String(m.keyMask || '(masked)') : 'Not configured';

  const hourly = Number(m.combinedHourlyRemainingPercent);
  const weekly = Number(m.combinedWeeklyRemainingPercent);
  q('combinedHourly').textContent = Number.isFinite(hourly) ? `${Math.round(hourly)}%` : '-';
  q('combinedWeekly').textContent = Number.isFinite(weekly) ? `${Math.round(weekly)}%` : '-';
}

function renderTable() {
  const tbody = q('usersTable').querySelector('tbody');
  const rows = state.rows || [];
  q('usersCount').textContent = `${fmtInt(rows.length)} users`;

  const pct = (v, err) => {
    if (v == null || v === '') {
      return err ? `<span title="${escapeHtml(err)}" class="panel-meta">-</span>` : '<span class="panel-meta">-</span>';
    }
    const n = Number(v);
    if (!Number.isFinite(n)) return '<span class="panel-meta">-</span>';
    return `${Math.round(Math.max(0, Math.min(100, n)))}%`;
  };

  tbody.innerHTML = rows.map((r) => {
    const portal = r.portalOnline ? '<span class="panel-meta">Online</span>' : '<span class="panel-meta">Offline</span>';
    const linked = r.codexConnected ? '<span class="status-ok">Linked</span>' : '<span class="status-bad">Not linked</span>';
    const keyCell = r.hasEndpointKey
      ? `<code title="${escapeHtml(r.endpointKeyLabel || '')}">${escapeHtml(r.endpointKeyMask || '(masked)')}</code> <button class="btn subtle reveal-btn" data-u="${escapeHtml(r.username || '')}">Reveal</button>`
      : '<span class="panel-meta">Not set</span>';

    return `
      <tr>
        <td>${escapeHtml(r.username || '')}</td>
        <td>${keyCell}</td>
        <td>${portal}</td>
        <td>${fmtInt(r.portalSessionCount || 0)}</td>
        <td>${linked}</td>
        <td>${pct(r.hourlyRemainingPercent, r.rateLimitsError)}</td>
        <td>${pct(r.weeklyRemainingPercent, r.rateLimitsError)}</td>
        <td>${escapeHtml(String(r.deviceAuthStatus || 'idle'))}</td>
        <td title="${escapeHtml(fmtDate(r.lastPortalLoginAt))}">${fmtAgo(r.lastPortalLoginAt)}</td>
        <td title="${escapeHtml(fmtDate(r.updatedAt))}">${fmtAgo(r.updatedAt)}</td>
        <td><button class="btn primary delete-btn" data-u="${escapeHtml(r.username || '')}">Delete</button></td>
      </tr>
    `;
  }).join('') || '<tr><td colspan="11">No users.</td></tr>';
}

async function loadData() {
  setStatus('Refreshing...');
  const data = await apiJson('/api/admin/openai-users');
  state.rows = data.rows || [];
  state.totals = data.totals || {};
  state.master = data.specialOwnerKey || {};
  renderCards();
  renderMaster();
  renderTable();
  setStatus('Ready.', 'ok');
}

async function rotateMasterKey() {
  const btn = q('rotateMasterBtn');
  btn.disabled = true;
  q('masterNew').textContent = 'Generating...';
  try {
    const label = String(q('masterKeyLabel').value || '').trim();
    const endpoints = [
      '/api/admin/openai-users/rotate-master-key',
      '/api/admin/openai-users/rotate-owner-key',
      '/api/admin/openai-users/rotate-owner-special-key',
    ];
    let payload = null;
    let lastErr = null;
    for (const ep of endpoints) {
      try {
        payload = await apiJson(ep, { method: 'POST', body: JSON.stringify({ label }) });
        break;
      } catch (err) {
        lastErr = err;
        if (String(err && err.message || '') !== 'Not found') throw err;
      }
    }
    if (!payload) throw lastErr || new Error('Failed to rotate master key');
    q('masterNew').textContent = String(payload.apiKey || '(no key returned)');
    setStatus('Master key generated.', 'ok');
    await loadData();
  } catch (err) {
    q('masterNew').textContent = `Error: ${String(err.message || err)}`;
    setStatus(`Error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function revealUserKey(username) {
  try {
    const payload = await apiJson('/api/admin/openai-users/reveal-key', {
      method: 'POST',
      body: JSON.stringify({ username }),
    });
    await navigator.clipboard.writeText(String(payload.apiKey || ''));
    setStatus(`Revealed key for ${username}. Copied to clipboard.`, 'ok');
  } catch (err) {
    setStatus(`Error: ${err.message}`, 'error');
  }
}

async function deleteUser(username, btn) {
  const confirmed = await confirmAction(`Delete OpenAI portal user ${username}?`);
  if (!confirmed) return;

  const prevText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Deleting...';
  try {
    await apiJson('/api/admin/openai-users/delete', {
      method: 'POST',
      body: JSON.stringify({ username }),
    });
    setStatus(`Deleted ${username}.`, 'ok');
    await loadData();
  } catch (err) {
    setStatus(`Error: ${err.message}`, 'error');
    btn.disabled = false;
    btn.textContent = prevText;
  }
}

async function logout() {
  try {
    await apiJson('/api/auth/logout', { method: 'POST', body: JSON.stringify({}) });
  } catch (_err) { }
  window.location.href = '/login';
}

q('refreshBtn').addEventListener('click', () => { loadData().catch((err) => setStatus(`Error: ${err.message}`, 'error')); });
q('logoutBtn').addEventListener('click', () => { logout(); });
q('rotateMasterBtn').addEventListener('click', () => { rotateMasterKey(); });

q('usersTable').addEventListener('click', (ev) => {
  const reveal = ev.target.closest('.reveal-btn');
  if (reveal) {
    const username = String(reveal.dataset.u || '').trim();
    if (username) revealUserKey(username);
    return;
  }
  const del = ev.target.closest('.delete-btn');
  if (del) {
    const username = String(del.dataset.u || '').trim();
    if (username) deleteUser(username, del);
  }
});

loadData().catch((err) => setStatus(`Error: ${err.message}`, 'error'));
