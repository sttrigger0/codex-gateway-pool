function q(id) {
  return document.getElementById(id);
}

function cleanDisplayText(raw) {
  const input = String(raw == null ? '' : raw);
  return input
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, '')
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
}

function setText(id, value) {
  const el = q(id);
  if (el) el.textContent = cleanDisplayText(String(value == null ? '' : value));
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    credentials: 'include',
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = body && body.error ? body.error : `HTTP ${res.status}`;
    throw new Error(message);
  }
  return body;
}

function showStatus(message) {
  const el = q('portalStatus');
  if (!el) return;
  el.classList.remove('ok', 'error');
  const text = String(message || '');
  if (/^Error:/i.test(text)) el.classList.add('error');
  else if (text) el.classList.add('ok');
  setText('portalStatus', text || 'Ready.');
}

const uiState = {
  models: [],
  defaultModel: '',
};

async function refreshModels() {
  const data = await api('/api/openai/v1/models');
  const list = Array.isArray(data && data.data) ? data.data : [];
  uiState.models = list;
  uiState.defaultModel = String(data && data.default_model || '');

  const select = q('testModel');
  if (select) {
    select.innerHTML = '';
    list.forEach((item) => {
      const opt = document.createElement('option');
      opt.value = String(item.id || '');
      opt.textContent = String(item.id || '');
      if (opt.value === uiState.defaultModel) opt.selected = true;
      select.appendChild(opt);
    });
  }

  setText('defaultModel', uiState.defaultModel || '-');
  setText('modelsList', list.map((item) => String(item.id || '')).join('\n') || 'No models reported.');
}

function updateUserUi(me) {
  if (!me || !me.ok || !me.user) {
    setText('userLabel', 'Not logged in');
    setText('codexStatus', 'Not connected');
    setText('keyMask', 'None');
    return;
  }

  const user = me.user;
  setText('userLabel', user.username);
  setText('codexStatus', user.codexConnected ? 'Connected' : 'Not connected');
  setText('keyMask', user.endpointKeyMask || 'None');

  const example = [
    `curl -sS https://${location.host}/api/openai/v1/chat/completions \\\n  -H 'Authorization: Bearer <YOUR_KEY>' \\\n  -H 'Content-Type: application/json' \\\n  -d '${JSON.stringify({ model: uiState.defaultModel || 'gpt-5.1-codex-mini', messages: [{ role: 'user', content: 'Reply with OK only.' }], max_output_tokens: 32, reasoning_mode: 'fast' })}'`,
  ].join('\n\n');
  setText('curlExample', example);
}

async function refreshMe() {
  const me = await api('/api/openai/auth/me');
  updateUserUi(me);
}

async function refreshDeviceStatus() {
  const data = await api('/api/openai/codex/device/status');
  const flow = data.flow || {};
  setText('deviceUrl', flow.loginUrl || '-');
  setText('userCode', flow.userCode || '-');

  const log = [
    `status=${flow.status || 'idle'} pid=${flow.pid || 0} exit=${flow.exitCode == null ? '-' : flow.exitCode}`,
    flow.error ? `error=${flow.error}` : '',
    flow.stdout ? `stdout:\n${flow.stdout}` : '',
    flow.stderr ? `stderr:\n${flow.stderr}` : '',
  ].filter(Boolean).join('\n\n');
  setText('deviceLogs', log || 'No device-auth logs yet.');
}

async function registerUser() {
  const username = String(q('username').value || '').trim();
  const password = String(q('password').value || '');
  await api('/api/openai/auth/register', {
    method: 'POST',
    body: { username, password },
  });
  await refreshMe();
  showStatus('Registered and logged in.');
}

async function loginUser() {
  const username = String(q('username').value || '').trim();
  const password = String(q('password').value || '');
  await api('/api/openai/auth/login', {
    method: 'POST',
    body: { username, password },
  });
  await refreshMe();
  showStatus('Logged in.');
}

async function logoutUser() {
  await api('/api/openai/auth/logout', { method: 'POST' });
  await refreshMe();
  setText('deviceLogs', 'No device-auth logs yet.');
  setText('deviceUrl', '-');
  setText('userCode', '-');
  setText('newKey', '(generate to reveal)');
  showStatus('Logged out.');
}

async function startDeviceAuth() {
  const data = await api('/api/openai/codex/device/start', { method: 'POST' });
  if (data.loginUrl) setText('deviceUrl', data.loginUrl);
  if (data.userCode) setText('userCode', data.userCode);
  await refreshDeviceStatus();
}

async function rotateKey() {
  const label = String(q('keyLabel').value || '').trim();
  const data = await api('/api/openai/keys/rotate', {
    method: 'POST',
    body: { label },
  });
  setText('newKey', data.apiKey || '(no key returned)');
  await refreshMe();
  showStatus('Endpoint key rotated.');
}

async function runSessionTest() {
  const prompt = String(q('testPrompt').value || '').trim();
  const cwd = String(q('testCwd').value || '/root').trim() || '/root';
  const model = q('testModel').value || uiState.defaultModel || '';

  setText('testOutput', 'Running...');
  const data = await api('/api/openai/codex/execute-session', {
    method: 'POST',
    body: { prompt, cwd, model },
  });
  if (!data.ok) {
    setText('testOutput', `Error: ${data.error || 'Request failed'}`);
    return;
  }
  setText('testOutput', data.output || '(empty output)');
}

function bind() {
  q('registerBtn').addEventListener('click', () => registerUser().catch((err) => showStatus(`Error: ${err.message}`)));
  q('loginBtn').addEventListener('click', () => loginUser().catch((err) => showStatus(`Error: ${err.message}`)));
  q('logoutBtn').addEventListener('click', () => logoutUser().catch((err) => showStatus(`Error: ${err.message}`)));
  q('startDeviceAuthBtn').addEventListener('click', () => startDeviceAuth().catch((err) => showStatus(`Error: ${err.message}`)));
  q('refreshStatusBtn').addEventListener('click', () => Promise.all([refreshMe(), refreshDeviceStatus()]).catch((err) => showStatus(`Error: ${err.message}`)));
  q('rotateKeyBtn').addEventListener('click', () => rotateKey().catch((err) => showStatus(`Error: ${err.message}`)));
  q('runTestBtn').addEventListener('click', () => runSessionTest().catch((err) => showStatus(`Error: ${err.message}`)));
}

bind();
Promise.all([refreshModels(), refreshMe(), refreshDeviceStatus()]).catch((err) => {
  showStatus(`Error: ${err && err.message ? err.message : 'Failed to load portal state'}`);
});
