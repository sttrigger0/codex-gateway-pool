const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile, spawn } = require('child_process');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const SETTINGS_FILE = path.join(ROOT, 'settings.json');
const STATE_FILE = path.join(DATA_DIR, 'state.json');

function safeReadJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_err) {
    return fallback;
  }
}

function writeJsonFile(filePath, payload) {
  fs.writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`);
}

function toInt(value, fallback = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.floor(n);
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function coerceBool(v, fallback = false) {
  if (v === true || v === false) return v;
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase();
    if (s === 'true' || s === '1' || s === 'yes') return true;
    if (s === 'false' || s === '0' || s === 'no') return false;
  }
  return fallback;
}

const settings = safeReadJson(SETTINGS_FILE, {});
const HOST = String(process.env.HOST || settings.host || '0.0.0.0');
const PORT = clamp(toInt(process.env.PORT || settings.port, 8787), 1, 65535);
const HTTPS_ENABLED = coerceBool(settings.httpsEnabled, false);

const DASHBOARD_AUTH_ENABLED = coerceBool(settings.dashboardAuthEnabled, true);
const DASHBOARD_SESSION_COOKIE = 'dashboard_session';
const OPENAI_PORTAL_SESSION_COOKIE = 'openai_portal_session';
const DASHBOARD_SESSION_TTL_MS = clamp(toInt(settings.dashboardSessionTtlMs, 1000 * 60 * 60 * 24 * 30), 60_000, 1000 * 60 * 60 * 24 * 365);
const OPENAI_PORTAL_SESSION_TTL_MS = clamp(toInt(settings.openaiPortalSessionTtlMs, 1000 * 60 * 60 * 24 * 30), 60_000, 1000 * 60 * 60 * 24 * 365);
const MAX_SESSIONS = clamp(toInt(settings.maxSessions, 5000), 100, 100_000);

const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || settings.adminUsername || 'admin').trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || settings.adminPassword || '').trim();

const OPENAI_API_KEY_PREFIX = String(process.env.OPENAI_API_KEY_PREFIX || settings.openaiApiKeyPrefix || 'rneo_codex_');
const OPENAI_MASTER_KEY_PREFIX = String(process.env.OPENAI_MASTER_KEY_PREFIX || settings.openaiMasterKeyPrefix || 'rneo_master_');
const OPENAI_KEY_ENCRYPTION_SECRET = String(
  process.env.OPENAI_KEY_ENCRYPTION_SECRET
  || settings.openaiKeyEncryptionSecret
  || ADMIN_PASSWORD
  || 'change-me'
);

const OPENAI_CODEX_TIMEOUT_MS = clamp(toInt(settings.openaiCodexTimeoutMs, 120_000), 5_000, 10 * 60 * 1000);
const OPENAI_RATE_LIMIT_CACHE_TTL_MS = clamp(toInt(settings.openaiRateLimitCacheTtlMs, 60_000), 5_000, 10 * 60 * 1000);
const OPENAI_PROMPT_MAX_LEN = clamp(toInt(settings.openaiPromptMaxLen, 48 * 1024), 1024, 512 * 1024);
const CODEX_HOME_ROOT = String(settings.codexHomeRoot || path.join(DATA_DIR, 'openai_codex'));
const OPENAI_MODEL_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const OPENAI_KEY_LABEL_MAX_LEN = 64;
const USERNAME_RE = /^[A-Za-z0-9._-]{2,32}$/;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(CODEX_HOME_ROOT, { recursive: true });

if (!fs.existsSync(STATE_FILE)) {
  writeJsonFile(STATE_FILE, {
    revision: 1,
    users: {},
    specialMasterKey: {
      keySalt: '',
      keyHash: '',
      keyMask: '',
      keyLabel: '',
      keyCipher: '',
      keyIv: '',
      keyTag: '',
      createdAt: 0,
      updatedAt: 0,
    },
  });
}

const dashboardSessions = new Map();
const openaiPortalSessions = new Map();
const openaiDeviceFlows = new Map();
const openaiRateLimitCache = new Map();
const masterKeyCursorByHash = new Map();

function readState() {
  const raw = safeReadJson(STATE_FILE, { revision: 1, users: {}, specialMasterKey: {} });
  const users = {};
  const srcUsers = raw && raw.users && typeof raw.users === 'object' ? raw.users : {};
  for (const [username, rec] of Object.entries(srcUsers)) {
    const name = String(username || '').trim();
    if (!USERNAME_RE.test(name)) continue;
    users[name] = {
      username: name,
      passwordSalt: String(rec.passwordSalt || ''),
      passwordHash: String(rec.passwordHash || ''),
      endpointKeySalt: String(rec.endpointKeySalt || ''),
      endpointKeyHash: String(rec.endpointKeyHash || ''),
      endpointKeyMask: String(rec.endpointKeyMask || ''),
      endpointKeyLabel: String(rec.endpointKeyLabel || '').slice(0, OPENAI_KEY_LABEL_MAX_LEN),
      endpointKeyCipher: String(rec.endpointKeyCipher || ''),
      endpointKeyIv: String(rec.endpointKeyIv || ''),
      endpointKeyTag: String(rec.endpointKeyTag || ''),
      createdAt: toInt(rec.createdAt, Date.now()),
      updatedAt: toInt(rec.updatedAt, Date.now()),
      lastLoginAt: toInt(rec.lastLoginAt, 0),
      codexConnectedAt: toInt(rec.codexConnectedAt, 0),
      codexHome: String(rec.codexHome || path.join(CODEX_HOME_ROOT, slugifyUsername(name))),
    };
  }
  const k = raw && raw.specialMasterKey && typeof raw.specialMasterKey === 'object' ? raw.specialMasterKey : {};
  const specialMasterKey = {
    keySalt: String(k.keySalt || ''),
    keyHash: String(k.keyHash || ''),
    keyMask: String(k.keyMask || ''),
    keyLabel: String(k.keyLabel || '').slice(0, OPENAI_KEY_LABEL_MAX_LEN),
    keyCipher: String(k.keyCipher || ''),
    keyIv: String(k.keyIv || ''),
    keyTag: String(k.keyTag || ''),
    createdAt: toInt(k.createdAt, 0),
    updatedAt: toInt(k.updatedAt, 0),
  };

  return {
    revision: Math.max(1, toInt(raw.revision, 1)),
    users,
    specialMasterKey,
  };
}

function writeState(state) {
  writeJsonFile(STATE_FILE, {
    revision: Math.max(1, toInt(state && state.revision, 1)),
    users: state && state.users && typeof state.users === 'object' ? state.users : {},
    specialMasterKey: state && state.specialMasterKey && typeof state.specialMasterKey === 'object'
      ? state.specialMasterKey
      : {
        keySalt: '', keyHash: '', keyMask: '', keyLabel: '', keyCipher: '', keyIv: '', keyTag: '', createdAt: 0, updatedAt: 0,
      },
  });
}

function slugifyUsername(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 32);
}

function hashSecret(input, salt) {
  const digest = crypto.scryptSync(String(input || ''), String(salt || ''), 64);
  return digest.toString('hex');
}

function verifySecret(input, salt, expectedHex) {
  const a = Buffer.from(hashSecret(input, salt), 'hex');
  const b = Buffer.from(String(expectedHex || ''), 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function getOpenAiKeyEncryptionKey() {
  return crypto.createHash('sha256').update(String(OPENAI_KEY_ENCRYPTION_SECRET || '')).digest();
}

function encryptKey(rawKey) {
  const key = getOpenAiKeyEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(rawKey || ''), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    cipher: enc.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function decryptKey(userRec) {
  try {
    const key = getOpenAiKeyEncryptionKey();
    const iv = Buffer.from(String(userRec && userRec.endpointKeyIv || ''), 'base64');
    const cipherText = Buffer.from(String(userRec && userRec.endpointKeyCipher || ''), 'base64');
    const tag = Buffer.from(String(userRec && userRec.endpointKeyTag || ''), 'base64');
    if (!iv.length || !cipherText.length || !tag.length) return '';
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8');
  } catch (_err) {
    return '';
  }
}

function maskKey(rawKey) {
  const v = String(rawKey || '');
  if (v.length <= 10) return `${v.slice(0, 2)}***`;
  return `${v.slice(0, 10)}...${v.slice(-4)}`;
}

function generateEndpointKey() {
  return `${OPENAI_API_KEY_PREFIX}${crypto.randomBytes(24).toString('hex')}`;
}

function generateMasterKey() {
  return `${OPENAI_MASTER_KEY_PREFIX}${crypto.randomBytes(24).toString('hex')}`;
}

function sanitizePortalUser(user) {
  const codexAuthFile = path.join(String(user.codexHome || ''), 'auth.json');
  return {
    username: String(user.username || ''),
    endpointKeyMask: String(user.endpointKeyMask || ''),
    endpointKeyLabel: String(user.endpointKeyLabel || ''),
    createdAt: toInt(user.createdAt, 0),
    updatedAt: toInt(user.updatedAt, 0),
    lastLoginAt: toInt(user.lastLoginAt, 0),
    codexConnectedAt: toInt(user.codexConnectedAt, 0),
    codexConnected: fs.existsSync(codexAuthFile),
  };
}

function parseCookies(req) {
  const raw = String(req && req.headers && req.headers.cookie || '');
  const out = {};
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch (_err) {
      out[key] = value;
    }
  }
  return out;
}

function appendSetCookie(res, value) {
  const prev = res.getHeader('Set-Cookie');
  if (!prev) {
    res.setHeader('Set-Cookie', value);
    return;
  }
  if (Array.isArray(prev)) {
    res.setHeader('Set-Cookie', [...prev, value]);
    return;
  }
  res.setHeader('Set-Cookie', [String(prev), value]);
}

function setSessionCookie(res, name, sessionId, ttlMs) {
  const maxAgeSec = Math.max(60, Math.floor(ttlMs / 1000));
  const parts = [
    `${name}=${encodeURIComponent(String(sessionId || ''))}`,
    `Max-Age=${maxAgeSec}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (HTTPS_ENABLED) parts.push('Secure');
  appendSetCookie(res, parts.join('; '));
}

function clearSessionCookie(res, name) {
  const parts = [
    `${name}=`,
    'Max-Age=0',
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (HTTPS_ENABLED) parts.push('Secure');
  appendSetCookie(res, parts.join('; '));
}

function pruneSessions(map) {
  const now = Date.now();
  for (const [sid, rec] of map.entries()) {
    if (!rec || toInt(rec.expiresAt, 0) <= now) map.delete(sid);
  }
}

function createSession(map, username, ttlMs) {
  pruneSessions(map);
  const id = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  map.set(id, {
    username: String(username || ''),
    createdAt: now,
    updatedAt: now,
    expiresAt: now + ttlMs,
  });
  if (map.size > MAX_SESSIONS) {
    const ordered = Array.from(map.entries()).sort((a, b) => toInt(a[1] && a[1].updatedAt, 0) - toInt(b[1] && b[1].updatedAt, 0));
    const over = map.size - MAX_SESSIONS;
    for (let i = 0; i < over; i += 1) map.delete(ordered[i][0]);
  }
  return id;
}

function getSession(map, req, cookieName, ttlMs) {
  pruneSessions(map);
  const cookies = parseCookies(req);
  const sid = String(cookies[cookieName] || '').trim();
  if (!sid) return { ok: false };
  const rec = map.get(sid);
  if (!rec) return { ok: false };
  if (toInt(rec.expiresAt, 0) <= Date.now()) {
    map.delete(sid);
    return { ok: false };
  }
  rec.updatedAt = Date.now();
  rec.expiresAt = rec.updatedAt + ttlMs;
  map.set(sid, rec);
  return { ok: true, sessionId: sid, username: String(rec.username || '') };
}

function writeJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendAuthChallenge(res, pathname = '/') {
  if (String(pathname || '').startsWith('/api/')) {
    writeJson(res, 401, { ok: false, error: 'Authentication required', loginRequired: true });
    return;
  }
  res.writeHead(302, {
    Location: '/login',
    'Cache-Control': 'no-store',
  });
  res.end();
}

function readBodyJson(req, maxBytes = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('error', (err) => reject(err));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (_err) {
        reject(new Error('Invalid JSON body'));
      }
    });
  });
}

function extractBearerToken(req) {
  const auth = String(req && req.headers && req.headers.authorization || '');
  if (!auth.toLowerCase().startsWith('bearer ')) return '';
  return auth.slice(7).trim();
}

function isValidModel(model) {
  return OPENAI_MODEL_RE.test(String(model || '').trim());
}

function listAvailableModels() {
  return [
    { id: 'gpt-5.3-codex', display_name: 'gpt-5.3-codex', description: '', supported_in_api: true, visibility: 'list' },
    { id: 'gpt-5.1-codex-mini', display_name: 'gpt-5.1-codex-mini', description: '', supported_in_api: true, visibility: 'list' },
    { id: 'gpt-5.1-codex', display_name: 'gpt-5.1-codex', description: '', supported_in_api: true, visibility: 'list' },
  ];
}

function pickDefaultModel() {
  const models = listAvailableModels();
  return String(models[0] && models[0].id || 'gpt-5.3-codex');
}

function pickFastModel() {
  const models = listAvailableModels();
  const mini = models.find((m) => String(m.id || '').includes('mini'));
  return String((mini && mini.id) || pickDefaultModel());
}

function normalizeReasoningMode(rawMode, fallback = 'normal') {
  const mode = String(rawMode || '').trim().toLowerCase();
  if (mode === 'fast' || mode === 'low') return 'fast';
  if (mode === 'normal' || mode === 'balanced' || mode === 'medium') return 'normal';
  if (mode === 'high') return 'high';
  if (mode === 'very_high' || mode === 'very-high' || mode === 'xhigh' || mode === 'max') return 'very_high';
  return fallback;
}

function modeToReasoningEffort(modeId) {
  if (modeId === 'fast') return 'low';
  if (modeId === 'high') return 'high';
  if (modeId === 'very_high') return 'xhigh';
  return 'medium';
}

function normalizeMessages(rawMessages) {
  const input = Array.isArray(rawMessages) ? rawMessages : [];
  const out = [];
  for (const item of input) {
    if (!item || typeof item !== 'object') continue;
    const role = String(item.role || '').trim().toLowerCase();
    if (!['system', 'user', 'assistant'].includes(role)) continue;
    let content = '';
    if (typeof item.content === 'string') {
      content = item.content;
    } else if (Array.isArray(item.content)) {
      content = item.content
        .filter((part) => part && typeof part === 'object' && String(part.type || '') === 'text')
        .map((part) => String(part.text || ''))
        .join('\n');
    }
    content = String(content || '').trim();
    if (!content) continue;
    out.push({ role, content: content.slice(0, OPENAI_PROMPT_MAX_LEN) });
  }
  return out;
}

function buildPromptFromMessages(messages) {
  const intro = [
    'You are a pure text/code generation assistant.',
    'Return only the direct assistant response.',
  ].join(' ');
  const lines = [intro, '', 'Conversation:'];
  for (const msg of messages) {
    lines.push(`${msg.role.toUpperCase()}: ${msg.content}`);
  }
  lines.push('ASSISTANT:');
  return lines.join('\n');
}

function parseCodexJsonLines(rawJsonl) {
  const lines = String(rawJsonl || '').split('\n').map((line) => line.trim()).filter(Boolean);
  let lastAssistantText = '';
  for (const line of lines) {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (_err) {
      continue;
    }
    const content = parsed && parsed.content;
    if (Array.isArray(content)) {
      const text = content
        .filter((part) => part && typeof part === 'object' && part.type === 'output_text')
        .map((part) => String(part.text || ''))
        .join('\n')
        .trim();
      if (text) lastAssistantText = text;
    }
    if (parsed && parsed.type === 'message' && parsed.role === 'assistant' && typeof parsed.text === 'string') {
      const text = parsed.text.trim();
      if (text) lastAssistantText = text;
    }
  }
  return lastAssistantText;
}

function normalizeCodexError(err, stderr) {
  const base = String((err && err.message) || stderr || err || '').trim();
  if (!base) return 'Codex request failed';
  return base.slice(0, 500);
}

function runCodexChatForUser(user, messages, options = {}) {
  const normalized = normalizeMessages(messages);
  if (!normalized.length) {
    return Promise.resolve({ ok: false, error: 'messages must contain at least one text message' });
  }

  const maxOutputTokens = clamp(toInt(options.maxOutputTokens, 512), 1, 8192);
  const requestedModel = String(options.model || '').trim();
  const selectedModel = isValidModel(requestedModel)
    ? requestedModel
    : (normalizeReasoningMode(options.reasoningMode, 'normal') === 'fast' ? pickFastModel() : pickDefaultModel());
  const reasoningMode = normalizeReasoningMode(options.reasoningMode || 'normal', 'normal');
  const reasoningEffort = modeToReasoningEffort(reasoningMode);
  const prompt = `${buildPromptFromMessages(normalized)}\n\nLimit your final response to at most ${maxOutputTokens} tokens.`;
  const timeoutMs = clamp(toInt(options.timeoutMs, OPENAI_CODEX_TIMEOUT_MS), 5_000, 10 * 60 * 1000);
  const outFile = path.join('/tmp', `codex_gateway_chat_${crypto.randomBytes(8).toString('hex')}.txt`);

  const args = [
    'exec',
    '--skip-git-repo-check',
    '--ephemeral',
    '-c',
    `model_reasoning_effort="${reasoningEffort}"`,
    '-c',
    'model_verbosity="low"',
    '-m',
    selectedModel,
    '--sandbox',
    'read-only',
    '--cd',
    '/tmp',
    '-o',
    outFile,
    prompt,
  ];

  return new Promise((resolve) => {
    execFile('codex', args, {
      env: {
        ...process.env,
        CODEX_HOME: user.codexHome,
      },
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    }, (err, stdout, stderr) => {
      let text = '';
      try {
        text = fs.readFileSync(outFile, 'utf8').trim();
      } catch (_readErr) {
        text = parseCodexJsonLines(stdout);
      }
      try { fs.unlinkSync(outFile); } catch (_err2) { }

      if (err) {
        resolve({
          ok: false,
          error: normalizeCodexError(err, stderr),
          stderr: String(stderr || '').slice(0, 2000),
          output: text,
        });
        return;
      }
      resolve({
        ok: true,
        output: String(text || '').trim(),
        stderr: String(stderr || '').slice(0, 2000),
        model: selectedModel,
        reasoningMode,
      });
    });
  });
}

function runCodexPromptForUser(user, prompt, options = {}) {
  const cleanPrompt = String(prompt || '').trim().slice(0, OPENAI_PROMPT_MAX_LEN);
  if (!cleanPrompt) return Promise.resolve({ ok: false, error: 'Prompt is required' });
  const cwd = String(options.cwd || '/root').trim() || '/root';
  const timeoutMs = clamp(toInt(options.timeoutMs, OPENAI_CODEX_TIMEOUT_MS), 5_000, 10 * 60 * 1000);
  const requestedModel = String(options.model || '').trim();
  const selectedModel = isValidModel(requestedModel) ? requestedModel : pickDefaultModel();
  const outFile = path.join('/tmp', `codex_gateway_exec_${crypto.randomBytes(8).toString('hex')}.txt`);

  const args = [
    'exec',
    '--skip-git-repo-check',
    '--json',
    '-m',
    selectedModel,
    '--sandbox',
    'workspace-write',
    '--cd',
    cwd,
    '-o',
    outFile,
    cleanPrompt,
  ];

  return new Promise((resolve) => {
    execFile('codex', args, {
      env: {
        ...process.env,
        CODEX_HOME: user.codexHome,
      },
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    }, (err, stdout, stderr) => {
      let output = '';
      try {
        output = fs.readFileSync(outFile, 'utf8').trim();
      } catch (_err) {
        output = parseCodexJsonLines(stdout);
      }
      try { fs.unlinkSync(outFile); } catch (_err2) { }

      if (err) {
        resolve({
          ok: false,
          error: normalizeCodexError(err, stderr),
          stderr: String(stderr || '').slice(0, 2000),
          output,
        });
        return;
      }

      resolve({
        ok: true,
        output,
        stderr: String(stderr || '').slice(0, 2000),
        model: selectedModel,
      });
    });
  });
}

function getOrCreateDeviceFlow(username) {
  const key = String(username || '');
  const existing = openaiDeviceFlows.get(key);
  if (existing) return existing;
  const flow = {
    username: key,
    status: 'idle',
    startedAt: 0,
    finishedAt: 0,
    pid: 0,
    exitCode: null,
    stdout: '',
    stderr: '',
    loginUrl: '',
    userCode: '',
    error: '',
  };
  openaiDeviceFlows.set(key, flow);
  return flow;
}

function appendFlowText(flow, field, text) {
  const prev = String(flow[field] || '');
  const next = `${prev}${text}`;
  flow[field] = next.slice(-16000);
  const urlMatch = next.match(/https:\/\/auth\.openai\.com\/\S+/i) || next.match(/https:\/\/\S+/i);
  if (urlMatch) flow.loginUrl = String(urlMatch[0]).replace(/[)\],.;]+$/, '');
  const codeMatch = next.match(/\b[A-Z0-9]{4}-[A-Z0-9]{4}\b/);
  if (codeMatch) flow.userCode = codeMatch[0];
}

function startDeviceAuthForUser(user) {
  const flow = getOrCreateDeviceFlow(user.username);
  if (flow.status === 'running') return flow;

  fs.mkdirSync(user.codexHome, { recursive: true });
  flow.status = 'running';
  flow.startedAt = Date.now();
  flow.finishedAt = 0;
  flow.pid = 0;
  flow.exitCode = null;
  flow.stdout = '';
  flow.stderr = '';
  flow.loginUrl = '';
  flow.userCode = '';
  flow.error = '';

  const child = spawn('codex', ['login', '--device-auth'], {
    env: {
      ...process.env,
      CODEX_HOME: user.codexHome,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  flow.pid = toInt(child.pid, 0);
  child.stdout.on('data', (chunk) => appendFlowText(flow, 'stdout', Buffer.from(chunk).toString('utf8')));
  child.stderr.on('data', (chunk) => appendFlowText(flow, 'stderr', Buffer.from(chunk).toString('utf8')));

  child.on('error', (err) => {
    flow.status = 'failed';
    flow.finishedAt = Date.now();
    flow.error = String(err && err.message || err || 'Failed to start login');
  });

  child.on('close', (code) => {
    flow.exitCode = code;
    flow.finishedAt = Date.now();
    if (toInt(code, 1) === 0) {
      flow.status = 'completed';
    } else {
      flow.status = 'failed';
      if (!flow.error) flow.error = String(flow.stderr || flow.stdout || `Device auth exited with code ${code}`).slice(0, 500);
    }
  });

  return flow;
}

function parseRateLimitWindow(raw) {
  const src = raw && typeof raw === 'object' ? raw : null;
  if (!src) return null;
  const used = Number(src.usedPercent ?? src.used_percent);
  const mins = Number(src.windowDurationMins ?? src.window_minutes);
  const resets = Number(src.resetsAt ?? src.resets_at);
  if (!Number.isFinite(used)) return null;
  return {
    usedPercent: clamp(Math.round(used), 0, 100),
    windowMinutes: Number.isFinite(mins) ? Math.max(0, Math.floor(mins)) : null,
    resetsAt: Number.isFinite(resets) ? Math.max(0, Math.floor(resets)) : null,
  };
}

function collectRateLimitWindows(payload) {
  const windows = [];
  const pushFromSnapshot = (snapshot) => {
    if (!snapshot || typeof snapshot !== 'object') return;
    const p = parseRateLimitWindow(snapshot.primary);
    const s = parseRateLimitWindow(snapshot.secondary);
    if (p) windows.push(p);
    if (s) windows.push(s);
  };
  if (payload && typeof payload === 'object') {
    pushFromSnapshot(payload.rateLimits);
    const byId = payload.rateLimitsByLimitId;
    if (byId && typeof byId === 'object') {
      for (const snap of Object.values(byId)) pushFromSnapshot(snap);
    }
  }
  return windows;
}

function pickWindowByDuration(windows, targetMinutes) {
  if (!Array.isArray(windows) || !windows.length) return null;
  const exact = windows.find((w) => w.windowMinutes === targetMinutes);
  if (exact) return exact;
  const withDuration = windows.filter((w) => Number.isFinite(w.windowMinutes) && w.windowMinutes > 0);
  if (!withDuration.length) return null;
  return withDuration
    .slice()
    .sort((a, b) => Math.abs((a.windowMinutes || 0) - targetMinutes) - Math.abs((b.windowMinutes || 0) - targetMinutes))[0];
}

function queryCodexRateLimitsForUser(user, options = {}) {
  const timeoutMs = clamp(toInt(options.timeoutMs, 8_000), 2_500, 30_000);
  return new Promise((resolve) => {
    let settled = false;
    let stdoutBuf = '';
    let stderrBuf = '';
    let timer = null;
    let child = null;

    const done = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (child && !child.killed) {
        try { child.kill('SIGTERM'); } catch (_err) { }
      }
      resolve(result);
    };

    const onStdoutChunk = (chunk) => {
      stdoutBuf += Buffer.from(chunk).toString('utf8');
      const lines = stdoutBuf.split('\n');
      stdoutBuf = lines.pop() || '';
      for (const lineRaw of lines) {
        const line = String(lineRaw || '').trim();
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch (_err) {
          continue;
        }
        if (String(msg.id || '') !== '2') continue;
        if (msg.error) {
          done({ ok: false, error: String((msg.error && msg.error.message) || 'Failed to read Codex rate limits') });
          return;
        }
        const result = msg.result && typeof msg.result === 'object' ? msg.result : {};
        const windows = collectRateLimitWindows(result);
        const hourly = pickWindowByDuration(windows, 60);
        const weekly = pickWindowByDuration(windows, 7 * 24 * 60);
        done({
          ok: true,
          hourlyRemainingPercent: hourly ? clamp(100 - hourly.usedPercent, 0, 100) : null,
          weeklyRemainingPercent: weekly ? clamp(100 - weekly.usedPercent, 0, 100) : null,
          hourlyResetsAt: hourly ? hourly.resetsAt : null,
          weeklyResetsAt: weekly ? weekly.resetsAt : null,
        });
        return;
      }
    };

    try {
      child = spawn('codex', ['app-server'], {
        env: {
          ...process.env,
          CODEX_HOME: user.codexHome,
        },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (err) {
      done({ ok: false, error: String(err && err.message || err || 'Failed to start codex app-server') });
      return;
    }

    child.stdout.on('data', onStdoutChunk);
    child.stderr.on('data', (chunk) => {
      stderrBuf = `${stderrBuf}${Buffer.from(chunk).toString('utf8')}`.slice(-2000);
    });
    child.on('error', (err) => done({ ok: false, error: String(err && err.message || err || 'Failed to start codex app-server') }));
    child.on('close', () => done({ ok: false, error: stderrBuf || 'Codex app-server exited unexpectedly' }));

    timer = setTimeout(() => done({ ok: false, error: 'Timed out while reading Codex rate limits' }), timeoutMs);

    try {
      child.stdin.write(`${JSON.stringify({ id: '1', method: 'initialize', params: { clientInfo: { name: 'codex-gateway-pool', version: '1.0.0' }, capabilities: null } })}\n`);
      child.stdin.write(`${JSON.stringify({ id: '2', method: 'account/rateLimits/read', params: undefined })}\n`);
    } catch (err) {
      done({ ok: false, error: String(err && err.message || err || 'Failed to communicate with codex app-server') });
    }
  });
}

async function getCachedCodexRateLimitsForUser(user) {
  const username = String(user && user.username || '');
  if (!username) return { ok: false, error: 'Missing username' };
  const cached = openaiRateLimitCache.get(username);
  const now = Date.now();
  if (cached && (now - toInt(cached.fetchedAt, 0)) <= OPENAI_RATE_LIMIT_CACHE_TTL_MS) {
    return cached.result;
  }

  const first = await queryCodexRateLimitsForUser(user, { timeoutMs: 8_000 });
  if (first && first.ok === true) {
    openaiRateLimitCache.set(username, { fetchedAt: now, result: first });
    return first;
  }

  const second = await queryCodexRateLimitsForUser(user, { timeoutMs: 12_000 });
  if (second && second.ok === true) {
    openaiRateLimitCache.set(username, { fetchedAt: now, result: second });
    return second;
  }

  if (cached && cached.result && cached.result.ok === true) {
    return {
      ...cached.result,
      stale: true,
      staleAgeMs: Math.max(0, now - toInt(cached.fetchedAt, 0)),
    };
  }

  return second || first || { ok: false, error: 'Failed to read Codex rate limits' };
}

function findUserByEndpointKey(state, apiKeyRaw) {
  const apiKey = String(apiKeyRaw || '').trim();
  if (!apiKey) return null;
  for (const user of Object.values(state.users || {})) {
    if (!user.endpointKeySalt || !user.endpointKeyHash) continue;
    if (verifySecret(apiKey, user.endpointKeySalt, user.endpointKeyHash)) return user;
  }
  return null;
}

async function resolveUserByApiKey(state, apiKeyRaw) {
  const apiKey = String(apiKeyRaw || '').trim();
  if (!apiKey) return { ok: false, error: 'Invalid API key' };

  const direct = findUserByEndpointKey(state, apiKey);
  if (direct) return { ok: true, user: direct, keyType: 'direct' };

  const master = state.specialMasterKey || {};
  if (!master.keyHash || !master.keySalt) return { ok: false, error: 'Invalid API key' };
  if (!verifySecret(apiKey, master.keySalt, master.keyHash)) return { ok: false, error: 'Invalid API key' };

  const candidates = Object.values(state.users || {})
    .filter((u) => String(u.endpointKeyHash || '').length > 0 && String(u.endpointKeySalt || '').length > 0)
    .filter((u) => fs.existsSync(path.join(String(u.codexHome || ''), 'auth.json')))
    .sort((a, b) => String(a.username || '').localeCompare(String(b.username || '')));

  if (!candidates.length) {
    return { ok: false, error: 'No linked key accounts available for master-key rotation' };
  }

  const checks = await Promise.all(candidates.map(async (u) => {
    const limits = await getCachedCodexRateLimitsForUser(u);
    const hourly = Number(limits && limits.hourlyRemainingPercent);
    const weekly = Number(limits && limits.weeklyRemainingPercent);
    const usable = limits && limits.ok === true && Number.isFinite(hourly) && Number.isFinite(weekly) && hourly > 0 && weekly > 0;
    return { user: u, usable };
  }));

  const available = checks.filter((c) => c.usable).map((c) => c.user);
  if (!available.length) {
    return { ok: false, error: 'All linked keys are exhausted (hourly or weekly remaining = 0%)' };
  }

  const cursorKey = String(master.keyHash || '');
  const prev = toInt(masterKeyCursorByHash.get(cursorKey), 0);
  const idx = prev % available.length;
  const selected = available[idx];
  masterKeyCursorByHash.set(cursorKey, idx + 1);
  return { ok: true, user: selected, keyType: 'master', rotatedPoolSize: available.length };
}

async function buildAdminOpenAiUsersResponse() {
  pruneSessions(openaiPortalSessions);
  const state = readState();

  const sessionCountByUser = {};
  for (const rec of openaiPortalSessions.values()) {
    const username = String(rec && rec.username || '');
    if (!username) continue;
    sessionCountByUser[username] = (sessionCountByUser[username] || 0) + 1;
  }

  const baseRows = Object.values(state.users || {})
    .map((user) => {
      const username = String(user.username || '');
      const flow = openaiDeviceFlows.get(username) || null;
      const codexAuthFile = path.join(String(user.codexHome || ''), 'auth.json');
      const portalSessionCount = toInt(sessionCountByUser[username], 0);
      return {
        username,
        hasEndpointKey: String(user.endpointKeyHash || '').length > 0,
        endpointKeyMask: String(user.endpointKeyMask || ''),
        endpointKeyLabel: String(user.endpointKeyLabel || ''),
        canRevealKey: String(user.endpointKeyCipher || '').length > 0 && String(user.endpointKeyIv || '').length > 0 && String(user.endpointKeyTag || '').length > 0,
        portalSessionCount,
        portalOnline: portalSessionCount > 0,
        lastPortalLoginAt: toInt(user.lastLoginAt, 0),
        codexConnected: fs.existsSync(codexAuthFile),
        codexHome: String(user.codexHome || ''),
        codexConnectedAt: toInt(user.codexConnectedAt, 0),
        deviceAuthStatus: flow ? String(flow.status || 'idle') : 'idle',
        updatedAt: toInt(user.updatedAt, 0),
        createdAt: toInt(user.createdAt, 0),
      };
    })
    .sort((a, b) => String(a.username).localeCompare(String(b.username)));

  const rows = await Promise.all(baseRows.map(async (row) => {
    if (!row.codexConnected || !row.codexHome) {
      return {
        ...row,
        hourlyRemainingPercent: null,
        weeklyRemainingPercent: null,
        rateLimitsError: '',
      };
    }
    const result = await getCachedCodexRateLimitsForUser({ username: row.username, codexHome: row.codexHome });
    return {
      ...row,
      hourlyRemainingPercent: result.ok ? result.hourlyRemainingPercent : null,
      weeklyRemainingPercent: result.ok ? result.weeklyRemainingPercent : null,
      rateLimitsError: result.ok ? '' : String(result.error || 'Failed to read rate limits'),
      staleRateLimits: result.ok && result.stale === true,
    };
  }));

  const linkedKeyRowsWithLimits = rows.filter((row) => {
    if (!(row.codexConnected === true && row.hasEndpointKey === true)) return false;
    const hourlyRaw = row.hourlyRemainingPercent;
    const weeklyRaw = row.weeklyRemainingPercent;
    if (hourlyRaw == null || weeklyRaw == null || hourlyRaw === '' || weeklyRaw === '') return false;
    const hourly = Number(hourlyRaw);
    const weekly = Number(weeklyRaw);
    return Number.isFinite(hourly) && Number.isFinite(weekly);
  });

  const combinedHourlyRemainingPercent = linkedKeyRowsWithLimits.length
    ? linkedKeyRowsWithLimits.reduce((acc, row) => acc + Number(row.hourlyRemainingPercent), 0) / linkedKeyRowsWithLimits.length
    : null;

  const combinedWeeklyRemainingPercent = linkedKeyRowsWithLimits.length
    ? linkedKeyRowsWithLimits.reduce((acc, row) => acc + Number(row.weeklyRemainingPercent), 0) / linkedKeyRowsWithLimits.length
    : null;

  return {
    rows: rows.map((row) => {
      const { codexHome, ...rest } = row;
      return rest;
    }),
    totals: {
      users: rows.length,
      withApiKey: rows.filter((r) => r.hasEndpointKey).length,
      portalOnline: rows.filter((r) => r.portalOnline).length,
      codexConnected: rows.filter((r) => r.codexConnected).length,
      deviceAuthRunning: rows.filter((r) => r.deviceAuthStatus === 'running').length,
    },
    masterKey: {
      configured: String(state.specialMasterKey && state.specialMasterKey.keyHash || '').length > 0,
      keyMask: String(state.specialMasterKey && state.specialMasterKey.keyMask || ''),
      keyLabel: String(state.specialMasterKey && state.specialMasterKey.keyLabel || ''),
      updatedAt: toInt(state.specialMasterKey && state.specialMasterKey.updatedAt, 0),
      combinedHourlyRemainingPercent: combinedHourlyRemainingPercent == null ? null : clamp(combinedHourlyRemainingPercent, 0, 100),
      combinedWeeklyRemainingPercent: combinedWeeklyRemainingPercent == null ? null : clamp(combinedWeeklyRemainingPercent, 0, 100),
      keyCountWithLimits: linkedKeyRowsWithLimits.length,
    },
  };
}

function getAdminAuth(req) {
  if (!DASHBOARD_AUTH_ENABLED) {
    return { ok: true, username: ADMIN_USERNAME || 'admin' };
  }
  return getSession(dashboardSessions, req, DASHBOARD_SESSION_COOKIE, DASHBOARD_SESSION_TTL_MS);
}

function getPortalAuth(req) {
  return getSession(openaiPortalSessions, req, OPENAI_PORTAL_SESSION_COOKIE, OPENAI_PORTAL_SESSION_TTL_MS);
}

function requiresAdminAuth(pathname) {
  if (pathname.startsWith('/api/openai/')) return false;
  if (pathname.startsWith('/api/auth/')) return false;
  if (pathname === '/openai' || pathname === '/openai.html' || pathname === '/openai.js' || pathname === '/openai.css') return false;
  if (pathname === '/login' || pathname === '/login.html' || pathname === '/login.js') return false;
  if (pathname === '/styles.css' || pathname === '/favicon.svg' || pathname === '/favicon.ico') return false;
  return true;
}

async function handleAuthApi(req, res, url, adminAuth) {
  if (req.method === 'GET' && url.pathname === '/api/auth/me') {
    if (!adminAuth.ok) {
      writeJson(res, 200, { ok: false });
      return;
    }
    writeJson(res, 200, { ok: true, username: String(adminAuth.username || '') });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/login') {
    try {
      const body = await readBodyJson(req, 16 * 1024);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
        writeJson(res, 500, { ok: false, error: 'Admin credentials are not configured' });
        return;
      }
      if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
        writeJson(res, 401, { ok: false, error: 'Invalid username or password' });
        return;
      }
      const sid = createSession(dashboardSessions, username, DASHBOARD_SESSION_TTL_MS);
      setSessionCookie(res, DASHBOARD_SESSION_COOKIE, sid, DASHBOARD_SESSION_TTL_MS);
      writeJson(res, 200, { ok: true, username });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/logout') {
    if (adminAuth.ok && adminAuth.sessionId) dashboardSessions.delete(adminAuth.sessionId);
    clearSessionCookie(res, DASHBOARD_SESSION_COOKIE);
    writeJson(res, 200, { ok: true });
    return;
  }

  writeJson(res, 404, { ok: false, error: 'Not found' });
}

async function getPortalUserOrRespond(req, res) {
  const auth = getPortalAuth(req);
  if (!auth.ok) {
    writeJson(res, 401, { ok: false, error: 'OpenAI portal authentication required' });
    return null;
  }
  const state = readState();
  const user = state.users[auth.username];
  if (!user) {
    if (auth.sessionId) openaiPortalSessions.delete(auth.sessionId);
    clearSessionCookie(res, OPENAI_PORTAL_SESSION_COOKIE);
    writeJson(res, 401, { ok: false, error: 'Session is invalid' });
    return null;
  }
  return { auth, state, user };
}

async function handleOpenAiPortalApi(req, res, url) {
  if (req.method === 'GET' && url.pathname === '/api/openai/auth/me') {
    const auth = getPortalAuth(req);
    if (!auth.ok) {
      writeJson(res, 200, { ok: false });
      return;
    }
    const state = readState();
    const user = state.users[auth.username];
    if (!user) {
      if (auth.sessionId) openaiPortalSessions.delete(auth.sessionId);
      clearSessionCookie(res, OPENAI_PORTAL_SESSION_COOKIE);
      writeJson(res, 200, { ok: false });
      return;
    }
    writeJson(res, 200, { ok: true, user: sanitizePortalUser(user) });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/auth/register') {
    try {
      const body = await readBodyJson(req, 32 * 1024);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!USERNAME_RE.test(username)) {
        writeJson(res, 400, { ok: false, error: 'Username must be 2-32 chars: letters, numbers, ., _, -' });
        return;
      }
      if (password.length < 8 || password.length > 128) {
        writeJson(res, 400, { ok: false, error: 'Password must be between 8 and 128 characters' });
        return;
      }

      const state = readState();
      if (state.users[username]) {
        writeJson(res, 409, { ok: false, error: 'Username already exists' });
        return;
      }

      const now = Date.now();
      const salt = crypto.randomBytes(16).toString('hex');
      const user = {
        username,
        passwordSalt: salt,
        passwordHash: hashSecret(password, salt),
        endpointKeySalt: '',
        endpointKeyHash: '',
        endpointKeyMask: '',
        endpointKeyLabel: '',
        endpointKeyCipher: '',
        endpointKeyIv: '',
        endpointKeyTag: '',
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
        codexConnectedAt: 0,
        codexHome: path.join(CODEX_HOME_ROOT, slugifyUsername(username) || 'user'),
      };

      fs.mkdirSync(user.codexHome, { recursive: true });
      state.users[username] = user;
      state.revision += 1;
      writeState(state);

      const sid = createSession(openaiPortalSessions, username, OPENAI_PORTAL_SESSION_TTL_MS);
      setSessionCookie(res, OPENAI_PORTAL_SESSION_COOKIE, sid, OPENAI_PORTAL_SESSION_TTL_MS);
      writeJson(res, 200, { ok: true, user: sanitizePortalUser(user) });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/auth/login') {
    try {
      const body = await readBodyJson(req, 32 * 1024);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const state = readState();
      const user = state.users[username];
      if (!user || !verifySecret(password, user.passwordSalt, user.passwordHash)) {
        writeJson(res, 401, { ok: false, error: 'Invalid username or password' });
        return;
      }

      user.lastLoginAt = Date.now();
      user.updatedAt = user.lastLoginAt;
      state.users[username] = user;
      state.revision += 1;
      writeState(state);

      const sid = createSession(openaiPortalSessions, username, OPENAI_PORTAL_SESSION_TTL_MS);
      setSessionCookie(res, OPENAI_PORTAL_SESSION_COOKIE, sid, OPENAI_PORTAL_SESSION_TTL_MS);
      writeJson(res, 200, { ok: true, user: sanitizePortalUser(user) });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/auth/logout') {
    const auth = getPortalAuth(req);
    if (auth.ok && auth.sessionId) openaiPortalSessions.delete(auth.sessionId);
    clearSessionCookie(res, OPENAI_PORTAL_SESSION_COOKIE);
    writeJson(res, 200, { ok: true });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/keys/rotate') {
    const ctx = await getPortalUserOrRespond(req, res);
    if (!ctx) return;

    try {
      const body = await readBodyJson(req, 16 * 1024);
      const label = String(body.label || '').trim().slice(0, OPENAI_KEY_LABEL_MAX_LEN);
      const key = generateEndpointKey();
      const salt = crypto.randomBytes(16).toString('hex');
      const encrypted = encryptKey(key);

      ctx.user.endpointKeySalt = salt;
      ctx.user.endpointKeyHash = hashSecret(key, salt);
      ctx.user.endpointKeyMask = maskKey(key);
      ctx.user.endpointKeyLabel = label;
      ctx.user.endpointKeyCipher = encrypted.cipher;
      ctx.user.endpointKeyIv = encrypted.iv;
      ctx.user.endpointKeyTag = encrypted.tag;
      ctx.user.updatedAt = Date.now();

      ctx.state.users[ctx.user.username] = ctx.user;
      ctx.state.revision += 1;
      writeState(ctx.state);

      writeJson(res, 200, {
        ok: true,
        apiKey: key,
        keyMask: ctx.user.endpointKeyMask,
        label: ctx.user.endpointKeyLabel,
      });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/openai/codex/status') {
    const ctx = await getPortalUserOrRespond(req, res);
    if (!ctx) return;
    const authFile = path.join(ctx.user.codexHome, 'auth.json');
    const connected = fs.existsSync(authFile);
    if (connected && ctx.user.codexConnectedAt <= 0) {
      ctx.user.codexConnectedAt = Date.now();
      ctx.user.updatedAt = ctx.user.codexConnectedAt;
      ctx.state.users[ctx.user.username] = ctx.user;
      ctx.state.revision += 1;
      writeState(ctx.state);
    }
    writeJson(res, 200, {
      ok: true,
      user: sanitizePortalUser(ctx.user),
      codexHome: ctx.user.codexHome,
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/codex/device/start') {
    const ctx = await getPortalUserOrRespond(req, res);
    if (!ctx) return;
    const flow = startDeviceAuthForUser(ctx.user);
    writeJson(res, 200, {
      ok: true,
      status: flow.status,
      startedAt: flow.startedAt,
      pid: flow.pid,
      loginUrl: flow.loginUrl,
      userCode: flow.userCode,
      stdout: flow.stdout,
      stderr: flow.stderr,
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/openai/codex/device/status') {
    const ctx = await getPortalUserOrRespond(req, res);
    if (!ctx) return;
    const flow = getOrCreateDeviceFlow(ctx.user.username);
    const authFile = path.join(ctx.user.codexHome, 'auth.json');
    const connected = fs.existsSync(authFile);
    if (connected && ctx.user.codexConnectedAt <= 0) {
      ctx.user.codexConnectedAt = Date.now();
      ctx.user.updatedAt = ctx.user.codexConnectedAt;
      ctx.state.users[ctx.user.username] = ctx.user;
      ctx.state.revision += 1;
      writeState(ctx.state);
    }
    writeJson(res, 200, {
      ok: true,
      flow: {
        status: flow.status,
        startedAt: flow.startedAt,
        finishedAt: flow.finishedAt,
        pid: flow.pid,
        exitCode: flow.exitCode,
        loginUrl: flow.loginUrl,
        userCode: flow.userCode,
        stdout: flow.stdout,
        stderr: flow.stderr,
        error: flow.error,
      },
      codexConnected: connected,
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/openai/v1/models') {
    const models = listAvailableModels();
    writeJson(res, 200, {
      object: 'list',
      data: models.map((m) => ({
        id: m.id,
        object: 'model',
        owned_by: 'openai',
        display_name: m.display_name || m.id,
        description: m.description || '',
        supported_in_api: true,
        visibility: m.visibility || 'list',
      })),
      default_model: pickDefaultModel(),
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/openai/v1/modes') {
    writeJson(res, 200, {
      object: 'list',
      default_reasoning_mode: 'normal',
      data: [
        { id: 'fast', object: 'reasoning_mode', description: 'Lowest latency, lighter reasoning.' },
        { id: 'normal', object: 'reasoning_mode', description: 'Balanced default.' },
        { id: 'high', object: 'reasoning_mode', description: 'More reasoning, slower.' },
        { id: 'very_high', object: 'reasoning_mode', description: 'Maximum reasoning depth, slowest.' },
      ],
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/v1/chat/completions') {
    try {
      const body = await readBodyJson(req, 512 * 1024);
      const apiKey = extractBearerToken(req) || String(req.headers['x-api-key'] || '').trim();
      const state = readState();
      const resolved = await resolveUserByApiKey(state, apiKey);
      if (!resolved.ok || !resolved.user) {
        writeJson(res, 401, { ok: false, error: String(resolved.error || 'Invalid API key') });
        return;
      }

      const requestedModel = String(body.model || '').trim();
      const reasoningMode = normalizeReasoningMode(body.reasoning_mode || body.reasoningMode || body.effort || body.reasoning_effort || 'normal', 'normal');
      const model = isValidModel(requestedModel) ? requestedModel : (reasoningMode === 'fast' ? pickFastModel() : pickDefaultModel());
      const maxOutputTokens = clamp(toInt(body.max_output_tokens != null ? body.max_output_tokens : body.max_tokens, 512), 1, 8192);
      const timeoutMs = clamp(toInt(body.timeoutMs, OPENAI_CODEX_TIMEOUT_MS), 5_000, 10 * 60 * 1000);

      const result = await runCodexChatForUser(resolved.user, body.messages, {
        model,
        maxOutputTokens,
        timeoutMs,
        reasoningMode,
      });

      if (!result.ok) {
        writeJson(res, 502, {
          error: {
            message: String(result.error || 'Chat completion failed'),
            type: 'server_error',
          },
        });
        return;
      }

      const output = String(result.output || '');
      const created = Math.floor(Date.now() / 1000);
      writeJson(res, 200, {
        id: `chatcmpl_${crypto.randomBytes(12).toString('hex')}`,
        object: 'chat.completion',
        created,
        model: String(result.model || model),
        choices: [
          {
            index: 0,
            message: { role: 'assistant', content: output },
            finish_reason: 'stop',
          },
        ],
        usage: {
          prompt_tokens: Math.max(1, Math.ceil(JSON.stringify(body.messages || []).length / 4)),
          completion_tokens: Math.max(1, Math.ceil(output.length / 4)),
          total_tokens: Math.max(1, Math.ceil(JSON.stringify(body.messages || []).length / 4)) + Math.max(1, Math.ceil(output.length / 4)),
        },
        reasoning_mode: reasoningMode,
      });
    } catch (err) {
      writeJson(res, 400, {
        error: {
          message: String(err.message || err),
          type: 'invalid_request_error',
        },
      });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/v1/codex/execute') {
    try {
      const body = await readBodyJson(req, 256 * 1024);
      const prompt = String(body.prompt || '').trim();
      const cwd = String(body.cwd || '/root').trim() || '/root';
      const timeoutMs = clamp(toInt(body.timeoutMs, OPENAI_CODEX_TIMEOUT_MS), 5_000, 10 * 60 * 1000);
      const requestedModel = String(body.model || '').trim();
      const model = isValidModel(requestedModel) ? requestedModel : pickDefaultModel();
      const apiKey = extractBearerToken(req) || String(req.headers['x-api-key'] || '').trim();

      const state = readState();
      const resolved = await resolveUserByApiKey(state, apiKey);
      if (!resolved.ok || !resolved.user) {
        writeJson(res, 401, { ok: false, error: String(resolved.error || 'Invalid API key') });
        return;
      }

      const result = await runCodexPromptForUser(resolved.user, prompt, { cwd, timeoutMs, model });
      writeJson(res, result.ok ? 200 : 502, {
        ok: result.ok,
        output: String(result.output || ''),
        error: result.ok ? '' : String(result.error || 'Codex request failed'),
        stderr: String(result.stderr || ''),
        username: resolved.user.username,
        model: String(result.model || model),
        keyType: String(resolved.keyType || 'direct'),
        rotatedPoolSize: toInt(resolved.rotatedPoolSize, 0),
      });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/openai/codex/execute-session') {
    try {
      const body = await readBodyJson(req, 256 * 1024);
      const prompt = String(body.prompt || '').trim();
      const cwd = String(body.cwd || '/root').trim() || '/root';
      const timeoutMs = clamp(toInt(body.timeoutMs, OPENAI_CODEX_TIMEOUT_MS), 5_000, 10 * 60 * 1000);
      const requestedModel = String(body.model || '').trim();
      const model = isValidModel(requestedModel) ? requestedModel : pickDefaultModel();

      const apiKey = extractBearerToken(req) || String(req.headers['x-api-key'] || '').trim();
      let user = null;
      let keyType = 'session';
      let rotatedPoolSize = 0;

      if (apiKey) {
        const state = readState();
        const resolved = await resolveUserByApiKey(state, apiKey);
        if (!resolved.ok || !resolved.user) {
          writeJson(res, 401, { ok: false, error: String(resolved.error || 'Invalid API key') });
          return;
        }
        user = resolved.user;
        keyType = String(resolved.keyType || 'direct');
        rotatedPoolSize = toInt(resolved.rotatedPoolSize, 0);
      } else {
        const ctx = await getPortalUserOrRespond(req, res);
        if (!ctx) return;
        user = ctx.user;
      }

      const result = await runCodexPromptForUser(user, prompt, { cwd, timeoutMs, model });
      writeJson(res, result.ok ? 200 : 502, {
        ok: result.ok,
        output: String(result.output || ''),
        error: result.ok ? '' : String(result.error || 'Codex request failed'),
        stderr: String(result.stderr || ''),
        username: user.username,
        model: String(result.model || model),
        keyType,
        rotatedPoolSize,
      });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  writeJson(res, 404, { ok: false, error: 'Not found' });
}

async function handleAdminApi(req, res, url, adminAuth) {
  if (!adminAuth.ok) {
    writeJson(res, 401, { ok: false, error: 'Authentication required', loginRequired: true });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/openai-users') {
    const payload = await buildAdminOpenAiUsersResponse();
    writeJson(res, 200, {
      ok: true,
      rows: payload.rows,
      totals: payload.totals,
      specialOwnerKey: payload.masterKey,
      generatedAt: Date.now(),
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/openai-users/reveal-key') {
    try {
      const body = await readBodyJson(req, 32 * 1024);
      const username = String(body.username || '').trim();
      if (!USERNAME_RE.test(username)) {
        writeJson(res, 400, { ok: false, error: 'Invalid username' });
        return;
      }
      const state = readState();
      const user = state.users && state.users[username];
      if (!user || !String(user.endpointKeyHash || '').length) {
        writeJson(res, 404, { ok: false, error: 'API key not found for user' });
        return;
      }
      const plain = decryptKey(user);
      if (!plain) {
        writeJson(res, 409, { ok: false, error: 'Key cannot be revealed. Rotate this user key once to enable reveal.' });
        return;
      }
      writeJson(res, 200, { ok: true, username, apiKey: plain });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/openai-users/delete') {
    try {
      const body = await readBodyJson(req, 32 * 1024);
      const username = String(body.username || '').trim();
      if (!USERNAME_RE.test(username)) {
        writeJson(res, 400, { ok: false, error: 'Invalid username' });
        return;
      }
      const state = readState();
      const user = state.users && state.users[username];
      if (!user) {
        writeJson(res, 404, { ok: false, error: 'OpenAI portal user not found' });
        return;
      }

      delete state.users[username];
      state.revision += 1;
      writeState(state);

      for (const [sid, rec] of openaiPortalSessions.entries()) {
        if (String(rec && rec.username || '') === username) openaiPortalSessions.delete(sid);
      }
      openaiDeviceFlows.delete(username);
      openaiRateLimitCache.delete(username);

      writeJson(res, 200, { ok: true, username, revision: state.revision });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  if (
    req.method === 'POST'
    && (
      url.pathname === '/api/admin/openai-users/rotate-owner-special-key'
      || url.pathname === '/api/admin/openai-users/rotate-owner-key'
      || url.pathname === '/api/admin/openai-users/rotate-special-key'
      || url.pathname === '/api/admin/openai-users/rotate-master-key'
    )
  ) {
    try {
      const body = await readBodyJson(req, 32 * 1024);
      const label = String(body.label || '').trim().slice(0, OPENAI_KEY_LABEL_MAX_LEN);
      const state = readState();
      const key = generateMasterKey();
      const salt = crypto.randomBytes(16).toString('hex');
      const encrypted = encryptKey(key);
      const now = Date.now();
      const prevHash = String((state.specialMasterKey && state.specialMasterKey.keyHash) || '');

      state.specialMasterKey = {
        keySalt: salt,
        keyHash: hashSecret(key, salt),
        keyMask: maskKey(key),
        keyLabel: label,
        keyCipher: encrypted.cipher,
        keyIv: encrypted.iv,
        keyTag: encrypted.tag,
        createdAt: toInt(state.specialMasterKey && state.specialMasterKey.createdAt, 0) || now,
        updatedAt: now,
      };

      if (prevHash) masterKeyCursorByHash.delete(prevHash);

      state.revision += 1;
      writeState(state);

      writeJson(res, 200, {
        ok: true,
        apiKey: key,
        keyMask: state.specialMasterKey.keyMask,
        label: state.specialMasterKey.keyLabel,
      });
    } catch (err) {
      writeJson(res, 400, { ok: false, error: String(err.message || err) });
    }
    return;
  }

  writeJson(res, 404, { ok: false, error: 'Not found' });
}

function serveStatic(pathname, res) {
  const normalized = pathname === '/'
    ? '/index.html'
    : (pathname === '/login'
      ? '/login.html'
      : (pathname === '/openai' ? '/openai.html' : pathname));

  const safePath = path.normalize(normalized).replace(/^\.+/, '');
  const filePath = path.join(PUBLIC_DIR, safePath);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    writeJson(res, 403, { error: 'Forbidden' });
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      writeJson(res, 404, { error: 'Not found' });
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const mime = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml; charset=utf-8',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.webp': 'image/webp',
      '.gif': 'image/gif',
      '.ico': 'image/x-icon',
    }[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': mime,
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch (_err) {
    writeJson(res, 400, { error: 'Bad request URL' });
    return;
  }

  try {
    const adminAuth = getAdminAuth(req);

    if (url.pathname.startsWith('/api/auth/')) {
      await handleAuthApi(req, res, url, adminAuth);
      return;
    }

    if (url.pathname.startsWith('/api/openai/')) {
      await handleOpenAiPortalApi(req, res, url);
      return;
    }

    if (url.pathname.startsWith('/api/admin/')) {
      await handleAdminApi(req, res, url, adminAuth);
      return;
    }

    if (url.pathname === '/api/health') {
      const state = readState();
      writeJson(res, 200, {
        ok: true,
        users: Object.keys(state.users || {}).length,
        hasMasterKey: String(state.specialMasterKey && state.specialMasterKey.keyHash || '').length > 0,
      });
      return;
    }

    if (adminAuth.ok && (url.pathname === '/login' || url.pathname === '/login.html')) {
      res.writeHead(302, { Location: '/', 'Cache-Control': 'no-store' });
      res.end();
      return;
    }

    if (requiresAdminAuth(url.pathname) && !adminAuth.ok) {
      sendAuthChallenge(res, url.pathname);
      return;
    }

    if (url.pathname.startsWith('/api/')) {
      writeJson(res, 404, { error: 'Not found' });
      return;
    }

    serveStatic(url.pathname, res);
  } catch (err) {
    writeJson(res, 500, { error: String(err && err.message || err || 'Internal error') });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[codex-gateway-pool] listening on http://${HOST}:${PORT}`);
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.warn('[codex-gateway-pool] WARNING: admin credentials not configured. Set adminUsername/adminPassword in settings.json or env.');
  }
});
