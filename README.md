# Codex Gateway Pool

codex-gateway-pool is a lightweight OAuth-powered gateway that converts authenticated ChatGPT accounts into an API endpoint, supporting both per-account routing and pooled round-robin request distribution for scalable, multi-account usage. It includes a simple web panel for managing connected accounts and pools, along with an easy installation process designed to get you up and running in minutes.

# Accounts

You can buy 1 month chatgpt plus/business accounts in bulk from resellers for 0.5-1$ a pop. The more accounts you have the higher the chance of them getting terminated, so i recommend using business plan accounts in perticular, since tthey seem to get flagged way less and not using more than 10-15 accounts per IP (Which is already way more than enough)

## Features

- Separate auth systems:
  - Admin auth for management panel
  - Portal user auth for account/link/key actions
- Per-user endpoint keys
- Master endpoint key with request-level key pool rotation
- Rate-limit aware key selection (hourly + weekly remaining must both be > 0)
- Admin user management actions:
  - list portal users
  - reveal key
  - delete portal user
  - rotate master key
- Combined remaining metrics in admin page:
  - total hourly remaining
  - total weekly remaining
  - only counts linked + keyed users with displayed values
- Codex device auth flow (`codex login --device-auth`)
- OpenAI-style endpoint support:
  - `/api/openai/v1/chat/completions`
  - `/api/openai/v1/models`
  - `/api/openai/v1/modes`

## Requirements

- Linux server (Ubuntu/Debian recommended)
- Node.js 18+ (Node 20+ recommended)
- `codex` CLI installed and available in PATH
- Optional: PM2 for process management

## Quick Install

```bash
cd /root
git clone <your-repo-url> codex-gateway-pool
cd codex-gateway-pool
chmod +x install.sh
./install.sh
```

Installer prompts for:

- panel port
- admin username
- admin password
- API key prefix
- master API key prefix

Installer then:

- writes `settings.json`
- creates `data/` files
- installs npm dependencies
- starts service (PM2 if available, otherwise nohup)
- prints direct panel links

## Access URLs

After install:

- Admin panel: `http://<server-ip>:<port>/`
- OpenAI portal: `http://<server-ip>:<port>/openai`
- Health: `http://<server-ip>:<port>/api/health`

## Project Structure

```text
codex-gateway-pool/
  server.js
  settings.example.json
  install.sh
  public/
    index.html        # admin panel
    app.js
    login.html
    login.js
    openai.html       # user portal
    openai.js
    openai.css
    styles.css
    favicon.svg
  data/
    state.json
    openai_codex/
  scripts/
    start.sh
    stop.sh
    healthcheck.sh
```

## Configuration

### `settings.json`

Main keys:

- `host`: bind host (default `0.0.0.0`)
- `port`: server port
- `adminUsername`, `adminPassword`
- `openaiApiKeyPrefix`: normal user key prefix
- `openaiMasterKeyPrefix`: master key prefix
- `openaiKeyEncryptionSecret`: encryption key for reveal functionality
- `codexHomeRoot`: base dir for per-user `CODEX_HOME`
- `openaiCodexTimeoutMs`
- `openaiRateLimitCacheTtlMs`

See `settings.example.json` for full template.

### Environment Overrides

Supported:

- `HOST`, `PORT`
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`
- `OPENAI_API_KEY_PREFIX`
- `OPENAI_MASTER_KEY_PREFIX`
- `OPENAI_KEY_ENCRYPTION_SECRET`

## Usage

### 1) Admin login

Go to `/login`, sign in with configured admin credentials.

### 2) Portal account flow (`/openai`)

- Register or login a portal user
- Start device auth and approve in browser
- Generate user endpoint key
- Test with quick session prompt

### 3) Master key flow (`/`)

- Rotate master key from admin panel
- Use master key on chat/completions endpoint
- Requests rotate across eligible linked user keys

## API Reference

### Admin auth

#### `POST /api/auth/login`

Body:

```json
{ "username": "admin", "password": "..." }
```

#### `POST /api/auth/logout`

Logs out admin session.

### Admin management

#### `GET /api/admin/openai-users`

Returns user table + totals + master key summary.

#### `POST /api/admin/openai-users/reveal-key`

Body:

```json
{ "username": "portal_user" }
```

Returns decrypted endpoint key when available.

#### `POST /api/admin/openai-users/delete`

Body:

```json
{ "username": "portal_user" }
```

Deletes portal user and clears sessions/cache/flow state.

#### `POST /api/admin/openai-users/rotate-master-key`

Aliases also supported:

- `/api/admin/openai-users/rotate-owner-key`
- `/api/admin/openai-users/rotate-owner-special-key`

Body:

```json
{ "label": "optional" }
```

Returns master key once.

### Portal auth

#### `POST /api/openai/auth/register`

```json
{ "username": "user1", "password": "strongpass" }
```

#### `POST /api/openai/auth/login`

```json
{ "username": "user1", "password": "strongpass" }
```

#### `POST /api/openai/auth/logout`

Portal logout.

#### `GET /api/openai/auth/me`

Returns current portal session info.

### Portal key + Codex link

#### `POST /api/openai/keys/rotate`

```json
{ "label": "optional" }
```

Returns user endpoint key once.

#### `POST /api/openai/codex/device/start`

Starts device auth flow.

#### `GET /api/openai/codex/device/status`

Returns status/logs/link/code for device auth.

### OpenAI-compatible endpoints

#### `POST /api/openai/v1/chat/completions`

Auth headers (either):

- `Authorization: Bearer <key>`
- `x-api-key: <key>`

Body example:

```json
{
  "model": "gpt-5.1-codex-mini",
  "messages": [{"role": "user", "content": "Reply with OK only."}],
  "max_output_tokens": 32,
  "reasoning_mode": "fast",
  "timeoutMs": 20000
}
```

#### `POST /api/openai/v1/codex/execute`

```json
{
  "prompt": "Say OK",
  "cwd": "/root",
  "model": "gpt-5.1-codex-mini",
  "timeoutMs": 20000
}
```

#### `POST /api/openai/codex/execute-session`

Can use portal cookie session OR API key headers.

#### `GET /api/openai/v1/models`

Returns model list.

#### `GET /api/openai/v1/modes`

Returns reasoning modes.

## Master Key Rotation Rules

Master key selects from users that satisfy all:

1. user has endpoint key
2. user is Codex linked (`auth.json` present)
3. hourly remaining exists and > 0
4. weekly remaining exists and > 0

Selection is round-robin among eligible users.

## Operational Scripts

- `scripts/start.sh`
- `scripts/stop.sh`
- `scripts/healthcheck.sh`

## Troubleshooting

### "Authentication required" on admin routes

Admin session missing/expired. Re-login at `/login`.

### Portal user linked but remaining values missing

Codex app-server read may have failed transiently. The server retries and can use stale successful cache values.

### Master key returns exhausted pool error

No eligible linked accounts currently have >0 hourly and weekly remaining.

### Device auth link/code not shown

Check `codex` CLI availability and openai device auth logs in `/openai` page.

## Security Notes

- Change defaults immediately.
- Use strong `openaiKeyEncryptionSecret`.
- Run behind TLS reverse proxy for production.
- Restrict panel access by firewall/IP if possible.

## License

MIT
