#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "== Codex Gateway Pool Installer =="

default_port="8787"
default_admin_user="admin"
default_key_prefix="rneo_codex_"
default_master_prefix="rneo_master_"

echo
read -r -p "Panel port [$default_port]: " PANEL_PORT
PANEL_PORT="${PANEL_PORT:-$default_port}"

read -r -p "Admin username [$default_admin_user]: " ADMIN_USERNAME
ADMIN_USERNAME="${ADMIN_USERNAME:-$default_admin_user}"

while true; do
  read -r -s -p "Admin password (required): " ADMIN_PASSWORD
  echo
  if [[ -n "$ADMIN_PASSWORD" ]]; then
    break
  fi
  echo "Password cannot be empty."
done

read -r -p "Normal API key prefix [$default_key_prefix]: " API_KEY_PREFIX
API_KEY_PREFIX="${API_KEY_PREFIX:-$default_key_prefix}"

read -r -p "Master API key prefix [$default_master_prefix]: " MASTER_KEY_PREFIX
MASTER_KEY_PREFIX="${MASTER_KEY_PREFIX:-$default_master_prefix}"

ENCRYPTION_SECRET="$(openssl rand -hex 32 2>/dev/null || true)"
if [[ -z "$ENCRYPTION_SECRET" ]]; then
  ENCRYPTION_SECRET="$(date +%s%N)_${RANDOM}_${RANDOM}_codex_gateway_pool"
fi

mkdir -p data/openai_codex

cat > settings.json <<JSON
{
  "host": "0.0.0.0",
  "port": ${PANEL_PORT},
  "httpsEnabled": false,
  "dashboardAuthEnabled": true,
  "adminUsername": "${ADMIN_USERNAME}",
  "adminPassword": "${ADMIN_PASSWORD}",
  "openaiApiKeyPrefix": "${API_KEY_PREFIX}",
  "openaiMasterKeyPrefix": "${MASTER_KEY_PREFIX}",
  "openaiKeyEncryptionSecret": "${ENCRYPTION_SECRET}",
  "openaiCodexTimeoutMs": 120000,
  "openaiRateLimitCacheTtlMs": 60000,
  "openaiPromptMaxLen": 49152,
  "dashboardSessionTtlMs": 2592000000,
  "openaiPortalSessionTtlMs": 2592000000,
  "maxSessions": 5000,
  "codexHomeRoot": "${ROOT_DIR}/data/openai_codex"
}
JSON

if [[ ! -f data/state.json ]]; then
cat > data/state.json <<'JSON'
{
  "revision": 1,
  "users": {},
  "specialMasterKey": {
    "keySalt": "",
    "keyHash": "",
    "keyMask": "",
    "keyLabel": "",
    "keyCipher": "",
    "keyIv": "",
    "keyTag": "",
    "createdAt": 0,
    "updatedAt": 0
  }
}
JSON
fi

echo
echo "Installing npm dependencies..."
npm install --silent >/dev/null 2>&1 || npm install

mkdir -p /tmp/codex-gateway-pool

if command -v pm2 >/dev/null 2>&1; then
  echo
  echo "Starting with PM2..."
  if pm2 describe codex-gateway-pool >/dev/null 2>&1; then
    pm2 restart codex-gateway-pool --update-env >/dev/null
  else
    pm2 start server.js --name codex-gateway-pool >/dev/null
  fi
  pm2 save >/dev/null 2>&1 || true
else
  echo
  echo "PM2 not found, starting with nohup..."
  if [[ -f /tmp/codex-gateway-pool/pid ]]; then
    OLD_PID="$(cat /tmp/codex-gateway-pool/pid || true)"
    if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
      kill "$OLD_PID" || true
      sleep 1
    fi
  fi
  nohup node server.js >/tmp/codex-gateway-pool/server.log 2>&1 &
  echo $! >/tmp/codex-gateway-pool/pid
fi

sleep 1

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP="127.0.0.1"
fi

echo
echo "== Install Complete =="
echo "Admin panel:  http://${SERVER_IP}:${PANEL_PORT}/"
echo "Portal page:  http://${SERVER_IP}:${PANEL_PORT}/openai"
echo "Admin login:  ${ADMIN_USERNAME}"
echo ""
echo "If you use a firewall, allow TCP port ${PANEL_PORT}."
