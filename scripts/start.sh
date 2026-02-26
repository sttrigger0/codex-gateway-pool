#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if command -v pm2 >/dev/null 2>&1; then
  if pm2 describe codex-gateway-pool >/dev/null 2>&1; then
    pm2 restart codex-gateway-pool --update-env
  else
    pm2 start server.js --name codex-gateway-pool
  fi
else
  mkdir -p /tmp/codex-gateway-pool
  if [[ -f /tmp/codex-gateway-pool/pid ]]; then
    OLD_PID="$(cat /tmp/codex-gateway-pool/pid || true)"
    if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
      kill "$OLD_PID" || true
      sleep 1
    fi
  fi
  nohup node server.js >/tmp/codex-gateway-pool/server.log 2>&1 &
  echo $! >/tmp/codex-gateway-pool/pid
  echo "Started PID $(cat /tmp/codex-gateway-pool/pid)"
fi
