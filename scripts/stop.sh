#!/usr/bin/env bash
set -euo pipefail
if command -v pm2 >/dev/null 2>&1; then
  pm2 stop codex-gateway-pool || true
else
  if [[ -f /tmp/codex-gateway-pool/pid ]]; then
    PID="$(cat /tmp/codex-gateway-pool/pid || true)"
    if [[ -n "$PID" ]] && kill -0 "$PID" >/dev/null 2>&1; then
      kill "$PID" || true
    fi
    rm -f /tmp/codex-gateway-pool/pid
  fi
fi
