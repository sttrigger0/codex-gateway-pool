#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="$(node -e "const fs=require('fs');try{const s=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));console.log(Number.isFinite(Number(s.port))?Number(s.port):8787)}catch(e){console.log(8787)}" "$ROOT_DIR/settings.json")"
curl -sS --max-time 5 "http://127.0.0.1:${PORT}/api/health"
