#!/usr/bin/env bash
# 本地无 Docker 时的三服务启动脚本 (需先准备好虚拟环境: python -m venv .venv && .venv/bin/pip install -r requirements.txt)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python

SERVICE_ROLE=primary setsid nohup "$PY" -m uvicorn app.quote_service:app \
  --host 127.0.0.1 --port 8001 >/tmp/shadow-demo-primary.log 2>&1 < /dev/null &
SERVICE_ROLE=shadow  setsid nohup "$PY" -m uvicorn app.quote_service:app \
  --host 127.0.0.1 --port 8002 >/tmp/shadow-demo-shadow.log 2>&1 < /dev/null &
PRIMARY_URL=http://127.0.0.1:8001 SHADOW_URL=http://127.0.0.1:8002 \
  SIGNING_SECRET="${SIGNING_SECRET:-dev-only-signing-secret-change-me}" \
  SIGN_WINDOW_S="${SIGN_WINDOW_S:-60}" MAX_NONCES="${MAX_NONCES:-1024}" \
  setsid nohup "$PY" -m uvicorn app.gateway:app \
  --host 127.0.0.1 --port 8000 >/tmp/shadow-demo-gateway.log 2>&1 < /dev/null &

echo "waiting for services..."
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8000/healthz >/dev/null; then
    echo "ready: http://127.0.0.1:8000/  (primary:8001, shadow:8002)"
    exit 0
  fi
  sleep 0.5
done
echo "services did not become ready; see /tmp/shadow-demo-*.log" >&2
exit 1
