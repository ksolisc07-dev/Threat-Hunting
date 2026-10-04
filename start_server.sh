#!/usr/bin/env bash
# Arranca el servidor de Threat Hunting (probado para Kali/Debian).
#   ./start_server.sh
# Configuración en .env (se crea sola la primera vez):
#   THL_ADMIN_TOKEN=...   token del panel
#   THL_ENROLL_KEY=...    clave para instalar agentes
#   THL_PORT=8000         puerto (opcional)
#   NGROK_URL=xxx.ngrok-free.dev   (opcional) arranca también el túnel ngrok
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[*] Creando entorno virtual (.venv)…"
  python3 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt
fi

if [ ! -f .env ]; then
  echo "[*] Generando credenciales en .env"
  umask 077
  {
    echo "THL_ADMIN_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    echo "THL_ENROLL_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  } > .env
fi
set -a; . ./.env; set +a
PORT="${PORT:-${THL_PORT:-8000}}"

PUBLIC="(sin túnel: solo red local)"
NGROK_PID=""
if [ -n "${NGROK_URL:-}" ]; then
  NGROK_URL="${NGROK_URL#https://}"; NGROK_URL="${NGROK_URL%/}"
  if command -v ngrok >/dev/null 2>&1; then
    pkill -f "ngrok http --url=${NGROK_URL}" 2>/dev/null || true
    ngrok http --url="${NGROK_URL}" "${PORT}" --log=stdout > ngrok.log 2>&1 &
    NGROK_PID=$!
    sleep 3
    if kill -0 "$NGROK_PID" 2>/dev/null; then
      PUBLIC="https://${NGROK_URL}"
    else
      echo "[!] ngrok no pudo arrancar. Últimas líneas de ngrok.log:"
      tail -n 5 ngrok.log || true
      NGROK_PID=""
    fi
  else
    echo "[!] NGROK_URL está definido pero ngrok no está instalado."
  fi
fi
cleanup() { [ -n "$NGROK_PID" ] && kill "$NGROK_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo
echo "============================================================"
echo " Panel web:            http://localhost:${PORT}"
echo " URL para agentes:     ${PUBLIC}"
echo " Token del panel:      ${THL_ADMIN_TOKEN}"
echo " Clave para el agente: ${THL_ENROLL_KEY}"
echo "============================================================"
echo " Ctrl+C detiene el servidor${NGROK_PID:+ y el túnel}."
echo
.venv/bin/uvicorn server.main:app --host 0.0.0.0 --port "${PORT}" --proxy-headers
