#!/usr/bin/env bash
# Arranca el servidor de Threat Hunting (probado para Kali/Debian).
#   ./start_server.sh            -> puerto 8000
#   PORT=9000 ./start_server.sh
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-8000}"

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

echo
echo "============================================================"
echo " Panel web:            http://localhost:${PORT}"
echo " Token del panel:      ${THL_ADMIN_TOKEN}"
echo " Clave para el agente: ${THL_ENROLL_KEY}"
echo "============================================================"
echo
exec .venv/bin/uvicorn server.main:app --host 0.0.0.0 --port "${PORT}" --proxy-headers
