"""Configuración del servidor (todo se puede sobreescribir con variables de entorno)."""
import os
import secrets


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


DB_PATH = os.environ.get("THL_DB", "threat_hunting.db")

# Clave compartida que un agente debe presentar para enrolarse.
ENROLL_KEY = os.environ.get("THL_ENROLL_KEY", "change-me-enroll-key")

# Token para el panel web / API de analista. Si no se define se genera uno
# aleatorio y se imprime al arrancar.
ADMIN_TOKEN = os.environ.get("THL_ADMIN_TOKEN") or secrets.token_urlsafe(24)
ADMIN_TOKEN_GENERATED = "THL_ADMIN_TOKEN" not in os.environ

# Cada cuántos segundos corre el motor de caza autónomo.
HUNT_INTERVAL = _env_int("THL_HUNT_INTERVAL", 60)

# Segundos sin heartbeat para considerar a un agente desconectado.
AGENT_OFFLINE_AFTER = _env_int("THL_AGENT_OFFLINE_AFTER", 180)

# Retención de telemetría cruda (días).
RETENTION_DAYS = _env_int("THL_RETENTION_DAYS", 14)

# Respuesta autónoma: el cazador puede encolar tareas de recolección
# adicionales en el agente cuando detecta algo (nunca ejecuta comandos
# arbitrarios: solo módulos de la lista blanca del agente).
AUTO_RESPONSE = os.environ.get("THL_AUTO_RESPONSE", "1") not in ("0", "false", "no")
