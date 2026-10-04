# Threat Hunting Platform

Plataforma web de *threat hunting* con agente de endpoint autónomo.

```
 ┌──────────────┐  telemetría (HTTPS/JSON)   ┌──────────────────────────────┐
 │ Agente       │ ─────────────────────────▶ │ Servidor FastAPI             │
 │ (psutil)     │                            │  · detección en tiempo real  │
 │ procesos,    │ ◀───────────────────────── │  · motor de caza autónomo    │
 │ red, persist.│  tareas forenses (lista    │  · respuesta autónoma        │
 └──────────────┘  blanca, solo lectura)     │  · SQLite + panel web (SPA)  │
                                             └──────────────────────────────┘
```

## Componentes

- **Agente** (`agent/th_agent.py`, Linux/Windows/macOS): recolecta procesos (árbol, usuario, cmdline, SHA256), muestrea
  conexiones nuevas cada 2 s (para detectar *beaconing*), puertos en escucha, sesiones y persistencia
  (cron, systemd, launchd, Run keys, servicios, tareas programadas, authorized_keys, ld.so.preload, perfiles de shell).
  Si pierde la conexión con el servidor, guarda los eventos y los reenvía después. Además ejecuta **solo** módulos forenses de lectura:
  `snapshot`, `process_tree`, `hash_file`, `scan_file` (firmas + entropía), `list_dir`, `connections`, `hunt_mode`.
  Nunca ejecuta comandos arbitrarios.
- **Detección en tiempo real** (`server/detections.py`): más de 20 reglas mapeadas a MITRE ATT&CK, comparación con la línea base
  (persistencia y puertos nuevos) e IOCs.
- **Caza autónoma** (`server/hunter.py`): cada `THL_HUNT_INTERVAL` segundos prueba hipótesis sobre toda la flota:
  beaconing C2 (regularidad estadística), binarios raros (*stack counting*), ráfagas de reconocimiento, movimiento lateral
  y escaneo, linaje de procesos inusual, caza retrospectiva de IOCs, agentes silenciados y correlación de la cadena de ataque.
- **Respuesta autónoma** (`server/responder.py`): ante hallazgos altos o críticos encola recolección forense en el agente.
  Los resultados (por ejemplo, firmas encontradas en un binario) vuelven a pasar por la detección. También calcula la puntuación de riesgo de cada host.
- **Panel web** (`server/static/`): panorama, agentes (árbol de procesos, red, persistencia, tareas), triaje de
  hallazgos, consola de caza con lenguaje de consulta y exportación CSV, matriz ATT&CK, IOCs y cola de tareas.

## Puesta en marcha

```bash
pip install -r requirements.txt
export THL_ADMIN_TOKEN='token-del-analista'   # acceso al panel
export THL_ENROLL_KEY='clave-de-enrolamiento' # la usan los agentes
uvicorn server.main:app --host 0.0.0.0 --port 8000
```

Abre `http://SERVIDOR:8000` e introduce el token. En cada endpoint (como root/Administrador para tener visibilidad completa):

```bash
pip install -r agent/requirements.txt
python agent/th_agent.py --server http://SERVIDOR:8000 --enroll-key 'clave-de-enrolamiento' --interval 60
```

En producción, usa HTTPS delante del servidor (proxy inverso). El agente admite `--ca` para una CA propia.

### Servidor en Kali (un comando)

```bash
git clone -b claude/great-bardeen-bkkcfr https://github.com/ksolisc07-dev/Threat-Hunting.git
cd Threat-Hunting
./start_server.sh
```

La primera vez crea el entorno, genera el **token del panel** y la **clave para el agente** (guardados en `.env`)
y los muestra en pantalla.

### Exponer el servidor a Internet (para agentes fuera de tu red)

Opción recomendada, **ngrok con dominio fijo gratuito** (HTTPS incluido, sin abrir puertos del router):

```bash
sudo apt install ngrok            # o descárgalo de ngrok.com
ngrok config add-authtoken <TU_TOKEN_DE_NGROK>
ngrok http --url=<tu-dominio>.ngrok-free.app 8000
```

Los agentes usarán `https://<tu-dominio>.ngrok-free.app`. Para que `./start_server.sh` arranque también el
túnel automáticamente, añade a `.env`:

```
THL_PORT=8000
NGROK_URL=<tu-dominio>.ngrok-free.app
``` Alternativa: redirigir un puerto del router a Kali
con DNS dinámico y un proxy HTTPS (Caddy/nginx). Usa siempre HTTPS si el tráfico va por Internet.

### Agente Windows: instalador `.exe`

No necesita Python ni PowerShell en el equipo: el ejecutable lo incluye todo.

1. Descarga `ThreatHuntingAgent-Setup.exe` desde la pestaña **Actions** del repositorio
   (workflow "Instalador del agente Windows" → último run → *Artifacts*).
2. Ejecútalo en el Windows, escribe la URL del servidor y la clave del agente, y pulsa Siguiente → Instalar.
3. El agente queda corriendo como SYSTEM y arranca con Windows. Log: `C:\ProgramData\ThreatHuntingAgent\agent.log`.
   Se desinstala desde *Configuración → Aplicaciones*.

Instalación desatendida: `ThreatHuntingAgent-Setup.exe /VERYSILENT /SERVER=https://... /KEY=...`

### Variables de entorno del servidor

| Variable | Defecto | Descripción |
|---|---|---|
| `THL_DB` | `threat_hunting.db` | Ruta SQLite |
| `THL_ADMIN_TOKEN` | aleatorio (se imprime) | Token del panel/API |
| `THL_ENROLL_KEY` | `change-me-enroll-key` | Clave de enrolamiento de agentes |
| `THL_HUNT_INTERVAL` | `60` | Segundos entre ciclos de caza |
| `THL_AUTO_RESPONSE` | `1` | Activa la recolección forense automática |
| `THL_RETENTION_DAYS` | `14` | Retención de telemetría |

## Lenguaje de consulta

```
name:powershell.exe -user:*SYSTEM* since:24h
parent:winword.exe|excel.exe
rport:>1024 -raddr:10.*
kind:cron value:*curl*
```

`campo:valor` (AND implícito), `-` niega, `|` hace OR, `*` es comodín, comparadores numéricos y `since:30m|2h|7d`.

## Pruebas

```bash
pip install -r requirements-dev.txt
pytest -q
```
