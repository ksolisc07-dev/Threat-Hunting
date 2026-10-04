# Threat Hunting Platform

Plataforma web de *threat hunting*: un **agente** instalado en cada equipo recolecta telemetría de forma autónoma y la
envía a un **servidor** (por ejemplo en Kali Linux), que detecta amenazas, caza de forma automática y muestra todo en un
panel web.

```
  Equipos Windows                        Internet (HTTPS)                 Kali Linux
 ┌──────────────────────┐                                          ┌────────────────────────────┐
 │ ThreatHuntingAgent   │  procesos, red, persistencia  ┌───────┐  │ start_server.sh            │
 │ (servicio SYSTEM)    │ ────────────────────────────▶ │ ngrok │ ─▶  · detección en tiempo real│
 │                      │ ◀──────────────────────────── │ túnel │  │  · caza autónoma (1 min)   │
 └──────────────────────┘  tareas forenses (solo lectura) └───────┘  │  · panel web :8000         │
                                                                   └────────────────────────────┘
```

## Índice

1. [Guía rápida](#guía-rápida)
2. [Primera instalación del servidor (Kali)](#1-primera-instalación-del-servidor-kali)
3. [Publicar el servidor en Internet con ngrok](#2-publicar-el-servidor-en-internet-con-ngrok)
4. [Instalar el agente en Windows](#3-instalar-el-agente-en-windows) (incluye [firma del agente](#33-firmar-el-agente-quitar-editor-desconocido))
5. [Uso diario](#4-uso-diario)
6. [Cómo hacer threat hunting con el panel](#5-cómo-hacer-threat-hunting-con-el-panel)
7. [Solución de problemas](#6-solución-de-problemas)
8. [Límites y consideraciones](#7-límites-y-consideraciones)
9. [Referencia técnica](#referencia-técnica)

---

## Guía rápida

| Cuándo | Dónde | Qué hacer |
|---|---|---|
| **Una sola vez** | Kali | Clonar el repo, crear `.env`, instalar ngrok y configurar su authtoken |
| **Una vez por equipo** | Windows | Ejecutar `ThreatHuntingAgent-Setup.exe` con la URL y la clave |
| **Cada vez que enciendes Kali** | Kali | `cd ~/Desktop/Threat-Hunting && ./start_server.sh` |
| **Nunca** | Windows | El agente arranca solo con el equipo y se reconecta solo |

---

## 1. Primera instalación del servidor (Kali)

```bash
cd ~/Desktop
git clone -b claude/great-bardeen-bkkcfr https://github.com/ksolisc07-dev/Threat-Hunting.git
cd Threat-Hunting
```

Crea el archivo de configuración `.env` con **tus propios valores** (no los compartas ni los subas a GitHub;
`.env` ya está en `.gitignore`):

```bash
cat > .env <<'EOF'
THL_ADMIN_TOKEN=pon-aqui-un-token-largo-para-el-panel
THL_ENROLL_KEY=pon-aqui-una-clave-larga-para-los-agentes
THL_PORT=8000
EOF
```

| Variable | Para qué sirve |
|---|---|
| `THL_ADMIN_TOKEN` | Contraseña para entrar al panel web |
| `THL_ENROLL_KEY` | Clave que se escribe en el instalador de cada equipo |
| `THL_PORT` | Puerto del servidor (por defecto 8000) |
| `NGROK_URL` | Tu dominio de ngrok (ver sección 2); si está, el túnel arranca solo |

> Si no creas `.env`, `start_server.sh` genera uno con valores aleatorios y los muestra en pantalla.
> Si pegas el bloque y la terminal se queda en `EOF` o `>`, pulsa **Enter**.

Arranca el servidor:

```bash
chmod +x start_server.sh
./start_server.sh
```

La primera vez tarda un poco (crea un entorno virtual `.venv` e instala dependencias). Después abre
**http://localhost:8000** en Kali y entra con tu `THL_ADMIN_TOKEN`.

---

## 2. Publicar el servidor en Internet con ngrok

Necesario para que equipos que **no** están en la misma red que Kali puedan reportar. ngrok da una URL HTTPS pública
fija sin abrir puertos en el router.

### 2.1 Crear la cuenta y obtener tu dominio

1. Regístrate gratis en <https://dashboard.ngrok.com/signup>.
2. En el panel de ngrok → **Domains** verás tu dominio gratuito (*dev domain*), algo como
   `palabra-palabra-palabra.ngrok-free.dev`.
3. En **Your Authtoken** (<https://dashboard.ngrok.com/get-started/your-authtoken>) copia tu token de ngrok.

### 2.2 Instalar ngrok en Kali (una vez)

```bash
cd ~/Downloads && wget -q https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz && tar xzf ngrok-v3-stable-linux-amd64.tgz && sudo mv ngrok /usr/local/bin/ && ngrok version
```

> Kali en ARM (`uname -m` = `aarch64`): usa `ngrok-v3-stable-linux-arm64.tgz`.
> Si el enlace falla: panel de ngrok → *Setup & Installation* → *Linux*.

Conecta ngrok con tu cuenta (en la terminal se pega con **Ctrl+Shift+V**):

```bash
ngrok config add-authtoken TU_AUTHTOKEN_DE_NGROK
```

Debe responder `Authtoken saved to configuration file`. Si al arrancar ngrok ves `ERR_NGROK_4018`, falta este paso.

### 2.3 Que el túnel arranque solo con el servidor

Añade tu dominio a `.env`:

```bash
cd ~/Desktop/Threat-Hunting
echo "NGROK_URL=tu-dominio.ngrok-free.dev" >> .env
```

Desde ahora `./start_server.sh` arranca servidor **y** túnel, y `Ctrl+C` detiene ambos. Al arrancar verás:

```
 Panel web:            http://localhost:8000
 URL para agentes:     https://tu-dominio.ngrok-free.dev
```

Comprobación desde cualquier navegador: `https://tu-dominio.ngrok-free.dev/api/health` debe mostrar `{"ok":true,...}`
(si ngrok muestra una página de aviso, pulsa *Visit Site*; al agente no le afecta).

> **Misma red local, sin Internet:** si los equipos están en la misma red que Kali (VM en modo *puente*), no hace
> falta ngrok: usa `http://IP-DE-KALI:8000` como URL (la IP sale con `ip a`).

---

## 3. Instalar el agente en Windows

El instalador incluye todo: **no hace falta instalar Python ni usar PowerShell**.

### 3.1 Descargar el instalador

1. En GitHub abre la pestaña **Actions** del repositorio.
2. Entra en el workflow **"Instalador del agente Windows"** → último run con ✅.
3. Abajo, en **Artifacts**, descarga **ThreatHuntingAgent-Setup** (un `.zip` con el `.exe`).

> Los artifacts caducan a los 90 días; cada cambio en `agent/` genera uno nuevo automáticamente.

### 3.2 Instalar

Ejecuta `ThreatHuntingAgent-Setup.exe` en cada equipo y escribe:

| Campo | Valor |
|---|---|
| **URL del servidor** | `https://tu-dominio.ngrok-free.dev` (o `http://IP-DE-KALI:8000` en red local) |
| **Clave de enrolamiento** | el valor de `THL_ENROLL_KEY` de tu `.env` |

Siguiente → Instalar → Finalizar. En menos de un minuto el equipo aparece en **Agentes** con el punto verde.

- El agente corre como **SYSTEM**, arranca con Windows y se reinicia solo si falla.
- Configuración y log: `C:\ProgramData\ThreatHuntingAgent\` (`config.json`, `agent.log`).
- Para cambiar URL o clave: vuelve a ejecutar el instalador (sobrescribe la configuración).
- Desinstalar: *Configuración → Aplicaciones → Threat Hunting Agent*.
- Despliegue masivo: `ThreatHuntingAgent-Setup.exe /VERYSILENT /SERVER=https://... /KEY=...`

> Mientras el instalador **no esté firmado**, SmartScreen/Defender pueden avisar (*Más información → Ejecutar de
> todas formas*). Para evitarlo, firma el agente: sección 3.3.

### 3.3 Firmar el agente (quitar "Editor desconocido")

El workflow firma automáticamente `th_agent.exe` y `ThreatHuntingAgent-Setup.exe` (SHA-256 + sello de tiempo) si
el repositorio tiene estos dos secretos: `CODESIGN_PFX_BASE64` y `CODESIGN_PASSWORD`. Sin ellos genera el instalador
sin firmar y muestra un aviso en el run.

Hay dos caminos según **dónde** se instalará el agente:

| | A. Certificado propio (gratis) | B. Certificado comercial (de pago) |
|---|---|---|
| Para | Tus equipos / laboratorio / tu empresa | Equipos de terceros que no controlas |
| Confianza | Solo en los equipos donde instales tu `.crt` | Todos los Windows del mundo |
| Coste | 0 | Desde ~25 €/año (p. ej. Certum Open Source) hasta varios cientos; Microsoft *Trusted Signing* por suscripción mensual (disponibilidad según país) |
| SmartScreen | Sin aviso en equipos con el `.crt` instalado | Puede avisar al principio hasta que el certificado gana reputación |

#### A. Certificado propio

1. **En Kali** (una vez), desde la carpeta del proyecto:
   ```bash
   ./agent/windows/create_codesign_cert.sh "Tu Nombre u Organización"
   ```
   Crea la carpeta `codesign/` (excluida de git) e imprime la contraseña.
2. **En GitHub**: *Settings → Secrets and variables → Actions → New repository secret*:
   - `CODESIGN_PFX_BASE64` = contenido de `codesign/th-codesign.pfx.b64` (`cat codesign/th-codesign.pfx.b64`)
   - `CODESIGN_PASSWORD` = la contraseña impresa por el script
3. **Generar el instalador firmado**: *Actions → Instalador del agente Windows → Run workflow*. Descarga el nuevo
   artifact.
4. **En cada equipo Windows** (una vez), copia `codesign/th-codesign.crt` y haz doble clic → *Instalar certificado…* →
   **Equipo local** → *Colocar todos los certificados en el siguiente almacén* → **Entidades de certificación raíz de
   confianza** → Finalizar. Repite el proceso eligiendo el almacén **Editores de confianza**.
   En un dominio de Active Directory se distribuye a todos los equipos por GPO
   (*Configuración del equipo → Directivas → Configuración de Windows → Configuración de seguridad → Directivas de
   clave pública*).
5. Comprueba: clic derecho sobre el instalador → *Propiedades → Firmas digitales* debe mostrar tu nombre, y el aviso de
   instalación muestra tu nombre como editor en lugar de "Editor desconocido".

> **Protege `codesign/th-codesign.pfx` y su contraseña.** Cualquiera que los tenga puede firmar programas en los que
> tus equipos confiarán. No los subas a GitHub (solo como secretos cifrados) ni los envíes por chat/correo.

#### B. Certificado comercial

Compra un certificado de firma de código (OV) a una autoridad reconocida. Desde 2023 la clave privada debe residir en
hardware (token USB o firma en la nube del proveedor), por lo que normalmente **no se entrega como `.pfx`**: en ese
caso hay que adaptar `agent/windows/sign.ps1` a la herramienta de firma del proveedor. Si el proveedor sí entrega un
`.pfx`, basta con usar los mismos dos secretos del camino A.

> La firma quita el "Editor desconocido", pero no garantiza que ningún antivirus lo marque: un agente que inspecciona
> procesos y red puede parecer sospechoso a algunos motores. Si ocurre, añade una exclusión para
> `C:\Program Files\ThreatHuntingAgent\` o envía el archivo al fabricante como falso positivo.

### Linux / macOS

No hay instalador; se ejecuta con Python:

```bash
pip install psutil
sudo python3 agent/th_agent.py --server https://tu-dominio.ngrok-free.dev --enroll-key TU_CLAVE
```

---

## 4. Uso diario

```bash
cd ~/Desktop/Threat-Hunting && ./start_server.sh
```

Nada más. Abre `http://localhost:8000`. Los agentes se reconectan solos cuando el servidor vuelve; las conexiones de red
observadas mientras Kali estaba apagado se guardan en el agente y se envían al reconectar.

Para actualizar el servidor a la última versión:

```bash
cd ~/Desktop/Threat-Hunting && git pull origin claude/great-bardeen-bkkcfr
```

Tu `.env` y la base de datos (`threat_hunting.db`) no se tocan.

---

## 5. Cómo hacer threat hunting con el panel

| Sección | Para qué |
|---|---|
| **Panorama** | Resumen: agentes en línea, hallazgos por severidad y hora, hosts con más riesgo, actividad del cazador |
| **Agentes** → equipo | Árbol de procesos (clic = ruta, hash, VirusTotal), conexiones de red, puertos en escucha, persistencia (Run keys, servicios, tareas programadas), tareas |
| **Hallazgos** | Lo detectado. Clic para ver evidencia y marcar *Investigar*, *Resolver* o *Falso positivo* |
| **Caza** | Búsquedas manuales sobre toda la telemetría + estado de las hipótesis automáticas |
| **ATT&CK** | Matriz MITRE con las técnicas observadas |
| **IOCs** | Indicadores (IP, hash, proceso…) que se buscan en tiempo real y en todo el histórico |
| **Tareas** | Recolección forense pedida a los agentes (🤖 automática, 👤 manual) |
| **Cazar ahora** | Lanza un ciclo de caza inmediato (también corre solo cada minuto) |

### Ejemplos de búsqueda (sección Caza)

| Ámbito | Consulta | Busca |
|---|---|---|
| Procesos | `name:powershell.exe` | Todas las ejecuciones de PowerShell |
| Procesos | `parent:winword.exe\|excel.exe` | Procesos lanzados por Office |
| Procesos | `exe:*\AppData\Local\Temp\*` | Ejecutables corriendo desde Temp |
| Red | `rport:443 -raddr:10.*` | Conexiones HTTPS fuera de la red interna |
| Persistencia | `kind:run_key` | Programas en claves Run del registro |

Sintaxis: `campo:valor` (se combinan con AND), `-campo:valor` niega, `a|b` es OR, `*` es comodín, `since:30m|2h|7d`
filtra por tiempo, y `rport:>1024` compara números.

### Prueba inofensiva para ver una detección

En un Windows con agente abre **cmd** y ejecuta: `whoami`, `ipconfig`, `systeminfo`, `net user`, `tasklist`.
Tras 1–2 minutos (o pulsando *Cazar ahora*) aparece el hallazgo **"Ráfaga de reconocimiento"** (MITRE T1082):
muchos comandos de enumeración en poco tiempo, como haría un atacante tras entrar.

### Qué detecta

- **En tiempo real** (20+ reglas MITRE ATT&CK): PowerShell codificado, Office lanzando intérpretes, web shells, abuso
  de LOLBins, ejecución desde Temp, volcado de credenciales, borrado de shadow copies/logs, suplantación de procesos
  del sistema, mineros, conexiones a puertos de C2, persistencia nueva o sospechosa, puertos nuevos en escucha, IOCs.
- **Caza autónoma cada minuto**: beaconing C2 (regularidad estadística), binarios raros en la flota, ráfagas de
  reconocimiento, movimiento lateral/escaneo, linaje de procesos inusual, IOCs retroactivos, agentes silenciados tras
  alertas y correlación de cadena de ataque (3+ tácticas en el mismo equipo).
- **Respuesta autónoma**: ante hallazgos altos/críticos pide al agente el árbol del proceso, escaneo del binario
  (firmas + entropía) y más frecuencia de recolección; los resultados se vuelven a analizar.

> "Binarios raros" y "linaje inusual" comparan equipos entre sí: se activan con **3 o más agentes**.

---

## 6. Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| `./start_server.sh: no such file` | Copia antigua del repo | `git pull origin claude/great-bardeen-bkkcfr` (si se queja: `git checkout start_server.sh` y repetir) |
| Panel dice "Token inválido" | Token distinto al de `.env` o servidor sin reiniciar | `cat .env`, reinicia `./start_server.sh` y usa `THL_ADMIN_TOKEN` |
| `ngrok: command not found` | ngrok no instalado | Sección 2.2 |
| `ERR_NGROK_4018` | Falta el authtoken | `ngrok config add-authtoken ...` |
| "URL para agentes: (sin túnel…)" | `NGROK_URL` no está en `.env` | Sección 2.3 |
| El equipo no aparece en Agentes | Ver `C:\ProgramData\ThreatHuntingAgent\agent.log` | Según el mensaje ↓ |
| Log: `HTTP Error 403` | La clave no coincide con `THL_ENROLL_KEY` | Reinstala el agente con la clave correcta |
| Log: `Servidor no disponible` / `timed out` | Kali apagado, túnel caído o URL/puerto incorrectos | Comprueba `https://tu-dominio/api/health` desde el equipo |
| No existe `agent.log` | El agente no arrancó | Reinicia Windows; revisa *Seguridad de Windows → Historial de protección* |
| Hallazgos de programas legítimos | Reglas sin ajustar a tu entorno | Márcalos como *Falso positivo* |

---

## 7. Límites y consideraciones

- **Plan gratuito de ngrok**: tiene cuotas mensuales de peticiones y tráfico (consulta las cifras actuales en
  **Usage** de tu panel de ngrok). Cada agente envía telemetría cada 60 s (~43.000 envíos/mes por equipo), por lo que
  **incluso un solo equipo puede agotar la cuota gratuita**; al superarla ngrok corta el túnel hasta el mes
  siguiente. Para varios equipos considera un plan de pago, un VPS o redirigir un puerto del router con HTTPS propio.
- **Seguridad**: el panel queda accesible desde Internet a través de ngrok; usa un `THL_ADMIN_TOKEN` largo y no
  compartas `.env`. El agente solo ejecuta módulos forenses de lectura en lista blanca: nunca comandos arbitrarios.
- **Kali encendido**: sin servidor no hay detección; los agentes guardan las conexiones de red y reintentan.
- **Firma digital**: sin certificado configurado el instalador sale sin firmar y genera avisos (sección 3.3).

---

## Referencia técnica

### Estructura

| Ruta | Contenido |
|---|---|
| `server/main.py` | API FastAPI y servidor del panel |
| `server/detections.py` | Reglas en tiempo real (MITRE ATT&CK) e IOCs |
| `server/hunter.py` | Motor de caza autónomo (hipótesis) |
| `server/responder.py` | Respuesta autónoma y puntuación de riesgo |
| `server/ingest.py` | Ingesta de telemetría y líneas base |
| `server/query.py` | Lenguaje de consulta de la consola de caza |
| `server/static/` | Panel web (HTML/CSS/JS sin dependencias) |
| `agent/th_agent.py` | Agente multiplataforma (psutil) |
| `agent/windows/` | Instalador Inno Setup, registro de la tarea SYSTEM, firma de código (`sign.ps1`, `create_codesign_cert.sh`) |
| `.github/workflows/build-agent-windows.yml` | Compila `th_agent.exe` (PyInstaller) y el instalador |
| `start_server.sh` | Arranque del servidor (+ ngrok opcional) |

### Variables del servidor (`.env`)

| Variable | Defecto | Descripción |
|---|---|---|
| `THL_ADMIN_TOKEN` | aleatorio | Token del panel/API |
| `THL_ENROLL_KEY` | aleatorio | Clave de enrolamiento de agentes |
| `THL_PORT` | `8000` | Puerto del servidor |
| `NGROK_URL` | — | Dominio ngrok; si está, se arranca el túnel |
| `THL_DB` | `threat_hunting.db` | Base de datos SQLite |
| `THL_HUNT_INTERVAL` | `60` | Segundos entre ciclos de caza |
| `THL_AUTO_RESPONSE` | `1` | Recolección forense automática |
| `THL_RETENTION_DAYS` | `14` | Días de retención de telemetría |

### Opciones del agente

`--server`, `--enroll-key`, `--interval` (s), `--config` (JSON; en Windows por defecto
`C:\ProgramData\ThreatHuntingAgent\config.json`), `--state-file`, `--log-file`, `--ca` (CA propia), `--once`.

### Pruebas

```bash
pip install -r requirements-dev.txt
pytest -q
```
