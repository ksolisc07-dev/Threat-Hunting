"""Reglas de detección en tiempo real (se evalúan en la ingesta de telemetría).

Cada regla está mapeada a MITRE ATT&CK. Las reglas de flota / estadísticas
(beaconing, rareza, correlación...) viven en `hunter.py`.
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable

SEVERITY_SCORE = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    tactic: str
    technique: str
    kind: str  # process | network | listener | persistence
    match: Callable[[dict], dict | None] = field(repr=False)

    def meta(self) -> dict:
        return {k: getattr(self, k) for k in ("id", "title", "description", "severity", "tactic", "technique", "kind")}


def _base(p: str | None) -> str:
    """Nombre base en minúsculas de un ejecutable (Windows o POSIX)."""
    if not p:
        return ""
    return re.split(r"[\\/]", p)[-1].lower()


def _rx(*patterns: str) -> re.Pattern:
    return re.compile("|".join(patterns), re.IGNORECASE)


def _search(rx: re.Pattern, text: str | None) -> dict | None:
    if not text:
        return None
    m = rx.search(text)
    return {"match": m.group(0)} if m else None


# ---------------------------------------------------------------------------
# Conjuntos de referencia
# ---------------------------------------------------------------------------
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "sh", "bash", "dash", "zsh", "ksh",
          "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "python",
          "python3", "perl", "ruby", "php", "nc", "ncat", "socat"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
          "mspub.exe", "onenote.exe", "visio.exe"}
WEB_SERVERS = {"w3wp.exe", "httpd", "apache2", "nginx", "php-fpm", "php-cgi", "tomcat",
               "tomcat9", "lighttpd", "caddy", "httpd.exe", "nginx.exe", "php-cgi.exe"}
SYSTEM_IMPERSONATED = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
                       "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe", "wininit.exe"}
NO_NETWORK_BINARIES = {"notepad.exe", "calc.exe", "mspaint.exe", "rundll32.exe", "regsvr32.exe",
                       "mshta.exe", "certutil.exe", "wordpad.exe", "write.exe", "cmstp.exe",
                       "msbuild.exe", "installutil.exe"}
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 6697, 5555, 9001, 9030, 9050, 9051,
                    3333, 14444, 45700, 8888, 1234, 12345, 50050}
DISCOVERY_CMDS = _rx(
    r"\bwhoami\b", r"\bnet1?(\.exe)?\s+(user|group|localgroup|view|share|accounts)\b", r"\bnltest\b",
    r"\bipconfig\b", r"\bsysteminfo\b", r"\bquser\b", r"\btasklist\b", r"\barp\s+-a\b",
    r"\buname\s+-a\b", r"^\s*id\s*$", r"\bifconfig\b", r"\bip\s+a(ddr)?\b", r"\bnetstat\b",
    r"\bcat\s+/etc/passwd\b", r"\bhostname\b", r"\bdsquery\b", r"\bget-ad(user|computer|group)\b",
    r"\bss\s+-[a-z]*t", r"\bsudo\s+-l\b", r"\bfind\s+/\s+-perm\b",
)
TEMP_PATHS = _rx(r"^/tmp/", r"^/dev/shm/", r"^/var/tmp/", r"\\appdata\\local\\temp\\",
                 r"\\users\\public\\", r"\\windows\\temp\\", r"\\programdata\\[^\\]+\.exe$",
                 r"\\\$recycle\.bin\\", r"\\perflogs\\")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


# ---------------------------------------------------------------------------
# Reglas de procesos
# ---------------------------------------------------------------------------
def _encoded_powershell(p):
    if _base(p.get("name")) not in ("powershell.exe", "pwsh.exe", "pwsh", "powershell"):
        return None
    return _search(_rx(r"\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}", r"frombase64string",
                       r"-w(indowstyle)?\s+hidden", r"\s-nop\b.*\s-e"), p.get("cmdline"))


def _office_child(p):
    if _base(p.get("parent_name")) in OFFICE and _base(p.get("name")) in SHELLS:
        return {"parent": p.get("parent_name"), "child": p.get("name")}
    return None


def _webshell(p):
    if _base(p.get("parent_name")) in WEB_SERVERS and _base(p.get("name")) in SHELLS:
        return {"parent": p.get("parent_name"), "child": p.get("name")}
    return None


LOLBINS = _rx(
    r"certutil(\.exe)?.*(-urlcache|-decode|-encode|verifyctl)", r"mshta(\.exe)?\s+.*(https?:|javascript:|vbscript:)",
    r"regsvr32(\.exe)?.*/i:\s*https?:", r"regsvr32(\.exe)?.*scrobj", r"rundll32(\.exe)?.*javascript:",
    r"bitsadmin(\.exe)?.*/transfer", r"wmic(\.exe)?.*process\s+call\s+create", r"wmic(\.exe)?.*/node:",
    r"msiexec(\.exe)?.*/q.*https?:", r"cmstp(\.exe)?.*/s", r"installutil(\.exe)?.*/u",
    r"esentutl(\.exe)?.*/y.*/vss",
)


def _lolbin(p):
    return _search(LOLBINS, p.get("cmdline"))


def _temp_exec(p):
    return _search(TEMP_PATHS, (p.get("exe") or "").lower())


def _deleted_binary(p):
    exe = p.get("exe") or ""
    return {"exe": exe} if exe.endswith(" (deleted)") else None


REVERSE_SHELL = _rx(
    r"/dev/tcp/\S+/\d+", r"/dev/udp/\S+/\d+", r"\bn(c|cat)(\.exe)?\s+.*-[a-z]*e\s+\S*(sh|cmd)",
    r"socat\s+.*exec:", r"python[0-9.]*\s+-c\s+.*socket.*(pty|subprocess|dup2)",
    r"perl\s+-e\s+.*socket", r"php\s+-r\s+.*fsockopen", r"mkfifo\s+.*\bnc\b", r"\bsh\s+-i\b.*[<>]&",
    r"new-object\s+system\.net\.sockets\.tcpclient",
)


def _reverse_shell(p):
    return _search(REVERSE_SHELL, p.get("cmdline"))


CRED_DUMP = _rx(
    r"mimikatz", r"sekurlsa", r"lsadump", r"procdump(64)?(\.exe)?.*lsass", r"comsvcs(\.dll)?.*minidump",
    r"reg(\.exe)?\s+save\s+hklm\\(sam|security|system)", r"ntdsutil.*(ifm|ac\s+i\s+ntds)",
    r"\bcat\s+/etc/shadow\b", r"unshadow", r"\bpypykatz\b", r"lazagne", r"vssadmin.*create\s+shadow",
)


def _cred_dump(p):
    return _search(CRED_DUMP, f"{p.get('name') or ''} {p.get('cmdline') or ''}")


INHIBIT_RECOVERY = _rx(r"vssadmin(\.exe)?\s+delete\s+shadows", r"wbadmin(\.exe)?\s+delete\s+catalog",
                       r"bcdedit(\.exe)?.*recoveryenabled\s+no", r"wmic(\.exe)?\s+shadowcopy\s+delete",
                       r"bcdedit(\.exe)?.*bootstatuspolicy\s+ignoreallfailures")


def _inhibit_recovery(p):
    return _search(INHIBIT_RECOVERY, p.get("cmdline"))


LOG_CLEAR = _rx(r"wevtutil(\.exe)?\s+(cl|clear-log)", r"clear-eventlog", r"\bhistory\s+-c\b",
                r"rm\s+(-[rf]+\s+)?\S*\.bash_history", r"unset\s+histfile", r">\s*/var/log/\S+",
                r"shred\s+.*?/var/log", r"auditctl\s+-D", r"fsutil\s+usn\s+deletejournal")


def _log_clear(p):
    return _search(LOG_CLEAR, p.get("cmdline"))


DOWNLOAD_EXEC = _rx(r"(curl|wget)\s+[^|;]*\|\s*(ba|da|z)?sh\b", r"(curl|wget)\s+.*-O-?\s*\|\s*python",
                    r"iex\s*\(?\s*\(?new-object\s+net\.webclient\)?\.downloadstring",
                    r"invoke-webrequest.*\|\s*iex", r"downloadstring\(", r"invoke-expression.*http",
                    r"(curl|wget)\s+\S+\s+.*&&\s*chmod\s+\+x")


def _download_exec(p):
    return _search(DOWNLOAD_EXEC, p.get("cmdline"))


def _masquerade(p):
    name = _base(p.get("name"))
    exe = (p.get("exe") or "").lower()
    if name in SYSTEM_IMPERSONATED and exe and "\\windows\\system32\\" not in exe \
            and "\\windows\\syswow64\\" not in exe and not (name == "explorer.exe" and exe.endswith("\\windows\\explorer.exe")):
        return {"name": name, "exe": p.get("exe")}
    if re.match(r"^\[?(kworker|kthreadd|ksoftirqd|migration|rcu_)", name) and exe:
        return {"name": name, "exe": p.get("exe"), "why": "hilo de kernel con binario en disco"}
    return None


MINER = _rx(r"stratum\+(tcp|ssl)://", r"\bxmrig\b", r"\bminerd\b", r"\bcpuminer\b", r"--donate-level",
            r"\bnicehash\b", r"cryptonight")


def _miner(p):
    return _search(MINER, f"{p.get('name') or ''} {p.get('cmdline') or ''}")


def _obfuscated(p):
    cmd = p.get("cmdline") or ""
    m = B64_BLOB.search(cmd)
    if m and _base(p.get("name")) not in ("java", "java.exe"):
        return {"blob_len": len(m.group(0)), "entropy": round(shannon_entropy(m.group(0)), 2)}
    return None


# ---------------------------------------------------------------------------
# Reglas de red
# ---------------------------------------------------------------------------
def is_public_ip(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return a.is_global


def _suspicious_port(c):
    if c.get("rport") in SUSPICIOUS_PORTS and c.get("raddr") and not ipaddress.ip_address(c["raddr"]).is_loopback:
        return {"raddr": c.get("raddr"), "rport": c.get("rport"), "process": c.get("process_name")}
    return None


def _no_network_binary(c):
    if _base(c.get("process_name")) in NO_NETWORK_BINARIES and is_public_ip(c.get("raddr")):
        return {"process": c.get("process_name"), "raddr": c.get("raddr"), "rport": c.get("rport")}
    return None


def _shell_network(c):
    if _base(c.get("process_name")) in {"sh", "bash", "dash", "cmd.exe", "powershell.exe", "nc", "ncat"} \
            and is_public_ip(c.get("raddr")):
        return {"process": c.get("process_name"), "raddr": c.get("raddr"), "rport": c.get("rport")}
    return None


def _shell_listener(l):
    if _base(l.get("process_name")) in {"sh", "bash", "dash", "zsh", "nc", "ncat", "socat", "cmd.exe",
                                         "powershell.exe"}:
        return {"process": l.get("process_name"), "port": l.get("port"), "addr": l.get("addr")}
    return None


# ---------------------------------------------------------------------------
# Reglas de persistencia
# ---------------------------------------------------------------------------
SUSPICIOUS_PERSIST = _rx(r"/tmp/", r"/dev/shm/", r"/dev/tcp/", r"curl\s", r"wget\s", r"base64\s+-d",
                         r"\s-enc(odedcommand)?\s", r"frombase64string", r"\\appdata\\local\\temp\\",
                         r"\\users\\public\\", r"mshta", r"regsvr32.*http", r"rundll32.*,\s*\w+\s+http",
                         r"\bnc\s+-", r"python[0-9.]*\s+-c")


def _suspicious_persistence(e):
    hit = _search(SUSPICIOUS_PERSIST, e.get("value"))
    if hit:
        hit.update({"kind": e.get("kind"), "location": e.get("location")})
    return hit


def _ld_preload(e):
    if e.get("kind") == "ld_preload" and (e.get("value") or "").strip():
        return {"location": e.get("location"), "value": e.get("value")}
    return None


RULES: list[Rule] = [
    Rule("TH-P001", "PowerShell codificado/oculto", "PowerShell ejecutado con comandos codificados en Base64 o ventana oculta.",
         "high", "Execution", "T1059.001", "process", _encoded_powershell),
    Rule("TH-P002", "Aplicación Office lanza intérprete", "Un documento de Office generó una shell o host de scripts (macro maliciosa).",
         "critical", "Initial Access", "T1566.001", "process", _office_child),
    Rule("TH-P003", "Servidor web lanza shell (web shell)", "Un proceso de servidor web generó un intérprete de comandos.",
         "critical", "Persistence", "T1505.003", "process", _webshell),
    Rule("TH-P004", "Abuso de LOLBin", "Binario legítimo del sistema usado para descargar, decodificar o ejecutar código.",
         "high", "Defense Evasion", "T1218", "process", _lolbin),
    Rule("TH-P005", "Ejecución desde directorio temporal", "Binario ejecutado desde una ruta temporal o con permisos de escritura global.",
         "medium", "Execution", "T1204.002", "process", _temp_exec),
    Rule("TH-P006", "Proceso con binario borrado", "El ejecutable del proceso fue eliminado del disco mientras corre (fileless/anti-forense).",
         "high", "Defense Evasion", "T1070.004", "process", _deleted_binary),
    Rule("TH-P007", "Shell inversa", "Patrón de línea de comandos típico de una reverse shell.",
         "critical", "Execution", "T1059.004", "process", _reverse_shell),
    Rule("TH-P008", "Volcado de credenciales", "Herramientas o técnicas de extracción de credenciales (LSASS, SAM, shadow).",
         "critical", "Credential Access", "T1003", "process", _cred_dump),
    Rule("TH-P009", "Inhibición de recuperación", "Borrado de shadow copies / catálogos de backup (precursor de ransomware).",
         "critical", "Impact", "T1490", "process", _inhibit_recovery),
    Rule("TH-P010", "Borrado de logs / historial", "Limpieza de registros de eventos o historial de comandos.",
         "high", "Defense Evasion", "T1070", "process", _log_clear),
    Rule("TH-P011", "Descarga y ejecución", "Descarga de contenido remoto ejecutado directamente (cradle).",
         "high", "Command and Control", "T1105", "process", _download_exec),
    Rule("TH-P012", "Suplantación de proceso del sistema", "Nombre de proceso del sistema ejecutándose desde una ruta no legítima.",
         "high", "Defense Evasion", "T1036.005", "process", _masquerade),
    Rule("TH-P013", "Minero de criptomonedas", "Indicadores de minería (stratum, xmrig...).",
         "high", "Impact", "T1496", "process", _miner),
    Rule("TH-P014", "Línea de comandos ofuscada", "Bloque Base64 extenso en la línea de comandos.",
         "medium", "Defense Evasion", "T1027", "process", _obfuscated),
    Rule("TH-N001", "Conexión a puerto sospechoso", "Conexión saliente a un puerto asociado a C2, Tor, IRC o minería.",
         "medium", "Command and Control", "T1571", "network", _suspicious_port),
    Rule("TH-N002", "Binario sin red conectándose a Internet", "Un binario que normalmente no usa red estableció conexión pública.",
         "high", "Command and Control", "T1218", "network", _no_network_binary),
    Rule("TH-N003", "Shell con conexión a Internet", "Un intérprete de comandos mantiene una conexión a una IP pública.",
         "critical", "Command and Control", "T1059", "network", _shell_network),
    Rule("TH-L001", "Shell escuchando en un puerto", "Un intérprete o netcat escucha conexiones entrantes (bind shell).",
         "critical", "Command and Control", "T1059", "listener", _shell_listener),
    Rule("TH-S001", "Persistencia con contenido sospechoso", "Mecanismo de persistencia que referencia rutas temporales, descargas u ofuscación.",
         "high", "Persistence", "T1053", "persistence", _suspicious_persistence),
    Rule("TH-S002", "Secuestro de cargador dinámico (ld.so.preload)", "Entrada en /etc/ld.so.preload: técnica típica de rootkits de usuario.",
         "critical", "Persistence", "T1574.006", "persistence", _ld_preload),
]

# Reglas de "deriva" (se generan comparando contra la línea base del host)
DRIFT_RULES = {
    "TH-S100": Rule("TH-S100", "Nueva persistencia", "Apareció un mecanismo de persistencia que no estaba en la línea base del host.",
                    "medium", "Persistence", "T1547", "persistence", lambda e: None),
    "TH-L100": Rule("TH-L100", "Nuevo puerto en escucha", "Un servicio comenzó a escuchar en un puerto que no estaba en la línea base.",
                    "low", "Command and Control", "T1571", "listener", lambda e: None),
}

# Reglas que se disparan a partir de resultados forenses de tareas del agente
FILE_RULES = {
    "TH-F001": Rule("TH-F001", "Firmas maliciosas en archivo",
                    "El escaneo forense del agente encontró cadenas asociadas a malware/herramientas ofensivas.",
                    "high", "Execution", "T1204.002", "file", lambda e: None),
    "TH-F002": Rule("TH-F002", "Binario empaquetado o cifrado",
                    "Entropía muy alta del archivo: indicio de empaquetado/cifrado para evadir análisis.",
                    "medium", "Defense Evasion", "T1027.002", "file", lambda e: None),
}

PERSISTENCE_TECHNIQUE = {
    "cron": "T1053.003", "systemd": "T1543.002", "rc_local": "T1037.004", "ld_preload": "T1574.006",
    "authorized_keys": "T1098.004", "shell_profile": "T1546.004", "launchd": "T1543.004",
    "run_key": "T1547.001", "startup_folder": "T1547.001", "service": "T1543.003",
    "scheduled_task": "T1053.005",
}

RULES_BY_ID = {r.id: r for r in RULES} | DRIFT_RULES | FILE_RULES


def shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def short_hash(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def make_finding(rule: Rule, agent_id: str | None, evidence: dict, key: str, source="realtime",
                 severity: str | None = None, technique: str | None = None, title: str | None = None) -> dict:
    sev = severity or rule.severity
    return {
        "agent_id": agent_id, "rule_id": rule.id, "title": title or rule.title,
        "description": rule.description, "severity": sev, "score": SEVERITY_SCORE[sev],
        "tactic": rule.tactic, "technique": technique or rule.technique, "source": source,
        "evidence": evidence, "dedup_key": f"{rule.id}:{agent_id}:{key}",
    }


def evaluate(kind: str, agent_id: str, item: dict) -> list[dict]:
    """Aplica todas las reglas de un tipo a un elemento de telemetría."""
    out = []
    for rule in RULES:
        if rule.kind != kind:
            continue
        try:
            hit = rule.match(item)
        except Exception:  # una regla defectuosa nunca debe romper la ingesta
            hit = None
        if not hit:
            continue
        evidence = {**_context(kind, item), "detail": hit}
        technique = None
        if kind == "persistence":
            technique = PERSISTENCE_TECHNIQUE.get(item.get("kind")) if rule.id == "TH-S001" else None
        out.append(make_finding(rule, agent_id, evidence, _key(kind, item), technique=technique))
    return out


def _context(kind: str, item: dict) -> dict:
    if kind == "process":
        keys = ("pid", "ppid", "name", "exe", "cmdline", "username", "parent_name", "parent_exe", "sha256")
    elif kind == "network":
        keys = ("pid", "process_name", "laddr", "lport", "raddr", "rport", "proto", "ts")
    elif kind == "listener":
        keys = ("pid", "process_name", "addr", "port", "proto")
    else:
        keys = ("kind", "location", "value")
    return {k: item.get(k) for k in keys if item.get(k) is not None}


def _key(kind: str, item: dict) -> str:
    if kind == "process":
        return short_hash(item.get("exe") or item.get("name"), item.get("cmdline"))
    if kind == "network":
        return short_hash(item.get("process_name"), item.get("raddr"), item.get("rport"))
    if kind == "listener":
        return short_hash(item.get("process_name"), item.get("port"))
    return short_hash(item.get("location"), item.get("value"))


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------
IOC_RULE = Rule("TH-I001", "Coincidencia con IOC", "La telemetría coincide con un indicador de compromiso registrado.",
                "high", "Command and Control", "T1588", "ioc", lambda x: None)
RULES_BY_ID[IOC_RULE.id] = IOC_RULE


def ioc_matches(iocs: list[dict], kind: str, item: dict) -> list[dict]:
    hits = []
    for ioc in iocs:
        t, v = ioc["type"], (ioc["value"] or "").strip()
        if not v:
            continue
        vl = v.lower()
        matched = False
        if kind == "process":
            if t == "sha256":
                matched = (item.get("sha256") or "").lower() == vl
            elif t == "process":
                matched = _base(item.get("name")) == vl or _base(item.get("exe")) == vl
            elif t in ("cmdline", "domain", "ip"):
                matched = vl in (item.get("cmdline") or "").lower()
        elif kind == "network" and t == "ip":
            matched = item.get("raddr") == v
        if matched:
            hits.append(ioc)
    return hits


def ioc_findings(iocs: list[dict], kind: str, agent_id: str, item: dict, source="ioc") -> list[dict]:
    out = []
    for ioc in ioc_matches(iocs, kind, item):
        evidence = {**_context(kind, item), "ioc": {k: ioc[k] for k in ("type", "value", "description")}}
        tactic_tech = ("Command and Control", "T1071") if ioc["type"] in ("ip", "domain") else ("Execution", "T1204")
        f = make_finding(IOC_RULE, agent_id, evidence, short_hash(ioc["type"], ioc["value"], _key(kind, item)),
                         source=source, severity=ioc.get("severity") or "high",
                         title=f"IOC {ioc['type']}: {ioc['value']}")
        f["tactic"], f["technique"] = tactic_tech
        out.append(f)
    return out
