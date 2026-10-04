#!/usr/bin/env python3
"""Agente de Threat Hunting (Linux / Windows / macOS).

Recolecta telemetría de forma autónoma y la envía al servidor:
  * procesos (con árbol, usuario, línea de comandos y SHA256 del binario)
  * conexiones de red nuevas (muestreo continuo en segundo plano, permite
    detectar beaconing), puertos en escucha y sesiones de usuario
  * mecanismos de persistencia (cron, systemd, launchd, Run keys, servicios,
    tareas programadas, authorized_keys, ld.so.preload, perfiles de shell)

Ejecuta tareas forenses que pide el servidor, SOLO de una lista blanca de
módulos de lectura (nunca ejecuta comandos arbitrarios).

Uso:
    python th_agent.py --server http://SERVIDOR:8000 --enroll-key CLAVE
"""
import argparse
import hashlib
import json
import math
import os
import platform
import random
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover
    sys.exit("Falta psutil: pip install psutil")

VERSION = "1.0.0"
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
MAX_HASH_SIZE = 64 * 1024 * 1024
MAX_SCAN_SIZE = 32 * 1024 * 1024

# Firmas YARA-lite para el módulo scan_file
SIGNATURES = {
    "mimikatz": [b"mimikatz", b"sekurlsa::", b"gentilkiwi"],
    "cobalt_strike": [b"beacon.dll", b"ReflectiveLoader", b"%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s"],
    "meterpreter": [b"metsrv", b"meterpreter", b"stdapi_"],
    "reverse_shell": [b"/dev/tcp/", b"bash -i >&", b"pty.spawn("],
    "process_injection": [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"NtUnmapViewOfSection"],
    "miner": [b"stratum+tcp://", b"xmrig", b"cryptonight"],
    "powershell_offensive": [b"Invoke-Mimikatz", b"Invoke-Shellcode", b"PowerSploit", b"Invoke-ReflectivePEInjection"],
    "ransomware_note": [b"Your files have been encrypted", b"bitcoin wallet", b".onion"],
    "webshell": [b"eval($_POST", b"eval(base64_decode", b"cmd.exe /c\" & request", b"Runtime.getRuntime().exec(request"],
    "rootkit_preload": [b"LD_PRELOAD", b"readdir64", b"hide_pid"],
}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ===========================================================================
# Utilidades
# ===========================================================================
class HashCache:
    def __init__(self):
        self._cache: dict[str, tuple] = {}

    def sha256(self, path: str | None) -> str | None:
        if not path or path.endswith(" (deleted)"):
            return None
        try:
            st = os.stat(path)
        except OSError:
            return None
        if st.st_size > MAX_HASH_SIZE:
            return None
        key = (st.st_mtime, st.st_size)
        hit = self._cache.get(path)
        if hit and hit[0] == key:
            return hit[1]
        digest = file_hashes(path).get("sha256")
        self._cache[path] = (key, digest)
        return digest


def file_hashes(path: str) -> dict:
    sha, md5 = hashlib.sha256(), hashlib.md5()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                sha.update(chunk)
                md5.update(chunk)
    except OSError:
        return {}
    return {"sha256": sha.hexdigest(), "md5": md5.hexdigest()}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def primary_ip(server: str) -> str:
    try:
        host = server.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0] or "8.8.8.8"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 9))
            return s.getsockname()[0]
    except OSError:
        return ""


def read_text(path: Path, limit: int = 256 * 1024) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


# ===========================================================================
# Recolectores
# ===========================================================================
class ConnectionSampler(threading.Thread):
    """Muestrea la tabla de conexiones cada `period` s y registra las nuevas.

    Cada conexión saliente nueva (tupla local+remota distinta) es un evento con
    marca de tiempo: así el servidor puede medir la periodicidad (beaconing)
    aunque las conexiones duren menos que el intervalo de reporte.
    """

    def __init__(self, period: float = 2.0, max_buffer: int = 20000):
        super().__init__(daemon=True)
        self.period = period
        self.max_buffer = max_buffer
        self._seen: set = set()
        self._events: list[dict] = []
        self._lock = threading.Lock()
        self._names: dict[int, str] = {}

    def _pname(self, pid):
        if not pid:
            return None
        if pid not in self._names:
            try:
                self._names[pid] = psutil.Process(pid).name()
            except (psutil.Error, OSError):
                self._names[pid] = None
        return self._names[pid]

    def sample(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return
        now = time.time()
        current = set()
        new = []
        for c in conns:
            if not c.raddr:
                continue
            key = (c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.type)
            current.add(key)
            if key in self._seen:
                continue
            new.append({
                "ts": now, "pid": c.pid, "process_name": self._pname(c.pid),
                "laddr": c.laddr.ip, "lport": c.laddr.port, "raddr": c.raddr.ip, "rport": c.raddr.port,
                "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp", "status": c.status,
            })
        self._seen = current
        if len(self._names) > 4096:
            self._names.clear()
        if new:
            with self._lock:
                self._events.extend(new)
                if len(self._events) > self.max_buffer:
                    self._events = self._events[-self.max_buffer:]

    def drain(self) -> list[dict]:
        with self._lock:
            ev, self._events = self._events, []
        return ev

    def requeue(self, events: list[dict]) -> None:
        with self._lock:
            self._events = (events + self._events)[-self.max_buffer:]

    def run(self):
        while True:
            self.sample()
            time.sleep(self.period)


def collect_host(server: str) -> dict:
    vm = psutil.virtual_memory()
    return {
        "hostname": socket.gethostname(), "os": platform.system(), "os_version": platform.release(),
        "platform": platform.platform(), "arch": platform.machine(), "ip": primary_ip(server),
        "boot_time": psutil.boot_time(), "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=None), "mem_percent": vm.percent,
        "mem_total": vm.total, "python": platform.python_version(),
    }


def collect_processes(hashes: HashCache) -> list[dict]:
    out = []
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
    for p in psutil.process_iter(attrs):
        info = p.info
        try:
            if not info.get("exe") and not IS_WIN and info["pid"] > 2:
                # binario borrado: psutil devuelve vacío, /proc/<pid>/exe dice "(deleted)"
                try:
                    link = os.readlink(f"/proc/{info['pid']}/exe")
                    if link.endswith(" (deleted)"):
                        info["exe"] = link
                except OSError:
                    pass
            cmd = info.get("cmdline") or []
            out.append({
                "pid": info["pid"], "ppid": info.get("ppid"), "name": info.get("name"),
                "exe": info.get("exe") or None,
                "cmdline": " ".join(cmd) if isinstance(cmd, list) else str(cmd),
                "username": info.get("username"), "create_time": info.get("create_time"),
                "sha256": hashes.sha256(info.get("exe")),
            })
        except (psutil.Error, OSError):
            continue
    return out


def collect_listeners() -> list[dict]:
    out, seen = [], set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return out
    for c in conns:
        is_listen = c.status == psutil.CONN_LISTEN or (c.type == socket.SOCK_DGRAM and not c.raddr)
        if not is_listen or not c.laddr:
            continue
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        key = (proto, c.laddr.port, c.laddr.ip)
        if key in seen:
            continue
        seen.add(key)
        try:
            name = psutil.Process(c.pid).name() if c.pid else None
        except psutil.Error:
            name = None
        out.append({"pid": c.pid, "process_name": name, "addr": c.laddr.ip, "port": c.laddr.port, "proto": proto})
    return out


def collect_users() -> list[dict]:
    try:
        return [{"name": u.name, "terminal": u.terminal, "host": u.host, "started": u.started} for u in psutil.users()]
    except (psutil.Error, OSError):
        return []


# --------------------------------------------------------------------------- persistencia
def _homes() -> list[Path]:
    homes = [Path.home()]
    for base in ("/home", "/Users", "C:\\Users"):
        try:
            homes += [p for p in Path(base).iterdir() if p.is_dir()]
        except OSError:
            pass
    if not IS_WIN:
        homes.append(Path("/root"))
    return list(dict.fromkeys(homes))


def _cron_lines(path: Path) -> list[str]:
    return [l.strip() for l in read_text(path).splitlines()
            if l.strip() and not l.strip().startswith("#") and not l.strip().startswith(("SHELL=", "PATH=", "MAILTO="))]


def persistence_linux() -> list[dict]:
    out = []
    crons = [Path("/etc/crontab")]
    for d in ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"):
        try:
            crons += [p for p in Path(d).iterdir() if p.is_file()]
        except OSError:
            pass
    for f in crons:
        out += [{"kind": "cron", "location": str(f), "value": l} for l in _cron_lines(f)]
    for d in ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system"):
        try:
            units = list(Path(d).glob("*.service")) + list(Path(d).glob("*.timer"))
        except OSError:
            continue
        for u in units:
            if d != "/etc/systemd/system" and u.is_symlink():
                continue
            for line in read_text(u, 64 * 1024).splitlines():
                if line.startswith(("ExecStart=", "ExecStartPre=", "ExecStartPost=", "OnCalendar=")):
                    out.append({"kind": "systemd", "location": str(u), "value": line.strip()})
    for home in _homes():
        user_units = home / ".config/systemd/user"
        if user_units.is_dir():
            for u in user_units.glob("*.service"):
                for line in read_text(u).splitlines():
                    if line.startswith("ExecStart"):
                        out.append({"kind": "systemd", "location": str(u), "value": line.strip()})
        ak = home / ".ssh/authorized_keys"
        for line in read_text(ak).splitlines():
            if line.strip() and not line.startswith("#"):
                parts = line.split()
                fp = hashlib.sha256(line.encode()).hexdigest()[:16]
                out.append({"kind": "authorized_keys", "location": str(ak),
                            "value": f"{parts[0] if parts else ''} …{fp} {parts[-1] if len(parts) > 2 else ''}".strip()})
        for prof in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
            pf = home / prof
            if pf.is_file():
                text = read_text(pf)
                interesting = [l.strip() for l in text.splitlines()
                               if any(k in l for k in ("curl", "wget", "nc ", "/dev/tcp", "base64", "LD_PRELOAD",
                                                       "alias sudo", "/tmp/", "python -c", "eval "))]
                for l in interesting:
                    out.append({"kind": "shell_profile", "location": str(pf), "value": l})
    rc = Path("/etc/rc.local")
    out += [{"kind": "rc_local", "location": str(rc), "value": l} for l in _cron_lines(rc) if l != "exit 0"]
    pre = Path("/etc/ld.so.preload")
    out += [{"kind": "ld_preload", "location": str(pre), "value": l} for l in _cron_lines(pre)]
    for f in Path("/etc/profile.d").glob("*.sh") if Path("/etc/profile.d").is_dir() else []:
        out.append({"kind": "shell_profile", "location": str(f),
                    "value": "sha256:" + (file_hashes(str(f)).get("sha256") or "?")})
    return out


def persistence_macos() -> list[dict]:
    import plistlib
    out = []
    dirs = ["/Library/LaunchAgents", "/Library/LaunchDaemons"] + [str(h / "Library/LaunchAgents") for h in _homes()]
    for d in dirs:
        try:
            plists = list(Path(d).glob("*.plist"))
        except OSError:
            continue
        for p in plists:
            try:
                with open(p, "rb") as fh:
                    data = plistlib.load(fh)
                prog = data.get("ProgramArguments") or [data.get("Program", "")]
                out.append({"kind": "launchd", "location": str(p), "value": " ".join(map(str, prog))})
            except Exception:
                out.append({"kind": "launchd", "location": str(p), "value": "(plist ilegible)"})
    for f in [Path("/etc/crontab")]:
        out += [{"kind": "cron", "location": str(f), "value": l} for l in _cron_lines(f)]
    return out


def persistence_windows() -> list[dict]:
    out = []
    import winreg  # type: ignore
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    ]
    for hive, path in keys:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if path.endswith("Winlogon") and name not in ("Shell", "Userinit"):
                        continue
                    out.append({"kind": "run_key", "location": f"{hive_name}\\{path}\\{name}", "value": str(value)})
        except OSError:
            continue
    startup_dirs = [Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"]
    startup_dirs += [h / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" for h in _homes()]
    for d in startup_dirs:
        try:
            for f in d.iterdir():
                if f.name.lower() != "desktop.ini":
                    out.append({"kind": "startup_folder", "location": str(d), "value": f.name})
        except OSError:
            pass
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
            except (psutil.Error, OSError):
                continue
            if info.get("start_type") == "automatic":
                out.append({"kind": "service", "location": f"service:{info.get('name')}", "value": info.get("binpath") or ""})
    except Exception:
        pass
    tasks_dir = Path(os.environ.get("SYSTEMROOT", "C:\\Windows")) / "System32" / "Tasks"
    import re
    for f in tasks_dir.rglob("*") if tasks_dir.is_dir() else []:
        if not f.is_file():
            continue
        text = read_text(f)
        cmds = re.findall(r"<Command>(.*?)</Command>\s*(?:<Arguments>(.*?)</Arguments>)?", text, re.S)
        for cmd, args in cmds:
            out.append({"kind": "scheduled_task", "location": str(f.relative_to(tasks_dir)), "value": f"{cmd} {args}".strip()})
    return out


def collect_persistence() -> list[dict]:
    try:
        if IS_WIN:
            return persistence_windows()
        if IS_MAC:
            return persistence_macos()
        return persistence_linux()
    except Exception as exc:  # pragma: no cover
        log(f"persistencia: {exc}")
        return []


# ===========================================================================
# Módulos de tarea (lista blanca, solo lectura)
# ===========================================================================
def _proc_dict(p: psutil.Process) -> dict:
    with p.oneshot():
        d = {"pid": p.pid}
        for attr in ("ppid", "name", "exe", "username", "create_time", "status"):
            try:
                d[attr] = getattr(p, attr)()
            except (psutil.Error, OSError):
                d[attr] = None
        try:
            d["cmdline"] = " ".join(p.cmdline())
        except (psutil.Error, OSError):
            d["cmdline"] = None
        try:
            d["connections"] = [f"{c.laddr.ip}:{c.laddr.port}->{c.raddr.ip}:{c.raddr.port} {c.status}"
                                for c in p.net_connections() if c.raddr][:50]
        except (psutil.Error, OSError, AttributeError):
            d["connections"] = []
        try:
            d["open_files"] = [f.path for f in p.open_files()][:50]
        except (psutil.Error, OSError):
            d["open_files"] = []
    return d


def task_process_tree(params: dict) -> dict:
    pid = int(params["pid"])
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"pid": pid, "alive": False}
    ancestors = []
    for parent in proc.parents():
        try:
            ancestors.append(_proc_dict(parent))
        except psutil.Error:
            pass
    children = []
    for child in proc.children(recursive=True)[:100]:
        try:
            children.append(_proc_dict(child))
        except psutil.Error:
            pass
    return {"pid": pid, "alive": True, "process": _proc_dict(proc), "ancestors": ancestors, "descendants": children}


def _stat(path: str) -> dict:
    st = os.stat(path)
    return {"path": path, "size": st.st_size, "mtime": st.st_mtime, "ctime": st.st_ctime,
            "mode": stat.filemode(st.st_mode), "uid": getattr(st, "st_uid", None)}


def task_hash_file(params: dict) -> dict:
    path = str(params["path"])
    return {**_stat(path), **file_hashes(path)}


def task_scan_file(params: dict) -> dict:
    path = str(params["path"])
    info = _stat(path)
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise ValueError("no es un archivo regular")
    with open(path, "rb") as fh:
        data = fh.read(MAX_SCAN_SIZE)
    lower = data.lower()
    matches = []
    for family, needles in SIGNATURES.items():
        hits = [n.decode(errors="replace") for n in needles if n.lower() in lower]
        if hits:
            matches.append({"family": family, "strings": hits})
    magic = data[:4]
    ftype = ("PE" if magic[:2] == b"MZ" else "ELF" if magic == b"\x7fELF" else
             "Mach-O" if magic in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe") else
             "script" if magic[:2] == b"#!" else "data")
    return {**info, **file_hashes(path), "type": ftype, "entropy": round(entropy(data[:4 * 1024 * 1024]), 3),
            "matches": matches, "scanned_bytes": len(data)}


def task_list_dir(params: dict) -> dict:
    path = str(params.get("path") or ".")
    entries = []
    with os.scandir(path) as it:
        for e in it:
            try:
                st = e.stat(follow_symlinks=False)
                entries.append({"name": e.name, "size": st.st_size, "mtime": st.st_mtime,
                                "mode": stat.filemode(st.st_mode)})
            except OSError:
                entries.append({"name": e.name})
            if len(entries) >= 500:
                break
    return {"path": path, "entries": sorted(entries, key=lambda x: -(x.get("mtime") or 0))}


def task_connections(_params: dict) -> dict:
    rows = []
    for c in psutil.net_connections(kind="inet"):
        try:
            name = psutil.Process(c.pid).name() if c.pid else None
        except psutil.Error:
            name = None
        rows.append({"pid": c.pid, "process": name, "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                     "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "", "status": c.status})
    return {"connections": rows[:2000]}


# ===========================================================================
# Agente
# ===========================================================================
class Agent:
    def __init__(self, server: str, enroll_key: str, interval: int, state_file: str,
                 persistence_every: int, cafile: str | None):
        self.server = server.rstrip("/")
        self.enroll_key = enroll_key
        self.base_interval = interval
        self.interval = interval
        self.hunt_mode_until = 0.0
        self.state_file = Path(state_file)
        self.persistence_every = persistence_every
        self.cycle = 0
        self.force_full = True
        self.hashes = HashCache()
        self.sampler = ConnectionSampler()
        self.ctx = ssl.create_default_context(cafile=cafile) if cafile else None
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}

    # -------------------------------------------------------------- http
    def _request(self, path: str, body: dict, auth: bool = True) -> dict:
        data = json.dumps(body, default=str).encode()
        req = urllib.request.Request(self.server + path, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": f"th-agent/{VERSION}"})
        if auth:
            req.add_header("Authorization", f"Bearer {self.state['token']}")
            req.add_header("X-Agent-Id", self.state["agent_id"])
        with urllib.request.urlopen(req, timeout=60, context=self.ctx) as resp:
            return json.loads(resp.read() or b"{}")

    def enroll(self) -> None:
        body = {"enroll_key": self.enroll_key, "hostname": socket.gethostname(), "os": platform.system(),
                "os_version": platform.release(), "arch": platform.machine(), "ip": primary_ip(self.server),
                "agent_version": VERSION}
        resp = self._request("/api/agent/enroll", body, auth=False)
        self.state = {"agent_id": resp["agent_id"], "token": resp["token"]}
        self.state_file.write_text(json.dumps(self.state))
        try:
            os.chmod(self.state_file, 0o600)
        except OSError:
            pass
        log(f"Enrolado como {self.state['agent_id']}")

    # -------------------------------------------------------------- ciclo
    def collect(self) -> dict:
        payload = {
            "agent_version": VERSION, "interval": self.interval,
            "host": collect_host(self.server),
            "processes": collect_processes(self.hashes),
            "connection_events": self.sampler.drain(),
            "listeners": collect_listeners(),
            "users": collect_users(),
        }
        if self.force_full or self.cycle % self.persistence_every == 0:
            payload["persistence"] = collect_persistence()
            self.force_full = False
        return payload

    def run_task(self, task: dict) -> None:
        module, params = task.get("module"), task.get("params") or {}
        handlers = {
            "process_tree": task_process_tree, "hash_file": task_hash_file, "scan_file": task_scan_file,
            "list_dir": task_list_dir, "connections": task_connections,
        }
        try:
            if module == "snapshot":
                self.force_full = True
                result, status = {"scheduled": True}, "ok"
            elif module == "hunt_mode":
                self.interval = max(5, int(params.get("interval", 15)))
                self.hunt_mode_until = time.time() + int(params.get("duration", 600))
                result, status = {"interval": self.interval, "until": self.hunt_mode_until}, "ok"
            elif module in handlers:
                result, status = handlers[module](params), "ok"
            else:
                result, status = {"error": f"módulo no permitido: {module}"}, "error"
        except Exception as exc:
            result, status = {"error": f"{type(exc).__name__}: {exc}"}, "error"
        log(f"Tarea {task.get('id')} {module} -> {status}")
        try:
            self._request(f"/api/agent/tasks/{task['id']}/result", {"status": status, "result": result})
        except (urllib.error.URLError, OSError) as exc:
            log(f"No se pudo enviar resultado de tarea: {exc}")

    def run(self, once: bool = False) -> None:
        self.sampler.sample()  # línea base de conexiones existentes
        self.sampler.drain()
        self.sampler.start()
        backoff = 5
        while True:
            if not self.state.get("token"):
                try:
                    self.enroll()
                except (urllib.error.URLError, OSError, KeyError) as exc:
                    log(f"Enrolamiento fallido: {exc}; reintento en {backoff}s")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 300)
                    continue
            if self.hunt_mode_until and time.time() > self.hunt_mode_until:
                self.interval, self.hunt_mode_until = self.base_interval, 0.0
                log("Fin del modo caza")
            payload = self.collect()
            try:
                resp = self._request("/api/agent/checkin", payload)
                backoff = 5
                self.cycle += 1
                log(f"Check-in OK: {len(payload['processes'])} procesos, {len(payload['connection_events'])} conexiones"
                    f", hallazgos nuevos {resp.get('new_findings', 0)}, tareas {len(resp.get('tasks', []))}")
                for task in resp.get("tasks", []):
                    self.run_task(task)
                if self.force_full:  # una tarea pidió snapshot: recolectar ya
                    continue
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    log("Token rechazado: re-enrolando")
                    self.state = {}
                else:
                    log(f"Error HTTP {exc.code}")
                self.sampler.requeue(payload["connection_events"])
            except (urllib.error.URLError, OSError) as exc:
                log(f"Servidor no disponible: {exc}")
                self.sampler.requeue(payload["connection_events"])
            if once:
                return
            time.sleep(self.interval + random.uniform(0, self.interval * 0.1))


def main():
    ap = argparse.ArgumentParser(description="Agente de Threat Hunting")
    ap.add_argument("--server", default=os.environ.get("THL_SERVER", "http://127.0.0.1:8000"))
    ap.add_argument("--enroll-key", default=os.environ.get("THL_ENROLL_KEY", "change-me-enroll-key"))
    ap.add_argument("--interval", type=int, default=int(os.environ.get("THL_INTERVAL", 60)),
                    help="segundos entre envíos de telemetría")
    ap.add_argument("--persistence-every", type=int, default=10, help="recolectar persistencia cada N ciclos")
    ap.add_argument("--state-file", default=os.environ.get("THL_STATE", "agent_state.json"))
    ap.add_argument("--ca", help="certificado CA para HTTPS con CA propia")
    ap.add_argument("--once", action="store_true", help="un único ciclo (pruebas)")
    args = ap.parse_args()
    agent = Agent(args.server, args.enroll_key, args.interval, args.state_file, args.persistence_every, args.ca)
    log(f"Agente {VERSION} -> {agent.server} (intervalo {args.interval}s)")
    try:
        agent.run(once=args.once)
    except KeyboardInterrupt:
        log("Detenido")


if __name__ == "__main__":
    main()
