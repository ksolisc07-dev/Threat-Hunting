"""Motor de caza autónomo.

Corre periódicamente sobre toda la telemetría de la flota y prueba un conjunto
de hipótesis de caza (analítica estadística y de comportamiento que no se
puede hacer evento a evento). Cada hallazgo nuevo de severidad alta dispara la
respuesta autónoma (tareas de recolección forense en el agente), cuyos
resultados vuelven a alimentar la detección.
"""
import json
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from . import config
from . import detections as det
from .db import Database
from .responder import auto_respond, update_risk


@dataclass
class Hypothesis:
    id: str
    title: str
    hypothesis: str
    tactic: str
    technique: str
    severity: str
    run: Callable[[Database, "Hypothesis"], list[dict]]

    def rule(self) -> det.Rule:
        return det.Rule(self.id, self.title, self.hypothesis, self.severity, self.tactic,
                        self.technique, "hunt", lambda x: None)

    def meta(self) -> dict:
        return {k: getattr(self, k) for k in ("id", "title", "hypothesis", "tactic", "technique", "severity")}


def _finding(h: Hypothesis, agent_id, evidence, key, severity=None, title=None, technique=None):
    return det.make_finding(h.rule(), agent_id, evidence, key, source="hunt",
                            severity=severity, title=title, technique=technique)


# ---------------------------------------------------------------------------
# H-01  Beaconing C2: conexiones a un mismo destino a intervalos regulares
# ---------------------------------------------------------------------------
def hunt_beaconing(db: Database, h: Hypothesis) -> list[dict]:
    since = time.time() - 6 * 3600
    rows = db.query(
        "SELECT agent_id, raddr, rport, ts, process_name, pid FROM net_events WHERE ts > ? "
        "ORDER BY agent_id, raddr, rport, ts", (since,))
    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        groups[(r["agent_id"], r["raddr"], r["rport"])].append(r)

    out = []
    for (agent_id, raddr, rport), evs in groups.items():
        if not det.is_public_ip(raddr) or len(evs) < 6:
            continue
        ts = []
        for e in evs:  # colapsa ráfagas (< 1 s) en una sola conexión
            if not ts or e["ts"] - ts[-1] >= 1:
                ts.append(e["ts"])
        if len(ts) < 6:
            continue
        deltas = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(deltas)
        if not 5 <= mean <= 3600:
            continue
        # robusto frente a huecos: usa la mediana y la desviación absoluta mediana
        med = statistics.median(deltas)
        mad = statistics.median([abs(d - med) for d in deltas])
        jitter = mad / med if med else 1
        regular = sum(1 for d in deltas if abs(d - med) <= max(2, 0.2 * med)) / len(deltas)
        if jitter <= 0.2 and regular >= 0.7:
            score = round(regular * (1 - jitter), 2)
            procs = sorted({e["process_name"] for e in evs if e["process_name"]})
            sev = "critical" if score >= 0.9 and len(ts) >= 20 else "high"
            out.append(_finding(h, agent_id, {
                "raddr": raddr, "rport": rport, "connections": len(ts), "interval_s": round(med, 1),
                "jitter": round(jitter, 3), "regularity": round(regular, 2), "beacon_score": score,
                "processes": procs, "pid": evs[-1]["pid"],
            }, det.short_hash(raddr, rport), severity=sev,
                title=f"Beaconing hacia {raddr}:{rport} cada ~{med:.0f}s"))
    return out


# ---------------------------------------------------------------------------
# H-02  Binarios raros en la flota (stack counting / long tail)
# ---------------------------------------------------------------------------
COMMON_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib", "c:\\windows\\", "c:\\program files", "/system/", "/applications/")


def hunt_rare_binaries(db: Database, h: Hypothesis) -> list[dict]:
    n_agents = db.scalar("SELECT COUNT(*) FROM agents")
    if n_agents < 3:
        return []
    rows = db.query(
        "SELECT COALESCE(sha256, lower(exe)) AS k, COUNT(DISTINCT agent_id) AS hosts, MIN(agent_id) AS agent_id,"
        " MIN(exe) AS exe, MIN(name) AS name, MIN(pid) AS pid, MIN(cmdline) AS cmdline, MIN(sha256) AS sha256,"
        " COUNT(*) AS n FROM processes WHERE last_seen > ? AND exe IS NOT NULL AND exe != ''"
        " GROUP BY k HAVING hosts = 1", (time.time() - 86400,))
    out = []
    for r in rows:
        exe = (r["exe"] or "").lower()
        if exe.startswith(COMMON_DIRS):
            continue
        out.append(_finding(h, r["agent_id"], {
            "exe": r["exe"], "name": r["name"], "sha256": r["sha256"], "pid": r["pid"],
            "cmdline": r["cmdline"], "fleet_hosts": 1, "fleet_size": n_agents, "executions": r["n"],
        }, det.short_hash(r["k"]), title=f"Binario único en la flota: {r['name']}"))
    return out


# ---------------------------------------------------------------------------
# H-03  Ráfaga de reconocimiento interno
# ---------------------------------------------------------------------------
def hunt_discovery_burst(db: Database, h: Hypothesis) -> list[dict]:
    rows = db.query("SELECT agent_id, first_seen, cmdline, name, username FROM processes WHERE first_seen > ?"
                    " ORDER BY agent_id, first_seen", (time.time() - 6 * 3600,))
    per_agent: dict[str, list] = defaultdict(list)
    for r in rows:
        m = det.DISCOVERY_CMDS.search(r["cmdline"] or r["name"] or "")
        if m:
            per_agent[r["agent_id"]].append((r["first_seen"], m.group(0).strip().lower(), r))
    out = []
    window = 15 * 60
    for agent_id, evs in per_agent.items():
        best: list = []
        j = 0
        for i in range(len(evs)):
            while evs[i][0] - evs[j][0] > window:
                j += 1
            win = evs[j:i + 1]
            if len({e[1] for e in win}) > len({e[1] for e in best}):
                best = win
        distinct = sorted({e[1] for e in best})
        if len(distinct) >= 4:
            out.append(_finding(h, agent_id, {
                "commands": distinct, "count": len(best),
                "users": sorted({e[2]["username"] for e in best if e[2]["username"]}),
                "window_start": best[0][0],
            }, det.short_hash(int(best[0][0] // window)),
                severity="high" if len(distinct) >= 7 else "medium"))
    return out


# ---------------------------------------------------------------------------
# H-04  Movimiento lateral / escaneo: un proceso contacta muchos hosts internos
# ---------------------------------------------------------------------------
LATERAL_PORTS = {22, 135, 139, 445, 3389, 5985, 5986, 1433, 3306, 5432}


def hunt_lateral(db: Database, h: Hypothesis) -> list[dict]:
    rows = db.query(
        "SELECT agent_id, process_name, rport, COUNT(DISTINCT raddr) AS targets, MIN(pid) AS pid,"
        " GROUP_CONCAT(DISTINCT raddr) AS addrs FROM net_events WHERE ts > ?"
        " GROUP BY agent_id, process_name, rport HAVING targets >= 8", (time.time() - 3600,))
    out = []
    for r in rows:
        addrs = (r["addrs"] or "").split(",")
        internal = [a for a in addrs if a and not det.is_public_ip(a)]
        if len(internal) < 8:
            continue
        lateral = r["rport"] in LATERAL_PORTS
        out.append(_finding(h, r["agent_id"], {
            "process_name": r["process_name"], "pid": r["pid"], "rport": r["rport"],
            "internal_targets": len(internal), "sample": internal[:15],
        }, det.short_hash(r["process_name"], r["rport"]),
            severity="high" if lateral else "medium",
            technique="T1021" if lateral else "T1046",
            title=(f"Posible movimiento lateral: {r['process_name']} → {len(internal)} hosts:{r['rport']}"
                   if lateral else f"Escaneo interno: {r['process_name']} → {len(internal)} hosts:{r['rport']}")))
    return out


# ---------------------------------------------------------------------------
# H-05  Parentesco raro: intérprete con un padre que nunca se ve en la flota
# ---------------------------------------------------------------------------
def hunt_rare_lineage(db: Database, h: Hypothesis) -> list[dict]:
    if db.scalar("SELECT COUNT(*) FROM agents") < 3:  # sin flota no hay base estadística
        return []
    interpreters = tuple(sorted(det.SHELLS))
    marks = ",".join("?" * len(interpreters))
    rows = db.query(
        f"SELECT lower(parent_name) AS parent, lower(name) AS child, COUNT(*) AS n,"
        f" COUNT(DISTINCT agent_id) AS hosts, MIN(agent_id) AS agent_id, MIN(cmdline) AS cmdline, MIN(pid) AS pid"
        f" FROM processes WHERE first_seen > ? AND lower(name) IN ({marks}) AND parent_name IS NOT NULL"
        f" GROUP BY parent, child HAVING n <= 2 AND hosts = 1",
        (time.time() - 86400, *interpreters))
    total_pairs = db.scalar("SELECT COUNT(DISTINCT lower(parent_name)||'>'||lower(name)) FROM processes")
    if (total_pairs or 0) < 30:  # poca historia todavía: no hay base estadística
        return []
    benign_parents = {"bash", "sh", "zsh", "sshd", "login", "explorer.exe", "cmd.exe", "tmux: server", "screen",
                      "systemd", "init", "su", "sudo", "code", "conhost.exe", "windowsterminal.exe", "cron"}
    return [
        _finding(h, r["agent_id"], {"parent_name": r["parent"], "name": r["child"], "cmdline": r["cmdline"],
                                    "pid": r["pid"], "occurrences": r["n"]},
                 det.short_hash(r["parent"], r["child"]),
                 title=f"Linaje inusual: {r['parent']} → {r['child']}")
        for r in rows if r["parent"] not in benign_parents
    ]


# ---------------------------------------------------------------------------
# H-06  Caza retrospectiva de IOCs sobre toda la retención
# ---------------------------------------------------------------------------
def hunt_ioc_retro(db: Database, h: Hypothesis) -> list[dict]:
    iocs = db.query("SELECT * FROM iocs")
    if not iocs:
        return []
    out = []
    ips = [i["value"] for i in iocs if i["type"] == "ip"]
    if ips:
        marks = ",".join("?" * len(ips))
        for c in db.query(f"SELECT * FROM net_events WHERE raddr IN ({marks}) GROUP BY agent_id, raddr, rport", ips):
            out += det.ioc_findings(iocs, "network", c["agent_id"], c, source="hunt")
    for ioc in iocs:
        if ioc["type"] == "sha256":
            procs = db.query("SELECT * FROM processes WHERE lower(sha256)=lower(?) GROUP BY agent_id", (ioc["value"],))
        elif ioc["type"] == "process":
            procs = db.query("SELECT * FROM processes WHERE lower(name)=lower(?) GROUP BY agent_id", (ioc["value"],))
        elif ioc["type"] in ("cmdline", "domain"):
            procs = db.query("SELECT * FROM processes WHERE instr(lower(cmdline), lower(?)) > 0 GROUP BY agent_id",
                             (ioc["value"],))
        else:
            procs = []
        for p in procs:
            out += det.ioc_findings([ioc], "process", p["agent_id"], p, source="hunt")
    return out


# ---------------------------------------------------------------------------
# H-07  Agente silenciado tras actividad sospechosa (evasión de defensas)
# ---------------------------------------------------------------------------
def hunt_silenced_agents(db: Database, h: Hypothesis) -> list[dict]:
    cutoff = time.time() - config.AGENT_OFFLINE_AFTER
    rows = db.query(
        "SELECT a.id, a.hostname, a.last_seen, COUNT(f.id) AS open_high FROM agents a JOIN findings f"
        " ON f.agent_id=a.id AND f.status IN ('new','investigating') AND f.severity IN ('high','critical')"
        " AND f.created_at > ? WHERE a.last_seen < ? GROUP BY a.id", (time.time() - 86400, cutoff))
    return [_finding(h, r["id"], {"hostname": r["hostname"], "last_seen": r["last_seen"],
                                  "open_high_findings": r["open_high"]},
                     det.short_hash(int(r["last_seen"])))
            for r in rows]


# ---------------------------------------------------------------------------
# H-08  Correlación de cadena de ataque (kill chain) por host
# ---------------------------------------------------------------------------
def hunt_kill_chain(db: Database, h: Hypothesis) -> list[dict]:
    rows = db.query(
        "SELECT agent_id, tactic, rule_id, title, severity, id FROM findings WHERE created_at > ?"
        " AND status IN ('new','investigating') AND rule_id != ? AND agent_id IS NOT NULL",
        (time.time() - 86400, h.id))
    per_agent: dict[str, list] = defaultdict(list)
    for r in rows:
        per_agent[r["agent_id"]].append(r)
    out = []
    order = {t: i for i, t in enumerate(det.TACTICS)}
    for agent_id, fs in per_agent.items():
        tactics = sorted({f["tactic"] for f in fs if f["tactic"]}, key=lambda t: order.get(t, 99))
        if len(tactics) < 3:
            continue
        high = sum(1 for f in fs if f["severity"] in ("high", "critical"))
        out.append(_finding(h, agent_id, {
            "tactics": tactics, "findings": len(fs), "high_or_critical": high,
            "chain": [{"id": f["id"], "rule": f["rule_id"], "title": f["title"], "tactic": f["tactic"]}
                      for f in sorted(fs, key=lambda f: order.get(f["tactic"], 99))][:25],
        }, time.strftime("%Y%m%d"), severity="critical" if len(tactics) >= 4 or high >= 3 else "high",
            title=f"Cadena de ataque: {len(tactics)} tácticas ATT&CK en el mismo host"))
    return out


HYPOTHESES: list[Hypothesis] = [
    Hypothesis("TH-H001", "Beaconing de C2", "Un implante contacta su C2 a intervalos regulares: buscamos series de conexiones "
               "a un mismo destino público con baja variación (jitter) entre intervalos.",
               "Command and Control", "T1071", "high", hunt_beaconing),
    Hypothesis("TH-H002", "Binarios raros (stack counting)", "Lo malicioso suele estar en la cola larga: binarios que solo "
               "existen en un host de la flota y fuera de rutas del sistema.",
               "Execution", "T1204", "low", hunt_rare_binaries),
    Hypothesis("TH-H003", "Ráfaga de reconocimiento", "Tras el acceso inicial el atacante enumera el entorno: varios comandos "
               "de descubrimiento distintos en una ventana de 15 minutos.",
               "Discovery", "T1082", "medium", hunt_discovery_burst),
    Hypothesis("TH-H004", "Movimiento lateral / escaneo interno", "Un proceso que contacta muchos hosts internos en poco "
               "tiempo, especialmente en SMB/RDP/WinRM/SSH.",
               "Lateral Movement", "T1021", "high", hunt_lateral),
    Hypothesis("TH-H005", "Linaje de procesos inusual", "Intérpretes lanzados por padres que nunca se observan en el resto "
               "de la flota.", "Execution", "T1059", "low", hunt_rare_lineage),
    Hypothesis("TH-H006", "Caza retrospectiva de IOCs", "Cuando llega inteligencia nueva, reaplicarla a toda la telemetría "
               "histórica retenida.", "Command and Control", "T1588", "high", hunt_ioc_retro),
    Hypothesis("TH-H007", "Agente silenciado", "Un agente deja de reportar justo después de generar hallazgos graves: "
               "posible manipulación de la defensa.", "Defense Evasion", "T1562.001", "high", hunt_silenced_agents),
    Hypothesis("TH-H008", "Correlación de cadena de ataque", "Hallazgos de 3+ tácticas ATT&CK distintas en el mismo host "
               "en 24h indican una intrusión en progreso, no ruido aislado.",
               "Impact", "TA0040", "critical", hunt_kill_chain),
]
for _h in HYPOTHESES:
    det.RULES_BY_ID[_h.id] = _h.rule()


def run_hunt(db: Database, trigger: str = "auto") -> dict:
    started = time.time()
    hunt_id = db.execute("INSERT INTO hunts(trigger, started_at) VALUES (?,?)", (trigger, started)).lastrowid
    summary, new_total, tasks_total = [], 0, 0
    touched_agents = set()
    for h in HYPOTHESES:
        t0 = time.time()
        try:
            found = h.run(db, h)
            error = None
        except Exception as exc:  # una hipótesis rota no detiene la caza
            found, error = [], f"{type(exc).__name__}: {exc}"
        new = 0
        for f in found:
            f["hunt_id"] = hunt_id
            fid, is_new = db.upsert_finding(f)
            touched_agents.add(f.get("agent_id"))
            if is_new:
                new += 1
                tasks_total += auto_respond(db, fid)
        new_total += new
        summary.append({"id": h.id, "title": h.title, "matches": len(found), "new": new,
                        "ms": round((time.time() - t0) * 1000, 1), "error": error})
    for a in db.query("SELECT id FROM agents"):
        update_risk(db, a["id"])
    db.purge(config.RETENTION_DAYS)
    db.execute("UPDATE hunts SET finished_at=?, findings=?, tasks=?, summary=? WHERE id=?",
               (time.time(), new_total, tasks_total, json.dumps(summary), hunt_id))
    return {"hunt_id": hunt_id, "new_findings": new_total, "tasks": tasks_total, "summary": summary}
