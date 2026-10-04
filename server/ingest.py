"""Ingesta de telemetría enviada por los agentes + detección en tiempo real."""
import json
import time

from . import detections as det
from .db import Database
from .responder import auto_respond, update_risk

MAX_PROCESSES = 5000
MAX_CONN_EVENTS = 20000


def _clip(s, n=4096):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def ingest(db: Database, agent_id: str, payload: dict) -> dict:
    now = time.time()
    findings: list[dict] = []
    iocs = db.query("SELECT * FROM iocs")

    host = payload.get("host") or {}
    if host:
        db.set_state(agent_id, "host", host)
        db.execute("UPDATE agents SET ip=COALESCE(?, ip), os_version=COALESCE(?, os_version) WHERE id=?",
                   (host.get("ip"), host.get("os_version"), agent_id))

    # -- procesos ----------------------------------------------------------
    procs = payload.get("processes")
    if isinstance(procs, list):
        procs = procs[:MAX_PROCESSES]
        by_pid = {p.get("pid"): p for p in procs}
        live = []
        for p in procs:
            parent = by_pid.get(p.get("ppid")) or {}
            p["parent_name"] = p.get("parent_name") or parent.get("name")
            p["parent_exe"] = p.get("parent_exe") or parent.get("exe")
            p["cmdline"] = _clip(p.get("cmdline"))
            p["create_time"] = p.get("create_time") or 0.0
            cur = db.execute(
                "INSERT OR IGNORE INTO processes(agent_id, pid, ppid, name, exe, cmdline, username, parent_name,"
                " parent_exe, sha256, create_time, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (agent_id, p.get("pid"), p.get("ppid"), p.get("name"), p.get("exe"), p.get("cmdline"),
                 p.get("username"), p.get("parent_name"), p.get("parent_exe"), p.get("sha256"),
                 p.get("create_time"), now, now),
            )
            if cur.rowcount:  # proceso nuevo -> reglas
                findings += det.evaluate("process", agent_id, p)
                findings += det.ioc_findings(iocs, "process", agent_id, p)
            else:
                live.append((now, p.get("sha256"), agent_id, p.get("pid"), p.get("create_time")))
            if live and len(live) >= 500:
                _touch(db, live)
                live = []
        _touch(db, live)
        db.set_state(agent_id, "processes", procs)

    # -- eventos de red ----------------------------------------------------
    conns = payload.get("connection_events")
    if isinstance(conns, list):
        rows = []
        for c in conns[:MAX_CONN_EVENTS]:
            if not c.get("raddr"):
                continue
            c.setdefault("ts", now)
            rows.append((agent_id, c["ts"], c.get("pid"), c.get("process_name"), c.get("laddr"), c.get("lport"),
                         c.get("raddr"), c.get("rport"), c.get("proto", "tcp"), c.get("status")))
            findings += det.evaluate("network", agent_id, c)
            findings += det.ioc_findings(iocs, "network", agent_id, c)
        if rows:
            db.executemany(
                "INSERT INTO net_events(agent_id, ts, pid, process_name, laddr, lport, raddr, rport, proto, status)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)", rows)

    # -- puertos en escucha (con línea base) -------------------------------
    listeners = payload.get("listeners")
    if isinstance(listeners, list):
        baseline = db.get_state(agent_id, "listeners_baseline")
        current = {f"{l.get('proto', 'tcp')}/{l.get('port')}": l for l in listeners}
        if baseline is None:
            db.set_state(agent_id, "listeners_baseline", sorted(current))
        else:
            for key, l in current.items():
                if key not in baseline:
                    rule = det.DRIFT_RULES["TH-L100"]
                    findings.append(det.make_finding(rule, agent_id, {"listener": l},
                                                     det.short_hash(key, l.get("process_name"))))
            db.set_state(agent_id, "listeners_baseline", sorted(set(baseline) | set(current)))
        for l in listeners:
            findings += det.evaluate("listener", agent_id, l)
        db.set_state(agent_id, "listeners", listeners)

    if isinstance(payload.get("users"), list):
        db.set_state(agent_id, "users", payload["users"])

    # -- persistencia (con línea base) -------------------------------------
    persist = payload.get("persistence")
    if isinstance(persist, list):
        first_time = not db.scalar("SELECT COUNT(*) FROM persistence WHERE agent_id=?", (agent_id,))
        for e in persist:
            value = _clip(e.get("value"), 2048) or ""
            location = e.get("location") or "?"
            cur = db.execute(
                "INSERT OR IGNORE INTO persistence(agent_id, kind, location, value, first_seen, last_seen, baseline)"
                " VALUES (?,?,?,?,?,?,?)",
                (agent_id, e.get("kind", "other"), location, value, now, now, 1 if first_time else 0))
            if cur.rowcount:
                e = {**e, "value": value, "location": location}
                findings += det.evaluate("persistence", agent_id, e)
                if not first_time:
                    rule = det.DRIFT_RULES["TH-S100"]
                    findings.append(det.make_finding(
                        rule, agent_id, {"kind": e.get("kind"), "location": location, "value": value},
                        det.short_hash(location, value),
                        technique=det.PERSISTENCE_TECHNIQUE.get(e.get("kind"), rule.technique)))
            else:
                db.execute("UPDATE persistence SET last_seen=? WHERE agent_id=? AND location=? AND value=?",
                           (now, agent_id, location, value))

    new_ids = []
    for f in findings:
        fid, is_new = db.upsert_finding(f)
        if is_new:
            new_ids.append(fid)
            auto_respond(db, fid)
    if findings:
        update_risk(db, agent_id)
    return {"findings": len(findings), "new_findings": len(new_ids)}


def _touch(db: Database, rows):
    if rows:
        db.executemany(
            "UPDATE processes SET last_seen=?, sha256=COALESCE(?, sha256) WHERE agent_id=? AND pid=? AND create_time IS ?",
            rows)


def task_result(db: Database, agent_id: str, task_id: int, status: str, result) -> bool:
    task = db.one("SELECT * FROM tasks WHERE id=? AND agent_id=?", (task_id, agent_id))
    if not task:
        return False
    db.execute("UPDATE tasks SET status=?, result=?, completed_at=? WHERE id=?",
               ("done" if status == "ok" else "error", json.dumps(result, default=str)[:500_000], time.time(), task_id))
    # Los resultados de tareas también alimentan la detección (p. ej. scan_file)
    if status == "ok" and isinstance(result, dict):
        from .responder import analyze_task_result
        analyze_task_result(db, task, result)
    return True
