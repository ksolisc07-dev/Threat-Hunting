"""API y panel web de la plataforma de Threat Hunting.

Arranque:  uvicorn server.main:app --host 0.0.0.0 --port 8000
"""
import asyncio
import contextlib
import hashlib
import hmac
import json
import secrets
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config
from . import detections as det
from .db import Database
from .hunter import HYPOTHESES, run_hunt
from .ingest import ingest, task_result
from .query import QueryError, compile_query
from .responder import ALLOWED_MODULES, auto_respond, update_risk

STATIC = Path(__file__).parent / "static"
AGENT_VERSION_MIN = "1.0"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_app(db_path: str | None = None, start_hunter: bool = True) -> FastAPI:
    db = Database(db_path or config.DB_PATH)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        task = None
        if config.ADMIN_TOKEN_GENERATED:
            print(f"\n[threat-hunting] Token de administrador generado: {config.ADMIN_TOKEN}\n", flush=True)
        if start_hunter:
            task = asyncio.create_task(_hunter_loop())
        yield
        if task:
            task.cancel()

    async def _hunter_loop():
        await asyncio.sleep(5)
        while True:
            try:
                await asyncio.to_thread(run_hunt, db, "auto")
            except Exception as exc:  # el bucle autónomo nunca debe morir
                print(f"[hunter] error: {exc}", flush=True)
            await asyncio.sleep(config.HUNT_INTERVAL)

    app = FastAPI(title="Threat Hunting Platform", version="1.0", lifespan=lifespan)
    app.state.db = db

    # ------------------------------------------------------------------ auth
    def require_admin(authorization: str = Header(default="")) -> None:
        token = authorization.removeprefix("Bearer ").strip()
        if not token or not hmac.compare_digest(token, config.ADMIN_TOKEN):
            raise HTTPException(401, "Token de analista inválido")

    def require_agent(authorization: str = Header(default=""), x_agent_id: str = Header(default="")) -> dict:
        token = authorization.removeprefix("Bearer ").strip()
        agent = db.one("SELECT * FROM agents WHERE id=?", (x_agent_id,))
        if not agent or not token or not hmac.compare_digest(agent["token_hash"], _hash(token)):
            raise HTTPException(401, "Agente no autenticado")
        return agent

    admin = [Depends(require_admin)]

    # ------------------------------------------------------------ agente API
    class Enroll(BaseModel):
        enroll_key: str
        hostname: str = Field(max_length=255)
        os: str = ""
        os_version: str = ""
        arch: str = ""
        ip: str = ""
        agent_version: str = ""

    @app.post("/api/agent/enroll")
    def enroll(body: Enroll, request: Request):
        if not hmac.compare_digest(body.enroll_key, config.ENROLL_KEY):
            raise HTTPException(403, "Clave de enrolamiento inválida")
        agent_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        now = time.time()
        db.execute(
            "INSERT INTO agents(id, hostname, os, os_version, arch, ip, agent_version, token_hash, enrolled_at, last_seen)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (agent_id, body.hostname, body.os, body.os_version, body.arch,
             body.ip or (request.client.host if request.client else ""), body.agent_version, _hash(token), now, now))
        return {"agent_id": agent_id, "token": token, "interval": 60}

    @app.post("/api/agent/checkin")
    async def checkin(request: Request, agent: dict = Depends(require_agent)):
        try:
            payload = await request.json()
        except json.JSONDecodeError:
            raise HTTPException(400, "JSON inválido")
        if not isinstance(payload, dict):
            raise HTTPException(400, "Se esperaba un objeto JSON")
        now = time.time()
        db.execute("UPDATE agents SET last_seen=?, agent_version=COALESCE(?, agent_version), interval=COALESCE(?, interval)"
                   " WHERE id=?", (now, payload.get("agent_version"), payload.get("interval"), agent["id"]))
        stats = await asyncio.to_thread(ingest, db, agent["id"], payload)
        tasks = db.query("SELECT id, module, params FROM tasks WHERE agent_id=? AND status='pending' ORDER BY id LIMIT 20",
                         (agent["id"],))
        if tasks:
            db.executemany("UPDATE tasks SET status='sent', sent_at=? WHERE id=?", [(now, t["id"]) for t in tasks])
        return {"ok": True, **stats,
                "tasks": [{"id": t["id"], "module": t["module"], "params": json.loads(t["params"])} for t in tasks]}

    class TaskResult(BaseModel):
        status: str = "ok"
        result: dict | list | str | None = None

    @app.post("/api/agent/tasks/{task_id}/result")
    def agent_task_result(task_id: int, body: TaskResult, agent: dict = Depends(require_agent)):
        if not task_result(db, agent["id"], task_id, body.status, body.result):
            raise HTTPException(404, "Tarea no encontrada")
        return {"ok": True}

    # -------------------------------------------------------- analista API
    def _agent_status(a: dict) -> dict:
        a = dict(a)
        a.pop("token_hash", None)
        a["online"] = bool(a.get("last_seen") and time.time() - a["last_seen"] < max(config.AGENT_OFFLINE_AFTER,
                                                                                     3 * (a.get("interval") or 60)))
        a["tags"] = json.loads(a.get("tags") or "[]")
        return a

    def _finding_out(f: dict) -> dict:
        f = dict(f)
        f["evidence"] = json.loads(f.get("evidence") or "{}")
        return f

    @app.get("/api/overview", dependencies=admin)
    def overview():
        now = time.time()
        agents = [_agent_status(a) for a in db.query("SELECT * FROM agents")]
        sev = {r["severity"]: r["n"] for r in db.query(
            "SELECT severity, COUNT(*) n FROM findings WHERE status IN ('new','investigating') GROUP BY severity")}
        # serie temporal de 24h por hora y severidad
        start = int(now // 3600 * 3600) - 23 * 3600
        series = {h: {s: 0 for s in det.SEVERITY_ORDER} for h in range(start, start + 24 * 3600, 3600)}
        for r in db.query("SELECT CAST(created_at/3600 AS INT)*3600 AS h, severity, COUNT(*) n FROM findings"
                          " WHERE created_at >= ? GROUP BY h, severity", (start,)):
            if r["h"] in series:
                series[r["h"]][r["severity"]] = r["n"]
        tactics = {r["tactic"]: r["n"] for r in db.query(
            "SELECT tactic, COUNT(*) n FROM findings WHERE status IN ('new','investigating') GROUP BY tactic")}
        last_hunt = db.one("SELECT * FROM hunts WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1")
        if last_hunt:
            last_hunt["summary"] = json.loads(last_hunt["summary"] or "[]")
        return {
            "agents_total": len(agents), "agents_online": sum(a["online"] for a in agents),
            "open_findings": sum(sev.values()), "by_severity": sev,
            "auto_tasks_24h": db.scalar("SELECT COUNT(*) FROM tasks WHERE created_by='hunter' AND created_at>?",
                                        (now - 86400,)),
            "events_24h": db.scalar("SELECT COUNT(*) FROM net_events WHERE ts>?", (now - 86400,))
                          + db.scalar("SELECT COUNT(*) FROM processes WHERE first_seen>?", (now - 86400,)),
            "timeline": [{"t": h, **v} for h, v in series.items()],
            "tactics": [{"tactic": t, "count": tactics.get(t, 0)} for t in det.TACTICS],
            "top_hosts": sorted(agents, key=lambda a: -a["risk_score"])[:8],
            "recent_findings": [_finding_out(f) for f in db.query(
                "SELECT f.*, a.hostname FROM findings f LEFT JOIN agents a ON a.id=f.agent_id"
                " ORDER BY f.updated_at DESC LIMIT 12")],
            "activity": db.query(
                "SELECT t.id, t.module, t.status, t.reason, t.created_at, t.completed_at, t.created_by, a.hostname"
                " FROM tasks t JOIN agents a ON a.id=t.agent_id ORDER BY t.id DESC LIMIT 12"),
            "last_hunt": last_hunt, "hunt_interval": config.HUNT_INTERVAL,
            "max_finding_id": db.scalar("SELECT COALESCE(MAX(id),0) FROM findings"),
            "server_time": now,
        }

    @app.get("/api/agents", dependencies=admin)
    def list_agents():
        counts = {r["agent_id"]: r for r in db.query(
            "SELECT agent_id, COUNT(*) open, SUM(severity='critical') critical FROM findings"
            " WHERE status IN ('new','investigating') GROUP BY agent_id")}
        out = []
        for a in db.query("SELECT * FROM agents ORDER BY risk_score DESC, hostname"):
            a = _agent_status(a)
            c = counts.get(a["id"]) or {}
            a["open_findings"], a["critical_findings"] = c.get("open", 0), c.get("critical", 0) or 0
            out.append(a)
        return out

    def _get_agent(agent_id: str) -> dict:
        a = db.one("SELECT * FROM agents WHERE id=?", (agent_id,))
        if not a:
            raise HTTPException(404, "Agente no encontrado")
        return _agent_status(a)

    @app.get("/api/agents/{agent_id}", dependencies=admin)
    def agent_detail(agent_id: str):
        a = _get_agent(agent_id)
        a["host"] = db.get_state(agent_id, "host", {})
        a["processes"] = db.get_state(agent_id, "processes", [])
        a["listeners"] = db.get_state(agent_id, "listeners", [])
        a["users"] = db.get_state(agent_id, "users", [])
        return a

    @app.get("/api/agents/{agent_id}/connections", dependencies=admin)
    def agent_connections(agent_id: str, limit: int = 300):
        _get_agent(agent_id)
        return db.query("SELECT * FROM net_events WHERE agent_id=? ORDER BY ts DESC LIMIT ?",
                        (agent_id, min(limit, 5000)))

    @app.get("/api/agents/{agent_id}/destinations", dependencies=admin)
    def agent_destinations(agent_id: str):
        _get_agent(agent_id)
        return db.query(
            "SELECT raddr, rport, COUNT(*) n, MIN(ts) first, MAX(ts) last, GROUP_CONCAT(DISTINCT process_name) procs"
            " FROM net_events WHERE agent_id=? GROUP BY raddr, rport ORDER BY n DESC LIMIT 200", (agent_id,))

    @app.get("/api/agents/{agent_id}/persistence", dependencies=admin)
    def agent_persistence(agent_id: str):
        _get_agent(agent_id)
        return db.query("SELECT * FROM persistence WHERE agent_id=? ORDER BY baseline, first_seen DESC", (agent_id,))

    @app.delete("/api/agents/{agent_id}", dependencies=admin)
    def delete_agent(agent_id: str):
        _get_agent(agent_id)
        for table in ("agent_state", "processes", "net_events", "persistence", "findings", "tasks"):
            db.execute(f"DELETE FROM {table} WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM agents WHERE id=?", (agent_id,))
        return {"ok": True}

    @app.get("/api/findings", dependencies=admin)
    def list_findings(status: str = "", severity: str = "", agent_id: str = "", q: str = "", limit: int = 300):
        where, params = [], []
        if status == "open":
            where.append("f.status IN ('new','investigating')")
        elif status:
            where.append("f.status=?")
            params.append(status)
        if severity:
            sevs = severity.split(",")
            where.append(f"f.severity IN ({','.join('?' * len(sevs))})")
            params += sevs
        if agent_id:
            where.append("f.agent_id=?")
            params.append(agent_id)
        if q:
            where.append("(f.title LIKE ? OR f.rule_id LIKE ? OR f.technique LIKE ? OR a.hostname LIKE ? OR f.evidence LIKE ?)")
            params += [f"%{q}%"] * 5
        sql = "SELECT f.*, a.hostname FROM findings f LEFT JOIN agents a ON a.id=f.agent_id"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += (" ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
                " WHEN 'low' THEN 3 ELSE 4 END, f.updated_at DESC LIMIT ?")
        params.append(min(limit, 2000))
        return [_finding_out(f) for f in db.query(sql, params)]

    @app.get("/api/findings/{fid}", dependencies=admin)
    def finding_detail(fid: int):
        f = db.one("SELECT f.*, a.hostname FROM findings f LEFT JOIN agents a ON a.id=f.agent_id WHERE f.id=?", (fid,))
        if not f:
            raise HTTPException(404, "Hallazgo no encontrado")
        f = _finding_out(f)
        f["tasks"] = [_task_out(t) for t in db.query("SELECT * FROM tasks WHERE finding_id=? ORDER BY id", (fid,))]
        rule = det.RULES_BY_ID.get(f["rule_id"])
        f["rule"] = rule.meta() if rule else None
        return f

    class FindingUpdate(BaseModel):
        status: str | None = None
        notes: str | None = None

    @app.patch("/api/findings/{fid}", dependencies=admin)
    def update_finding(fid: int, body: FindingUpdate):
        f = db.one("SELECT * FROM findings WHERE id=?", (fid,))
        if not f:
            raise HTTPException(404, "Hallazgo no encontrado")
        if body.status and body.status not in ("new", "investigating", "resolved", "false_positive"):
            raise HTTPException(400, "Estado inválido")
        db.execute("UPDATE findings SET status=COALESCE(?, status), notes=COALESCE(?, notes), updated_at=? WHERE id=?",
                   (body.status, body.notes, time.time(), fid))
        if f["agent_id"]:
            update_risk(db, f["agent_id"])
        return {"ok": True}

    @app.post("/api/findings/{fid}/respond", dependencies=admin)
    def respond_finding(fid: int):
        if not db.one("SELECT id FROM findings WHERE id=?", (fid,)):
            raise HTTPException(404, "Hallazgo no encontrado")
        return {"tasks": auto_respond(db, fid)}

    def _task_out(t: dict) -> dict:
        t = dict(t)
        t["params"] = json.loads(t.get("params") or "{}")
        t["result"] = json.loads(t["result"]) if t.get("result") else None
        return t

    @app.get("/api/tasks", dependencies=admin)
    def list_tasks(agent_id: str = "", limit: int = 200):
        sql = ("SELECT t.*, a.hostname FROM tasks t JOIN agents a ON a.id=t.agent_id"
               + (" WHERE t.agent_id=?" if agent_id else "") + " ORDER BY t.id DESC LIMIT ?")
        rows = db.query(sql, ([agent_id] if agent_id else []) + [min(limit, 1000)])
        return [_task_out(t) for t in rows]

    @app.get("/api/tasks/{tid}", dependencies=admin)
    def task_detail(tid: int):
        t = db.one("SELECT t.*, a.hostname FROM tasks t JOIN agents a ON a.id=t.agent_id WHERE t.id=?", (tid,))
        if not t:
            raise HTTPException(404, "Tarea no encontrada")
        return _task_out(t)

    class NewTask(BaseModel):
        agent_id: str
        module: str
        params: dict = {}

    @app.post("/api/tasks", dependencies=admin)
    def new_task(body: NewTask):
        _get_agent(body.agent_id)
        if body.module not in ALLOWED_MODULES:
            raise HTTPException(400, f"Módulo no permitido. Opciones: {', '.join(ALLOWED_MODULES)}")
        tid = db.create_task(body.agent_id, body.module, body.params, "Solicitado por analista", "analyst")
        if not tid:
            raise HTTPException(409, "Ya existe una tarea idéntica pendiente")
        return {"id": tid}

    @app.get("/api/modules", dependencies=admin)
    def modules():
        return ALLOWED_MODULES

    @app.get("/api/hunts", dependencies=admin)
    def hunts(limit: int = 50):
        out = db.query("SELECT * FROM hunts ORDER BY id DESC LIMIT ?", (min(limit, 500),))
        for h in out:
            h["summary"] = json.loads(h["summary"] or "[]")
        return out

    @app.post("/api/hunts/run", dependencies=admin)
    async def hunt_now():
        return await asyncio.to_thread(run_hunt, db, "manual")

    @app.get("/api/rules", dependencies=admin)
    def rules():
        hits = {r["rule_id"]: r for r in db.query(
            "SELECT rule_id, COUNT(*) n, MAX(updated_at) last FROM findings GROUP BY rule_id")}
        realtime = [{**r.meta(), "hits": hits.get(r.id, {}).get("n", 0)}
                    for r in list(det.RULES) + list(det.DRIFT_RULES.values()) + list(det.FILE_RULES.values())]
        hyps = [{**h.meta(), "hits": hits.get(h.id, {}).get("n", 0)} for h in HYPOTHESES]
        return {"realtime": realtime, "hypotheses": hyps}

    @app.get("/api/mitre", dependencies=admin)
    def mitre():
        rows = db.query(
            "SELECT tactic, technique, COUNT(*) n, MAX(score) max_score, GROUP_CONCAT(DISTINCT rule_id) rules,"
            " COUNT(DISTINCT agent_id) hosts FROM findings WHERE status != 'false_positive'"
            " GROUP BY tactic, technique")
        by_tactic = {t: [] for t in det.TACTICS}
        for r in rows:
            by_tactic.setdefault(r["tactic"] or "Other", []).append(r)
        return [{"tactic": t, "techniques": sorted(v, key=lambda r: -r["n"])} for t, v in by_tactic.items()]

    class Query(BaseModel):
        q: str = ""
        scope: str = "processes"
        limit: int = 200

    @app.post("/api/query", dependencies=admin)
    def run_query(body: Query):
        try:
            sql, params = compile_query(body.q, body.scope, body.limit)
        except QueryError as exc:
            raise HTTPException(400, str(exc))
        t0 = time.time()
        rows = db.query(sql, params)
        return {"rows": rows, "count": len(rows), "ms": round((time.time() - t0) * 1000, 1)}

    @app.get("/api/iocs", dependencies=admin)
    def list_iocs():
        return db.query("SELECT * FROM iocs ORDER BY id DESC")

    class IOC(BaseModel):
        type: str
        value: str = Field(min_length=1, max_length=1024)
        description: str = ""
        severity: str = "high"

    @app.post("/api/iocs", dependencies=admin)
    def add_iocs(items: list[IOC]):
        added = 0
        for i in items:
            if i.type not in ("ip", "domain", "sha256", "process", "cmdline"):
                raise HTTPException(400, f"Tipo de IOC inválido: {i.type}")
            if i.severity not in det.SEVERITY_SCORE:
                raise HTTPException(400, f"Severidad inválida: {i.severity}")
            cur = db.execute("INSERT OR IGNORE INTO iocs(type, value, description, severity, created_at) VALUES (?,?,?,?,?)",
                             (i.type, i.value.strip(), i.description, i.severity, time.time()))
            added += cur.rowcount
        return {"added": added}

    @app.delete("/api/iocs/{iid}", dependencies=admin)
    def delete_ioc(iid: int):
        db.execute("DELETE FROM iocs WHERE id=?", (iid,))
        return {"ok": True}

    @app.get("/api/health")
    def health():
        return {"ok": True, "time": time.time()}

    # ---------------------------------------------------------------- web
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    return app


app = create_app()
