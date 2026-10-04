"""Respuesta autónoma: el motor decide qué recolección adicional pedir al agente.

Por diseño solo se encolan módulos de la lista blanca del agente (forense de
solo lectura + ajuste de frecuencia). Nunca se ejecutan comandos arbitrarios.
"""
import json
import math
import re
import time

from . import config
from . import detections as det
from .db import Database

ALLOWED_MODULES = {
    "snapshot": "Recolección completa inmediata (incluye persistencia)",
    "process_tree": "Árbol de procesos (ancestros y descendientes) de un PID",
    "hash_file": "Hashes (SHA256/MD5), tamaño y fechas de un archivo",
    "scan_file": "Escaneo de firmas (YARA-lite) y entropía de un archivo",
    "list_dir": "Listado de un directorio",
    "connections": "Tabla de conexiones actual",
    "hunt_mode": "Aumenta temporalmente la frecuencia de recolección",
}

MAX_AUTO_TASKS_PER_HOUR = 40
PATH_RX = re.compile(r"(/(?:tmp|dev/shm|var/tmp|usr|opt|home|root|etc|bin|sbin)/[^\s'\";|&>]+|[A-Za-z]:\\[^\s'\";|&>]+)")


def auto_respond(db: Database, finding_id: int) -> int:
    """Encola tareas de recolección para enriquecer un hallazgo nuevo. Devuelve nº de tareas."""
    if not config.AUTO_RESPONSE:
        return 0
    f = db.one("SELECT * FROM findings WHERE id=?", (finding_id,))
    if not f or not f["agent_id"] or f["severity"] not in ("high", "critical"):
        return 0
    agent_id = f["agent_id"]
    recent = db.scalar("SELECT COUNT(*) FROM tasks WHERE agent_id=? AND created_by='hunter' AND created_at>?",
                       (agent_id, time.time() - 3600))
    if recent >= MAX_AUTO_TASKS_PER_HOUR:
        return 0

    ev = json.loads(f["evidence"] or "{}")
    reason = f"[{f['rule_id']}] {f['title']}"
    planned: list[tuple[str, dict]] = []

    pid = ev.get("pid")
    if pid:
        planned.append(("process_tree", {"pid": pid}))
    exe = ev.get("exe")
    if exe and not str(exe).endswith(" (deleted)"):
        planned.append(("scan_file", {"path": exe}))
    for key in ("value", "cmdline"):
        for path in PATH_RX.findall(str(ev.get(key) or ""))[:2]:
            if path != exe:
                planned.append(("scan_file", {"path": path}))
    if ev.get("raddr") or f["tactic"] == "Command and Control":
        planned.append(("connections", {}))
    if f["severity"] == "critical":
        planned.append(("hunt_mode", {"interval": 15, "duration": 600}))
        planned.append(("snapshot", {}))

    created = 0
    for module, params in planned:
        if db.create_task(agent_id, module, params, reason, "hunter", finding_id):
            created += 1
    return created


def analyze_task_result(db: Database, task: dict, result: dict) -> None:
    """Los resultados forenses pueden generar nuevos hallazgos (bucle autónomo)."""
    agent_id = task["agent_id"]
    module = task["module"]
    new = []
    if module in ("scan_file", "hash_file"):
        path = result.get("path")
        if result.get("matches"):
            sev = "critical" if len(result["matches"]) >= 2 else "high"
            new.append(det.make_finding(det.RULES_BY_ID["TH-F001"], agent_id, {"path": path, "sha256": result.get("sha256"),
                                                         "matches": result["matches"], "task_id": task["id"]},
                                        det.short_hash(path, result.get("sha256")), source="hunt", severity=sev))
        if (result.get("entropy") or 0) >= 7.2 and (result.get("size") or 0) > 4096:
            new.append(det.make_finding(det.RULES_BY_ID["TH-F002"], agent_id, {"path": path, "entropy": result["entropy"],
                                                         "sha256": result.get("sha256")},
                                        det.short_hash(path, "entropy"), source="hunt"))
        if result.get("sha256"):
            iocs = db.query("SELECT * FROM iocs WHERE type='sha256' AND lower(value)=lower(?)", (result["sha256"],))
            new += det.ioc_findings(iocs, "process", agent_id, {"sha256": result["sha256"], "exe": path})
    for f in new:
        fid, is_new = db.upsert_finding(f)
        if is_new:
            auto_respond(db, fid)
    if new:
        update_risk(db, agent_id)


def update_risk(db: Database, agent_id: str) -> float:
    """Riesgo 0-100: suma de puntuaciones de hallazgos abiertos con decaimiento (vida media 24h)."""
    now = time.time()
    rows = db.query("SELECT score, updated_at FROM findings WHERE agent_id=? AND status IN ('new','investigating')"
                    " AND updated_at > ?", (agent_id, now - 7 * 86400))
    total = sum(r["score"] * 0.5 ** ((now - r["updated_at"]) / 86400) for r in rows)
    risk = round(100 * (1 - math.exp(-total / 150)), 1)
    db.execute("UPDATE agents SET risk_score=? WHERE id=?", (risk, agent_id))
    return risk
