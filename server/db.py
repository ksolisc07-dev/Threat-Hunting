"""Capa de persistencia SQLite (thread-safe, una sola conexión con lock)."""
import json
import sqlite3
import threading
import time
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT, os_version TEXT, arch TEXT, ip TEXT,
    agent_version TEXT,
    token_hash TEXT NOT NULL,
    enrolled_at REAL NOT NULL,
    last_seen REAL,
    interval INTEGER DEFAULT 60,
    risk_score REAL DEFAULT 0,
    tags TEXT DEFAULT '[]'
);

-- Último estado conocido por tipo (processes, listeners, users, host...)
CREATE TABLE IF NOT EXISTS agent_state (
    agent_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    collected_at REAL NOT NULL,
    PRIMARY KEY (agent_id, kind)
);

CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    pid INTEGER, ppid INTEGER,
    name TEXT, exe TEXT, cmdline TEXT, username TEXT,
    parent_name TEXT, parent_exe TEXT, sha256 TEXT,
    create_time REAL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE (agent_id, pid, create_time)
);
CREATE INDEX IF NOT EXISTS ix_proc_agent ON processes(agent_id, last_seen);
CREATE INDEX IF NOT EXISTS ix_proc_sha ON processes(sha256);
CREATE INDEX IF NOT EXISTS ix_proc_name ON processes(name);

-- Eventos de conexión (cada conexión nueva observada por el agente)
CREATE TABLE IF NOT EXISTS net_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    ts REAL NOT NULL,
    pid INTEGER, process_name TEXT,
    laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER,
    proto TEXT, status TEXT
);
CREATE INDEX IF NOT EXISTS ix_net_agent ON net_events(agent_id, raddr, rport, ts);
CREATE INDEX IF NOT EXISTS ix_net_ts ON net_events(ts);

CREATE TABLE IF NOT EXISTS persistence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    location TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    baseline INTEGER DEFAULT 0,
    UNIQUE (agent_id, location, value)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    tactic TEXT, technique TEXT,
    source TEXT NOT NULL,           -- realtime | hunt | correlation | ioc
    evidence TEXT,
    status TEXT DEFAULT 'new',      -- new | investigating | resolved | false_positive
    dedup_key TEXT UNIQUE,
    hits INTEGER DEFAULT 1,
    hunt_id INTEGER,
    notes TEXT DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_find_agent ON findings(agent_id, created_at);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    module TEXT NOT NULL,
    params TEXT DEFAULT '{}',
    status TEXT DEFAULT 'pending',  -- pending | sent | done | error
    reason TEXT,
    created_by TEXT,                -- hunter | analyst
    finding_id INTEGER,
    result TEXT,
    created_at REAL NOT NULL,
    sent_at REAL, completed_at REAL
);
CREATE INDEX IF NOT EXISTS ix_task_agent ON tasks(agent_id, status);

CREATE TABLE IF NOT EXISTS hunts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger TEXT NOT NULL,          -- auto | manual
    started_at REAL NOT NULL,
    finished_at REAL,
    findings INTEGER DEFAULT 0,
    tasks INTEGER DEFAULT 0,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,             -- ip | domain | sha256 | process | cmdline
    value TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'high',
    created_at REAL NOT NULL,
    UNIQUE (type, value)
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # -- helpers -----------------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur

    def executemany(self, sql: str, seq: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self.conn.executemany(sql, seq)
            self.conn.commit()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        with self._lock:
            row = self.conn.execute(sql, tuple(params)).fetchone()
            return dict(row) if row else None

    def scalar(self, sql: str, params: Iterable[Any] = ()) -> Any:
        with self._lock:
            row = self.conn.execute(sql, tuple(params)).fetchone()
            return row[0] if row else None

    # -- estado de agente --------------------------------------------------
    def set_state(self, agent_id: str, kind: str, data: Any) -> None:
        self.execute(
            "INSERT INTO agent_state(agent_id, kind, data, collected_at) VALUES (?,?,?,?) "
            "ON CONFLICT(agent_id, kind) DO UPDATE SET data=excluded.data, collected_at=excluded.collected_at",
            (agent_id, kind, json.dumps(data), time.time()),
        )

    def get_state(self, agent_id: str, kind: str, default: Any = None) -> Any:
        row = self.one("SELECT data FROM agent_state WHERE agent_id=? AND kind=?", (agent_id, kind))
        return json.loads(row["data"]) if row else default

    # -- hallazgos ---------------------------------------------------------
    def upsert_finding(self, f: dict) -> tuple[int, bool]:
        """Inserta un hallazgo o incrementa `hits` si ya existe (dedup_key).

        Devuelve (id, es_nuevo). Un hallazgo resuelto que reaparece se reabre.
        """
        now = time.time()
        with self._lock:
            existing = self.conn.execute(
                "SELECT id, status FROM findings WHERE dedup_key=?", (f["dedup_key"],)
            ).fetchone()
            if existing:
                status = existing["status"]
                if status == "resolved":
                    status = "new"
                self.conn.execute(
                    "UPDATE findings SET hits=hits+1, updated_at=?, evidence=?, status=? WHERE id=?",
                    (now, json.dumps(f.get("evidence", {}), default=str), status, existing["id"]),
                )
                self.conn.commit()
                return existing["id"], False
            cur = self.conn.execute(
                "INSERT INTO findings(agent_id, rule_id, title, description, severity, score, tactic, technique,"
                " source, evidence, dedup_key, hunt_id, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    f.get("agent_id"), f["rule_id"], f["title"], f.get("description", ""),
                    f["severity"], f["score"], f.get("tactic"), f.get("technique"),
                    f.get("source", "realtime"), json.dumps(f.get("evidence", {}), default=str),
                    f["dedup_key"], f.get("hunt_id"), now, now,
                ),
            )
            self.conn.commit()
            return cur.lastrowid, True

    def create_task(self, agent_id: str, module: str, params: dict, reason: str,
                    created_by: str, finding_id: int | None = None) -> int | None:
        """Crea una tarea salvo que ya exista una idéntica pendiente/enviada."""
        p = json.dumps(params, sort_keys=True)
        with self._lock:
            dup = self.conn.execute(
                "SELECT id FROM tasks WHERE agent_id=? AND module=? AND params=? AND status IN ('pending','sent')",
                (agent_id, module, p),
            ).fetchone()
            if dup:
                return None
            cur = self.conn.execute(
                "INSERT INTO tasks(agent_id, module, params, reason, created_by, finding_id, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (agent_id, module, p, reason, created_by, finding_id, time.time()),
            )
            self.conn.commit()
            return cur.lastrowid

    def purge(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400
        self.execute("DELETE FROM net_events WHERE ts < ?", (cutoff,))
        self.execute("DELETE FROM processes WHERE last_seen < ?", (cutoff,))
