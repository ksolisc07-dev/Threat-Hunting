"""Lenguaje de consulta para caza manual.

Ejemplos:
    name:powershell.exe cmdline:*-enc*
    host:web* -user:root since:2h
    raddr:185.* rport:>1024 process:python*
    name:cmd.exe|powershell.exe parent:winword.exe
    mimikatz                      (texto libre -> busca en cmdline / proceso)

Reglas: términos separados por espacios se combinan con AND; `-campo:valor`
niega; `|` dentro de un valor hace OR; `*` es comodín; comparadores >, <, >=, <=
para campos numéricos; `since:30m|2h|7d` filtra por tiempo.
"""
import re
import shlex
import time

SCOPES = {
    "processes": {
        "table": "processes p JOIN agents a ON a.id = p.agent_id",
        "select": "p.id, p.agent_id, a.hostname AS host, p.pid, p.ppid, p.name, p.exe, p.cmdline, p.username,"
                  " p.parent_name, p.sha256, p.first_seen, p.last_seen",
        "time": "p.first_seen",
        "free": ["p.cmdline", "p.name"],
        "fields": {"host": "a.hostname", "name": "p.name", "exe": "p.exe", "cmdline": "p.cmdline",
                   "user": "p.username", "parent": "p.parent_name", "sha256": "p.sha256",
                   "pid": "p.pid", "ppid": "p.ppid", "agent": "p.agent_id"},
        "numeric": {"pid", "ppid"},
    },
    "network": {
        "table": "net_events n JOIN agents a ON a.id = n.agent_id",
        "select": "n.id, n.agent_id, a.hostname AS host, n.ts, n.pid, n.process_name, n.laddr, n.lport,"
                  " n.raddr, n.rport, n.proto, n.status",
        "time": "n.ts",
        "free": ["n.process_name", "n.raddr"],
        "fields": {"host": "a.hostname", "process": "n.process_name", "raddr": "n.raddr", "rport": "n.rport",
                   "laddr": "n.laddr", "lport": "n.lport", "pid": "n.pid", "proto": "n.proto",
                   "agent": "n.agent_id"},
        "numeric": {"rport", "lport", "pid"},
    },
    "persistence": {
        "table": "persistence s JOIN agents a ON a.id = s.agent_id",
        "select": "s.id, s.agent_id, a.hostname AS host, s.kind, s.location, s.value, s.baseline,"
                  " s.first_seen, s.last_seen",
        "time": "s.first_seen",
        "free": ["s.value", "s.location"],
        "fields": {"host": "a.hostname", "kind": "s.kind", "location": "s.location", "value": "s.value",
                   "agent": "s.agent_id"},
        "numeric": set(),
    },
}

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class QueryError(ValueError):
    pass


def _like(value: str) -> str:
    v = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return v.replace("*", "%")


def compile_query(q: str, scope: str = "processes", limit: int = 200) -> tuple[str, list]:
    if scope not in SCOPES:
        raise QueryError(f"Ámbito desconocido: {scope}")
    s = SCOPES[scope]
    try:
        tokens = shlex.split(q or "")
    except ValueError as exc:
        raise QueryError(f"Consulta mal formada: {exc}") from exc

    where, params = [], []
    for tok in tokens:
        if tok.upper() == "AND":
            continue
        neg = tok.startswith("-") and ":" in tok
        if neg:
            tok = tok[1:]
        if ":" in tok:
            field, value = tok.split(":", 1)
            field = field.lower()
        else:
            field, value = None, tok
        if not value:
            raise QueryError(f"Valor vacío en '{tok}'")

        if field == "since":
            m = re.fullmatch(r"(\d+)([smhd])", value)
            if not m:
                raise QueryError("since requiere formato 30m, 2h, 7d…")
            where.append(f"{s['time']} >= ?")
            params.append(time.time() - int(m.group(1)) * _UNITS[m.group(2)])
            continue

        if field is None:
            clause = " OR ".join(f"{col} LIKE ? ESCAPE '\\'" for col in s["free"])
            where.append(f"({clause})")
            params += [f"%{_like(value)}%"] * len(s["free"])
            continue

        if field not in s["fields"]:
            raise QueryError(f"Campo '{field}' no válido. Campos: {', '.join(sorted(s['fields']))}, since")
        col = s["fields"][field]
        ors = []
        for alt in value.split("|"):
            if field in s["numeric"]:
                m = re.fullmatch(r"(>=|<=|>|<|=)?(\d+)", alt)
                if not m:
                    raise QueryError(f"'{field}' es numérico")
                ors.append(f"{col} {m.group(1) or '='} ?")
                params.append(int(m.group(2)))
            else:
                ors.append(f"COALESCE({col}, '') LIKE ? ESCAPE '\\'")
                params.append(_like(alt))
        clause = "(" + " OR ".join(ors) + ")"
        where.append(f"NOT {clause}" if neg else clause)

    sql = f"SELECT {s['select']} FROM {s['table']}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {s['time']} DESC LIMIT ?"
    params.append(max(1, min(int(limit), 2000)))
    return sql, params
