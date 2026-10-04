import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("THL_ADMIN_TOKEN", "test-admin")
os.environ.setdefault("THL_ENROLL_KEY", "test-enroll")

from fastapi.testclient import TestClient  # noqa: E402

from server.main import create_app  # noqa: E402
from server.query import QueryError, compile_query  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}


@pytest.fixture()
def client(tmp_path):
    app = create_app(str(tmp_path / "t.db"), start_hunter=False)
    with TestClient(app) as c:
        yield c


def enroll(client, hostname="host-a"):
    r = client.post("/api/agent/enroll", json={"enroll_key": "test-enroll", "hostname": hostname, "os": "Linux"})
    assert r.status_code == 200
    d = r.json()
    return d["agent_id"], {"Authorization": f"Bearer {d['token']}", "X-Agent-Id": d["agent_id"]}


def test_auth_required(client):
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/overview", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/overview", headers=ADMIN).status_code == 200


def test_enroll_rejects_bad_key(client):
    r = client.post("/api/agent/enroll", json={"enroll_key": "bad", "hostname": "x"})
    assert r.status_code == 403


def test_checkin_and_views(client):
    agent_id, h = enroll(client)
    payload = {
        "host": {"hostname": "host-a", "ip": "10.0.0.5"},
        "processes": [{"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init", "cmdline": "/sbin/init",
                       "username": "root", "create_time": 1.0}],
        "connection_events": [{"ts": 1.0, "pid": 1, "process_name": "init", "raddr": "10.0.0.1", "rport": 53}],
        "listeners": [{"pid": 1, "process_name": "sshd", "addr": "0.0.0.0", "port": 22, "proto": "tcp"}],
        "persistence": [{"kind": "cron", "location": "/etc/crontab", "value": "0 * * * * root run-parts /etc/cron.hourly"}],
    }
    r = client.post("/api/agent/checkin", json=payload, headers=h)
    assert r.status_code == 200 and r.json()["ok"]
    d = client.get(f"/api/agents/{agent_id}", headers=ADMIN).json()
    assert d["online"] and len(d["processes"]) == 1
    assert client.get(f"/api/agents/{agent_id}/persistence", headers=ADMIN).json()[0]["baseline"] == 1
    # a new listener after the baseline produces a drift finding
    payload["listeners"].append({"pid": 2, "process_name": "nginx", "addr": "0.0.0.0", "port": 8080, "proto": "tcp"})
    client.post("/api/agent/checkin", json=payload, headers=h)
    rules = {f["rule_id"] for f in client.get("/api/findings", headers=ADMIN).json()}
    assert "TH-L100" in rules


def test_task_whitelist_and_result(client):
    agent_id, h = enroll(client)
    bad = client.post("/api/tasks", headers=ADMIN, json={"agent_id": agent_id, "module": "exec", "params": {}})
    assert bad.status_code == 400
    ok = client.post("/api/tasks", headers=ADMIN, json={"agent_id": agent_id, "module": "list_dir", "params": {"path": "/"}})
    tid = ok.json()["id"]
    tasks = client.post("/api/agent/checkin", json={}, headers=h).json()["tasks"]
    assert [t["id"] for t in tasks] == [tid]
    r = client.post(f"/api/agent/tasks/{tid}/result", headers=h, json={"status": "ok", "result": {"entries": []}})
    assert r.status_code == 200
    assert client.get(f"/api/tasks/{tid}", headers=ADMIN).json()["status"] == "done"


def test_ioc_crud_and_manual_hunt(client):
    r = client.post("/api/iocs", headers=ADMIN, json=[{"type": "ip", "value": "198.51.100.7"}])
    assert r.json()["added"] == 1
    assert client.post("/api/iocs", headers=ADMIN, json=[{"type": "bogus", "value": "x"}]).status_code == 400
    hunt = client.post("/api/hunts/run", headers=ADMIN).json()
    assert all(s["error"] is None for s in hunt["summary"])


def test_query_compiler():
    sql, params = compile_query("name:bash|zsh -user:root since:2h", "processes")
    assert "NOT" in sql and "bash" in params and "zsh" in params
    sql, params = compile_query("rport:>1024", "network")
    assert "n.rport > ?" in sql and 1024 in params
    with pytest.raises(QueryError):
        compile_query("nosuchfield:x", "processes")
    with pytest.raises(QueryError):
        compile_query("rport:abc", "network")
