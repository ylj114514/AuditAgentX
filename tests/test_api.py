"""API 冒烟测试（不触发 LLM）。"""
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_agents_list():
    r = client.get("/api/agents")
    assert r.status_code == 200
    assert r.json()["total"] >= 5


def test_create_and_parse_local_project():
    r = client.post("/api/projects", json={
        "name": "demo_flask_app", "source_type": "local",
        "local_path": "examples/vulnerable_projects/demo_flask_app",
    })
    assert r.status_code == 200
    pid = r.json()["project_id"]

    r2 = client.post(f"/api/projects/{pid}/parse")
    assert r2.status_code == 200
    assert "Python" in r2.json()["metadata"]["languages"]
