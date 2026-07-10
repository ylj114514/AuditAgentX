"""对比分析与统计模块测试。"""
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal
from backend.core import ids
from backend.models import Project, Scan, Finding
from backend.analytics import aggregate, benchmark

client = TestClient(app)


def _seed():
    db = SessionLocal()
    p = Project(id=ids.project_id(), name="analytics_demo", source_type="local",
                status="parsed", metadata_json='{"languages":["Python"],"loc":100,"file_count":2}')
    db.add(p); db.commit()
    s = Scan(id=ids.scan_id(), project_id=p.id, status="done"); db.add(s); db.commit()
    db.add(Finding(id=ids.finding_id(), scan_id=s.id, type="SQL Injection",
                   severity="high", verified=True, status="confirmed"))
    db.add(Finding(id=ids.finding_id(), scan_id=s.id, type="Command Injection",
                   severity="critical", verified=True, status="confirmed"))
    db.commit()
    project_id = p.id
    db.close()
    return project_id


def test_overview_aggregates_findings():
    _seed()
    db = SessionLocal()
    ov = aggregate.overview(db)
    db.close()
    assert ov["projects"] >= 1
    assert ov["findings_total"] >= 2
    assert set(ov["severity_distribution"].keys()) == {"critical", "high", "medium", "low", "info"}
    assert isinstance(ov["top_vulnerability_types"], list)


def test_project_comparison_has_risk_score():
    pid = _seed()
    db = SessionLocal()
    rows = aggregate.project_comparison(db)
    db.close()
    mine = [r for r in rows if r["project_id"] == pid]
    assert mine and mine[0]["risk_score"] > 0
    assert mine[0]["findings_total"] >= 2


def test_benchmark_structure():
    b = benchmark.benchmark()
    assert len(b["dimensions"]) >= 8
    assert any(s.get("is_self") for s in b["systems"])
    assert b["innovations"]


def test_analytics_api_endpoints():
    _seed()
    assert client.get("/api/analytics/overview").status_code == 200
    assert client.get("/api/analytics/projects").json()["total"] >= 1
    assert client.get("/api/analytics/benchmark").json()["systems"]
