"""API 冒烟测试（不触发 LLM）。"""
import json
from datetime import datetime, timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal
from backend.core import ids
from backend.models import Evidence, Finding, Project, Report, Scan

client = TestClient(app)


def test_evidence_decoder_returns_safe_artifact_metadata_without_absolute_paths():
    from backend.api.routes_findings import _decode_evidence

    stored = SimpleNamespace(
        source="null", sink="null", data_flow="[]", logs="[]",
        poc_result=json.dumps({
            "exploit": {}, "runtime": {},
            "poc_file": {"path": r"C:\\private\\pocs\\f-1.md", "sha256": "a" * 64,
                         "label": "validated"},
            "forensic_poc_file": {"path": "pocs/f-1.function-forensic.md", "sha256": "b" * 64},
            "artifacts": {"validated_poc": {"name": "f-1.md", "persistence_status": "persisted"}},
        }),
    )

    evidence = _decode_evidence(stored)

    assert evidence["poc_file"]["name"] == "f-1.md"
    assert "path" not in evidence["poc_file"]
    assert evidence["forensic_poc_file"]["name"] == "f-1.function-forensic.md"
    assert "path" not in evidence["forensic_poc_file"]
    assert evidence["artifacts"]["validated_poc"]["persistence_status"] == "persisted"


def test_evidence_decoder_hides_legacy_candidate_code():
    from backend.api.routes_findings import _decode_evidence

    stored = SimpleNamespace(
        source="null", sink="null", data_flow="[]", logs="[]",
        poc_result=json.dumps({
            "exploit": {"exploit_code": "print('old candidate')", "payloads": ["; id"]},
            "attack_plan": {"plan_status": "candidate_plan_pending_review", "code": "print('old candidate')"},
            "verification": {"final_verdict": "needs_review", "dynamically_verified": False},
        }),
    )

    evidence = _decode_evidence(stored)

    assert evidence["exploit"]["exploit_code"] is None
    assert evidence["attack_plan"]["code"] is None
    assert "old candidate" not in json.dumps(evidence)


def test_evidence_decoder_redacts_windows_and_unix_sandbox_roots_recursively():
    from backend.api.routes_findings import _decode_evidence

    for root in (r"C:\\private\\project", "/srv/private/project"):
        stored = SimpleNamespace(
            source=json.dumps({"file": "src/app.py"}), sink="null", data_flow="[]",
            logs=json.dumps([f"diagnostic at {root}/logs/build.log"]),
            poc_result=json.dumps({
                "exploit": {"trigger_location": "src/app.py:4"},
                "runtime": {"sandbox": {"code_root": root, "diagnostics": [f"read {root}/.env"]}},
                "sandbox": {"code_root": root, "logs_excerpt": f"failed under {root}/tmp"},
                "poc_file": {"path": f"{root}/pocs/f.md", "sha256": "a" * 64},
                "forensic_poc_file": {"path": f"{root}/pocs/f.forensic.md", "sha256": "b" * 64},
            }),
        )

        payload = json.dumps(_decode_evidence(stored), ensure_ascii=False)

        assert root not in payload
        assert "src/app.py" in payload
        assert "<project_root>" in payload


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_cancel_active_scan_reports_cancelling_without_claiming_cleanup(monkeypatch):
    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name=f"cancel_{ids.project_id()}", source_type="local",
        local_path="examples/vulnerable_projects/demo_flask_app", status="created",
    )
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="deep", status="running")
    db.add_all([project, scan])
    db.commit()
    scan_id = scan.id
    db.close()

    monkeypatch.setattr("backend.api.routes_scans.request_cancel", lambda _scan_id: 2)
    monkeypatch.setattr("backend.scanners.base.cancel_scan_processes", lambda _scan_id: 1)

    response = client.post(f"/api/scans/{scan_id}/cancel")

    assert response.status_code == 200
    assert response.json() == {
        "scan_id": scan_id,
        "status": "cancelling",
        "terminated_resources": 2,
        "terminated_scanners": 1,
        "terminated_total": 3,
    }
    check = SessionLocal()
    stored = check.get(Scan, scan_id)
    assert stored.status == "cancelling"
    assert stored.error == "用户已请求停止扫描"
    assert stored.finished_at is None
    check.close()


def test_orchestrator_recognizes_cancelling_database_status():
    from backend.agents.orchestrator_agent import OrchestratorAgent

    orchestrator = object.__new__(OrchestratorAgent)
    orchestrator.scan = SimpleNamespace(id="scan-cancelling", status="cancelling")
    orchestrator.db = SimpleNamespace(refresh=lambda _scan: None)

    assert orchestrator._cancel_requested() is True


def test_stale_orphaned_cancelling_scan_converges_to_cancelled(monkeypatch):
    from backend.api.routes_scans import _mark_stale_scan_if_needed

    scan = SimpleNamespace(
        id="stale-cancelling", status="cancelling",
        started_at=datetime.utcnow() - timedelta(hours=2), finished_at=None,
        current_stage="Persisting", progress=95, error="用户已请求停止扫描",
    )
    monkeypatch.setattr("backend.api.routes_scans.has_active_scan_resources", lambda _scan_id: False)
    monkeypatch.setattr("backend.api.routes_scans.settings.stale_scan_after_seconds", 3600)

    assert _mark_stale_scan_if_needed(scan) is True
    assert scan.status == "cancelled"
    assert scan.error == "用户已请求停止扫描"
    assert scan.finished_at is not None


def _scan_with_fake_terminal_acp(*, status="running", scanner_status=None):
    """Create an isolated persisted scan for terminal-ACP reconciliation tests."""
    from backend.api import routes_scans

    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name=f"acp_reconcile_{ids.project_id()}", source_type="local",
        local_path="examples/vulnerable_projects/demo_flask_app", status="created",
    )
    scan = Scan(
        id=ids.scan_id(), project_id=project.id, scan_type="deep", status=status,
        progress=88, current_stage="ExploitAgent/DynamicVerify",
        config_json=json.dumps({
            "enabled_tools": ["semgrep"],
            "scanner_status": scanner_status or [],
        }),
    )
    db.add_all([project, scan])
    db.commit()

    class FakeTerminalTracer:
        def __init__(self, scan_id):
            assert scan_id == scan.id

        def load_by_type(self, message_type):
            return [object()] if message_type == "scan.complete" else []

    return routes_scans, db, scan, FakeTerminalTracer


def test_terminal_acp_trace_reconciles_a_running_scan(monkeypatch):
    routes_scans, db, scan, tracer = _scan_with_fake_terminal_acp()
    monkeypatch.setattr(routes_scans, "ACPTracer", tracer)
    try:
        assert routes_scans.reconcile_scan_terminal_from_acp(db, scan) is True
        assert scan.status == "done"
        assert scan.progress == 100
        assert scan.current_stage == "finished"
        assert scan.finished_at is not None
        assert routes_scans.reconcile_scan_terminal_from_acp(db, scan) is False
    finally:
        db.close()


def test_reconciliation_never_infers_terminal_state_without_scan_complete(monkeypatch):
    routes_scans, db, scan, _tracer = _scan_with_fake_terminal_acp()

    class EmptyTracer:
        def __init__(self, _scan_id):
            pass

        def load_by_type(self, _message_type):
            return []

    monkeypatch.setattr(routes_scans, "ACPTracer", EmptyTracer)
    try:
        assert routes_scans.reconcile_scan_terminal_from_acp(db, scan) is False
        assert scan.status == "running"
        assert scan.progress == 88
    finally:
        db.close()


def test_terminal_acp_trace_preserves_partial_scanner_status(monkeypatch):
    routes_scans, db, scan, tracer = _scan_with_fake_terminal_acp(
        scanner_status=[{"tool": "semgrep", "success": False, "partial_results": True}],
    )
    monkeypatch.setattr(routes_scans, "ACPTracer", tracer)
    try:
        assert routes_scans.reconcile_scan_terminal_from_acp(db, scan) is True
        assert scan.status == "partial_completed"
        assert scan.current_stage == "finished_with_tool_failures"
        assert scan.progress == 100
    finally:
        db.close()


def test_terminal_acp_trace_converges_cancelling_scan_to_cancelled(monkeypatch):
    routes_scans, db, scan, tracer = _scan_with_fake_terminal_acp(status="cancelling")
    monkeypatch.setattr(routes_scans, "ACPTracer", tracer)
    try:
        assert routes_scans.reconcile_scan_terminal_from_acp(db, scan) is True
        assert scan.status == "cancelled"
        assert scan.current_stage == "finished"
        assert scan.progress == 100
        assert scan.finished_at is not None
    finally:
        db.close()


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

    r3 = client.get(f"/api/projects/{pid}/tree")
    assert r3.status_code == 200
    body = r3.json()
    assert any(item["path"] == "app.py" for item in body["tree"])
    # /tree 现在返回完整项目结构（供前端"项目结构"页展示）
    assert "Python" in body["languages"]
    assert body["file_count"] >= 1
    assert "dependencies" in body and "entrypoints" in body and "frameworks" in body


def test_verify_finding_api_records_evidence_and_ingests_dynamic_confirmation_after_commit(monkeypatch):
    class FakeDynamicResult:
        def __init__(self):
            self.verified = True
            self.reproducible = True
            self.reproduction_status = "dynamic_confirmed"
            self.matched_indicator = "SQL syntax"
            self.confirmed_record = {
                "url": "http://target.local/user",
                "method": "GET",
                "params": {"id": "1' OR '1'='1"},
                "payload": "1' OR '1'='1",
                "status_code": 200,
                "response_headers": {"content-type": "text/plain"},
                "response_excerpt": "You have an error in your SQL syntax",
                "elapsed_ms": 12,
            }
            self.baseline_record = {
                "url": "http://target.local/user",
                "method": "GET",
                "params": {"id": "1"},
                "payload": "1",
                "status_code": 200,
                "response_headers": {"content-type": "text/plain"},
                "response_excerpt": "normal response",
                "role": "baseline",
            }
            self.server_binding = {
                "kind": "source_route",
                "route_file": "app.py",
                "route_line": 18,
            }
            self.records = [self.confirmed_record]
            self.logs = ["matched test indicator"]
            self.skipped = False
            self.reason = ""
            self.error = ""

    def fake_exploit_run(self, finding):
        return {
            "vuln_type": "SQL Injection",
            "trigger_location": "app.py:21",
            "exploit_path": "id parameter reaches SQL string concatenation",
            "attack_vector": "HTTP GET id",
            "payloads": ["1' OR '1'='1"],
            "exploit_code": "print('local poc')",
            "verification_method": "match SQL syntax indicator",
            "success_indicators": ["SQL syntax"],
            "impact": "unauthorized data read",
        }

    def fake_verify(self, base_url, exploit, endpoints=None, **_kwargs):
        return FakeDynamicResult()

    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", fake_exploit_run)
    monkeypatch.setattr("backend.verifier.dynamic_verifier.DynamicVerifier.verify", fake_verify)

    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name="api_verify_demo", source_type="local",
        local_path="examples/vulnerable_projects/demo_flask_app", status="created",
    )
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan)
    db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21,
        code_snippet='cur.execute("select * from users where id=" + uid)',
        confidence=0.7, verified=False, status="confirmed",
        detail_json=json.dumps({"_verify": {"call_path": [
            {"stage": "route", "path": "/user", "file": "app.py", "line": 18},
        ]}}),
    )
    db.add(finding)
    db.commit()
    fid = finding.id
    db.close()

    ingested = []

    def assert_ingested_after_commit(learned_finding):
        check = SessionLocal()
        try:
            persisted = check.get(Finding, fid)
            assert persisted is not None
            assert persisted.status == "confirmed"
            assert persisted.verified is True
            assert check.query(Evidence).filter(Evidence.finding_id == fid).count() == 1
        finally:
            check.close()
        ingested.append(learned_finding)
        return True

    monkeypatch.setattr(
        "backend.rag.feedback_learner.ingest_dynamic_confirmation",
        assert_ingested_after_commit,
    )

    r = client.post(f"/api/findings/{fid}/verify", json={
        "mode": "url",
        "base_url": "http://127.0.0.1:18080",
        "endpoints": ["/user"],
        "timeout": 5,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True
    assert body["reproducible"] is True
    assert body["matched_indicator"] == "SQL syntax"
    assert body["evidence_id"]
    assert len(ingested) == 1
    assert ingested[0]["status"] == "confirmed"
    assert ingested[0]["evidence"]["verification"]["dynamic_method"] == "http_dynamic"

    ev = client.get(f"/api/findings/{fid}/evidence")
    assert ev.status_code == 200
    evidence = ev.json()["evidence"]
    assert evidence["exploit"]["trigger_location"] == "app.py:21"
    assert evidence["runtime"]["reproducible"] is True
    assert evidence["runtime"]["response_status"] == 200
    assert evidence["artifacts"]["validated_poc"]["persistence_status"] == "persisted"
    assert evidence["artifacts"]["validated_poc"]["sha256"]
    assert evidence["reproduction_metadata"]["dynamic_method"] == "http_dynamic"

    detail = client.get(f"/api/findings/{fid}")
    assert detail.status_code == 200
    assert detail.json()["verification"]["reproducible"] is True


def test_verify_finding_api_unresolved_endpoint_does_not_send_http(monkeypatch):
    monkeypatch.setattr(
        "backend.agents.exploit_agent.ExploitAgent.run",
        lambda *_args: {"payloads": ["../etc/passwd"], "_injection_points": ["path"]},
    )
    monkeypatch.setattr(
        "backend.verifier.dynamic_verifier.DynamicVerifier.verify",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="api_endpoint_unresolved", source_type="local", status="created")
    db.add(project); db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan); db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="Path Traversal", severity="high",
        file_path="storage.py", start_line=41, code_snippet="open(path)",
        confidence=0.7, verified=False, status="needs_review",
    )
    db.add(finding); db.commit()
    finding_id = finding.id
    db.close()

    response = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": ["/tasks/"],
    })

    assert response.status_code == 200
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert evidence["runtime"]["reproduction_status"] == "endpoint_unresolved"
    assert evidence["runtime"]["records"] == []


def test_verify_finding_api_nearest_route_without_parameter_proof_sends_no_http(monkeypatch, tmp_path):
    """Route proximity alone is not an HTTP capability for manual verification."""
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/near')\n"
        "def nearby_handler():\n"
        "    request_id = request.args.get('id')\n"
        "    fixed_id = '1'\n"
        "    cursor.execute('select * from users where id=' + fixed_id)\n",
        encoding="utf-8",
    )
    calls = []

    class FakeDynamicResult:
        verified = False
        reproducible = False
        reproduction_status = "not_reproduced"
        records = []
        logs = []
        skipped = False
        reason = ""
        error = ""

    monkeypatch.setattr(
        "backend.agents.exploit_agent.ExploitAgent.run",
        lambda *_args: {"payloads": ["'"], "_injection_points": ["id"]},
    )
    monkeypatch.setattr(
        "backend.verifier.dynamic_verifier.DynamicVerifier.verify",
        lambda *_args, **_kwargs: (calls.append(True) or FakeDynamicResult()),
    )
    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name="api_nearest_route_only", source_type="local",
        local_path=str(tmp_path), status="created",
    )
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=7,
        code_snippet="cursor.execute('select * from users where id=' + fixed_id)",
        confidence=0.7, verified=False, status="needs_review",
    )
    db.add_all([project, scan, finding])
    db.commit()
    finding_id = finding.id
    db.close()

    response = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": ["/near"],
    })

    assert response.status_code == 200
    assert calls == []
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert evidence["runtime"]["reproduction_status"] == "endpoint_unresolved"
    assert evidence["runtime"]["records"] == []


def test_verify_finding_api_static_counterevidence_skips_http_unless_explicitly_overridden(monkeypatch):
    calls = []

    class FakeDynamicResult:
        verified = False
        reproducible = False
        reproduction_status = "not_reproduced"
        records = []
        logs = []
        skipped = False
        reason = ""
        error = ""

    monkeypatch.setattr(
        "backend.agents.exploit_agent.ExploitAgent.run",
        lambda *_args: {"payloads": ["'"], "_injection_points": ["id"]},
    )
    monkeypatch.setattr(
        "backend.verifier.dynamic_verifier.DynamicVerifier.verify",
        lambda *_args, **_kwargs: (calls.append(True) or FakeDynamicResult()),
    )
    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name="api_counterevidence", source_type="local",
        local_path="examples/vulnerable_projects/demo_flask_app", status="created",
    )
    db.add(project); db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan); db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21, code_snippet="cursor.execute(query)",
        confidence=0.7, verified=False, status="needs_review",
        detail_json=json.dumps({"_verify": {
            "false_positive_reason": "query is parameterized",
            "call_path": [{"stage": "route", "path": "/user", "file": "app.py", "line": 18}],
        }}),
    )
    db.add(finding); db.commit()
    finding_id = finding.id
    db.close()

    response = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": ["/user"],
    })

    assert response.status_code == 200
    assert calls == []
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert evidence["runtime"]["reproduction_status"] == "policy_skipped"
    assert "false_positive_reason" in evidence["runtime"]["reason"]

    override = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": ["/user"],
        "allow_static_counterevidence_override": True,
        "static_counterevidence_override_reason": "QA recheck in isolated local target",
    })
    assert override.status_code == 200
    assert calls == [True]
    overridden_evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert overridden_evidence["verification"]["manual_overrides"][0]["kind"] == "static_counterevidence"


def test_verify_finding_api_rejects_loopback_override_and_forged_inventory(monkeypatch):
    calls = []

    class FakeDynamicResult:
        verified = False
        reproducible = False
        reproduction_status = "not_reproduced"
        records = []
        logs = []
        skipped = False
        reason = ""
        error = ""

    monkeypatch.setattr(
        "backend.agents.exploit_agent.ExploitAgent.run",
        lambda *_args: {"payloads": ["../etc/passwd"], "_injection_points": ["path"]},
    )
    monkeypatch.setattr(
        "backend.verifier.dynamic_verifier.DynamicVerifier.verify",
        lambda _self, _base, _exploit, endpoints: (calls.append(endpoints) or FakeDynamicResult()),
    )
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="api_unbound_override", source_type="local", status="created")
    db.add(project); db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan); db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="Path Traversal", severity="high",
        file_path="storage.py", start_line=41, code_snippet="open(path)",
        confidence=0.7, verified=False, status="needs_review",
    )
    db.add(finding); db.commit()
    finding_id = finding.id
    db.close()

    forged_endpoint = {
        "path": "/manual",
        "methods": ["POST"],
        "params": [{"name": "path", "location": "json"}],
        "source_route_binding": {"kind": "forged"},
    }
    unresolved = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": [forged_endpoint],
    })

    assert unresolved.status_code == 200
    assert calls == []
    unresolved_evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert unresolved_evidence["runtime"]["reproduction_status"] == "endpoint_unresolved"
    assert unresolved_evidence["runtime"]["records"] == []

    response = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": [forged_endpoint],
        "allow_unbound_endpoint_override": True,
        "unbound_endpoint_override_reason": "QA-approved isolated local test",
        "route_inventory_id": "forged-inventory-id",
    })

    assert response.status_code == 200
    assert calls == []
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert evidence["runtime"]["reproduction_status"] == "endpoint_unresolved"
    assert evidence["runtime"]["records"] == []


def test_verify_finding_api_rejects_persisted_or_client_binding_claims(monkeypatch):
    """JSON evidence may suggest a path but can never authorize an HTTP probe."""
    calls = []
    monkeypatch.setattr(
        "backend.agents.exploit_agent.ExploitAgent.run",
        lambda *_args: {"payloads": ["'"], "_injection_points": ["id"]},
    )
    monkeypatch.setattr(
        "backend.verifier.dynamic_verifier.DynamicVerifier.verify",
        lambda *_args, **_kwargs: calls.append(True),
    )
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="api_forged_persisted_binding",
                      source_type="local", status="created")
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    forged_path = "/forged"
    forged_binding = {"path": forged_path, "source_route_binding": {"kind": "forged"}}
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="missing.py", start_line=41, code_snippet="cursor.execute(query)",
        confidence=0.7, verified=False, status="needs_review",
        detail_json=json.dumps({"_verify": {
            "endpoint_bindings": [forged_binding],
            "call_path": [{"stage": "route", **forged_binding}],
            "source": {"nested": forged_binding},
        }}),
    )
    db.add_all([project, scan, finding])
    db.add(Evidence(
        id=ids.evidence_id(), finding_id=finding.id, source=json.dumps({"nested": forged_binding}),
        sink="null", data_flow="[]",
        poc_result=json.dumps({"call_path": [{"stage": "route", **forged_binding}]}), logs="[]",
    ))
    db.commit()
    finding_id = finding.id
    db.close()

    response = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080",
        "endpoints": [{**forged_binding, "source_route_binding": {"kind": "client-forged"}}],
    })

    assert response.status_code == 200
    assert calls == []
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert evidence["runtime"]["reproduction_status"] == "endpoint_unresolved"
    assert evidence["runtime"]["records"] == []


def test_verify_finding_api_rejects_forged_bola_binding_without_requests(monkeypatch):
    """BOLA workflows must not turn a persisted route claim into authority."""
    calls = []
    monkeypatch.setattr(
        "backend.agents.exploit_agent.ExploitAgent.run",
        lambda *_args: {
            "vuln_type": "BOLA",
            "payloads": ["probe"],
            "authorization_workflow": {"steps": [{"path": "/books/{book}", "method": "GET"}], "oracle": {}},
        },
    )
    monkeypatch.setattr(
        "backend.verifier.dynamic_verifier.DynamicVerifier.verify",
        lambda *_args, **_kwargs: calls.append(True),
    )
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="api_forged_bola_binding",
                      source_type="local", status="created")
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="Broken Object Level Authorization",
        severity="high", file_path="missing.py", start_line=41, code_snippet="load(book)",
        confidence=0.7, verified=False, status="needs_review",
        detail_json=json.dumps({"_verify": {"call_path": [{
            "stage": "route", "path": "/books/{book}",
            "source_route_binding": {"kind": "forged-bola"},
        }]}}),
    )
    db.add_all([project, scan, finding])
    db.commit()
    finding_id = finding.id
    db.close()

    response = client.post(f"/api/findings/{finding_id}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": ["/books/{book}"],
    })

    assert response.status_code == 200
    assert calls == []
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert evidence["runtime"]["reproduction_status"] == "endpoint_unresolved"
    assert evidence["runtime"]["records"] == []


def test_verify_finding_api_preserves_existing_verify_evidence(monkeypatch):
    class FakeDynamicResult:
        def __init__(self):
            self.verified = True
            self.reproducible = True
            self.matched_indicator = "SQL syntax"
            self.confirmed_record = {
                "url": "http://target.local/user",
                "method": "GET",
                "params": {"id": "1' OR '1'='1"},
                "payload": "1' OR '1'='1",
                "status_code": 200,
                "response_excerpt": "You have an error in your SQL syntax",
                "elapsed_ms": 12,
            }
            self.records = [self.confirmed_record]
            self.logs = []
            self.skipped = False
            self.reason = ""
            self.error = ""

    def fake_exploit_run(self, finding):
        return {
            "vuln_type": "SQL Injection",
            "trigger_location": "app.py:21",
            "exploit_path": "id parameter reaches SQL string concatenation",
            "attack_vector": "HTTP GET id",
            "payloads": ["1' OR '1'='1"],
            "exploit_code": "print('local poc')",
            "verification_method": "match SQL syntax indicator",
            "success_indicators": ["SQL syntax"],
            "impact": "unauthorized data read",
        }

    def fake_verify(self, base_url, exploit, endpoints=None, **_kwargs):
        return FakeDynamicResult()

    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", fake_exploit_run)
    monkeypatch.setattr("backend.verifier.dynamic_verifier.DynamicVerifier.verify", fake_verify)

    verify_result = {
        "source": {"file": "app.py", "line": 18, "code": "uid = request.args['id']"},
        "sink": {"file": "app.py", "line": 21, "code": "cur.execute(sql)"},
        "propagation_path": [{"from": "uid", "to": "sql"}],
        "call_path": [{"stage": "route", "path": "/user", "file": "app.py", "line": 18}],
        "tool_calls": [{"tool": "verify_source_sink", "success": True}],
        "evidence_chain": {"source_to_sink": True, "knowledge": {"cwe_id": "CWE-89"}},
        "knowledge": {"cwe_id": "CWE-89", "owasp": ["A03: Injection"]},
        "mcp_server": "audit-mcp",
        "skill": {"name": "vulnerability_verification"},
        "static_verdict": "confirmed_static",
        "dynamic_verdict": "not_executed",
        "final_verdict": "confirmed_static",
    }
    original_poc = {
        "tool_calls": verify_result["tool_calls"],
        "static_evidence_chain": verify_result["evidence_chain"],
        "knowledge": verify_result["knowledge"],
        "verification": {
            "mcp_server": verify_result["mcp_server"],
            "skill": verify_result["skill"],
            "static_verdict": verify_result["static_verdict"],
            "dynamic_verdict": verify_result["dynamic_verdict"],
            "final_verdict": verify_result["final_verdict"],
        },
    }

    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name="api_verify_preserve_demo", source_type="local",
        local_path="examples/vulnerable_projects/demo_flask_app", status="created",
    )
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan)
    db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21,
        code_snippet='cur.execute("select * from users where id=" + uid)',
        confidence=0.7, verified=True, status="confirmed",
        detail_json=json.dumps({"_verify": verify_result}, ensure_ascii=False),
    )
    db.add(finding)
    db.commit()
    db.add(Evidence(
        id=ids.evidence_id(), finding_id=finding.id,
        source=json.dumps(verify_result["source"], ensure_ascii=False),
        sink=json.dumps(verify_result["sink"], ensure_ascii=False),
        data_flow=json.dumps(verify_result["propagation_path"], ensure_ascii=False),
        poc_result=json.dumps(original_poc, ensure_ascii=False),
        logs=json.dumps(["VerifyAgent 独立复核通过"], ensure_ascii=False),
    ))
    db.commit()
    fid = finding.id
    db.close()

    r = client.post(f"/api/findings/{fid}/verify", json={
        "mode": "url",
        "base_url": "http://127.0.0.1:18080",
        "endpoints": ["/user"],
        "timeout": 5,
    })
    assert r.status_code == 200

    ev = client.get(f"/api/findings/{fid}/evidence")
    assert ev.status_code == 200
    evidence = ev.json()["evidence"]
    assert evidence["runtime"]["reproducible"] is True
    assert evidence["source"] == verify_result["source"]
    assert evidence["sink"] == verify_result["sink"]
    assert evidence["data_flow"] == verify_result["propagation_path"]
    assert evidence["tool_calls"] == verify_result["tool_calls"]
    assert evidence["static_evidence_chain"] == verify_result["evidence_chain"]
    assert evidence["knowledge"]["cwe_id"] == verify_result["knowledge"]["cwe_id"]
    assert evidence["knowledge"]["owasp"] == verify_result["knowledge"]["owasp"]
    assert "verification_checks" in evidence["knowledge"]
    assert "false_positive_signals" in evidence["knowledge"]
    assert "remediation" in evidence["knowledge"]
    assert "references" in evidence["knowledge"]
    assert evidence["verification"]["static_verdict"] == "confirmed_static"


def test_verify_finding_api_rejects_external_url_by_default():
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="api_external_guard", source_type="local", status="created")
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan)
    db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=1, code_snippet="cursor.execute(q)",
        confidence=0.7, verified=False, status="confirmed",
    )
    db.add(finding)
    db.commit()
    fid = finding.id
    db.close()

    r = client.post(f"/api/findings/{fid}/verify", json={
        "mode": "url",
        "base_url": "http://example.com",
        "endpoints": ["/"],
    })

    assert r.status_code == 400


def test_verify_finding_api_context_blocks_workflow_confirmation(monkeypatch):
    class FakeDynamicResult:
        verified = True
        reproducible = True
        reproduction_status = "dynamic_confirmed"
        matched_indicator = "uid=1000"
        confirmed_record = {"url": "http://127.0.0.1:18080/", "method": "GET", "params": {}, "payload": "", "status_code": 200}
        records = [confirmed_record]
        logs = []
        skipped = False
        reason = ""
        error = ""

    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", lambda self, finding: {
        "payloads": ["; id"], "success_indicators": ["uid=\\d+"], "_injection_points": ["cmd"]})
    monkeypatch.setattr("backend.verifier.dynamic_verifier.DynamicVerifier.verify", lambda self, base_url, exploit, endpoints=None: FakeDynamicResult())

    db = SessionLocal()
    project = Project(id=ids.project_id(), name="api_context_guard", source_type="local", status="created")
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan)
    db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="run-shell-injection", severity="high",
        file_path=".github/workflows/test.yml", start_line=10,
        code_snippet="run: make ${{ inputs.target }}",
        confidence=0.7, verified=False, status="needs_review",
    )
    db.add(finding)
    db.commit()
    fid = finding.id
    db.close()

    r = client.post(f"/api/findings/{fid}/verify", json={
        "mode": "url", "base_url": "http://127.0.0.1:18080", "endpoints": ["/"]})

    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is False
    db = SessionLocal()
    stored = db.get(Finding, fid)
    assert stored.status == "needs_review"
    assert stored.verified is False
    db.close()


def test_report_generation_preserves_evidence_tool_calls(monkeypatch, tmp_path):
    captured = {}

    def fake_summary(self, project_ctx, scan_ctx, findings, stats):
        return {
            "executive_summary": "ok",
            "overall_risk": "high",
            "static_summary": "ok",
            "dynamic_summary": "ok",
            "workflow_summary": [],
            "remediation_plan": [],
            "key_risks": [],
            "conclusion": "ok",
        }

    def fake_generate(project_ctx, scan_ctx, findings, summary, fmt="html", **kwargs):
        captured["findings"] = findings
        captured["report_options"] = kwargs.get("options")
        captured["report_id"] = kwargs.get("report_id")
        output = tmp_path / "report.html"
        output.write_text("ok", encoding="utf-8")
        return output

    monkeypatch.setattr("backend.api.routes_reports.SummaryAgent.run", fake_summary)
    monkeypatch.setattr("backend.api.routes_reports.report_builder.generate", fake_generate)

    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name="report_tool_calls_demo", source_type="local",
        local_path="examples/vulnerable_projects/demo_flask_app", status="created",
        metadata_json=json.dumps({"languages": ["Python"]}, ensure_ascii=False),
    )
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan)
    db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21, code_snippet="cursor.execute(sql)",
        confidence=0.7, verified=True, status="confirmed",
        detail_json=json.dumps({"_verify": {}}, ensure_ascii=False),
    )
    db.add(finding)
    db.commit()
    db.add(Evidence(
        id=ids.evidence_id(), finding_id=finding.id,
        source=json.dumps("uid"), sink=json.dumps("cursor.execute"), data_flow=json.dumps([]),
        poc_result=json.dumps({
            "tool_calls": [
                {"name": "verify_source_sink", "success": True},
                {"name": "retrieve_security_knowledge", "success": True},
            ],
            "runtime": {"reproduction_status": "not_executed"},
        }, ensure_ascii=False),
        logs=json.dumps([], ensure_ascii=False),
    ))
    db.commit()
    scan_id = scan.id
    db.close()

    response = client.post("/api/reports", json={"scan_id": scan_id, "format": "html"})

    assert response.status_code == 200
    assert captured["report_id"]
    assert captured["report_options"] == {"include_poc": True, "include_fix": True}
    evidence = captured["findings"][0]["evidence"]
    assert [tool["name"] for tool in evidence["tool_calls"]] == [
        "verify_source_sink",
        "retrieve_security_knowledge",
    ]


def test_report_rejects_unsupported_format():
    response = client.post(
        "/api/reports", json={"scan_id": "scan-does-not-matter", "format": "docx"},
    )
    assert response.status_code == 422


def test_download_revokes_historical_poc_report_after_finding_label(monkeypatch, tmp_path):
    """A report generated while confirmed cannot leak its old PoC after a downgrade."""
    monkeypatch.setattr("backend.rag.feedback_learner.ingest_feedback", lambda *_args: True)
    monkeypatch.setattr("backend.api.routes_reports.SummaryAgent.run", lambda *_args: {})

    def fake_generate(*_args, **_kwargs):
        output = tmp_path / "historical-poc.html"
        output.write_text("<pre>print('historical formal poc')</pre>", encoding="utf-8")
        return output

    monkeypatch.setattr("backend.api.routes_reports.report_builder.generate", fake_generate)
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="historical_report_revoke", source_type="local", status="created")
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21, confidence=0.99, verified=True, status="confirmed",
    )
    db.add_all([project, scan, finding])
    db.add(Evidence(
        id=ids.evidence_id(), finding_id=finding.id, source=json.dumps({"file": "app.py", "line": 20}),
        sink=json.dumps({"file": "app.py", "line": 21}), data_flow=json.dumps([]), logs="[]",
        poc_result=json.dumps({
            "exploit": {"exploit_code": "print('historical formal poc')"},
            "attack_plan": {"code": "print('historical formal poc')"},
            "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
            "artifacts": {"validated_poc": {"persistence_status": "persisted", "sha256": "a" * 64}},
        }),
    ))
    db.commit()
    scan_id, finding_id = scan.id, finding.id
    db.close()

    created = client.post("/api/reports", json={"scan_id": scan_id, "format": "html"})
    assert created.status_code == 200
    report_id = created.json()["report_id"]
    assert client.post(f"/api/findings/{finding_id}/label", json={"label": "false_positive"}).status_code == 200

    blocked = client.get(f"/api/reports/{report_id}/download")
    assert blocked.status_code in {409, 410}
    assert "historical formal poc" not in blocked.text


def test_download_allows_confirmed_report_with_valid_persisted_poc(tmp_path):
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="report_download_valid", source_type="local", status="created")
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    finding = Finding(id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
                      file_path="app.py", start_line=21, confidence=0.99, verified=True, status="confirmed")
    output = tmp_path / "valid-report.html"
    output.write_text("<pre>print('validated replay')</pre>", encoding="utf-8")
    report = Report(id=ids.report_id(), scan_id=scan.id, format="html", file_path=str(output))
    db.add_all([project, scan, finding, report])
    db.add(Evidence(
        id=ids.evidence_id(), finding_id=finding.id, source=json.dumps({"file": "app.py", "line": 20}),
        sink=json.dumps({"file": "app.py", "line": 21}), data_flow="[]", logs="[]",
        poc_result=json.dumps({
            "exploit": {"exploit_code": "print('validated replay')"},
            "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
            "artifacts": {"validated_poc": {"persistence_status": "persisted", "sha256": "b" * 64}},
        }),
    ))
    db.commit()
    report_id = report.id
    db.close()

    response = client.get(f"/api/reports/{report_id}/download")
    assert response.status_code == 200
    assert "validated replay" in response.text


def test_download_allows_downgraded_report_without_poc_code(tmp_path):
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="report_download_no_code", source_type="local", status="created")
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    finding = Finding(id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
                      file_path="app.py", start_line=21, confidence=0.2, verified=False, status="false_positive")
    output = tmp_path / "summary-only.html"
    output.write_text("<h1>Executive summary only</h1>", encoding="utf-8")
    report = Report(id=ids.report_id(), scan_id=scan.id, format="html", file_path=str(output))
    db.add_all([project, scan, finding, report])
    db.commit()
    report_id = report.id
    db.close()

    response = client.get(f"/api/reports/{report_id}/download")
    assert response.status_code == 200
    assert "Executive summary only" in response.text


def test_list_scans_and_search_by_project_name():
    """GET /api/scans 作为历史记录的后端数据源，可按项目名/ID/scan_id 搜索。"""
    # 用唯一 token 命名，避免持久测试库里同名旧数据 + limit 截断导致搜不到本条（测试隔离）
    uniq = ids.project_id().replace("proj_", "")
    proj_name = f"scan_history_demo_{uniq}"
    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name=proj_name, source_type="git",
        url="https://github.com/example/scan-history-demo", status="created",
    )
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="deep", status="done",
                progress=100)
    db.add(scan)
    db.commit()
    scan_id, project_name = scan.id, project.name
    db.close()

    # 全量列表可用（未开始/新扫描优先展示）
    r = client.get("/api/scans")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    # 按唯一 token 模糊搜索能命中，且回带项目名/target
    r2 = client.get("/api/scans", params={"q": uniq})
    assert r2.status_code == 200
    hits = r2.json()["scans"]
    assert any(s["scan_id"] == scan_id for s in hits)
    hit = next(s for s in hits if s["scan_id"] == scan_id)
    assert hit["project_name"] == project_name
    assert hit["target"] == "https://github.com/example/scan-history-demo"

    # 按 scan_id 精确搜索能命中
    r3 = client.get("/api/scans", params={"q": scan_id})
    assert any(s["scan_id"] == scan_id for s in r3.json()["scans"])

    # 无关键词无命中
    r4 = client.get("/api/scans", params={"q": "no_such_project_xyz_123"})
    assert all(s["scan_id"] != scan_id for s in r4.json()["scans"])


def test_delete_scan_cascades_findings_and_evidence():
    """DELETE /api/scans/{id} 应级联删除扫描及其 findings/evidence，历史页删除按钮才不留死数据。"""
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="del_demo_proj", source_type="local",
                      local_path="x", status="created")
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan)
    db.commit()
    finding = Finding(id=ids.finding_id(), scan_id=scan.id, type="SQL Injection",
                      severity="high", file_path="a.py", start_line=1, confidence=0.7,
                      status="confirmed")
    db.add(finding)
    db.commit()
    db.add(Evidence(id=ids.evidence_id(), finding_id=finding.id,
                    source=json.dumps("u"), sink=json.dumps("s"),
                    data_flow=json.dumps([]), poc_result=json.dumps({}), logs=json.dumps([])))
    db.commit()
    scan_id, finding_id = scan.id, finding.id
    db.close()

    # 删除前存在
    assert client.get(f"/api/scans/{scan_id}").status_code == 200

    # 删除
    r = client.delete(f"/api/scans/{scan_id}")
    assert r.status_code == 200 and r.json()["deleted"] == scan_id

    # 扫描与级联数据均已消失
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    check = SessionLocal()
    assert check.get(Finding, finding_id) is None
    check.close()

    # 重复删除返回 404
    assert client.delete(f"/api/scans/{scan_id}").status_code == 404


def test_label_finding_ingests_human_feedback(tmp_path, monkeypatch):
    """人工标注端点：把真漏洞/误报（黄金 ground truth）录入 RAG 自进化知识库。"""
    import backend.rag.retriever as R
    monkeypatch.setattr(R, "feedback_dir", lambda: tmp_path)
    R.load_default_items.cache_clear()


    db = SessionLocal()
    project = Project(id=ids.project_id(), name="label_demo", source_type="local",
                      local_path="x", status="created")
    db.add(project); db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan); db.commit()
    finding = Finding(id=ids.finding_id(), scan_id=scan.id, type="Command Injection",
                      severity="high", file_path="a.py", start_line=1, confidence=0.6,
                      status="needs_review",
                      detail_json=json.dumps({"detail": {"source": "request.args", "sink": "os.system"}},
                                             ensure_ascii=False))
    db.add(finding); db.commit()
    fid = finding.id
    db.close()

    # 非法 label -> 400
    assert client.post(f"/api/findings/{fid}/label", json={"label": "maybe"}).status_code == 400
    # 人工标注真漏洞 -> 录入
    r = client.post(f"/api/findings/{fid}/label", json={"label": "true_positive"})
    assert r.status_code == 200
    body = r.json()
    assert body["label_source"] == "human" and body["learned"] is True
    assert (tmp_path / "learned_feedback.json").exists()
    # 标注误报 -> 落库并录入
    r2 = client.post(f"/api/findings/{fid}/label", json={"label": "false_positive"})
    assert r2.json()["learned"] is True
    R.load_default_items.cache_clear()


def test_label_false_positive_revokes_persisted_poc_from_api_detail_and_evidence(monkeypatch):
    """状态降级后，当前 API 视图不能再泄露已保存 PoC 的任何代码。"""
    monkeypatch.setattr("backend.rag.feedback_learner.ingest_feedback", lambda *_args: True)
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="revoke_poc", source_type="local", status="created")
    db.add(project); db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan); db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21, code_snippet="cursor.execute(query)",
        confidence=0.99, verified=True, status="confirmed",
    )
    db.add(finding); db.commit()
    db.add(Evidence(
        id=ids.evidence_id(), finding_id=finding.id, source=json.dumps({"file": "app.py", "line": 20}),
        sink=json.dumps({"file": "app.py", "line": 21}), data_flow=json.dumps([]), logs=json.dumps([]),
        poc_result=json.dumps({
            "exploit": {"exploit_code": "print('persisted formal poc')"},
            "attack_plan": {"code": "print('persisted plan')"},
            "harness": {"harness_code": "print('persisted harness')"},
            "artifacts": {"validated_poc": {"persistence_status": "persisted", "sha256": "a" * 64}},
            "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
        }),
    ))
    db.commit(); finding_id = finding.id; db.close()

    before = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert before["exploit"]["exploit_code"] == "print('persisted formal poc')"
    assert before["attack_plan"]["code"] == "print('persisted plan')"

    response = client.post(f"/api/findings/{finding_id}/label", json={"label": "false_positive"})
    assert response.status_code == 200

    detail = client.get(f"/api/findings/{finding_id}").json()
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert detail["verification"]["status"] == "false_positive"
    assert "persisted formal poc" not in json.dumps(detail)
    assert evidence["exploit"]["exploit_code"] is None
    assert evidence["attack_plan"]["code"] is None
    assert evidence["harness"]["harness_code"] is None
    assert evidence["artifacts"]["validated_poc"]["sha256"] == "a" * 64
    assert evidence["artifacts"]["validated_poc"]["revoked_by_finding_status"] == "false_positive"


def test_label_out_of_scope_revokes_persisted_poc(monkeypatch):
    """All non-confirmed product labels must revoke a previously persisted PoC."""
    monkeypatch.setattr("backend.rag.feedback_learner.ingest_feedback", lambda *_args: True)
    db = SessionLocal()
    project = Project(id=ids.project_id(), name="out_of_scope_poc", source_type="local", status="created")
    db.add(project); db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan); db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21, code_snippet="cursor.execute(query)",
        confidence=0.99, verified=True, status="confirmed",
    )
    db.add(finding); db.commit()
    db.add(Evidence(
        id=ids.evidence_id(), finding_id=finding.id, source="null", sink="null", data_flow="[]", logs="[]",
        poc_result=json.dumps({
            "attack_plan": {"code": "print('persisted plan')"},
            "runtime": {},
            "artifacts": {"validated_poc": {"persistence_status": "persisted", "sha256": "b" * 64}},
            "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
        }),
    ))
    db.commit(); finding_id = finding.id; db.close()

    response = client.post(f"/api/findings/{finding_id}/label", json={"label": "out_of_scope"})

    assert response.status_code == 200
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()["evidence"]
    assert evidence["attack_plan"]["code"] is None
    assert evidence["artifacts"]["validated_poc"]["revoked_by_finding_status"] == "out_of_scope"
