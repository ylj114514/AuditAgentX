"""API 冒烟测试（不触发 LLM）。"""
import json

from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal
from backend.core import ids
from backend.models import Evidence, Finding, Project, Scan

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

    r3 = client.get(f"/api/projects/{pid}/tree")
    assert r3.status_code == 200
    body = r3.json()
    assert any(item["path"] == "app.py" for item in body["tree"])
    # /tree 现在返回完整项目结构（供前端"项目结构"页展示）
    assert "Python" in body["languages"]
    assert body["file_count"] >= 1
    assert "dependencies" in body and "entrypoints" in body and "frameworks" in body


def test_verify_finding_api_records_evidence(monkeypatch):
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

    def fake_verify(self, base_url, exploit, endpoints=None):
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
    )
    db.add(finding)
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
    body = r.json()
    assert body["verified"] is True
    assert body["reproducible"] is True
    assert body["matched_indicator"] == "SQL syntax"
    assert body["evidence_id"]

    ev = client.get(f"/api/findings/{fid}/evidence")
    assert ev.status_code == 200
    evidence = ev.json()["evidence"]
    assert evidence["exploit"]["trigger_location"] == "app.py:21"
    assert evidence["runtime"]["reproducible"] is True
    assert evidence["runtime"]["response_status"] == 200

    detail = client.get(f"/api/findings/{fid}")
    assert detail.status_code == 200
    assert detail.json()["verification"]["reproducible"] is True


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

    def fake_verify(self, base_url, exploit, endpoints=None):
        return FakeDynamicResult()

    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", fake_exploit_run)
    monkeypatch.setattr("backend.verifier.dynamic_verifier.DynamicVerifier.verify", fake_verify)

    verify_result = {
        "source": {"file": "app.py", "line": 18, "code": "uid = request.args['id']"},
        "sink": {"file": "app.py", "line": 21, "code": "cur.execute(sql)"},
        "propagation_path": [{"from": "uid", "to": "sql"}],
        "call_path": [{"stage": "source", "file": "app.py", "line": 18}],
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

    def fake_generate(project_ctx, scan_ctx, findings, summary, fmt="html"):
        captured["findings"] = findings
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
    evidence = captured["findings"][0]["evidence"]
    assert [tool["name"] for tool in evidence["tool_calls"]] == [
        "verify_source_sink",
        "retrieve_security_knowledge",
    ]


def test_list_scans_and_search_by_project_name():
    """GET /api/scans 作为历史记录的后端数据源，可按项目名/ID/scan_id 搜索。"""
    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name="scan_history_demo_proj", source_type="git",
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

    # 按项目名模糊搜索能命中，且回带项目名/target
    r2 = client.get("/api/scans", params={"q": "scan_history_demo"})
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
