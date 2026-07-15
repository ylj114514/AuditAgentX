import json
from pathlib import Path
from types import SimpleNamespace

from backend.report import report_builder


def _confirmed_finding():
    return {
        "finding_id": "f-report", "type": "SQL Injection", "severity": "high",
        "file": "app.py", "start_line": 21, "status": "confirmed", "verified": True,
        "_evidence": {
            "call_path": [
                {"stage": "source", "file": "app.py", "line": 18, "symbol": "search", "detail": "request.args[id]"},
                {"stage": "sink", "file": "app.py", "line": 21, "symbol": "execute", "detail": "cursor.execute"},
            ],
            "source": {"file": "app.py", "line": 18, "symbol": "search"},
            "sink": {"file": "app.py", "line": 21, "symbol": "cursor.execute"},
            "data_flow": [
                {"stage": "source", "detail": "request.args[id]"},
                {"stage": "sink", "detail": "cursor.execute(query)"},
            ],
            "exploit": {
                "preconditions": ["Authenticated user"],
                "exploit_path": ["Submit crafted id", "Reach SQL sink"],
                "payloads": ["1' OR '1'='1"],
                "exploit_code": "import httpx\n# exact confirmed request",
                "impact": "Read arbitrary user records",
                "verification_method": "Compare baseline and attack responses",
            },
            "runtime": {
                "reproduction_status": "dynamic_confirmed", "reproducible": True,
                "request": {
                    "method": "GET", "url": "http://127.0.0.1/search?id=1",
                    "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.abc.signature"},
                },
                "baseline_record": {"status": 200, "response_excerpt": "[]"},
                "attack_record": {"status": 200, "response_excerpt": "[{\"token\":\"eyJhbGciOiJIUzI1NiJ9.abc.signature\"}]"},
                "confirmation_record": {"matched_indicator": "multiple rows"},
                "elapsed_seconds": 0.12,
            },
            "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
            "knowledge": {
                "cwe_id": "CWE-89", "owasp": ["A03:2021-Injection"],
                "remediation": ["Use parameterized queries."],
            },
            "poc_file": {"path": "pocs/f-report.md", "sha256": "abc123"},
            "artifacts": {
                "validated_poc": {
                    "persistence_status": "persisted", "sha256": "abc123",
                },
            },
            "reproduction_metadata": {
                "source_commit": "deadbeef", "sandbox_image": "target:verified",
                "request_hash": "reqhash", "response_hash": "resphash",
            },
        },
    }


def test_structured_reports_preserve_required_dynamic_contract():
    ctx = report_builder.build_context(
        {"name": "demo"}, {
            "id": "scan-report", "scan_type": "deep", "status": "partial_completed",
            "config": {
                "scan_mode": "deep",
                "scanner_status": [{
                    "tool": "semgrep", "success": True, "partial_results": True,
                    "finding_count": 1, "error": "one parser warning",
                }],
                "options": {"max_files": 20000, "include_test_findings": False},
            },
        },
        [_confirmed_finding()], {"dynamic_breakdown": {}, "remediation_plan": []},
        report_id="report-contract",
    )

    assert ctx["schema_version"] == "1.0.0"
    assert ctx["report"]["id"] == "report-contract"
    assert ctx["report"]["completeness"] == "partial"
    assert ctx["toc"][0] == {
        "level": 2, "title": "1. 执行摘要", "anchor": "executive-summary",
    }
    assert next(item for item in ctx["toc"] if item["anchor"] == "scope-config")["level"] == 3
    assert any(item["anchor"] == "finding-details" for item in ctx["toc"])
    assert ctx["metrics"]["by_status"]["confirmed"] == 1
    assert ctx["metrics"]["actionable_total"] == 1
    assert ctx["metrics"]["dynamically_verified"] == 1
    assert ctx["methodology"]["tools"][0]["status"] == "partial"
    assert ctx["limitations"]
    normalized = ctx["findings"][0]
    assert not any(key.startswith("_") for key in normalized)
    assert normalized["severity"] == "high"
    assert normalized["evidence"]["call_path"][1]["detail"] == "cursor.execute"
    assert normalized["classification"]["cwe"] == "CWE-89"
    assert normalized["exploit_chain"]["status"] == "confirmed"
    assert normalized["evidence"]["evidence_complete"] is True
    assert normalized["evidence"]["actionable"] is True
    assert normalized["evidence"]["exploitable"] is True
    assert normalized["exploit_chain"]["stages"]
    assert "<redacted>" in json.dumps(normalized["evidence"]["runtime"], ensure_ascii=False)
    assert "eyJhbGci" not in json.dumps(ctx, ensure_ascii=False)
    assert "parameterized" in normalized["fix_suggestion"]

    markdown = report_builder.render_markdown(ctx)
    html = report_builder.render_html(ctx)
    structured = json.loads(json.dumps(ctx, ensure_ascii=False))
    assert "## 目录" in markdown
    assert '<ul class="toc"' in markdown
    assert 'class="toc-level-3"' in markdown
    assert '<a href="#executive-summary">1. 执行摘要</a>' in markdown
    assert "### 2.1 审计范围与配置" in markdown
    assert '<nav class="toc" aria-label="目录">' in html
    assert 'href="#finding-details"' in html
    assert 'id="finding-details"' in html
    assert '<h3 id="scope-config">2.1 审计范围与配置</h3>' in html
    for output in (markdown, html):
        assert "SQL Injection" in output
        assert "cursor.execute" in output
        assert "exact confirmed request" in output
        assert "Use parameterized queries" in output
        assert "pocs/f-report.md" in output
        assert "target:verified" in output
        assert "漏洞利用链" in output
        assert "工具执行矩阵" in output
        assert "限制与覆盖缺口" in output
    assert structured["findings"][0]["evidence"]["verification"]["dynamically_verified"] is True


def test_report_options_can_omit_poc_and_fix_content():
    ctx = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "scan_type": "deep", "status": "done"},
        [_confirmed_finding()], {},
        report_id="report-options",
        options={"include_poc": False, "include_fix": False},
    )

    finding = ctx["findings"][0]
    assert finding["fix_suggestion"] is None
    assert "exploit_code" not in finding["evidence"]["exploit"]
    assert "payloads" not in finding["evidence"]["exploit"]
    assert "poc_file" not in finding["evidence"]


def test_report_actionable_metrics_require_confirmed_complete_evidence():
    confirmed = _confirmed_finding()
    confirmed["_evidence"]["runtime"] = {
        "reproduction_status": "blocked", "reason": "authentication_failed",
    }
    confirmed["_evidence"]["verification"] = {
        "static_verdict": "confirmed", "final_verdict": "confirmed",
        "dynamically_verified": False,
    }
    candidate = _confirmed_finding()
    candidate["finding_id"] = "f-candidate"
    candidate["status"] = "candidate"
    needs_review = _confirmed_finding()
    needs_review["finding_id"] = "f-function"
    needs_review["status"] = "needs_review"
    needs_review["_evidence"]["verification"] = {
        "final_verdict": "needs_review", "dynamically_verified": False,
        "evidence_level": "function_unit_reproduced",
    }
    needs_review["_evidence"]["harness"] = {"verdict": "function_reproduced"}

    ctx = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "status": "done"},
        [confirmed, candidate, needs_review], {},
    )

    by_id = {item["finding_id"]: item for item in ctx["findings"]}
    assert ctx["metrics"]["actionable_total"] == 1
    assert by_id["f-report"]["evidence"]["actionable"] is True
    assert by_id["f-candidate"]["evidence"]["actionable"] is False
    assert by_id["f-function"]["evidence"]["exploitable"] is False
    assert "exploit_code" not in by_id["f-function"]["evidence"]["exploit"]


def test_report_keeps_static_confirmed_validation_metadata_separate_from_confirmed_poc():
    finding = _confirmed_finding()
    finding["_evidence"].pop("poc_file")
    finding["_evidence"].pop("artifacts")
    finding["_evidence"]["verification"] = {
        "static_verdict": "confirmed", "final_verdict": "statically_verified",
        "dynamically_verified": False,
    }
    finding["_evidence"]["attack_plan"] = {
        "plan_status": "static_confirmed_pending_runtime",
        "label": "静态已确认；待运行验证",
        "code": None,
        "code_kind": "candidate_metadata",
        "generation_status": "validation_pending",
        "execution_scope": "localhost_only",
    }

    ctx = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "status": "done"}, [finding], {},
    )

    plan = ctx["findings"][0]["evidence"]["attack_plan"]
    assert plan["plan_status"] == "static_confirmed_pending_runtime"
    assert plan["code"] is None
    assert "poc_file" not in ctx["findings"][0]["evidence"]
    availability = ctx["findings"][0]["evidence_availability"]
    assert availability["exploit_plan"] == "planned"
    assert availability["confirmed_poc"] == "not_available"
    assert availability["exploit"] == "planned"


def test_report_hides_candidate_code_even_in_legacy_evidence():
    finding = _confirmed_finding()
    finding["status"] = "needs_review"
    finding["verified"] = False
    finding["_evidence"]["verification"] = {"final_verdict": "needs_review", "dynamically_verified": False}
    finding["_evidence"]["exploit"]["exploit_code"] = "print('candidate')"
    finding["_evidence"]["attack_plan"] = {"plan_status": "candidate_plan_pending_review", "code": "print('candidate')"}

    ctx = report_builder.build_context({"name": "demo"}, {"id": "scan-report"}, [finding], {})

    evidence = ctx["findings"][0]["evidence"]
    assert evidence["exploit"].get("exploit_code") is None
    assert evidence["attack_plan"]["code"] is None


def test_report_only_marks_confirmed_poc_available_when_artifact_persisted():
    finding = _confirmed_finding()
    finding["_evidence"]["artifacts"] = {
        "validated_poc": {
            "generation_status": "generated", "validation_status": "validated",
            "persistence_status": "persistence_failed", "name": "f-report.md",
            "sha256": None, "failure_code": "artifact_persistence_failed",
        }
    }

    failed = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "status": "done"}, [finding], {},
    )["findings"][0]["evidence_availability"]
    assert failed["confirmed_poc"] == "persistence_failed"

    finding["_evidence"]["artifacts"]["validated_poc"].update({
        "persistence_status": "persisted", "sha256": "a" * 64,
    })
    persisted = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "status": "done"}, [finding], {},
    )["findings"][0]["evidence_availability"]
    assert persisted["confirmed_poc"] == "available"


def test_report_hides_confirmed_code_without_persisted_hashed_artifact():
    """A confirmed label alone never authorizes code exposure."""
    finding = _confirmed_finding()
    finding["_evidence"]["exploit"]["exploit_code"] = "print('unpersisted confirmed exploit')"
    finding["_evidence"]["attack_plan"] = {"code": "print('unpersisted confirmed plan')"}
    finding["_evidence"]["harness"] = {"harness_code": "print('unpersisted confirmed harness')"}

    for artifact in (
        {"persistence_status": "persistence_failed", "sha256": "a" * 64},
        {"persistence_status": "persisted", "sha256": None},
    ):
        finding["_evidence"]["artifacts"] = {"validated_poc": artifact}
        ctx = report_builder.build_context(
            {"name": "demo"}, {"id": "scan-report", "status": "done"}, [finding], {},
        )

        rendered = json.dumps(ctx, ensure_ascii=False)
        assert "unpersisted confirmed exploit" not in rendered
        assert "unpersisted confirmed plan" not in rendered
        assert "unpersisted confirmed harness" not in rendered


def test_report_marks_legacy_poc_hash_unverified_and_omits_all_poc_code():
    finding = _confirmed_finding()
    finding["_evidence"].pop("artifacts")
    finding["_evidence"]["poc_file"] = {"sha256": "legacy-hash", "name": "legacy.md"}
    finding["_evidence"]["exploit"]["exploit_code"] = "print('legacy exploit')"
    finding["_evidence"]["attack_plan"] = {
        "code": "print('legacy plan')",
        "nested": {"harness_code": "print('nested legacy harness')"},
    }
    finding["_evidence"]["harness"] = {"harness_code": "print('legacy harness')"}

    ctx = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "status": "done"}, [finding], {},
    )

    normalized = ctx["findings"][0]
    assert normalized["evidence_availability"]["confirmed_poc"] == "unavailable_unverified_legacy"
    rendered = json.dumps(ctx, ensure_ascii=False)
    assert "legacy exploit" not in rendered
    assert "legacy plan" not in rendered
    assert "legacy harness" not in rendered
    assert "nested legacy harness" not in rendered
    assert "legacy exploit" not in report_builder.render_markdown(ctx)
    assert "legacy exploit" not in report_builder.render_html(ctx)


def test_report_rejects_whitespace_validated_poc_hash_and_omits_poc_code():
    """A non-empty-looking but invalid hash must not release a confirmed PoC."""
    finding = _confirmed_finding()
    finding["_evidence"]["artifacts"]["validated_poc"]["sha256"] = "   "
    finding["_evidence"]["exploit"]["exploit_code"] = "print('whitespace hash exploit')"
    finding["_evidence"]["attack_plan"] = {
        "code": "print('whitespace hash plan')",
        "nested": {"harness_code": "print('nested whitespace hash harness')"},
    }
    finding["_evidence"]["harness"] = {"harness_code": "print('whitespace hash harness')"}

    ctx = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "status": "done"}, [finding], {},
    )

    normalized = ctx["findings"][0]
    assert normalized["evidence_availability"]["confirmed_poc"] == "unavailable_unverified"
    rendered = json.dumps(ctx, ensure_ascii=False)
    assert "whitespace hash exploit" not in rendered
    assert "whitespace hash plan" not in rendered
    assert "whitespace hash harness" not in rendered
    assert "nested whitespace hash harness" not in rendered


def test_report_does_not_make_confirmed_complete_without_a_location():
    finding = _confirmed_finding()
    finding["file"] = None
    finding["start_line"] = None
    finding["_evidence"].pop("source")
    finding["_evidence"].pop("sink")
    finding["_evidence"]["call_path"] = []
    finding["_evidence"]["data_flow"] = []
    finding["_evidence"]["exploit"].pop("trigger_location", None)

    ctx = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "status": "done"}, [finding], {},
    )

    evidence = ctx["findings"][0]["evidence"]
    assert evidence["evidence_complete"] is False
    assert evidence["actionable"] is False
    assert ctx["metrics"]["actionable_total"] == 0


def test_report_artifacts_use_report_id_and_do_not_overwrite(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(report_builder, "settings", SimpleNamespace(data_path=tmp_path))
    first = report_builder.generate(
        {"name": "demo"}, {"id": "scan-report", "scan_type": "quick", "status": "done"},
        [], {}, fmt="json", report_id="report-one",
    )
    second = report_builder.generate(
        {"name": "demo"}, {"id": "scan-report", "scan_type": "quick", "status": "done"},
        [], {}, fmt="json", report_id="report-two",
    )

    assert first.name == "report-one.json"
    assert second.name == "report-two.json"
    assert first != second
    assert first.is_file() and second.is_file()
