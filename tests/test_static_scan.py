"""静态扫描（自定义规则）测试 —— 无需外部工具与 LLM。"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.acp.factory import make_message
from backend.acp.models import ACPMessageType
from backend.agents.static_scan_agent import StaticScanAgent
from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.skills.loader import load_skill
from backend.scanners import registry
from backend.scanners.base import RawFinding, is_non_production_path
from backend.scanners.custom_rules import CustomRuleScanner
from backend.scanners.gitleaks_runner import _parse_gitleaks_report, _redact_secret_snippet
from backend.scanners.semgrep_runner import (
    SemgrepScanner,
    _prepare_ascii_semgrep_workspace,
    _finding_type,
    _parse_semgrep_process,
    _plan_semgrep_batches,
)

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_custom_scanner_finds_known_vulns():
    findings = CustomRuleScanner().run(DEMO)
    types = {f.type for f in findings}
    assert "SQL Injection" in types
    assert "Command Injection" in types
    assert "Hardcoded Secret" in types
    assert len(findings) >= 4


def test_semgrep_snippet_uses_source_not_requires_login(monkeypatch, tmp_path: Path):
    workflow = tmp_path / ".github" / "workflows" / "test-ssllib.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: test\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: ${{ inputs.libmake }}\n",
        encoding="utf-8",
    )
    payload = {
        "results": [{
            "check_id": "yaml.github-actions.security.run-shell-injection",
            "path": str(workflow),
            "start": {"line": 5},
            "end": {"line": 5},
            "extra": {
                "lines": "requires login",
                "severity": "ERROR",
                "message": "shell injection",
                "metadata": {"confidence": "LOW", "cwe": ["CWE-78"]},
                "fingerprint": "requires login",
            },
        }]
    }
    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)
    monkeypatch.setattr(SemgrepScanner, "_exec", lambda *a, **k: SimpleNamespace(stdout=json.dumps(payload), returncode=0, stderr=""))

    findings = SemgrepScanner().run(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == ".github/workflows/test-ssllib.yml"
    assert "requires login" not in finding.code_snippet
    assert "${{ inputs.libmake }}" in finding.code_snippet
    assert finding.extra["raw_tool_lines"] == "requires login"
    assert finding.extra["source_snippet"] == finding.code_snippet


def test_gitleaks_snippet_redacts_secret_but_keeps_source_context():
    snippet = "7 API_TOKEN=super-secret-token-12345"

    redacted = _redact_secret_snippet(snippet, "super-secret-token-12345")

    assert "super-secret-token-12345" not in redacted
    assert "API_TOKEN=" in redacted
    assert "<redacted>" in redacted


def test_semgrep_plans_c_cpp_local_rules_and_respects_max_files(tmp_path: Path):
    root = tmp_path / "work"
    src = root / "src"
    rules = root / "rules"
    src.mkdir(parents=True)
    rules.mkdir()
    (rules / "c_cpp_security.yaml").write_text("rules: []\n", encoding="utf-8")
    for index in range(5):
        (src / f"file{index}.c").write_text("strcpy(dst, src);\n", encoding="utf-8")

    batches = _plan_semgrep_batches(src, rules, max_files=3)

    c_batch = next(batch for batch in batches if batch["name"] == "local-c-cpp-security")
    assert c_batch["includes"] == ["**/*.c", "**/*.h"]
    assert len(c_batch["target_files"]) == 3
    assert any(batch["name"] == "c:p/c" for batch in batches)


def test_semgrep_ascii_workspace_respects_max_files(tmp_path: Path):
    source = tmp_path / "source"
    rules = tmp_path / "rules"
    source.mkdir()
    rules.mkdir()
    for index in range(5):
        (source / f"file{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")

    work_root, scan_root, _, workspace = _prepare_ascii_semgrep_workspace(
        source, rules, max_files=2,
    )
    try:
        assert len(list(scan_root.rglob("*.py"))) == 2
        assert workspace["copied_files"] == 2
        assert workspace["truncated"] is True
    finally:
        import shutil
        shutil.rmtree(work_root, ignore_errors=True)


def test_semgrep_ascii_workspace_includes_tests_only_when_requested(tmp_path: Path):
    source = tmp_path / "source"
    rules = tmp_path / "rules"
    (source / "tests").mkdir(parents=True)
    rules.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "tests" / "test_app.py").write_text("VALUE = 2\n", encoding="utf-8")

    default_work, default_root, _, _ = _prepare_ascii_semgrep_workspace(source, rules)
    included_work, included_root, _, _ = _prepare_ascii_semgrep_workspace(
        source, rules, include_test_findings=True,
    )
    try:
        assert (default_root / "app.py").exists()
        assert not (default_root / "tests" / "test_app.py").exists()
        assert (included_root / "tests" / "test_app.py").exists()
    finally:
        import shutil
        shutil.rmtree(default_work, ignore_errors=True)
        shutil.rmtree(included_work, ignore_errors=True)


def test_semgrep_workspace_non_source_files_do_not_consume_budget(tmp_path: Path):
    source = tmp_path / "source"
    rules = tmp_path / "rules"
    source.mkdir()
    rules.mkdir()
    for index in range(5):
        (source / f"aaa{index}.txt").write_text("documentation\n", encoding="utf-8")
    (source / "vulnerable.py").write_text("eval(input())\n", encoding="utf-8")

    work_root, scan_root, _, workspace = _prepare_ascii_semgrep_workspace(
        source, rules, max_files=1,
    )
    try:
        assert (scan_root / "vulnerable.py").exists()
        assert workspace["copied_files"] == 1
    finally:
        import shutil
        shutil.rmtree(work_root, ignore_errors=True)


def test_semgrep_workspace_enforces_byte_limit(tmp_path: Path):
    source = tmp_path / "source"
    rules = tmp_path / "rules"
    source.mkdir()
    rules.mkdir()
    (source / "a.py").write_text("A" * 30, encoding="utf-8")
    (source / "b.py").write_text("B" * 30, encoding="utf-8")

    work_root, _, _, workspace = _prepare_ascii_semgrep_workspace(
        source, rules, max_total_bytes=40,
    )
    try:
        assert workspace["truncated"] is True
        assert "byte limit" in workspace["reason"]
        assert workspace["copied_files"] == 1
    finally:
        import shutil
        shutil.rmtree(work_root, ignore_errors=True)


def test_semgrep_parse_warnings_keep_findings_but_mark_partial(tmp_path: Path):
    source = tmp_path / "src" / "app.c"
    source.parent.mkdir()
    source.write_text("strcpy(dst, src);\n", encoding="utf-8")
    payload = {
        "results": [{
            "check_id": "rules.auditagentx-c-unsafe-string-copy",
            "path": str(source),
            "start": {"line": 1},
            "end": {"line": 1},
            "extra": {
                "lines": "strcpy(dst, src);",
                "severity": "WARNING",
                "message": "unsafe copy",
                "metadata": {"confidence": "MEDIUM", "cwe": "CWE-120"},
            },
        }],
        "errors": [{"level": "warn", "message": f"Syntax error at line {source}:1"}],
    }
    proc = SimpleNamespace(stdout=json.dumps(payload), returncode=0, stderr="")

    findings, degraded = _parse_semgrep_process(tmp_path / "src", proc)

    assert "Syntax error" in degraded
    assert str(tmp_path) not in degraded
    assert "<scan-root>" in degraded
    assert len(findings) == 1
    assert findings[0].type == "Buffer Overflow Risk"


def test_semgrep_runner_records_batch_status(monkeypatch, tmp_path: Path):
    source = tmp_path / "app.c"
    source.write_text("strcpy(dst, src);\n", encoding="utf-8")
    payload = {
        "results": [{
            "check_id": "rules.auditagentx-c-unsafe-string-copy",
            "path": "app.c",
            "start": {"line": 1},
            "end": {"line": 1},
            "extra": {
                "lines": "strcpy(dst, src);",
                "severity": "WARNING",
                "message": "unsafe copy",
                "metadata": {"confidence": "MEDIUM"},
            },
        }]
    }
    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)
    monkeypatch.setattr(
        SemgrepScanner,
        "_exec",
        lambda *a, **k: SimpleNamespace(stdout=json.dumps(payload), returncode=0, stderr=""),
    )

    scanner = SemgrepScanner()
    findings = scanner.run(tmp_path)

    assert findings
    assert any(batch["name"] == "local-c-cpp-security" for batch in scanner.batch_status)
    assert any(batch["success"] for batch in scanner.batch_status)
    local_batch = next(batch for batch in scanner.batch_status if batch["name"] == "local-c-cpp-security")
    assert local_batch["config"] == "local/c_cpp_security.yaml"


def test_semgrep_c_rule_ids_map_to_readable_types():
    assert _finding_type("rules.auditagentx-c-unsafe-string-copy", {}) == "Buffer Overflow Risk"
    assert _finding_type("rules.auditagentx-c-command-execution", {}) == "Command Execution Risk"
    assert _finding_type("rules.auditagentx-c-format-string-variable", {}) == "Format String"


def test_registry_exposes_scanner_batch_status(monkeypatch, tmp_path: Path):
    class BatchScanner:
        batch_status = [{
            "name": "local-c-cpp-security",
            "config": "local/c_cpp_security.yaml",
            "success": True,
            "finding_count": 1,
        }]
        degraded_reason = None

        def available(self):
            return True

        def run(self, target):
            assert self.include_test_findings is True
            return [RawFinding(
                type="Buffer Overflow Risk", file="app.c", line=1,
                severity="medium", source="semgrep",
            )]

    monkeypatch.setitem(registry._SCANNERS, "batch-test", BatchScanner)

    findings, status = registry.run_scanner_tool(
        "batch-test", tmp_path, include_test_findings=True,
    )

    assert len(findings) == 1
    assert status["success"] is True
    assert status["batches"] == BatchScanner.batch_status


def test_registry_rejects_missing_scan_target(tmp_path: Path):
    findings, status = registry.run_scanner_tool(
        "custom", tmp_path / "missing-project",
    )

    assert findings == []
    assert status["executed"] is False
    assert status["success"] is False
    assert status["error"] == "target_not_found"


def test_static_agent_marks_partial_scanner_as_incomplete(monkeypatch, tmp_path: Path):
    agent = StaticScanAgent()

    def fake_run(self, code_root, enabled_tools, **kwargs):
        self.scanner_status = [{
            "tool": "semgrep", "success": True, "partial_results": True,
            "error": "one batch timed out", "finding_count": 1,
        }]
        self.tool_calls = []
        return []

    monkeypatch.setattr(StaticScanAgent, "run", fake_run)
    request = make_message(
        sender="orchestrator", receiver="static_scan_agent",
        message_type=ACPMessageType.STATIC_SCAN_REQUEST,
        payload={"code_root": str(tmp_path), "enabled_tools": ["semgrep"]},
    )

    response = agent.run_acp(request)

    assert response.payload["complete"] is False
    assert response.payload["failed_tools"][0]["tool"] == "semgrep"


def test_static_agent_does_not_hide_skill_load_failure(monkeypatch):
    def fail_load(name):
        raise FileNotFoundError(name)

    monkeypatch.setattr("backend.skills.loader.load_skill", fail_load)

    with pytest.raises(FileNotFoundError):
        StaticScanAgent()


def test_static_skill_reports_unknown_requested_scanner(tmp_path: Path):
    result = AuditMCPClient().run_static_scanning_skill(
        tmp_path, ["unknown-tool"], load_skill("static-scanning"),
    )

    unknown = next(item for item in result["scanner_status"] if item["tool"] == "unknown-tool")
    assert unknown["success"] is False
    assert unknown["error"] == "unknown_scanner"


def test_semgrep_workspace_truncation_marks_scan_partial(monkeypatch, tmp_path: Path):
    (tmp_path / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("VALUE = 2\n", encoding="utf-8")
    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)
    monkeypatch.setattr(
        SemgrepScanner, "_exec",
        lambda *a, **k: SimpleNamespace(
            stdout=json.dumps({"results": []}), returncode=0, stderr="",
        ),
    )
    scanner = SemgrepScanner()
    scanner.max_files = 1

    scanner.run(tmp_path)

    assert scanner.workspace_status["truncated"] is True
    assert "source file limit" in scanner.degraded_reason


def test_semgrep_marks_large_file_skip_as_incomplete_coverage(monkeypatch, tmp_path: Path):
    (tmp_path / "app.py").write_text("VALUE = " + "1" * 600_000, encoding="utf-8")
    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)

    scanner = SemgrepScanner()
    scanner.run(tmp_path)

    assert scanner.workspace_status["skipped_large_files"] == 1
    assert scanner.workspace_status["truncated"] is True
    assert "file size limit" in scanner.degraded_reason


def test_semgrep_marks_zero_rule_batches_as_incomplete_coverage(monkeypatch, tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\n", encoding="utf-8")
    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)

    scanner = SemgrepScanner()
    findings = scanner.run(tmp_path)

    assert findings == []
    assert scanner.workspace_status["coverage_status"] == "not_scanned"
    assert "no applicable rule batches" in scanner.degraded_reason
    assert scanner.batch_status == [{
        "name": "planning",
        "config": None,
        "command_count": 0,
        "target_file_count": 1,
        "success": False,
        "partial_results": False,
        "error": "no applicable rule batches",
        "finding_count": 0,
    }]


def test_non_production_scope_is_shared_by_secret_parser(tmp_path: Path):
    source = tmp_path / "tests" / "config.py"
    source.parent.mkdir()
    source.write_text('TOKEN="example-secret"\n', encoding="utf-8")
    report = [{
        "File": str(source), "StartLine": 1, "EndLine": 1,
        "Secret": "example-secret", "RuleID": "generic-api-key",
    }]

    assert is_non_production_path("tests/config.py") is True
    assert _parse_gitleaks_report(tmp_path, report) == []
    assert len(_parse_gitleaks_report(tmp_path, report, include_test_findings=True)) == 1


def test_command_taint_rule_does_not_treat_regex_escape_as_shell_sanitizer():
    rule = Path("rules/semgrep/taint_injection.yaml").read_text(encoding="utf-8")
    assert "re.escape(...)" not in rule
