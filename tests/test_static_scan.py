"""静态扫描（自定义规则）测试 —— 无需外部工具与 LLM。"""
import json
import shutil
import subprocess
import time
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
    _build_semgrep_commands,
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


def test_semgrep_chunks_large_python_batches_without_changing_small_project_mode(tmp_path: Path):
    root = tmp_path / "work"
    rules = root / "rules"
    root.mkdir()
    rules.mkdir()
    (rules / "taint_injection.yaml").write_text("rules: []\n", encoding="utf-8")
    for index in range(41):
        (root / f"module_{index:03}.py").write_text("VALUE = 1\n", encoding="utf-8")

    large = _plan_semgrep_batches(root, rules)
    for name in ("local-python-taint", "python:p/python"):
        batch = next(item for item in large if item["name"] == name)
        commands = _build_semgrep_commands(batch, root)
        assert len(batch["target_files"]) == 41
        assert len(commands) == 2
        assert all("--timeout" in command for _label, command in commands)
        target_operands = [
            operand for _label, command in commands for operand in command
            if operand in batch["target_files"]
        ]
        assert set(target_operands) == set(batch["target_files"])

    small_root = tmp_path / "small"
    small_root.mkdir()
    for index in range(40):
        (small_root / f"module_{index:03}.py").write_text("VALUE = 1\n", encoding="utf-8")
    small = _plan_semgrep_batches(small_root, rules)
    assert "target_files" not in next(item for item in small if item["name"] == "local-python-taint")
    assert "target_files" not in next(item for item in small if item["name"] == "python:p/python")


def test_semgrep_explicit_batches_preserve_github_actions_include_scope(tmp_path: Path):
    rules = tmp_path / "rules"
    workflows = tmp_path / ".github" / "workflows"
    rules.mkdir()
    workflows.mkdir(parents=True)
    for index in range(41):
        (workflows / f"workflow_{index:03}.yml").write_text("name: test\n", encoding="utf-8")
        (tmp_path / f"application_{index:03}.yml").write_text("name: config\n", encoding="utf-8")

    batches = _plan_semgrep_batches(tmp_path, rules)
    workflow_batch = next(item for item in batches if item["name"] == "github-actions:p/github-actions")
    assert len(workflow_batch["target_files"]) == 41
    assert all(".github" in path and "workflows" in path for path in workflow_batch["target_files"])


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


def test_semgrep_workspace_records_exact_large_file_coverage_gap(tmp_path: Path):
    source = tmp_path / "source"
    rules = tmp_path / "rules"
    source.mkdir()
    rules.mkdir()
    (source / "large.py").write_text("x" * 100, encoding="utf-8")

    work_root, _, _, workspace = _prepare_ascii_semgrep_workspace(
        source, rules, max_file_bytes=10,
    )
    try:
        assert workspace["coverage_missing_files"] == [{
            "file": "large.py", "reason": "file_size_limit",
        }]
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


def test_semgrep_workspace_skips_lockfiles_without_creating_coverage_gap(tmp_path: Path):
    source = tmp_path / "source"
    rules = tmp_path / "rules"
    source.mkdir()
    rules.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n" * 100, encoding="utf-8")

    work_root, scan_root, _, workspace = _prepare_ascii_semgrep_workspace(
        source, rules, max_file_bytes=100,
    )
    try:
        assert (scan_root / "app.py").exists()
        assert not (scan_root / "pnpm-lock.yaml").exists()
        assert workspace["skipped_large_files"] == 0
        assert workspace["coverage_missing_files"] == []
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


def test_semgrep_recovers_python_batch_and_marks_only_parser_unsupported_file(monkeypatch, tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    good = source / "good.py"
    bad = source / "bad.py"
    good.write_text("value = 1\n", encoding="utf-8")
    bad.write_text("value = 'unterminated-like payload'\n", encoding="utf-8")
    scanner = SemgrepScanner()

    def fake_exec(command, **_kwargs):
        if any(Path(str(item)).name == "bad.py" for item in command):
            return SimpleNamespace(
                stdout=json.dumps({"results": [], "errors": [{"message": "Lexical error"}]}),
                returncode=0, stderr="",
            )
        return SimpleNamespace(stdout=json.dumps({"results": []}), returncode=0, stderr="")

    monkeypatch.setattr(scanner, "_exec", fake_exec)
    recovered, errors = scanner._retry_failed_file_command(
        {"name": "python:p/python", "config": "p/python", "suffixes": {".py"}},
        ["semgrep", "scan", "--config", "p/python", str(source)],
        tmp_path, source, source, {"PYTHONUTF8": "1"},
    )

    assert recovered == ([], 2)
    assert errors == ["bad.py: Lexical error"]


def test_semgrep_timeout_does_not_trigger_file_by_file_recovery(monkeypatch, tmp_path: Path):
    """A process timeout is a budget failure, not evidence of one bad source file.

    Retrying a timed-out directory scan as 80-file chunks turned one 300-second
    TypeScript timeout into a 19-minute scan on Evershop.  Parser isolation is
    only valid for parser/lexical failures reported by Semgrep.
    """
    (tmp_path / "app.ts").write_text("export const value = 1;\n", encoding="utf-8")
    scanner = SemgrepScanner()
    recovery_calls: list[object] = []

    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)
    monkeypatch.setattr(
        scanner, "_exec",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("semgrep", 300)
        ),
    )
    monkeypatch.setattr(
        scanner,
        "_retry_failed_file_command",
        lambda *_args, **_kwargs: recovery_calls.append(True) or (None, []),
    )

    assert scanner.run(tmp_path) == []
    assert recovery_calls == []
    batch = next(item for item in scanner.batch_status if item["name"] == "typescript:p/typescript")
    assert batch["recovery"] == "not attempted: execution_timeout"
    assert "timed out after 300s" in batch["error"]


def test_static_coverage_gaps_prioritize_custom_findings_for_audit():
    from backend.agents.orchestrator_agent import (
        _apply_static_coverage_priority,
        _collect_static_coverage_gaps,
    )

    statuses = [{
        "tool": "semgrep",
        "workspace": {"coverage_missing_files": [{"file": "large.py", "reason": "file_size_limit"}]},
        "batches": [{"coverage_missing_files": [{"file": "bad.py", "reason": "parser_unsupported"}]}],
    }]
    raw = [
        RawFinding("SQL Injection", "bad.py", 8, "high", "custom", extra={}),
        RawFinding("SQL Injection", "good.py", 8, "high", "custom", extra={}),
    ]

    gaps = _collect_static_coverage_gaps(statuses)
    _apply_static_coverage_priority(raw, gaps)

    assert gaps == [
        {"file": "large.py", "reason": "file_size_limit", "tool": "semgrep"},
        {"file": "bad.py", "reason": "parser_unsupported", "tool": "semgrep"},
    ]
    assert raw[0].extra["static_coverage_gap"] == "parser_unsupported"
    assert raw[0].extra["audit_priority"] == "high"
    assert "static_coverage_gap" not in raw[1].extra


def test_audit_agent_collects_bounded_snippet_for_uncovered_file(tmp_path: Path):
    from backend.agents.audit_agent import AuditAgent

    (tmp_path / "bad.py").write_text("dangerous = request.args['q']\n", encoding="utf-8")
    snippets = AuditAgent._collect_coverage_gap_snippets(
        tmp_path, [{"file": "bad.py", "reason": "parser_unsupported", "tool": "semgrep"}],
    )

    assert snippets == [{
        "file": "bad.py", "coverage_reason": "parser_unsupported",
        "tool": "semgrep", "code": "1 dangerous = request.args['q']",
    }]


def test_semgrep_ascii_workspace_includes_tests_only_when_requested(tmp_path: Path):
    source = tmp_path / "source"
    rules = tmp_path / "rules"
    (source / "tests").mkdir(parents=True)
    (source / "__tests__").mkdir(parents=True)
    rules.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "tests" / "test_app.py").write_text("VALUE = 2\n", encoding="utf-8")
    (source / "__tests__" / "ruleEngine.test.ts").write_text("export const value = 2;\n", encoding="utf-8")
    (source / "widget.spec.ts").write_text("export const value = 3;\n", encoding="utf-8")

    default_work, default_root, _, _ = _prepare_ascii_semgrep_workspace(source, rules)
    included_work, included_root, _, _ = _prepare_ascii_semgrep_workspace(
        source, rules, include_test_findings=True,
    )
    try:
        assert (default_root / "app.py").exists()
        assert not (default_root / "tests" / "test_app.py").exists()
        assert not (default_root / "__tests__" / "ruleEngine.test.ts").exists()
        assert not (default_root / "widget.spec.ts").exists()
        assert (included_root / "tests" / "test_app.py").exists()
        assert (included_root / "__tests__" / "ruleEngine.test.ts").exists()
        assert (included_root / "widget.spec.ts").exists()
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


def test_semgrep_scoped_parser_errors_do_not_retry_every_source_file(monkeypatch, tmp_path: Path):
    (tmp_path / "Privacy.tsx").write_text("export const Privacy = () => null;\n", encoding="utf-8")
    (tmp_path / "Terms.tsx").write_text("export const Terms = () => null;\n", encoding="utf-8")
    scanner = SemgrepScanner()
    retry_calls: list[object] = []

    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)

    def fake_exec(command, **_kwargs):
        scan_root = str(command[-1]).replace("/", "\\")
        return SimpleNamespace(
            stdout=json.dumps({
                "results": [],
                "errors": [
                    {"message": f"Syntax error at line {scan_root}\\Privacy.tsx:1: unsupported syntax"},
                    {"message": f"Syntax error at line {scan_root}\\Terms.tsx:1: unsupported syntax"},
                ],
            }),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(scanner, "_exec", fake_exec)
    monkeypatch.setattr(
        scanner,
        "_retry_failed_file_command",
        lambda *_args, **_kwargs: retry_calls.append(True) or (None, []),
    )

    scanner.run(tmp_path)

    batch = next(item for item in scanner.batch_status if item["name"] == "typescript:p/typescript")
    assert retry_calls == []
    assert batch["coverage_missing_files"] == [
        {"file": "Privacy.tsx", "reason": "parser_unsupported"},
        {"file": "Terms.tsx", "reason": "parser_unsupported"},
    ]
    assert batch["recovery"] == "not required: parser failures already scoped to 2 file(s)"


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


def test_semgrep_local_c_rules_target_copied_source_files(tmp_path: Path):
    (tmp_path / "a.c").write_text("int a(void) { return 1; }\n", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.hpp").write_text("int b();\n", encoding="utf-8")
    work_root, scan_root, rules_root, _ = _prepare_ascii_semgrep_workspace(
        tmp_path, SemgrepScanner.custom_rules_dir,
    )
    try:
        batches = _plan_semgrep_batches(scan_root, rules_root)
    finally:
        import shutil
        shutil.rmtree(work_root, ignore_errors=True)

    local_batch = next(batch for batch in batches if batch["name"] == "local-c-cpp-security")
    assert set(local_batch["target_files"]) == {
        str(scan_root / "a.c"),
        str(scan_root / "nested" / "b.hpp"),
    }


def test_semgrep_retries_failed_local_c_chunk_per_file(monkeypatch, tmp_path: Path):
    (tmp_path / "good.c").write_text("int good(void) { return 1; }\n", encoding="utf-8")
    (tmp_path / "bad.c").write_text("int bad(void) { return 0; }\n", encoding="utf-8")
    local_calls = []

    def fake_exec(self, command, **kwargs):
        config = str(command[command.index("--config") + 1])
        source_files = [Path(item).name for item in command if str(item).endswith(".c")]
        if config.endswith("c_cpp_security.yaml"):
            local_calls.append(source_files)
            if len(source_files) > 1:
                raise RuntimeError("combined C parse failure")
            if source_files == ["bad.c"]:
                raise RuntimeError("bad.c syntax error")
        return SimpleNamespace(stdout=json.dumps({"results": []}), returncode=0, stderr="")

    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)
    monkeypatch.setattr(SemgrepScanner, "_exec", fake_exec)

    scanner = SemgrepScanner()
    scanner.run(tmp_path)

    assert local_calls == [["bad.c", "good.c"], ["bad.c"], ["good.c"]]
    local_batch = next(batch for batch in scanner.batch_status if batch["name"] == "local-c-cpp-security")
    assert local_batch["partial_results"] is True
    assert local_batch["success"] is False
    assert "bad.c syntax error" in local_batch["error"]


def test_semgrep_retries_json_parse_degradation_per_local_c_file(monkeypatch, tmp_path: Path):
    (tmp_path / "good.c").write_text("int good(void) { return 1; }\n", encoding="utf-8")
    (tmp_path / "bad.c").write_text("int bad(void) { return 0; }\n", encoding="utf-8")
    local_calls = []

    def fake_exec(self, command, **kwargs):
        config = str(command[command.index("--config") + 1])
        source_files = [Path(item).name for item in command if str(item).endswith(".c")]
        if config.endswith("c_cpp_security.yaml"):
            local_calls.append(source_files)
            if len(source_files) > 1 or source_files == ["bad.c"]:
                return SimpleNamespace(
                    stdout=json.dumps({"results": [], "errors": [{"message": "C parse warning"}]}),
                    returncode=0, stderr="",
                )
        return SimpleNamespace(stdout=json.dumps({"results": []}), returncode=0, stderr="")

    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)
    monkeypatch.setattr(SemgrepScanner, "_exec", fake_exec)

    scanner = SemgrepScanner()
    scanner.run(tmp_path)

    assert local_calls == [["bad.c", "good.c"], ["bad.c"], ["good.c"]]
    local_batch = next(batch for batch in scanner.batch_status if batch["name"] == "local-c-cpp-security")
    assert local_batch["partial_results"] is True
    assert "bad.c: C parse warning" in local_batch["error"]
    assert "combined C parse" not in local_batch["error"]


def test_semgrep_bisects_degraded_local_c_chunk_before_single_file_retries(monkeypatch, tmp_path: Path):
    for filename in ("bad.c", "good-a.c", "good-b.c", "good-c.c"):
        (tmp_path / filename).write_text("int main(void) { return 0; }\n", encoding="utf-8")
    local_calls = []

    def fake_exec(self, command, **kwargs):
        config = str(command[command.index("--config") + 1])
        source_files = [Path(item).name for item in command if str(item).endswith(".c")]
        if config.endswith("c_cpp_security.yaml"):
            local_calls.append(source_files)
            if "bad.c" in source_files:
                return SimpleNamespace(
                    stdout=json.dumps({"results": [], "errors": [{"message": "C parse warning"}]}),
                    returncode=0, stderr="",
                )
        return SimpleNamespace(stdout=json.dumps({"results": []}), returncode=0, stderr="")

    monkeypatch.setattr(SemgrepScanner, "available", lambda self: True)
    monkeypatch.setattr(SemgrepScanner, "_exec", fake_exec)

    scanner = SemgrepScanner()
    scanner.run(tmp_path)

    assert local_calls == [
        ["bad.c", "good-a.c", "good-b.c", "good-c.c"],
        ["bad.c", "good-a.c"],
        ["bad.c"],
        ["good-a.c"],
        ["good-b.c", "good-c.c"],
    ]
    local_batch = next(batch for batch in scanner.batch_status if batch["name"] == "local-c-cpp-security")
    assert local_batch["partial_results"] is True
    assert "bad.c: C parse warning" in local_batch["error"]


def test_semgrep_c_rule_ids_map_to_readable_types():
    assert _finding_type("rules.auditagentx-c-unsafe-string-copy", {}) == "Buffer Overflow Risk"
    assert _finding_type("rules.auditagentx-c-command-execution", {}) == "Command Execution Risk"
    assert _finding_type("rules.auditagentx-c-format-string-variable", {}) == "Format String"


def test_semgrep_react_dom_rule_id_normalizes_to_dom_xss():
    assert _finding_type("typescript.react.security.react-dangerouslySetInnerHTML", {}) == "DOM XSS"


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


def test_large_java_profile_is_split_into_bounded_semgrep_commands(tmp_path: Path):
    for index in range(201):
        (tmp_path / f"Example{index}.java").write_text("class Example {}\n", encoding="utf-8")

    batches = _plan_semgrep_batches(tmp_path, tmp_path / "missing-rules")
    java_batch = next(batch for batch in batches if batch["name"] == "java:p/java")
    commands = _build_semgrep_commands(java_batch, tmp_path)

    assert len(java_batch["target_files"]) == 201
    assert len(commands) == 2
    assert [sum(value.endswith(".java") for value in command) for _, command in commands] == [200, 1]


def test_static_skill_runs_mcp_tools_in_parallel_and_keeps_skill_order(tmp_path: Path):
    class DelayedServer:
        server_name = "test-mcp"

        def list_tools(self):
            return [{"name": name} for name in (
                "check_static_tool_availability", "run_semgrep", "run_gitleaks", "run_custom_rules",
            )]

        def call_tool(self, name, arguments):
            if name == "check_static_tool_availability":
                return {"structuredContent": {"tools": []}}
            time.sleep(0.2)
            return {"structuredContent": {
                "raw_findings": [],
                "scanner_status": {
                    "tool": {"run_semgrep": "semgrep", "run_gitleaks": "gitleaks",
                             "run_custom_rules": "custom"}[name],
                    "success": True, "finding_count": 0,
                },
            }}

    started = time.perf_counter()
    result = AuditMCPClient(DelayedServer()).run_static_scanning_skill(
        tmp_path, ["semgrep", "gitleaks", "custom"],
        {"tools": ["check_static_tool_availability", "run_semgrep", "run_gitleaks", "run_custom_rules"]},
    )
    elapsed = time.perf_counter() - started

    assert elapsed < 0.45
    assert [item["tool"] for item in result["scanner_status"]] == ["semgrep", "gitleaks", "custom"]
    assert [item["name"] for item in result["tools_used"]] == [
        "check_static_tool_availability", "run_semgrep", "run_gitleaks", "run_custom_rules",
    ]


def test_static_skill_dispatches_bandit_and_trivy_when_selected(tmp_path: Path):
    class ScannerServer:
        server_name = "test-mcp"

        def list_tools(self):
            return [{"name": name} for name in (
                "check_static_tool_availability", "run_bandit", "run_trivy", "run_custom_rules",
            )]

        def call_tool(self, name, _arguments):
            if name == "check_static_tool_availability":
                return {"structuredContent": {"tools": []}}
            scanner = {
                "run_bandit": "bandit", "run_trivy": "trivy", "run_custom_rules": "custom",
            }[name]
            return {"structuredContent": {
                "raw_findings": [],
                "scanner_status": {
                    "tool": scanner, "available": True, "executed": True,
                    "success": True, "finding_count": 0,
                },
            }}

    result = AuditMCPClient(ScannerServer()).run_static_scanning_skill(
        tmp_path, ["bandit", "trivy"],
        {"tools": ["check_static_tool_availability", "run_bandit", "run_trivy", "run_custom_rules"]},
    )

    assert [item["tool"] for item in result["scanner_status"]] == ["bandit", "trivy", "custom"]
    assert [item["name"] for item in result["tools_used"]] == [
        "check_static_tool_availability", "run_bandit", "run_trivy", "run_custom_rules",
    ]


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
