"""静态扫描（自定义规则）测试 —— 无需外部工具与 LLM。"""
import json
from pathlib import Path
from types import SimpleNamespace

from backend.scanners.custom_rules import CustomRuleScanner
from backend.scanners.gitleaks_runner import _redact_secret_snippet
from backend.scanners.semgrep_runner import SemgrepScanner

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
