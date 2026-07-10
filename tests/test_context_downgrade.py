from __future__ import annotations

from pathlib import Path

from backend.agents.verification_tools import build_verification_context
from backend.agents.verify_agent import VerifyAgent
from backend.verifier.context_classifier import classify_finding_context
from backend.verifier.pipeline import ExploitPipeline


def _pipeline() -> ExploitPipeline:
    return object.__new__(ExploitPipeline)


def test_sample_private_key_context_blocks_confirmed(tmp_path: Path):
    key_file = tmp_path / "sample" / "sample-keys" / "server.key"
    key_file.parent.mkdir(parents=True)
    key_file.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", encoding="utf-8")

    finding = {
        "type": "Hardcoded Secret",
        "file": "sample/sample-keys/server.key",
        "line": 1,
        "severity": "high",
        "code_snippet": "-----BEGIN PRIVATE KEY-----",
    }

    ctx = classify_finding_context(finding)
    assert ctx["allow_confirmed"] is False
    assert ctx["context"] == "test_fixture"
    assert ctx["risk_modifier"] == "informational"

    verification = build_verification_context(finding, tmp_path)
    merged = VerifyAgent._merge_verdict(finding, verification, {"is_valid": True, "confidence": 0.95})
    assert merged["needs_review"] is True
    assert merged["confidence"] <= 0.65
    assert "sample/sample-keys" in merged["confirmed_blockers"][0]


def test_pipeline_does_not_upgrade_fixture_even_when_http_reproduced():
    finding = {
        "type": "Command Injection",
        "file": "tests/test_cli.sh",
        "status": "needs_review",
        "severity": "high",
        "confidence": 0.5,
    }
    dyn_result = {"reproducible": True, "reproduction_status": "dynamic_confirmed", "records": []}

    _pipeline()._assemble(finding, {}, dyn_result, None, None)

    assert finding["status"] == "needs_review"
    assert finding.get("dynamically_verified") is not True
    assert finding["runtime_verification_status"] == "dynamic_confirmed_blocked_by_context"
    assert finding["context"] == "test_fixture"


def test_pipeline_requires_real_target_harness_for_confirmed():
    finding = {
        "type": "Command Injection",
        "file": "src/app.py",
        "status": "needs_review",
        "severity": "high",
        "confidence": 0.5,
    }
    harness = {
        "verdict": "target_confirmed",
        "dynamically_triggered": True,
        "function_extracted": False,
        "target_function_called": True,
        "harness_source": "llm",
        "verification_level": "target_specific",
    }

    _pipeline()._assemble(finding, {}, None, harness, None)

    assert finding["status"] == "needs_review"
    assert finding.get("dynamically_verified") is not True
    assert finding["runtime_verification_status"] == "harness_target_blocked"
    assert any("function_extracted=false" in b for b in finding["confirmed_blockers"])


def test_workflow_reusable_inputs_do_not_confirm_rce():
    finding = {
        "type": "Command Injection",
        "file": ".github/workflows/test-ssllib.yml",
        "line": 42,
        "severity": "high",
        "code_snippet": "run: ./configure ${{ inputs.ssl_library }}",
    }

    ctx = classify_finding_context(finding)
    assert ctx["context"] == "github_workflow"
    assert ctx["allow_confirmed"] is False
    assert "trusted reusable workflow" in ctx["reason"]


def test_absolute_workflow_path_is_classified_as_github_workflow():
    finding = {
        "type": "run-shell-injection",
        "file": r"C:\Users\me\repo\.github\workflows\test-ssllib.yml",
        "line": 88,
        "severity": "high",
        "code_snippet": "run: make OPENSSL_LIB=${{ inputs.libmake }}",
    }

    ctx = classify_finding_context(finding)

    assert ctx["context"] == "github_workflow"
    assert ctx["allow_confirmed"] is False
    assert ctx["dynamic_applicable"] is False


def test_shell_echo_is_not_xss_sink():
    finding = {
        "type": "XSS",
        "file": "distro/dns-scripts/update-systemd-resolved.sh",
        "line": 12,
        "severity": "medium",
        "code_snippet": "echo \"foreign_option_${i}=dns $trusted_ip\"",
    }

    ctx = classify_finding_context(finding)
    assert ctx["allow_confirmed"] is False
    assert ctx["context"] == "non_web_output"
    assert ctx["risk_modifier"] == "false_positive"


def test_verify_agent_generic_llm_confirmation_without_sast_match_needs_review():
    finding = {
        "type": "insecure-use-strtok-fn",
        "file": "src/openvpn/ssl_ncp.c",
        "line": 177,
        "severity": "medium",
        "code_snippet": "177 token = strtok(NULL, \":\")",
    }
    tool_context = {
        "heuristic_result": {"is_valid": None, "confidence": 0.55},
        "sast_replay": {"matched_rules": [], "snippet_available": True},
        "tools_used": [],
        "context_classification": {
            "context": "production",
            "risk_modifier": "none",
            "allow_confirmed": True,
            "confirmed_blockers": [],
            "reason": "production path",
        },
    }

    merged = VerifyAgent._merge_verdict(finding, tool_context, {"is_valid": True, "confidence": 0.95})

    assert merged["needs_review"] is True
    assert merged["confidence"] <= 0.75
    assert any("deterministic" in b for b in merged["confirmed_blockers"])
