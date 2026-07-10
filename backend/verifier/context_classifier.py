"""Deterministic context downgrades for findings.

These checks are intentionally conservative: they do not prove a finding safe, but
they define when automated evidence is not strong enough to mark it confirmed.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any


FIXTURE_PARTS = {
    "sample", "samples", "example", "examples", "demo", "demos",
    "test", "tests", "fixture", "fixtures", "benchmark", "benchmarks",
    "doc", "docs",
}
SECRET_FIXTURE_PARTS = {
    "sample-keys", "sample_config_files", "sample-config-files", "testdata",
}
WORKFLOW_PREFIX = ".github/workflows/"

_SHELL_OUTPUT_RE = re.compile(r"\b(echo|printf|cat|logger)\b", re.I)
_WEB_OUTPUT_RE = re.compile(
    r"(innerHTML|document\.write|dangerouslySetInnerHTML|render_template_string|"
    r"res\.(send|write|end)\s*\(|Response\.Write|HttpContext|w\.Write\s*\(|"
    r"fmt\.Fprint(?:f|ln)?\s*\(\s*w\b|<%=|\|\s*safe|html_safe|raw\s*\()",
    re.I,
)
_WORKFLOW_UNTRUSTED_RE = re.compile(
    r"(workflow_dispatch:|pull_request_target:|repository_dispatch:|github\.event\."
    r"(client_payload|issue|comment|pull_request|head_commit)|github\.(head_ref|event\.pull_request\.title)|"
    r"\$\{\{\s*(github\.event|inputs\.))",
    re.I,
)
_WORKFLOW_TRUSTED_INPUT_RE = re.compile(r"\$\{\{\s*inputs\.[A-Za-z0-9_-]+\s*\}\}", re.I)
_PATH_SINK_RE = re.compile(r"\b(open|fopen|readfile|file_get_contents|include|require)\s*\(", re.I)
_USER_SOURCE_RE = re.compile(r"(request|_GET|_POST|params|args\.get|input\s*\(|argv\[|req\.)", re.I)


def classify_finding_context(finding: dict[str, Any], snippet: str | None = None) -> dict[str, Any]:
    """Return context metadata used to block unsafe auto-confirmation."""
    file_path = _norm_path(finding.get("file") or finding.get("file_path") or "")
    vuln_type = str(finding.get("type") or finding.get("vulnerability_type") or "").lower()
    text = "\n".join([
        str(finding.get("code_snippet") or finding.get("vulnerable_code") or ""),
        snippet or "",
    ])
    parts = {p.lower() for p in PurePosixPath(file_path).parts if p not in (".", "")}

    result = {
        "context": "production",
        "risk_modifier": "none",
        "reason": "production path; no deterministic context downgrade matched",
        "allow_confirmed": True,
        "confirmed_blockers": [],
        "dynamic_applicable": True,
    }

    if _is_workflow_path(file_path):
        return _workflow_context(file_path, text)

    if "xss" in vuln_type and _is_non_web_output(file_path, text):
        return _blocked(
            "non_web_output",
            "false_positive",
            "XSS requires browser/HTML/JS/HTTP response output; shell/CLI output is not an XSS sink.",
            dynamic_applicable=False,
        )

    if parts & (FIXTURE_PARTS | SECRET_FIXTURE_PARTS):
        modifier = "informational" if _is_secret(vuln_type) else "downgrade"
        reason = f"{file_path} is under sample/test/demo/docs/fixtures context; automated confirmed is blocked."
        return _blocked("test_fixture", modifier, reason, dynamic_applicable=not _is_secret(vuln_type))

    if _is_secret(vuln_type) and re.search(r"(testing purposes only|sample|example|demo|dummy|test key)", text, re.I):
        return _blocked(
            "test_fixture",
            "informational",
            "Secret-like material is documented as sample/testing/demo data.",
            dynamic_applicable=False,
        )

    if ("path" in vuln_type or "traversal" in vuln_type) and _PATH_SINK_RE.search(text):
        if not _USER_SOURCE_RE.search(text):
            return _blocked(
                "missing_source_to_sink",
                "needs_review",
                "Path Traversal requires attacker-controlled source reaching a file path sink; no source was found.",
            )

    return result


def apply_context_to_finding(finding: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    ctx = context or classify_finding_context(finding)
    finding["context"] = ctx.get("context")
    finding["risk_modifier"] = ctx.get("risk_modifier")
    finding["dynamic_applicable"] = ctx.get("dynamic_applicable", True)
    if not ctx.get("allow_confirmed", True):
        reason = ctx.get("reason") or "context blocks automated confirmation"
        finding["downgrade_reason"] = reason
        finding.setdefault("false_positive_reason", reason if ctx.get("risk_modifier") == "false_positive" else None)
        blockers = list(finding.get("confirmed_blockers") or [])
        blockers.extend(ctx.get("confirmed_blockers") or [reason])
        finding["confirmed_blockers"] = _dedupe(blockers)
        if str(finding.get("status") or "").lower() == "confirmed":
            finding["status"] = "needs_review"
            finding["verified"] = False
    if ctx.get("risk_modifier") == "informational":
        finding["severity"] = "info"
        finding["confidence"] = min(float(finding.get("confidence") or 0.5), 0.65)
    return ctx


def can_auto_confirm(finding: dict[str, Any], context: dict[str, Any] | None = None) -> bool:
    ctx = context or classify_finding_context(finding)
    return bool(ctx.get("allow_confirmed", True))


def _workflow_context(file_path: str, text: str) -> dict[str, Any]:
    if _WORKFLOW_UNTRUSTED_RE.search(text) and not _WORKFLOW_TRUSTED_INPUT_RE.search(text):
        return {
            "context": "github_workflow",
            "risk_modifier": "workflow_untrusted_input",
            "reason": "GitHub Actions finding references an untrusted workflow event/context; manual review required before confirmed.",
            "allow_confirmed": False,
            "confirmed_blockers": ["workflow input trust boundary requires manual validation"],
            "dynamic_applicable": False,
        }
    if _WORKFLOW_TRUSTED_INPUT_RE.search(text):
        return _blocked(
            "github_workflow",
            "needs_review",
            "GitHub Actions reusable workflow inputs are not automatically attacker-controlled; trusted reusable workflow input requires call-site review.",
            dynamic_applicable=False,
        )
    return _blocked(
        "github_workflow",
        "needs_review",
        f"{file_path} is workflow configuration; confirmed requires explicit untrusted event-to-shell flow.",
        dynamic_applicable=False,
    )


def _blocked(context: str, modifier: str, reason: str, *, dynamic_applicable: bool = True) -> dict[str, Any]:
    return {
        "context": context,
        "risk_modifier": modifier,
        "reason": reason,
        "allow_confirmed": False,
        "confirmed_blockers": [reason],
        "dynamic_applicable": dynamic_applicable,
    }


def _is_secret(vuln_type: str) -> bool:
    return any(token in vuln_type for token in ("secret", "credential", "key", "password", "token"))


def _is_non_web_output(file_path: str, text: str) -> bool:
    suffix = PurePosixPath(file_path).suffix.lower()
    if suffix in {".sh", ".bash", ".zsh", ".c", ".h", ".cc", ".cpp"} and _SHELL_OUTPUT_RE.search(text):
        return not _WEB_OUTPUT_RE.search(text)
    return False


def _norm_path(path: str) -> str:
    normalized = str(path).replace("\\", "/").lower()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _is_workflow_path(path: str) -> bool:
    return path.startswith(WORKFLOW_PREFIX) or f"/{WORKFLOW_PREFIX}" in path


def _dedupe(items: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out
