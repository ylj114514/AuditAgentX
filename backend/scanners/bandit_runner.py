"""Bandit 扫描器封装（Python 安全扫描）。"""
from __future__ import annotations

import json
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity, redact_secret_text
from backend.scanners.semgrep_runner import normalize_result_path, read_source_snippet


class BanditScanner(BaseScanner):
    name = "bandit"
    cli = "bandit"

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        cmd = ["bandit", "-r", str(target), "-f", "json", "-q"]
        if not getattr(self, "include_test_findings", False):
            cmd += ["-x", "test,tests,sample,samples,example,examples,demo,docs,doc"]
        proc = self._exec(cmd, timeout=600)
        findings: list[RawFinding] = []
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("bandit did not produce valid JSON") from exc
        if proc.returncode not in (0, 1) and not data.get("results"):
            raise RuntimeError(f"bandit failed with exit={proc.returncode}: {(proc.stderr or '')[:1000]}")
        for r in data.get("results", []):
            filename = r.get("filename", "")
            line = r.get("line_number", 0)
            test_id = str(r.get("test_id") or "")
            confidence = {"high": 0.85, "medium": 0.65, "low": 0.4}.get(
                str(r.get("issue_confidence") or "medium").lower(), 0.65)
            if test_id in {"B401", "B403", "B404", "B405", "B406", "B407", "B408"}:
                confidence = min(confidence, 0.35)  # 仅 import/使用风险库，不等于可利用漏洞
            finding_type = _bandit_type(test_id, r.get("test_name", "bandit-finding"))
            snippet = read_source_snippet(target, filename, line, line) or r.get("code", "")
            if finding_type == "Hardcoded Secret":
                snippet = redact_secret_text(snippet)
            findings.append(RawFinding(
                type=finding_type,
                file=normalize_result_path(target, filename),
                line=line,
                severity=normalize_severity(r.get("issue_severity", "MEDIUM")),
                source=self.name,
                code_snippet=snippet,
                message=r.get("issue_text", ""),
                rule_id=test_id,
                extra={"confidence": confidence, "cwe": r.get("issue_cwe") or {},
                       "more_info": r.get("more_info")},
            ))
        return findings


def _bandit_type(test_id: str, fallback: str) -> str:
    if test_id == "B608":
        return "SQL Injection"
    if test_id in {"B602", "B604", "B605"}:
        return "Command Injection"
    if test_id in {"B301", "B302", "B506"}:
        return "Insecure Deserialization"
    if test_id in {"B105", "B106", "B107"}:
        return "Hardcoded Secret"
    if test_id in {"B401", "B403", "B404", "B405", "B406", "B407", "B408"}:
        return "Risky Security-Sensitive Import"
    return str(fallback or "bandit-finding")
