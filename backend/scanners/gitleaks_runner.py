"""Gitleaks 扫描器封装（硬编码密钥扫描）。"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding
from backend.scanners.semgrep_runner import normalize_result_path, read_source_snippet


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    cli = "gitleaks"

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            report_path = tf.name
        cmd = ["gitleaks", "detect", "--source", str(target),
               "--report-format", "json", "--report-path", report_path,
               "--no-git", "--exit-code", "0"]
        self._exec(cmd, timeout=600)
        findings: list[RawFinding] = []
        try:
            data = json.loads(Path(report_path).read_text(encoding="utf-8") or "[]")
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError("gitleaks did not produce a readable JSON report") from exc
        for r in data:
            start_line = r.get("StartLine", 0)
            rel_path = normalize_result_path(target, r.get("File", ""))
            source_snippet = read_source_snippet(target, r.get("File", ""), start_line, r.get("EndLine") or start_line)
            findings.append(RawFinding(
                type="Hardcoded Secret",
                file=rel_path,
                line=start_line,
                severity="high",
                source=self.name,
                code_snippet=_redact_secret_snippet(source_snippet, r.get("Secret", "")),
                message=f"检测到疑似密钥: {r.get('RuleID', '')}",
                rule_id=r.get("RuleID", ""),
                extra={
                    "raw_match": r.get("Match", ""),
                    "description": r.get("Description", ""),
                    "fingerprint": r.get("Fingerprint", ""),
                    "tags": r.get("Tags", []),
                },
            ))
        return findings


def _redact_secret_snippet(snippet: str, secret: str = "") -> str:
    if not snippet:
        return ""
    secret = str(secret or "")
    redacted_lines = []
    for line in snippet.splitlines():
        if secret:
            line = line.replace(secret, "<redacted>")
        if "=" in line or ":" in line:
            redacted_lines.append(line[:160])
        else:
            redacted_lines.append(line[:80] + ("..." if len(line) > 80 else ""))
    return "\n".join(redacted_lines)
