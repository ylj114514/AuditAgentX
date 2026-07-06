"""Gitleaks 扫描器封装（硬编码密钥扫描）。"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding


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
        except (json.JSONDecodeError, OSError):
            return []
        for r in data:
            findings.append(RawFinding(
                type="Hardcoded Secret",
                file=r.get("File", ""),
                line=r.get("StartLine", 0),
                severity="high",
                source=self.name,
                code_snippet=r.get("Match", "")[:200],
                message=f"检测到疑似密钥: {r.get('RuleID', '')}",
                rule_id=r.get("RuleID", ""),
            ))
        return findings
