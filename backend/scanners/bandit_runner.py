"""Bandit 扫描器封装（Python 安全扫描）。"""
from __future__ import annotations

import json
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity


class BanditScanner(BaseScanner):
    name = "bandit"
    cli = "bandit"

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        cmd = ["bandit", "-r", str(target), "-f", "json", "-q"]
        proc = self._exec(cmd, timeout=600)
        findings: list[RawFinding] = []
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []
        for r in data.get("results", []):
            findings.append(RawFinding(
                type=r.get("test_name", "bandit-finding"),
                file=r.get("filename", ""),
                line=r.get("line_number", 0),
                severity=normalize_severity(r.get("issue_severity", "MEDIUM")),
                source=self.name,
                code_snippet=r.get("code", ""),
                message=r.get("issue_text", ""),
                rule_id=r.get("test_id", ""),
            ))
        return findings
