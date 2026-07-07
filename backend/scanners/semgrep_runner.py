"""Semgrep 扫描器封装（通用代码安全规则）。"""
from __future__ import annotations

import json
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    cli = "semgrep"

    # 项目自定义 taint mode 规则目录
    custom_rules_dir = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep"

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        # 官方规则集 auto + 项目自定义 taint 规则（source→sink 污点追踪，降误报）
        cmd = ["semgrep", "scan", "--config", "auto"]
        if self.custom_rules_dir.exists() and any(self.custom_rules_dir.glob("*.y*ml")):
            cmd += ["--config", str(self.custom_rules_dir)]
        cmd += ["--json", "--quiet", str(target)]
        proc = self._exec(cmd, timeout=900)
        findings: list[RawFinding] = []
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            findings.append(RawFinding(
                type=r.get("check_id", "semgrep-finding").split(".")[-1],
                file=r.get("path", ""),
                line=r.get("start", {}).get("line", 0),
                severity=normalize_severity(extra.get("severity", "warning")),
                source=self.name,
                code_snippet=extra.get("lines", ""),
                message=extra.get("message", ""),
                rule_id=r.get("check_id", ""),
            ))
        return findings
