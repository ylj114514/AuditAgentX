"""Trivy 扫描器封装（依赖漏洞扫描）。"""
from __future__ import annotations

import json
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity


class TrivyScanner(BaseScanner):
    name = "trivy"
    cli = "trivy"

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        cmd = ["trivy", "fs", "--scanners", "vuln", "--format", "json",
               "--quiet", str(target)]
        proc = self._exec(cmd, timeout=900)
        findings: list[RawFinding] = []
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []
        for result in data.get("Results", []):
            target_file = result.get("Target", "")
            for v in result.get("Vulnerabilities", []) or []:
                findings.append(RawFinding(
                    type=f"CVE: {v.get('VulnerabilityID', '')}",
                    file=target_file,
                    line=0,
                    severity=normalize_severity(v.get("Severity", "MEDIUM")),
                    source=self.name,
                    code_snippet=f"{v.get('PkgName', '')}@{v.get('InstalledVersion', '')}",
                    message=v.get("Title", "") or v.get("Description", "")[:200],
                    rule_id=v.get("VulnerabilityID", ""),
                    extra={"fixed_version": v.get("FixedVersion", "")},
                ))
        return findings
