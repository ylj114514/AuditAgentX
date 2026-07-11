"""Trivy filesystem scanner: dependency CVEs, secrets and IaC misconfigurations."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity
from backend.scanners.semgrep_runner import normalize_result_path, read_source_snippet


def _trivy_bin() -> str | None:
    found = shutil.which("trivy")
    if found:
        return found
    candidates: list[Path] = []
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        candidates += list((Path(local) / "Microsoft" / "WinGet" / "Packages").glob(
            "AquaSecurity.Trivy*/trivy.exe"))
        candidates.append(Path(local) / "Microsoft" / "WinGet" / "Links" / "trivy.exe")
    candidates += [Path("/usr/local/bin/trivy"), Path("/usr/bin/trivy")]
    return next((str(path) for path in candidates if path.exists()), None)


def _docker_trivy_available() -> bool:
    return shutil.which("docker") is not None


class TrivyScanner(BaseScanner):
    name = "trivy"
    cli = "trivy"

    def __init__(self) -> None:
        self.degraded_reason: str | None = None

    def available(self) -> bool:
        return _trivy_bin() is not None or _docker_trivy_available()

    def run(self, target: Path) -> list[RawFinding]:
        binary = _trivy_bin()
        use_docker = not binary
        scanners = "vuln,secret,misconfig"
        if use_docker and os.environ.get("AUDITAGENTX_TRIVY_ENABLE_VULN", "0") != "1":
            # The vulnerability DB is ~100 MB. On restricted links a first
            # download can take tens of minutes, blocking every scan. Keep
            # secret/IaC coverage operational and report the missing SCA phase
            # honestly until an operator pre-warms the persistent cache.
            scanners = "secret,misconfig"
            self.degraded_reason = (
                "Trivy Docker fallback ran secret+misconfig only; dependency CVE DB is not pre-warmed. "
                "Set AUDITAGENTX_TRIVY_ENABLE_VULN=1 after warming auditagentx-trivy-cache."
            )
        fd, report_name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        report = Path(report_name)
        if use_docker:
            mount = f"{target.resolve()}:/workspace:ro"
            cmd = [
                "docker", "run", "--rm", "-v", mount,
                "-v", "auditagentx-trivy-cache:/root/.cache/trivy",
                "aquasec/trivy:0.72.0", "fs", "--format", "json",
                "--scanners", scanners, "--exit-code", "0",
                "--skip-dirs", ".git", "--skip-dirs", "node_modules",
                "--skip-dirs", "vendor", "/workspace",
            ]
        else:
            cmd = [
                binary, "fs", "--format", "json", "--output", str(report),
                "--scanners", scanners, "--exit-code", "0",
                "--skip-dirs", ".git", "--skip-dirs", "node_modules",
                "--skip-dirs", "vendor", str(target),
            ]
        try:
            proc = self._exec(cmd, timeout=1200, env={"TRIVY_DISABLE_VEX_NOTICE": "true"})
            if proc.returncode != 0:
                raise RuntimeError(f"trivy failed with exit={proc.returncode}: {(proc.stderr or '')[:300]}")
            try:
                raw_json = proc.stdout if use_docker else report.read_text(encoding="utf-8")
                data = json.loads(raw_json or "{}")
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError("trivy did not produce a readable JSON report") from exc
            return _parse_trivy_report(target, data)
        finally:
            report.unlink(missing_ok=True)


def _parse_trivy_report(target: Path, data: dict) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for result in data.get("Results") or []:
        result_target = str(result.get("Target") or "")
        rel = normalize_result_path(target, result_target)
        for item in result.get("Vulnerabilities") or []:
            vuln_id = str(item.get("VulnerabilityID") or "dependency-vulnerability")
            package = str(item.get("PkgName") or "dependency")
            fixed = str(item.get("FixedVersion") or "")
            findings.append(RawFinding(
                type="Dependency Vulnerability", file=rel, line=0,
                severity=normalize_severity(item.get("Severity") or "medium"), source="trivy",
                message=f"{vuln_id} affects {package}" + (f"; fixed in {fixed}" if fixed else ""),
                rule_id=vuln_id,
                extra={
                    "confidence": 0.9, "package": package,
                    "installed_version": item.get("InstalledVersion"), "fixed_version": fixed,
                    "title": item.get("Title"), "references": (item.get("References") or [])[:5],
                    "scanner_class": "sca", "dynamic_verification": None,
                },
            ))
        for item in result.get("Misconfigurations") or []:
            cause = item.get("CauseMetadata") or {}
            line = int(cause.get("StartLine") or 0)
            findings.append(RawFinding(
                type=str(item.get("Title") or item.get("Type") or "IaC Misconfiguration"),
                file=rel, line=line,
                severity=normalize_severity(item.get("Severity") or "medium"), source="trivy",
                code_snippet=read_source_snippet(target, result_target, line, line),
                message=str(item.get("Message") or item.get("Description") or "IaC misconfiguration"),
                rule_id=str(item.get("ID") or item.get("AVDID") or "trivy-misconfig"),
                extra={
                    "confidence": 0.85, "resolution": item.get("Resolution"),
                    "references": (item.get("References") or [])[:5], "scanner_class": "iac",
                },
            ))
        for item in result.get("Secrets") or []:
            line = int(item.get("StartLine") or 0)
            # Secret/Match 字段绝不进入 RawFinding，避免扫描结果本身成为凭据泄漏通道。
            findings.append(RawFinding(
                type="Hardcoded Secret", file=rel, line=line,
                severity=normalize_severity(item.get("Severity") or "high"), source="trivy",
                code_snippet="<redacted secret>",
                message=str(item.get("Title") or "Trivy detected a secret"),
                rule_id=str(item.get("RuleID") or "trivy-secret"),
                extra={"confidence": 0.9, "category": item.get("Category"),
                       "scanner_class": "secret"},
            ))
    return findings
