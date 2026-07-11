"""Gitleaks 扫描器封装（硬编码密钥扫描）。"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding, redact_secret_text
from backend.scanners.semgrep_runner import normalize_result_path, read_source_snippet


def _gitleaks_bin() -> str | None:
    """定位 gitleaks 可执行文件：PATH -> winget Packages/Links -> choco/常见位置。

    gitleaks 是独立 Go 二进制，winget 安装后不一定进当前进程 PATH，
    这里主动补齐常见安装位置，避免"装了却检测不到"。可用 GITLEAKS_PATH 显式覆盖。
    """
    override = os.environ.get("GITLEAKS_PATH")
    if override and Path(override).exists():
        return override
    found = shutil.which("gitleaks")
    if found:
        return found
    candidates: list[Path] = []
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        pkg = Path(local) / "Microsoft" / "WinGet" / "Packages"
        if pkg.exists():
            candidates += list(pkg.glob("Gitleaks.Gitleaks*/gitleaks.exe"))
        candidates.append(Path(local) / "Microsoft" / "WinGet" / "Links" / "gitleaks.exe")
    candidates += [Path(r"C:\ProgramData\chocolatey\bin\gitleaks.exe"),
                   Path("/usr/local/bin/gitleaks"), Path("/usr/bin/gitleaks")]
    for c in candidates:
        try:
            if c.exists():
                return str(c)
        except OSError:
            continue
    return None


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    cli = "gitleaks"

    def available(self) -> bool:
        return _gitleaks_bin() is not None

    def run(self, target: Path) -> list[RawFinding]:
        binary = _gitleaks_bin()
        if not binary:
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            report_path = tf.name
        cmd = [binary, "detect", "--source", str(target),
               "--report-format", "json", "--report-path", report_path,
               "--no-git", "--exit-code", "0"]
        findings: list[RawFinding] = []
        try:
            proc = self._exec(cmd, timeout=600)
            report_text = Path(report_path).read_text(encoding="utf-8")
            if proc.returncode != 0:
                raise RuntimeError(
                    f"gitleaks failed with exit={proc.returncode}: {(proc.stderr or '')[:300]}"
                )
            if not report_text.strip():
                raise RuntimeError("gitleaks produced an empty JSON report")
            data = json.loads(report_text)
            if not isinstance(data, list):
                raise RuntimeError("gitleaks JSON report must be an array")
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError("gitleaks did not produce a readable JSON report") from exc
        finally:
            try:
                Path(report_path).unlink(missing_ok=True)
            except OSError:
                pass
        findings.extend(_parse_gitleaks_report(target, data))
        return findings


def _parse_gitleaks_report(target: Path, data: list[dict]) -> list[RawFinding]:
    """Parse a successful report; separated so the normal success path is regression-tested."""
    findings: list[RawFinding] = []
    for r in data:
        start_line = r.get("StartLine", 0)
        rel_path = normalize_result_path(target, r.get("File", ""))
        source_snippet = read_source_snippet(
            target, r.get("File", ""), start_line, r.get("EndLine") or start_line,
        )
        findings.append(RawFinding(
            type="Hardcoded Secret",
            file=rel_path,
            line=start_line,
            severity="high",
            source="gitleaks",
            code_snippet=_redact_secret_snippet(source_snippet, r.get("Secret", "")),
            message=f"检测到疑似密钥: {r.get('RuleID', '')}",
            rule_id=r.get("RuleID", ""),
            extra={
                "description": r.get("Description", ""),
                "fingerprint": r.get("Fingerprint", ""),
                "tags": r.get("Tags", []),
                "confidence": 0.9,
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
        line = redact_secret_text(line)
        if "=" in line or ":" in line:
            redacted_lines.append(line[:160])
        else:
            redacted_lines.append(line[:80] + ("..." if len(line) > 80 else ""))
    return "\n".join(redacted_lines)
