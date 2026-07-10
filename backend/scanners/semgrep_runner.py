"""Semgrep 扫描器封装（通用代码安全规则）。"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity

logger = logging.getLogger(__name__)


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    cli = "semgrep"

    # 项目自定义 taint mode 规则目录
    custom_rules_dir = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep"

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        # 官方规则集 auto + 语言专项规则包 + 项目自定义 taint 规则（source→sink 污点追踪，降误报）。
        # p/java：Semgrep 官方 Java 安全规则（含 taint mode 跨方法），显著增强对 Java Web
        # 特定类别（XSS/弱加密/弱随机/LDAP/XPath/Trust Boundary）的覆盖，弥补正则窗口短板。
        cmd = ["semgrep", "scan", "--config", "auto", "--config", "p/java"]
        if self.custom_rules_dir.exists() and any(self.custom_rules_dir.glob("*.y*ml")):
            cmd += ["--config", str(self.custom_rules_dir)]
        # --no-git-ignore：不受 .gitignore 影响，vendored/被忽略但存在的代码也扫
        cmd += ["--no-git-ignore", "--json", "--quiet", str(target)]
        # 关键：强制 UTF-8。中文 Windows 默认 GBK，semgrep 读含中文的 UTF-8 规则文件会崩（exit 2）
        env = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        proc = self._exec(cmd, timeout=900, env=env)
        findings: list[RawFinding] = []
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            # 静默失败会让"专业工具在跑"成为假象；如实记录 semgrep 报错
            logger.warning("semgrep 执行失败(exit=%s)，未产出有效 JSON。stderr: %s",
                           proc.returncode, (proc.stderr or "")[:500])
            raise RuntimeError("semgrep did not produce valid JSON") from exc
        if proc.returncode not in (0, 1) and not data.get("results"):
            raise RuntimeError(f"semgrep failed with exit={proc.returncode}: {(proc.stderr or '')[:300]}")
        for r in data.get("results", []):
            extra = r.get("extra", {})
            start_line = r.get("start", {}).get("line", 0)
            end_line = r.get("end", {}).get("line") or start_line
            rel_path = normalize_result_path(target, r.get("path", ""))
            tool_lines = extra.get("lines", "") or ""
            source_snippet = read_source_snippet(target, r.get("path", ""), start_line, end_line)
            code_snippet = _choose_source_snippet(tool_lines, source_snippet)
            findings.append(RawFinding(
                type=r.get("check_id", "semgrep-finding").split(".")[-1],
                file=rel_path,
                line=start_line,
                severity=normalize_severity(extra.get("severity", "warning")),
                source=self.name,
                code_snippet=code_snippet,
                message=extra.get("message", ""),
                rule_id=r.get("check_id", ""),
                extra=_semgrep_extra(extra, tool_lines, source_snippet, r),
            ))
        return findings


def normalize_result_path(target: Path, result_path: str) -> str:
    """Normalize Semgrep path to a project-relative POSIX path when possible."""
    raw = str(result_path or "")
    if not raw:
        return ""
    target = Path(target).resolve()
    candidate = Path(raw)
    try:
        resolved = candidate.resolve() if candidate.is_absolute() else (Path.cwd() / candidate).resolve()
        return resolved.relative_to(target).as_posix()
    except (OSError, ValueError):
        pass
    raw_posix = raw.replace("\\", "/")
    target_posix = target.as_posix().lower().rstrip("/") + "/"
    lowered = raw_posix.lower()
    if lowered.startswith(target_posix):
        return raw_posix[len(target_posix):]
    return raw_posix.lstrip("./")


def read_source_snippet(target: Path, result_path: str, start_line: int | None,
                        end_line: int | None = None, *, context: int = 0) -> str:
    """Read the matched source lines from disk instead of trusting tool-provided text."""
    line = _to_int(start_line)
    if line is None or line <= 0:
        return ""
    end = _to_int(end_line) or line
    root = Path(target).resolve()
    raw = Path(str(result_path or ""))
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    candidates.append(root / raw)
    rel = normalize_result_path(root, str(result_path or ""))
    if rel:
        candidates.append(root / rel)
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if not resolved.is_file():
            continue
        try:
            lines = resolved.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return ""
        start = max(1, line - context)
        finish = min(len(lines), max(line, end) + context)
        return "\n".join(
            f"{idx} {lines[idx - 1]}" for idx in range(start, finish + 1)
        )
    return ""


def _choose_source_snippet(tool_lines: str, source_snippet: str) -> str:
    if not source_snippet:
        return "" if _bad_tool_lines(tool_lines) else tool_lines
    if _bad_tool_lines(tool_lines):
        return source_snippet
    tool_norm = _normalize_text(tool_lines)
    source_norm = _normalize_text(source_snippet)
    if tool_norm and tool_norm not in source_norm and source_norm not in tool_norm:
        return source_snippet
    return source_snippet or tool_lines


def _bad_tool_lines(value: str) -> bool:
    text = str(value or "").strip().lower()
    return not text or text == "requires login"


def _normalize_text(value: str) -> str:
    return " ".join(str(value or "").split()).lower()


def _semgrep_extra(extra: dict[str, Any], tool_lines: str, source_snippet: str, result: dict[str, Any]) -> dict:
    metadata = extra.get("metadata") or {}
    return {
        "raw_tool_lines": tool_lines,
        "source_snippet": source_snippet,
        "semgrep_metadata": metadata,
        "confidence": _confidence(metadata, extra),
        "technology": metadata.get("technology") or metadata.get("technologies") or [],
        "cwe": metadata.get("cwe") or [],
        "owasp": metadata.get("owasp") or [],
        "fingerprint": extra.get("fingerprint"),
        "semgrep_path": result.get("path"),
    }


def _confidence(metadata: dict[str, Any], extra: dict[str, Any]) -> float:
    raw = metadata.get("confidence") or extra.get("confidence")
    if isinstance(raw, (int, float)):
        return max(0.0, min(float(raw), 1.0))
    mapping = {"high": 0.85, "medium": 0.65, "low": 0.45}
    return mapping.get(str(raw or "").lower(), 0.6)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
