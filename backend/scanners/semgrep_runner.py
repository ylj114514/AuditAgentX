"""Semgrep 扫描器封装（通用代码安全规则）。"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity, redact_secret_text

logger = logging.getLogger(__name__)


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    cli = "semgrep"

    # 项目自定义 taint mode 规则目录
    custom_rules_dir = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep"

    def __init__(self) -> None:
        self.degraded_reason: str | None = None

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        # 官方规则集 auto + 语言专项规则包 + 项目自定义 taint 规则（source→sink 污点追踪，降误报）。
        # p/java：Semgrep 官方 Java 安全规则（含 taint mode 跨方法），显著增强对 Java Web
        # 特定类别（XSS/弱加密/弱随机/LDAP/XPath/Trust Boundary）的覆盖，弥补正则窗口短板。
        cmd = ["semgrep", "scan", "--config", "auto"]
        # p/java is expensive and only useful when Java sources are present. Loading it for
        # C/PHP repositories made real scans spend minutes on an irrelevant ruleset.
        if _project_has_suffix(target, ".java"):
            cmd += ["--config", "p/java"]
        if self.custom_rules_dir.exists() and any(self.custom_rules_dir.glob("*.y*ml")):
            cmd += ["--config", str(self.custom_rules_dir)]
        # 尊重 .gitignore 并显式排除生成物/依赖，避免把 vendored code 和报告当成本项目漏洞。
        cmd += [
            # Semgrep 的 `auto` 注册表配置要求 metrics=auto/on；强制 off 会直接 exit 2。
            # Semgrep on Windows defaults to one job. Real OpenVPN runs exceeded the
            # process timeout at that setting, so use bounded parallelism explicitly.
            "--disable-version-check", "--jobs", "4", "--json", "--quiet",
            "--exclude", "node_modules", "--exclude", "vendor", "--exclude", "dist",
            "--exclude", "build", "--exclude", "reports",
            # 生成后的压缩包和明确的第三方前端组件不属于项目源代码。继续扫描它们
            # 会把 jQuery/UEditor/DPlayer 内部实现当成项目漏洞，且无法给出可修复位置。
            "--exclude", "**/*.min.js", "--exclude", "**/*.map",
            "--exclude", "**/third-party/**", "--exclude", "**/ueditor/**",
            "--exclude", "**/dplayer/**", "--exclude", "**/layui/**",
            str(target),
        ]
        # 关键：强制 UTF-8。中文 Windows 默认 GBK，semgrep 读含中文的 UTF-8 规则文件会崩（exit 2）
        env = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        proc = self._exec(cmd, timeout=900, env=env)
        findings: list[RawFinding] = []
        if not (proc.stdout or "").strip():
            raise RuntimeError(
                f"semgrep produced no JSON (exit={proc.returncode}): {(proc.stderr or '')[:300]}"
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            # 静默失败会让"专业工具在跑"成为假象；如实记录 semgrep 报错
            logger.warning("semgrep 执行失败(exit=%s)，未产出有效 JSON。stderr: %s",
                           proc.returncode, (proc.stderr or "")[:500])
            raise RuntimeError("semgrep did not produce valid JSON") from exc
        if not isinstance(data.get("results"), list):
            raise RuntimeError("semgrep JSON response is missing the results array")
        if proc.returncode != 0 and not data.get("results"):
            raise RuntimeError(f"semgrep failed with exit={proc.returncode}: {(proc.stderr or '')[:300]}")
        semgrep_errors = data.get("errors") or []
        if semgrep_errors or proc.returncode != 0:
            first = semgrep_errors[0] if semgrep_errors else {"message": proc.stderr}
            detail = first.get("message") or first.get("long_msg") or first.get("type") or str(first)
            self.degraded_reason = f"semgrep partial scan: {str(detail)[:260]}"
        for r in data.get("results", []):
            extra = r.get("extra", {})
            check_id = r.get("check_id", "")
            if _framework_rule_mismatch(target, r.get("path", ""), check_id):
                continue
            start_line = r.get("start", {}).get("line", 0)
            end_line = r.get("end", {}).get("line") or start_line
            rel_path = normalize_result_path(target, r.get("path", ""))
            tool_lines = extra.get("lines", "") or ""
            source_snippet = read_source_snippet(target, r.get("path", ""), start_line, end_line)
            finding_type = _finding_type(check_id or "semgrep-finding", extra.get("metadata") or {})
            code_snippet = _choose_source_snippet(tool_lines, source_snippet)
            message = extra.get("message", "")
            if finding_type == "Hardcoded Secret":
                code_snippet = redact_secret_text(code_snippet)
                message = redact_secret_text(message)
                tool_lines = redact_secret_text(tool_lines)
                source_snippet = redact_secret_text(source_snippet)
            findings.append(RawFinding(
                type=finding_type,
                file=rel_path,
                line=start_line,
                severity=normalize_severity(extra.get("severity", "warning")),
                source=self.name,
                code_snippet=code_snippet,
                message=message,
                rule_id=check_id,
                extra=_semgrep_extra(extra, tool_lines, source_snippet, r),
            ))
        return findings


def _project_has_suffix(target: Path, suffix: str) -> bool:
    wanted = str(suffix or "").lower()
    for path in Path(target).rglob(f"*{wanted}"):
        if not path.is_file():
            continue
        if any(part.lower() in {".git", "node_modules", "vendor", "dist", "build", "target"}
               for part in path.parts):
            continue
        return True
    return False


def normalize_result_path(target: Path, result_path: str) -> str:
    """Normalize Semgrep path to a project-relative POSIX path when possible."""
    raw = str(result_path or "")
    if not raw:
        return ""
    target = Path(target).resolve()
    candidate = Path(raw)
    if not candidate.is_absolute():
        try:
            # Prefer an existing path relative to the scanner process cwd. Without
            # this ordering, target/candidate is syntactically inside target even
            # when it duplicates data/projects/<id> and does not exist.
            resolved = (Path.cwd() / candidate).resolve()
            if resolved.is_file():
                return resolved.relative_to(target).as_posix()
        except (OSError, ValueError):
            pass
    try:
        resolved = candidate.resolve() if candidate.is_absolute() else (target / candidate).resolve()
        return resolved.relative_to(target).as_posix()
    except (OSError, ValueError):
        pass
    if not candidate.is_absolute():
        try:
            # Some tools include the scanned directory name in relative paths.
            parts = Path(raw.replace("\\", "/")).parts
            if parts and parts[0].lower() == target.name.lower():
                return Path(*parts[1:]).as_posix()
        except (OSError, ValueError):
            pass
    raw_posix = raw.replace("\\", "/")
    target_posix = target.as_posix().lower().rstrip("/") + "/"
    lowered = raw_posix.lower()
    if lowered.startswith(target_posix):
        return raw_posix[len(target_posix):]
    while raw_posix.startswith("./"):
        raw_posix = raw_posix[2:]
    return raw_posix


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
    else:
        candidates.append(Path.cwd() / raw)
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


def _finding_type(check_id: str, metadata: dict[str, Any]) -> str:
    """从规则 ID 恢复稳定漏洞类型，避免自定义规则全部退化成无意义的 `taint`。"""
    text = str(check_id or "").lower().replace("_", "-")
    mapping = [
        (("sql", "inject"), "SQL Injection"), (("command", "inject"), "Command Injection"),
        (("raw-query",), "SQL Injection"), (("os-system",), "Command Injection"),
        (("dangerous-system-call",), "Command Injection"),
        (("path", "travers"), "Path Traversal"), (("cross-site", "script"), "XSS"),
        (("xss",), "XSS"), (("server-side-request",), "SSRF"), (("ssrf",), "SSRF"),
        (("template", "inject"), "Server-Side Template Injection"),
        (("deserial",), "Insecure Deserialization"), (("open-redirect",), "Open Redirect"),
        (("hardcoded", "secret"), "Hardcoded Secret"), (("ldap", "inject"), "LDAP Injection"),
        (("xpath", "inject"), "XPath Injection"),
    ]
    for terms, label in mapping:
        if all(term in text for term in terms):
            return label
    return str(check_id.rsplit(".", 1)[-1] or "semgrep-finding")


def _framework_rule_mismatch(target: Path, result_path: str, check_id: str) -> bool:
    """只在文件明确使用互斥框架时抑制错投规则（如 Flask 文件命中 Django 规则）。"""
    lowered = str(check_id or "").lower()
    rule_framework = next((name for name in (
        "django", "flask", "spring", "symfony", "laravel", "thinkphp",
    )
                           if f".{name}." in lowered), None)
    if not rule_framework:
        return False
    frameworks = _detect_project_frameworks(str(Path(target).resolve()))
    # 项目已经明确采用另一套后端框架时，连 HTML/YAML 等无 import 的文件也必须过滤。
    exclusive = {"django", "flask", "spring", "symfony", "laravel", "thinkphp"}
    if frameworks & exclusive and rule_framework not in frameworks:
        return True
    header = read_source_snippet(target, result_path, 1, 100).lower()
    uses_flask = bool(re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b", header))
    uses_django = bool(re.search(r"\bfrom\s+django\b|\bimport\s+django\b", header))
    return (".django." in lowered and uses_flask and not uses_django) or (
        ".flask." in lowered and uses_django and not uses_flask
    )


@lru_cache(maxsize=64)
def _detect_project_frameworks(target: str) -> frozenset[str]:
    """从依赖清单确定强框架信号，供 Semgrep 规则投放校验。"""
    root = Path(target)
    frameworks: set[str] = set()
    manifests = {
        "requirements.txt", "pyproject.toml", "pipfile", "pom.xml",
        "build.gradle", "build.gradle.kts", "composer.json",
    }
    checked = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.name.lower() not in manifests:
            continue
        if any(part.lower() in {".git", "node_modules", "vendor", "build", "target"}
               for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:500_000].lower()
        except OSError:
            continue
        checked += 1
        if "django" in text:
            frameworks.add("django")
        if re.search(r"(^|[^a-z])flask([^a-z]|$)", text):
            frameworks.add("flask")
        if "spring-boot" in text or "org.springframework" in text:
            frameworks.add("spring")
        if "thinkphp" in text or "topthink/" in text:
            frameworks.add("thinkphp")
        # 只把完整框架包当强信号，避免 symfony/polyfill 等组件误判成 Symfony 应用。
        if "symfony/framework-bundle" in text:
            frameworks.add("symfony")
        if "laravel/framework" in text:
            frameworks.add("laravel")
        if checked >= 30:
            break
    # 一些旧版 ThinkPHP 项目直接内置框架源码，composer 根清单未声明框架依赖。
    if (root / "thinkphp").is_dir() and (root / "application").is_dir():
        frameworks.add("thinkphp")
    return frozenset(frameworks)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
