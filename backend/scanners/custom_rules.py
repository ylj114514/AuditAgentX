"""自定义正则规则扫描（SQL 注入 / 命令执行 / 路径遍历等）。

作为外部工具缺失时的兜底，保证系统"离线也能跑出结果"，便于演示。
"""
from __future__ import annotations

import re
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding
from backend.repository.language_detector import scan_files

# (漏洞类型, 严重级, 正则)
RULES: list[tuple[str, str, re.Pattern]] = [
    ("SQL Injection", "high",
     re.compile(r"""(execute|query|cursor\.execute)\s*\(\s*['"].*?\+|f['"].*?(select|insert|update|delete).*?\{""", re.I)),
    ("Command Injection", "high",
     re.compile(r"(os\.system|subprocess\.(call|run|Popen)|exec|eval|shell_exec|passthru)\s*\(.*?(\+|%|format|\{)", re.I)),
    ("Path Traversal", "medium",
     re.compile(r"(open|file_get_contents|readfile|include|require)\s*\(.*?(request|_GET|_POST|params|input)", re.I)),
    ("Hardcoded Secret", "high",
     re.compile(r"""(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*['"][^'"]{6,}['"]""", re.I)),
    ("Insecure Deserialization", "high",
     re.compile(r"(pickle\.loads|yaml\.load\s*\((?!.*Loader)|unserialize)\s*\(", re.I)),
    ("SSRF", "medium",
     re.compile(r"(requests\.(get|post)|urllib\.request\.urlopen|curl_exec)\s*\(.*?(request|_GET|_POST|params|input)", re.I)),
]


class CustomRuleScanner(BaseScanner):
    name = "custom"

    def available(self) -> bool:
        return True  # 纯 Python，永远可用

    def run(self, target: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for f in scan_files(target):
            try:
                lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            rel = f.relative_to(target).as_posix() if target in f.parents or target == f.parent else f.name
            for idx, line in enumerate(lines, start=1):
                for vuln_type, sev, pattern in RULES:
                    if pattern.search(line):
                        findings.append(RawFinding(
                            type=vuln_type,
                            file=rel,
                            line=idx,
                            severity=sev,
                            source=self.name,
                            code_snippet=line.strip()[:200],
                            message=f"自定义规则命中: {vuln_type}",
                            rule_id=f"custom-{vuln_type.lower().replace(' ', '-')}",
                        ))
        return findings
