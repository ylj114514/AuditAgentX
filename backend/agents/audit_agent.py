"""AuditAgent —— 语义安全审计智能体（LLM）。

输入：项目元信息 + 静态扫描结果 + 关键代码片段
输出：候选漏洞列表（结合语义理解，可发现工具漏报）
"""
from __future__ import annotations

import json
from pathlib import Path

from backend.agents.base_agent import BaseAgent
from backend.scanners.base import RawFinding


class AuditAgent(BaseAgent):
    name = "audit_agent"
    prompt_file = "audit_agent_prompt.md"

    def run(self, metadata: dict, raw_findings: list[RawFinding],
            code_root: Path, max_snippets: int = 30) -> list[dict]:
        # 聚合静态扫描命中的文件，取片段给 LLM 做语义复核 + 补漏
        hot_files = self._collect_snippets(raw_findings, code_root, max_snippets)
        user_content = json.dumps({
            "project_metadata": {
                "languages": metadata.get("languages", []),
                "frameworks": metadata.get("frameworks", []),
                "entrypoints": metadata.get("entrypoints", []),
            },
            "static_findings": [f.to_dict() for f in raw_findings[:100]],
            "code_snippets": hot_files,
        }, ensure_ascii=False)

        result = self._call(user_content)
        if isinstance(result, dict):
            return result.get("findings", [])
        if isinstance(result, list):
            return result
        return []

    @staticmethod
    def _collect_snippets(raw_findings: list[RawFinding], code_root: Path,
                          limit: int) -> list[dict]:
        seen: set[str] = set()
        snippets: list[dict] = []
        for f in raw_findings:
            if f.file in seen or len(snippets) >= limit:
                continue
            seen.add(f.file)
            fp = code_root / f.file
            if not fp.exists():
                snippets.append({"file": f.file, "code": f.code_snippet})
                continue
            try:
                lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            start = max(0, f.line - 8)
            end = min(len(lines), f.line + 8)
            snippets.append({
                "file": f.file,
                "around_line": f.line,
                "code": "\n".join(lines[start:end]),
            })
        return snippets
