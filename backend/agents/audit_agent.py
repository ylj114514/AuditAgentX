"""AuditAgent —— 语义安全审计智能体（LLM）。

输入：项目元信息 + 静态扫描结果 + 关键代码片段
输出：候选漏洞列表（结合语义理解，可发现工具漏报）
"""
from __future__ import annotations

import json
from pathlib import Path

from backend.agents.base_agent import BaseAgent
from backend.scanners.base import RawFinding
from backend.dynamic.symbol_resolver import resolve_symbol, extract_referenced_symbols


class AuditAgent(BaseAgent):
    name = "audit_agent"
    prompt_file = "audit_agent_prompt.md"

    def run(self, metadata: dict, raw_findings: list[RawFinding],
            code_root: Path, max_snippets: int = 30,
            *, expand_call_chain: bool = True) -> list[dict]:
        # 聚合静态扫描命中的文件，取片段给 LLM 做语义复核 + 补漏
        hot_files = self._collect_snippets(raw_findings, code_root, max_snippets)

        # Vulnhuntr 式跨文件调用链补全：从命中片段提取被引用符号，
        # 递归解析其他文件里的定义，拼出更完整的上下文喂给 LLM（发现跨文件逻辑漏洞）
        call_chain_context = []
        if expand_call_chain:
            call_chain_context = self._expand_call_chain(hot_files, code_root)

        user_content = json.dumps({
            "project_metadata": {
                "languages": metadata.get("languages", []),
                "frameworks": metadata.get("frameworks", []),
                "entrypoints": metadata.get("entrypoints", []),
            },
            "static_findings": [f.to_dict() for f in raw_findings[:100]],
            "code_snippets": hot_files,
            "cross_file_call_chain": call_chain_context,
        }, ensure_ascii=False)

        result = self._call(user_content)
        if isinstance(result, dict):
            return result.get("findings", [])
        if isinstance(result, list):
            return result
        return []

    @staticmethod
    def _expand_call_chain(hot_files: list[dict], code_root: Path,
                           *, max_symbols: int = 20, max_depth: int = 2) -> list[dict]:
        """从命中代码片段递归补全跨文件符号定义（Vulnhuntr 思路）。

        广度优先：先从热点片段抽符号 → 解析定义 → 从定义里再抽符号（限深度），
        避免爆炸，去重且限总量。
        """
        resolved: list[dict] = []
        seen: set[str] = set()
        # 第 0 层：热点片段里的符号
        frontier: list[str] = []
        for hf in hot_files:
            frontier.extend(extract_referenced_symbols(hf.get("code", "")))

        depth = 0
        while frontier and depth < max_depth and len(resolved) < max_symbols:
            next_frontier: list[str] = []
            for sym in frontier:
                if sym in seen or len(resolved) >= max_symbols:
                    continue
                seen.add(sym)
                r = resolve_symbol(code_root, sym, max_defs=1)
                if not r.get("found"):
                    continue
                for d in r["definitions"]:
                    resolved.append({
                        "symbol": sym, "file": d["file"],
                        "start_line": d["start_line"], "code": d["code"],
                    })
                    # 从新解析的定义里再抽符号，供下一层
                    next_frontier.extend(extract_referenced_symbols(d["code"]))
            frontier = next_frontier
            depth += 1
        return resolved

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
