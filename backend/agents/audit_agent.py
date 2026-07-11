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
from backend.rag.retriever import SecurityKnowledgeRetriever


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

        # RAG 知识增强（DeepAudit 式）：按静态扫描命中的漏洞类型检索 CWE/OWASP 知识，
        # 作为参考喂给 LLM，帮助更准判断"这段代码属于哪类已知漏洞"
        security_knowledge = self._retrieve_knowledge(raw_findings)

        user_content = json.dumps({
            "project_metadata": {
                "languages": metadata.get("languages", []),
                "frameworks": metadata.get("frameworks", []),
                "entrypoints": metadata.get("entrypoints", []),
            },
            "static_findings": [f.to_dict() for f in raw_findings[:100]],
            "code_snippets": hot_files,
            "cross_file_call_chain": call_chain_context,
            "security_knowledge": security_knowledge,
        }, ensure_ascii=False)

        result = self._call(user_content)
        if isinstance(result, dict):
            return result.get("findings", [])
        if isinstance(result, list):
            return result
        return []

    def run_acp(self, request: "ACPMessage") -> "ACPMessage":  # noqa: F821
        """ACP 接口：audit.request → audit.result。

        输入 payload.metadata + payload.raw_findings + payload.code_root；
        输出 payload.findings 为统一 ACPFinding 列表，payload.legacy_findings
        保留 AuditAgent.run() 的原始候选 dict，供 Orchestrator/DB 兼容层使用。
        """
        from backend.acp.factory import make_reply
        from backend.acp.models import ACPMessageType, ACPState
        from backend.acp.adapters import audit_finding_to_acp
        from backend.scanners.base import RawFinding

        metadata = request.payload.get("metadata") or {}
        code_root_str = request.payload.get("code_root") or request.context.code_root
        # raw_findings 可能是 ACPFinding dict 或原 RawFinding dict；还原成 RawFinding 供 run() 使用
        raw_in = request.payload.get("raw_findings") or []
        raw_findings = [_to_raw_finding(item) for item in raw_in]
        raw_findings = [rf for rf in raw_findings if rf is not None]

        code_root = Path(code_root_str) if code_root_str else Path(".")
        llm_findings = self.run(metadata, raw_findings, code_root)
        acp_findings = [audit_finding_to_acp(lf) for lf in llm_findings]
        return make_reply(
            request, sender=self.name,
            message_type=ACPMessageType.AUDIT_RESULT,
            intent=f"LLM 语义审计完成，补充 {len(acp_findings)} 条",
            payload={"findings": acp_findings, "legacy_findings": llm_findings},
            state=ACPState.SUCCESS,
            confidence=_avg_confidence(llm_findings),
        )

    @staticmethod
    def _retrieve_knowledge(raw_findings: list[RawFinding], *, max_types: int = 8) -> list[dict]:
        """按静态扫描命中的漏洞类型去重检索知识库，返回精简的知识条目列表。"""
        retriever = SecurityKnowledgeRetriever()
        seen: set[str] = set()
        knowledge: list[dict] = []
        for f in raw_findings:
            vt = (f.type or "").strip()
            if not vt or vt.lower() in seen or len(knowledge) >= max_types:
                continue
            seen.add(vt.lower())
            out = retriever.retrieve(candidate={"type": vt, "code_snippet": f.code_snippet})
            top = out.get("top_result")
            if top:
                knowledge.append({
                    "for_type": vt,
                    "cwe_id": top.get("cwe_id"),
                    "title": top.get("title"),
                    "owasp": top.get("owasp"),
                    "verification_checks": top.get("verification_checks"),
                    "false_positive_signals": top.get("false_positive_signals"),
                })
        return knowledge

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
        root = code_root.resolve()
        for f in raw_findings:
            if f.file in seen or len(snippets) >= limit:
                continue
            seen.add(f.file)
            try:
                fp = (root / f.file).resolve()
                fp.relative_to(root)
                if fp.is_symlink():
                    continue
            except (OSError, ValueError):
                continue
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


def _to_raw_finding(item: dict):
    """把 ACPFinding dict 或 RawFinding dict 还原为 RawFinding（供 AuditAgent.run 使用）。"""
    from backend.scanners.base import RawFinding
    if not isinstance(item, dict):
        return None
    # ACPFinding 结构（含 location/code/source）
    if "location" in item or "code" in item:
        loc = item.get("location") or {}
        code = item.get("code") or {}
        src = item.get("source") or {}
        return RawFinding(
            type=item.get("type") or "", file=loc.get("file") or "",
            line=loc.get("start_line") or 0, severity=item.get("severity", "medium"),
            source=src.get("tool") or src.get("agent") or "", code_snippet=code.get("snippet", ""),
            message=item.get("description", ""), rule_id=src.get("rule_id", ""),
            extra=item.get("extra") or {},
        )
    # 原 RawFinding dict（扁平字段）
    return RawFinding(
        type=item.get("type") or "", file=item.get("file") or "",
        line=item.get("line") or 0, severity=item.get("severity", "medium"),
        source=item.get("source") or "", code_snippet=item.get("code_snippet", ""),
        message=item.get("message", ""), rule_id=item.get("rule_id", ""),
        extra=item.get("extra") or {},
    )


def _avg_confidence(findings: list[dict]) -> float | None:
    values = []
    for finding in findings:
        try:
            values.append(float(finding.get("confidence")))
        except (TypeError, ValueError, AttributeError):
            continue
    if not values:
        return None
    return max(0.0, min(sum(values) / len(values), 1.0))
