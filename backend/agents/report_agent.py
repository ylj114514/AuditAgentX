"""ReportAgent —— 报告生成智能体（LLM）。

负责生成执行摘要与总体风险结论；明细表格由 report_builder 模板渲染。

新增 run_acp() 方法，符合 AuditAgentX-ACP 协议：
  输入：message_type="report.request"
  输出：message_type="report.result"，payload.report 含执行摘要
"""
from __future__ import annotations

import json

from backend.agents.base_agent import BaseAgent
from backend.rag.retriever import SecurityKnowledgeRetriever


class ReportAgent(BaseAgent):
    name = "report_agent"
    prompt_file = "report_agent_prompt.md"

    def run(self, metadata: dict, findings_summary: dict) -> dict:
        # RAG 知识增强：为报告涉及的漏洞类型检索标准修复建议（引用 CWE/OWASP，而非泛泛而谈）
        remediation_knowledge = self._retrieve_remediation(findings_summary)
        user_content = json.dumps({
            "project_metadata": metadata,
            "findings_summary": findings_summary,
            "remediation_knowledge": remediation_knowledge,
        }, ensure_ascii=False)
        result = self._call(user_content)
        if not isinstance(result, dict):
            return {
                "executive_summary": "自动摘要生成失败，请查看明细。",
                "overall_risk": "medium",
                "key_risks": [],
                "conclusion": "",
            }
        return result

    @staticmethod
    def _retrieve_remediation(findings_summary: dict, *, max_types: int = 10) -> list[dict]:
        """按报告涉及的漏洞类型检索标准修复建议（供 LLM 引用 CWE/OWASP）。"""
        # 从 findings_summary 里尽力提取漏洞类型列表
        types: list[str] = []
        for key in ("types", "top_vulnerability_types", "vuln_types"):
            val = findings_summary.get(key)
            if isinstance(val, list):
                for it in val:
                    types.append(it.get("type") if isinstance(it, dict) else str(it))
        for f in findings_summary.get("findings", []) or []:
            if isinstance(f, dict) and f.get("type"):
                types.append(f["type"])

        retriever = SecurityKnowledgeRetriever()
        seen: set[str] = set()
        out: list[dict] = []
        for vt in types:
            vt = (vt or "").strip()
            if not vt or vt.lower() in seen or len(out) >= max_types:
                continue
            seen.add(vt.lower())
            res = retriever.retrieve(candidate={"type": vt})
            top = res.get("top_result")
            if top and top.get("remediation"):
                out.append({"for_type": vt, "cwe_id": top.get("cwe_id"),
                            "owasp": top.get("owasp"), "remediation": top.get("remediation")})
        return out

    def run_acp(self, request: "ACPMessage") -> "ACPMessage":  # noqa: F821
        """ACP 接口：输入 report.request，输出 report.result。

        Parameters
        ----------
        request : ACPMessage
            message_type = "report.request"
            payload.metadata         = 项目元信息
            payload.findings_summary = findings 汇总

        Returns
        -------
        ACPMessage
            message_type = "report.result"
            payload.report = 执行摘要报告
        """
        from backend.acp.factory import make_reply
        from backend.acp.models import ACPMessageType, ACPState

        metadata = request.payload.get("metadata") or {}
        findings_summary = request.payload.get("findings_summary") or {}

        report = self.run(metadata, findings_summary)

        return make_reply(
            request,
            sender=self.name,
            message_type=ACPMessageType.REPORT_RESULT,
            intent="报告摘要生成完成",
            payload={"report": report},
            state=ACPState.SUCCESS,
        )
