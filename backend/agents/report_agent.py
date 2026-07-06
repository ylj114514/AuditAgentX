"""ReportAgent —— 报告生成智能体（LLM）。

负责生成执行摘要与总体风险结论；明细表格由 report_builder 模板渲染。
"""
from __future__ import annotations

import json

from backend.agents.base_agent import BaseAgent


class ReportAgent(BaseAgent):
    name = "report_agent"
    prompt_file = "report_agent_prompt.md"

    def run(self, metadata: dict, findings_summary: dict) -> dict:
        user_content = json.dumps({
            "project_metadata": metadata,
            "findings_summary": findings_summary,
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
