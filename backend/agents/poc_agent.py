"""PocAgent —— PoC 生成智能体（LLM）。

仅生成面向本地沙箱的验证方案，严禁攻击真实第三方系统（md 合规要求）。
"""
from __future__ import annotations

import json

from backend.agents.base_agent import BaseAgent


class PocAgent(BaseAgent):
    name = "poc_agent"
    prompt_file = "poc_agent_prompt.md"

    def run(self, verified_finding: dict) -> dict:
        user_content = json.dumps({"verified_finding": verified_finding}, ensure_ascii=False)
        result = self._call(user_content)
        if not isinstance(result, dict):
            return {"poc_type": "unknown", "_note": "poc 输出异常"}
        # 强制注入安全声明
        result.setdefault("safety_notes", "仅限本地授权沙箱环境验证，禁止攻击真实第三方系统。")
        return result
