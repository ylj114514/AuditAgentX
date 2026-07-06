"""VerifyAgent —— 独立漏洞验证智能体（LLM）。

对候选漏洞进行二次交叉复核，判定真伪、降低误报（md 双智能体交叉验证创新点）。
"""
from __future__ import annotations

import json

from backend.agents.base_agent import BaseAgent


class VerifyAgent(BaseAgent):
    name = "verify_agent"
    prompt_file = "verify_agent_prompt.md"

    def run(self, candidate: dict) -> dict:
        """输入单条候选漏洞，返回验证结论。"""
        user_content = json.dumps({"candidate_finding": candidate}, ensure_ascii=False)
        result = self._call(user_content)
        if not isinstance(result, dict):
            return {"is_valid": True, "confidence": 0.5, "_note": "verify 输出异常，保守保留"}
        return result

    def run_batch(self, candidates: list[dict]) -> list[dict]:
        return [self.run(c) for c in candidates]
