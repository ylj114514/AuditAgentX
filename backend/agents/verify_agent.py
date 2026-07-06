"""VerifyAgent: independent MCP+Skill review agent for candidate findings."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.agents.verification_tools import build_verification_context
from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.skills.loader import load_skill


logger = logging.getLogger(__name__)


class VerifyAgent(BaseAgent):
    name = "verify_agent"
    prompt_file = "verify_agent_prompt.md"

    def run(self, candidate: dict[str, Any], code_root: Path | None = None) -> dict[str, Any]:
        """Review one candidate finding and return a normalized verdict."""
        tool_context = self._build_mcp_skill_context(candidate, code_root)
        user_content = json.dumps({
            "candidate_finding": candidate,
            "tool_evidence": tool_context,
            "instruction": (
                "Use the MCP+Skill tool_evidence to independently confirm or reject the finding. "
                "Return JSON with is_valid, false_positive_reason, confidence, source, "
                "sink, propagation_path, call_path, tool_calls, evidence_chain, "
                "required_runtime_conditions, and recommended_poc_strategy."
            ),
        }, ensure_ascii=False)

        llm_result = self._call(user_content)
        if not isinstance(llm_result, dict):
            llm_result = {"_error": "verify_agent returned non-dict output"}

        return self._merge_verdict(candidate, tool_context, llm_result)

    def run_batch(self, candidates: list[dict[str, Any]],
                  code_root: Path | None = None) -> list[dict[str, Any]]:
        return [self.run(c, code_root=code_root) for c in candidates]

    @staticmethod
    def _build_mcp_skill_context(candidate: dict[str, Any], code_root: Path | None) -> dict[str, Any]:
        try:
            skill = load_skill("vulnerability-verification")
            return AuditMCPClient().run_verification_skill(candidate, code_root, skill)
        except Exception as exc:  # noqa: BLE001
            logger.exception("MCP+Skill verification failed, falling back to local tools: %s", exc)
            context = build_verification_context(candidate, code_root)
            context["architecture"] = "local-tool-fallback"
            context["mcp_error"] = str(exc)
            return context

    @staticmethod
    def _merge_verdict(candidate: dict[str, Any], tool_context: dict[str, Any],
                       llm_result: dict[str, Any]) -> dict[str, Any]:
        heuristic = tool_context.get("heuristic_result", {}) or {}
        local_valid = heuristic.get("is_valid")

        verdict = dict(llm_result)
        if local_valid is False:
            verdict["is_valid"] = False
            verdict["false_positive_reason"] = (
                heuristic.get("false_positive_reason")
                or verdict.get("false_positive_reason")
                or heuristic.get("reason")
                or "Local verification tools rejected this candidate."
            )
        elif "is_valid" not in verdict or verdict.get("_error"):
            verdict["is_valid"] = True if local_valid is None else bool(local_valid)

        if not verdict.get("confidence"):
            verdict["confidence"] = heuristic.get("confidence", candidate.get("confidence", 0.5))
        verdict["confidence"] = _bounded_float(verdict.get("confidence"), default=0.5)

        for field in ("source", "sink", "propagation_path", "recommended_poc_strategy", "call_path"):
            if not verdict.get(field) and heuristic.get(field):
                verdict[field] = heuristic[field]

        if not verdict.get("evidence_chain"):
            verdict["evidence_chain"] = tool_context.get("evidence_chain") or {
                "tool_calls": tool_context.get("tools_used", []),
                "call_path": verdict.get("call_path", []),
                "checks": heuristic.get("checks", []),
                "sast_replay": tool_context.get("sast_replay", {}),
            }
        verdict["tool_calls"] = tool_context.get("tools_used", [])

        if not verdict.get("required_runtime_conditions"):
            verdict["required_runtime_conditions"] = _runtime_conditions(candidate, heuristic)

        verdict.setdefault("mcp_server", tool_context.get("mcp_server"))
        verdict.setdefault("skill", tool_context.get("skill"))
        verdict["_tool_evidence"] = tool_context
        verdict["_llm_result"] = llm_result
        return verdict


def _bounded_float(value: Any, *, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0.0, min(parsed, 1.0))


def _runtime_conditions(candidate: dict[str, Any], heuristic: dict[str, Any]) -> list[str]:
    vuln_type = str(candidate.get("type") or "").lower()
    if "secret" in vuln_type:
        return ["Confirm whether the literal credential is real and reachable by runtime code."]
    if heuristic.get("is_valid") is False:
        return ["No runtime verification required unless a new unsafe path is identified."]
    return ["Run only against a local authorized target or sandbox.", "Use the recommended PoC strategy if dynamic validation is enabled."]
