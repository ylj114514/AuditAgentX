"""MCP client adapter used by VerifyAgent."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.mcp.audit_mcp_server import AuditMCPServer


class AuditMCPClient:
    """Executes a verification Skill by calling MCP tools in order."""

    def __init__(self, server: AuditMCPServer | None = None) -> None:
        self.server = server or AuditMCPServer()

    def run_verification_skill(
        self,
        candidate: dict[str, Any],
        code_root: Path | None,
        skill: dict[str, Any],
    ) -> dict[str, Any]:
        tool_manifest = self.server.list_tools()
        allowed_tools = {tool["name"] for tool in tool_manifest}
        skill_tools = list(skill.get("tools") or [])
        missing = [tool for tool in skill_tools if tool not in allowed_tools]
        if missing:
            raise ValueError(f"Skill references unavailable MCP tools: {', '.join(missing)}")

        tools_used: list[dict[str, Any]] = []
        code_context: dict[str, Any] = {}
        sast_replay: dict[str, Any] = {}
        heuristic_result: dict[str, Any] = {}
        evidence_chain: dict[str, Any] = {}

        for tool_name in skill_tools:
            if tool_name == "read_code_context":
                code_context = self._call(tool_name, {
                    "candidate": candidate,
                    "code_root": str(code_root) if code_root else None,
                    "radius": skill.get("context_radius", 8),
                })
                tools_used.append(_tool_call(tool_name, "Read source context through the MCP server.", code_context))
            elif tool_name == "run_sast_replay":
                sast_replay = self._call(tool_name, {
                    "candidate": candidate,
                    "code_context": code_context,
                })
                tools_used.append(_tool_call(
                    tool_name,
                    "Replay local SAST checks through the MCP server.",
                    sast_replay,
                    matched_rules=[rule["rule_id"] for rule in sast_replay.get("matched_rules", [])],
                ))
            elif tool_name == "verify_source_sink":
                heuristic_result = self._call(tool_name, {
                    "candidate": candidate,
                    "code_context": code_context,
                })
                tools_used.append(_tool_call(tool_name, "Verify source-to-sink flow through the MCP server.", heuristic_result))
            elif tool_name == "build_evidence_chain":
                evidence_chain = self._call(tool_name, {
                    "heuristic_result": heuristic_result,
                    "sast_replay": sast_replay,
                    "tool_calls": tools_used,
                })
                tools_used.append(_tool_call(tool_name, "Build structured evidence chain through the MCP server.", evidence_chain))

        return {
            "architecture": "MCP+Skill",
            "mcp_server": self.server.server_name,
            "skill": {
                "name": skill.get("name"),
                "version": skill.get("version"),
                "workflow": skill.get("workflow", []),
            },
            "tool_manifest": tool_manifest,
            "tools_used": tools_used,
            "code_context": code_context,
            "sast_replay": sast_replay,
            "heuristic_result": heuristic_result,
            "evidence_chain": evidence_chain,
        }

    def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.server.call_tool(name, arguments)["structuredContent"]


def _tool_call(name: str, purpose: str, result: dict[str, Any], **extra: Any) -> dict[str, Any]:
    record = {
        "name": name,
        "purpose": purpose,
        "success": True,
        "result_summary": _summarize(result),
    }
    record.update(extra)
    return record


def _summarize(result: dict[str, Any]) -> dict[str, Any]:
    keys = ("found", "is_valid", "confidence", "reason", "false_positive_reason")
    return {key: result[key] for key in keys if key in result}
