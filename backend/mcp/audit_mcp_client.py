"""MCP client adapter used by VerifyAgent.

已扩展支持 vulnerability-verification skill v2.0 新增工具：
  dynamic_http_verify, extract_target_function,
  generate_fuzzing_harness, run_fuzzing_harness

新工具在 run_verification_skill() 中按 Skill 工作流顺序调用。
"""
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
        *,
        base_url: str | None = None,
        endpoints: list[str] | None = None,
        enable_dynamic: bool = False,
        enable_harness: bool = False,
    ) -> dict[str, Any]:
        """按 Skill 工作流依序调用 MCP tools，返回工具证据汇总。

        Parameters
        ----------
        candidate      : 候选漏洞 dict（旧格式）
        code_root      : 代码根目录
        skill          : load_skill() 返回的 dict
        base_url       : 动态目标 URL（为空则 dynamic_http_verify 返回 not_executed）
        endpoints      : 动态目标端点列表
        enable_dynamic : 是否调用 dynamic_http_verify 工具（默认 False）
        enable_harness : 是否调用 harness 相关工具（默认 False）

        向后兼容说明：
          旧代码调用不传 enable_dynamic/enable_harness 时默认均为 False，
          仅运行核心 4 工具（read_code_context/run_sast_replay/verify_source_sink/build_evidence_chain），
          与 v1.0 行为一致。
        """
        tool_manifest = self.server.list_tools()
        allowed_tools = {tool["name"] for tool in tool_manifest}
        skill_tools = list(skill.get("tools") or [])
        # 仅检查核心工具是否可用（新增的工具允许在 allowed 中但可选执行）
        core_tools = {"read_code_context", "run_sast_replay", "verify_source_sink", "build_evidence_chain"}
        missing_core = [t for t in skill_tools if t in core_tools and t not in allowed_tools]
        if missing_core:
            raise ValueError(f"Skill references unavailable MCP tools: {', '.join(missing_core)}")

        tools_used: list[dict[str, Any]] = []
        code_context: dict[str, Any] = {}
        sast_replay: dict[str, Any] = {}
        heuristic_result: dict[str, Any] = {}
        evidence_chain: dict[str, Any] = {}
        harness_result: dict[str, Any] = {}
        dynamic_result: dict[str, Any] = {}
        knowledge_result: dict[str, Any] = {}
        playbook_result: dict[str, Any] = {}
        remediation_result: dict[str, Any] = {}

        for tool_name in skill_tools:
            if tool_name == "retrieve_security_knowledge":
                knowledge_result = self._call(tool_name, {
                    "candidate": candidate,
                    "limit": 3,
                })
                tools_used.append(_tool_call(
                    tool_name,
                    "Retrieve CWE/OWASP security knowledge through the MCP server.",
                    knowledge_result,
                ))

            elif tool_name == "retrieve_verification_playbook":
                playbook_result = self._call(tool_name, {
                    "candidate": candidate,
                    "limit": 2,
                })
                tools_used.append(_tool_call(
                    tool_name,
                    "Retrieve verification playbook and false-positive checks.",
                    playbook_result,
                ))

            elif tool_name == "retrieve_remediation_advice":
                remediation_result = self._call(tool_name, {
                    "candidate": candidate,
                    "limit": 2,
                })
                tools_used.append(_tool_call(
                    tool_name,
                    "Retrieve remediation guidance for the finding.",
                    remediation_result,
                ))

            elif tool_name == "read_code_context":
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

            elif tool_name == "dynamic_http_verify":
                # 未启用动态验证时跳过，避免在不需要时发起 HTTP 请求
                if not enable_dynamic:
                    continue
                # 未配置 base_url 时将返回 not_executed（工具层保证语义正确）
                from backend.verifier import exploit_templates
                template = exploit_templates.match_template(candidate.get("type"))
                exploit_hint = {
                    "vuln_type": candidate.get("type"),
                    "payloads": heuristic_result.get("suggested_payloads") or (
                        list(template.payloads) if template else []),
                    "success_indicators": heuristic_result.get("success_indicators") or (
                        list(template.success_indicators) if template else []),
                    "_injection_points": list(template.injection_points) if template else [],
                }
                dynamic_result = self._call(tool_name, {
                    "finding": candidate,
                    "exploit": exploit_hint,
                    "base_url": base_url,
                    "endpoints": endpoints,
                })
                tools_used.append(_tool_call(
                    tool_name,
                    "Perform dynamic HTTP verification through the MCP server.",
                    dynamic_result,
                ))

            elif tool_name == "extract_target_function":
                # 未启用 harness 时跳过
                if not enable_harness:
                    continue
                # Harness 只有一个权威入口。旧实现先提取函数、随后却丢弃提取结果，
                # 又生成通用模板，最终只凭 triggered=True 就可能自证 harness_confirmed。
                # 统一委托 HarnessVerifier，让 nonce、来源认证和证据分级在同一处完成。
                from backend.verifier.harness_verifier import HarnessVerifier
                harness_result = HarnessVerifier().run(candidate, code_root)
                tools_used.append(_tool_call(
                    "harness_verifier",
                    "Run the authoritative target-aware harness verifier.",
                    harness_result,
                ))

            elif tool_name == "generate_fuzzing_harness":
                # 已由上面的权威 HarnessVerifier 完成；禁止重复走通用模板自证路径。
                continue

            elif tool_name == "run_fuzzing_harness":
                # 已由上面的权威 HarnessVerifier 完成。
                continue

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
            "knowledge_result": knowledge_result,
            "playbook_result": playbook_result,
            "remediation_result": remediation_result,
            "dynamic_result": dynamic_result,
            "harness_result": harness_result,
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
    keys = (
        "found", "is_valid", "confidence", "reason", "false_positive_reason",
        "top_result", "summary", "query",
    )
    return {key: result[key] for key in keys if key in result}
