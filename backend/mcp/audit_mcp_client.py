"""MCP client adapter used by VerifyAgent.

已扩展支持 vulnerability-verification skill v2.0 新增工具：
  dynamic_http_verify, extract_target_function,
  generate_fuzzing_harness, run_fuzzing_harness

新工具在 run_verification_skill() 中按 Skill 工作流顺序调用。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from backend.mcp.audit_mcp_server import AuditMCPServer
from backend.scanners.base import RawFinding
from backend.scanners.registry import consolidate_findings


_STATIC_TOOL_TO_SCANNER = {
    "run_semgrep": "semgrep",
    "run_bandit": "bandit",
    "run_gitleaks": "gitleaks",
    "run_trivy": "trivy",
    "run_custom_rules": "custom",
}


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
                    "code_root": str(code_root) if code_root else None,
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

    def run_static_scanning_skill(
        self,
        code_root: Path,
        enabled_tools: list[str],
        skill: dict[str, Any],
        *,
        max_files: int = 20000,
        severity_threshold: str = "low",
        scan_id: str | None = None,
        include_test_findings: bool = False,
    ) -> dict[str, Any]:
        """Run StaticScanAgent's Skill through MCP scanner tools.

        This is the missing architecture bridge: StaticScanAgent loads the
        `static-scanning` Skill, this client validates the Skill tool names
        against the MCP manifest, then executes each selected scanner through
        `AuditMCPServer.call_tool()` instead of calling subprocess wrappers
        directly from the agent.
        """
        tool_manifest = self.server.list_tools()
        allowed_tools = {tool["name"] for tool in tool_manifest}
        skill_tools = [tool for tool in (skill.get("tools") or []) if tool in _STATIC_TOOL_TO_SCANNER]
        selected_scanners = set(dict.fromkeys(list(enabled_tools or []) + ["custom"]))
        known_scanners = set(_STATIC_TOOL_TO_SCANNER.values())
        selected_skill_tools = [
            tool for tool in skill_tools
            if _STATIC_TOOL_TO_SCANNER[tool] in selected_scanners
        ]
        missing = [tool for tool in selected_skill_tools if tool not in allowed_tools]
        if missing:
            raise ValueError(f"Static scanning Skill references unavailable MCP tools: {', '.join(missing)}")

        all_findings: list[RawFinding] = []
        scanner_status: list[dict[str, Any]] = [
            {
                "tool": scanner, "available": False, "executed": False,
                "success": False, "error": "unknown_scanner", "finding_count": 0,
                "partial_results": False,
            }
            for scanner in sorted(selected_scanners - known_scanners)
        ]
        selected_by_skill = {_STATIC_TOOL_TO_SCANNER[tool] for tool in selected_skill_tools}
        scanner_status.extend({
            "tool": scanner, "available": False, "executed": False,
            "success": False, "error": "scanner_missing_from_skill", "finding_count": 0,
            "partial_results": False,
        } for scanner in sorted((selected_scanners & known_scanners) - selected_by_skill))
        tools_used: list[dict[str, Any]] = []

        preflight: dict[str, Any] = {}
        if "check_static_tool_availability" in (skill.get("tools") or []):
            if "check_static_tool_availability" not in allowed_tools:
                raise ValueError("Static scanning Skill references unavailable MCP tool: check_static_tool_availability")
            preflight = self._call("check_static_tool_availability", {
                "enabled_tools": list(selected_scanners),
            })
            tools_used.append(_tool_call(
                "check_static_tool_availability",
                "Check scanner availability through the MCP server before execution.",
                preflight,
                success=True,
            ))

        def run_tool(tool_name: str) -> tuple[str, dict[str, Any]]:
            scanner_name = _STATIC_TOOL_TO_SCANNER[tool_name]
            result = self._call(tool_name, {
                "code_root": str(code_root),
                "max_files": max_files,
                "scan_id": scan_id,
                "include_test_findings": include_test_findings,
            })
            return scanner_name, result

        # Static tools have no data dependency on one another.  Keep the MCP
        # boundary and one tool-call record per scanner, but run the independent
        # work concurrently as the pre-MCP registry path did.
        results_by_tool: dict[str, tuple[str, dict[str, Any]]] = {}
        if selected_skill_tools:
            with ThreadPoolExecutor(max_workers=min(len(selected_skill_tools), 5),
                                    thread_name_prefix="mcp-static") as pool:
                futures = {
                    tool_name: pool.submit(run_tool, tool_name)
                    for tool_name in selected_skill_tools
                }
                for tool_name, future in futures.items():
                    results_by_tool[tool_name] = future.result()

        # Results are recorded in Skill order so reports and ACP evidence remain
        # deterministic even though execution above is concurrent.
        for tool_name in selected_skill_tools:
            scanner_name, result = results_by_tool[tool_name]
            status = dict(result.get("scanner_status") or {})
            scanner_status.append(status)
            raw_items = result.get("raw_findings") or []
            all_findings.extend(_raw_finding_from_dict(item) for item in raw_items)
            tools_used.append(_tool_call(
                tool_name,
                f"Run {scanner_name} through the MCP static scanning tool.",
                {
                    "scanner_status": status,
                    "finding_count": len(raw_items),
                },
                scanner=scanner_name,
                success=bool(status.get("success")),
            ))

        consolidated = consolidate_findings(all_findings)
        threshold = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            str(severity_threshold or "low").lower(), 1,
        )
        consolidated = [
            finding for finding in consolidated
            if {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(
                str(finding.severity).lower(), 1,
            ) >= threshold
        ]
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
            "preflight": preflight,
            "raw_findings": [finding.to_dict() for finding in consolidated],
            "scanner_status": scanner_status,
        }

    def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.server.call_tool(name, arguments)["structuredContent"]


def _tool_call(name: str, purpose: str, result: dict[str, Any], **extra: Any) -> dict[str, Any]:
    record = {
        "name": name,
        "purpose": purpose,
        "success": bool(extra.pop("success", True)),
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


def _raw_finding_from_dict(item: dict[str, Any]) -> RawFinding:
    return RawFinding(
        type=str(item.get("type") or "unknown"),
        file=str(item.get("file") or ""),
        line=int(item.get("line") or 0),
        severity=str(item.get("severity") or "low"),
        source=str(item.get("source") or ""),
        code_snippet=str(item.get("code_snippet") or ""),
        message=str(item.get("message") or ""),
        rule_id=str(item.get("rule_id") or ""),
        extra=dict(item.get("extra") or {}),
    )
