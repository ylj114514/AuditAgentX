"""StaticScanAgent: tool-calling scanner agent.

It dispatches SAST/secret/SCA/custom-rule tools through the scanner registry and
normalizes their output into RawFinding records.
"""
from __future__ import annotations

from pathlib import Path

from backend.scanners.registry import run_scanners
from backend.scanners.base import RawFinding


class StaticScanAgent:
    name = "static_scan_agent"

    def __init__(self) -> None:
        self.tool_calls: list[dict] = []
        # 加载 static-scanning Skill（声明扫描工具工作流，统一 Agent×Skill 结构）
        try:
            from backend.skills.loader import load_skill
            self.skill = load_skill("static-scanning")
        except Exception:  # noqa: BLE001
            self.skill = {}

    def run(self, code_root: Path, enabled_tools: list[str]) -> list[RawFinding]:
        tools = list(dict.fromkeys(enabled_tools + ["custom"]))
        self.tool_calls = [
            {
                "tool": tool,
                "purpose": _tool_purpose(tool),
                "target": str(code_root),
            }
            for tool in tools
        ]
        return run_scanners(code_root, enabled_tools)

    def run_acp(self, request: "ACPMessage") -> "ACPMessage":  # noqa: F821
        """ACP 接口：static_scan.request → static_scan.result。

        输入 payload.code_root + payload.enabled_tools；
        输出 payload.findings 为统一 ACPFinding 列表，payload.raw_findings
        保留原 RawFinding dict（供内部 legacy 链路复用）。
        """
        from backend.acp.factory import make_reply
        from backend.acp.models import ACPMessageType, ACPState, ACPToolCall
        from backend.acp.adapters import raw_finding_to_acp

        code_root_str = request.payload.get("code_root") or request.context.code_root
        enabled_tools = (request.payload.get("enabled_tools")
                         or request.context.enabled_tools or ["semgrep", "gitleaks"])
        if not code_root_str:
            return make_reply(
                request, sender=self.name,
                message_type=ACPMessageType.STATIC_SCAN_RESULT,
                intent="缺少 code_root，无法扫描",
                state=ACPState.FAILED, error="missing code_root",
            )
        raw = self.run(Path(code_root_str), enabled_tools)
        acp_findings = [raw_finding_to_acp(rf) for rf in raw]
        raw_findings = [rf.to_dict() for rf in raw]
        tool_calls = [ACPToolCall(tool_name=tc["tool"], input={"target": tc["target"]},
                                  output={"purpose": tc["purpose"]}) for tc in self.tool_calls]
        return make_reply(
            request, sender=self.name,
            message_type=ACPMessageType.STATIC_SCAN_RESULT,
            intent=f"静态扫描完成，命中 {len(acp_findings)} 条",
            payload={
                "findings": acp_findings,
                "raw_findings": raw_findings,
                # 兼容既有测试/调用方，第一阶段不强制删除旧字段。
                "_raw": raw_findings,
            },
            tools=tool_calls,
            state=ACPState.SUCCESS,
        )


def _tool_purpose(tool: str) -> str:
    return {
        "semgrep": "SAST rule scanning for injection, traversal, XSS, and framework risks.",
        "bandit": "Python security linting.",
        "gitleaks": "Secret and credential leakage detection.",
        "trivy": "Dependency, container, and configuration vulnerability scanning.",
        "custom": "Built-in offline rules for SQL injection, command injection, path traversal, and hardcoded secrets.",
    }.get(tool, "External or custom static analysis tool.")
