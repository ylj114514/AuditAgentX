"""StaticScanAgent: MCP+Skill tool-calling scanner agent.

It loads the static-scanning Skill, dispatches SAST/secret/SCA/custom-rule tools
through the AuditAgentX MCP tool boundary, and normalizes their output into
RawFinding records.
"""
from __future__ import annotations

from pathlib import Path

from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.scanners.base import RawFinding


class StaticScanAgent:
    name = "static_scan_agent"

    def __init__(self) -> None:
        self.tool_calls: list[dict] = []
        self.scanner_status: list[dict] = []
        # 加载 static-scanning Skill（声明扫描工具工作流，统一 Agent×Skill 结构）
        try:
            from backend.skills.loader import load_skill
            self.skill = load_skill("static-scanning")
        except Exception:  # noqa: BLE001
            self.skill = {}
        self.mcp_client = AuditMCPClient()

    def run(self, code_root: Path, enabled_tools: list[str], *, max_files: int | None = None,
            severity_threshold: str | None = None, scan_id: str | None = None) -> list[RawFinding]:
        max_files = max_files or getattr(self, "_max_files", 20000)
        severity_threshold = severity_threshold or getattr(self, "_severity_threshold", "low")
        try:
            max_files = max(1, min(int(max_files), 200000))
        except (TypeError, ValueError):
            max_files = 20000
        tools = list(dict.fromkeys(enabled_tools + ["custom"]))
        result = self.mcp_client.run_static_scanning_skill(
            code_root,
            enabled_tools,
            self.skill,
            max_files=max_files,
            severity_threshold=severity_threshold,
            scan_id=scan_id or getattr(self, "_scan_id", None),
        )
        findings = [_raw_finding_from_dict(item) for item in (result.get("raw_findings") or [])]
        self.scanner_status = list(result.get("scanner_status") or [])
        status_by_tool = {item.get("tool"): item for item in self.scanner_status}
        self.tool_calls = [
            {
                "tool": _mcp_tool_name(tool),
                "scanner": tool,
                "purpose": _tool_purpose(tool),
                "target": str(code_root),
                "status": status_by_tool.get(tool) or {},
                "architecture": result.get("architecture"),
                "mcp_server": result.get("mcp_server"),
            }
            for tool in tools
        ]
        return findings

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
                         or request.context.enabled_tools or ["semgrep", "bandit", "gitleaks", "trivy"])
        if not code_root_str:
            return make_reply(
                request, sender=self.name,
                message_type=ACPMessageType.STATIC_SCAN_RESULT,
                intent="缺少 code_root，无法扫描",
                state=ACPState.FAILED, error="missing code_root",
            )
        self._max_files = request.payload.get("max_files") or 20000
        self._severity_threshold = request.payload.get("severity_threshold") or "low"
        self._scan_id = request.context.scan_id or getattr(request, "task_id", None)
        raw = self.run(Path(code_root_str), enabled_tools)
        acp_findings = [raw_finding_to_acp(rf) for rf in raw]
        raw_findings = [rf.to_dict() for rf in raw]
        failed_tools = [
            item for item in self.scanner_status
            if item.get("tool") in set(enabled_tools) and not item.get("success")
        ]
        tool_calls = [ACPToolCall(
            tool_name=tc["tool"], input={"target": tc["target"]},
            output={
                "purpose": tc["purpose"],
                "scanner": tc.get("scanner"),
                "architecture": tc.get("architecture"),
                "mcp_server": tc.get("mcp_server"),
                "status": tc.get("status") or {},
            },
            success=bool((tc.get("status") or {}).get("success")),
        ) for tc in self.tool_calls]
        return make_reply(
            request, sender=self.name,
            message_type=ACPMessageType.STATIC_SCAN_RESULT,
            intent=f"静态扫描完成，命中 {len(acp_findings)} 条",
            payload={
                "findings": acp_findings,
                "raw_findings": raw_findings,
                # 兼容既有测试/调用方，第一阶段不强制删除旧字段。
                "_raw": raw_findings,
                "scanner_status": self.scanner_status,
                "complete": not failed_tools,
                "failed_tools": failed_tools,
            },
            tools=tool_calls,
            # A partial scanner result is still returned so healthy tools are not
            # discarded.  The orchestrator promotes this to partial_completed;
            # callers must never confuse it with a fully successful scan.
            state=ACPState.SUCCESS,
        )


def _tool_purpose(tool: str) -> str:
    return {
        "semgrep": "SAST rule scanning for injection, traversal, XSS, and framework risks.",
        "bandit": "Python security linting.",
        "gitleaks": "Secret and credential leakage detection.",
        "trivy": "Dependency CVE, secret, container and infrastructure-as-code scanning.",
        "custom": "Built-in offline rules for SQL injection, command injection, path traversal, and hardcoded secrets.",
    }.get(tool, "External or custom static analysis tool.")


def _mcp_tool_name(scanner: str) -> str:
    return {
        "semgrep": "run_semgrep",
        "bandit": "run_bandit",
        "gitleaks": "run_gitleaks",
        "trivy": "run_trivy",
        "custom": "run_custom_rules",
    }.get(scanner, scanner)


def _raw_finding_from_dict(item: dict) -> RawFinding:
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
