"""Optional stdio MCP entrypoint for AuditAgentX verification tools.

Run this module only after installing the official MCP Python SDK. The backend
runtime uses `AuditMCPServer` directly so normal tests do not require that
optional dependency.
"""
from __future__ import annotations

from backend.mcp.audit_mcp_server import AuditMCPServer


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - optional runtime path
        raise SystemExit("Install the optional 'mcp' Python package to run the stdio MCP server.") from exc

    bridge = AuditMCPServer()
    mcp = FastMCP(bridge.server_name)

    @mcp.tool()
    def read_code_context(candidate: dict, code_root: str | None = None, radius: int = 8) -> dict:
        return bridge.call_tool("read_code_context", {
            "candidate": candidate,
            "code_root": code_root,
            "radius": radius,
        })["structuredContent"]

    @mcp.tool()
    def run_sast_replay(candidate: dict, code_context: dict) -> dict:
        return bridge.call_tool("run_sast_replay", {
            "candidate": candidate,
            "code_context": code_context,
        })["structuredContent"]

    @mcp.tool()
    def verify_source_sink(candidate: dict, code_context: dict) -> dict:
        return bridge.call_tool("verify_source_sink", {
            "candidate": candidate,
            "code_context": code_context,
        })["structuredContent"]

    @mcp.tool()
    def build_evidence_chain(heuristic_result: dict, sast_replay: dict, tool_calls: list) -> dict:
        return bridge.call_tool("build_evidence_chain", {
            "heuristic_result": heuristic_result,
            "sast_replay": sast_replay,
            "tool_calls": tool_calls,
        })["structuredContent"]

    @mcp.tool()
    def extract_target_function(candidate: dict, code_root: str | None = None) -> dict:
        return bridge.call_tool("extract_target_function", {
            "candidate": candidate,
            "code_root": code_root,
        })["structuredContent"]

    @mcp.tool()
    def generate_fuzzing_harness(vuln_type: str, code_snippet: str | None = None) -> dict:
        return bridge.call_tool("generate_fuzzing_harness", {
            "vuln_type": vuln_type,
            "code_snippet": code_snippet,
        })["structuredContent"]

    @mcp.tool()
    def run_fuzzing_harness(harness_code: str, timeout: int | None = None) -> dict:
        return bridge.call_tool("run_fuzzing_harness", {
            "harness_code": harness_code,
            "timeout": timeout,
        })["structuredContent"]

    # ---- 新增工具 ----

    @mcp.tool()
    def dynamic_http_verify(
        finding: dict,
        exploit: dict,
        base_url: str | None = None,
        endpoints: list | None = None,
        payloads: list | None = None,
        success_indicators: list | None = None,
    ) -> dict:
        """动态 HTTP 验证工具。base_url 为空时返回 not_executed。"""
        return bridge.call_tool("dynamic_http_verify", {
            "finding": finding,
            "exploit": exploit,
            "base_url": base_url,
            "endpoints": endpoints,
            "payloads": payloads,
            "success_indicators": success_indicators,
        })["structuredContent"]

    @mcp.tool()
    def build_final_evidence(
        verify_result: dict,
        exploit: dict | None = None,
        dynamic: dict | None = None,
        harness: dict | None = None,
        poc_result: dict | None = None,
    ) -> dict:
        """汇总所有验证阶段的证据链。"""
        return bridge.call_tool("build_final_evidence", {
            "verify_result": verify_result,
            "exploit": exploit,
            "dynamic": dynamic,
            "harness": harness,
            "poc_result": poc_result,
        })["structuredContent"]

    @mcp.tool()
    def resolve_symbol(symbol: str, code_root: str | None = None, max_defs: int = 3) -> dict:
        """跨文件符号解析：按名字找函数/类定义源码，供调用链递归补全。"""
        return bridge.call_tool("resolve_symbol", {
            "symbol": symbol,
            "code_root": code_root,
            "max_defs": max_defs,
        })["structuredContent"]

    mcp.run()


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
