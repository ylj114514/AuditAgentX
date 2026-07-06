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

    mcp.run()


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
