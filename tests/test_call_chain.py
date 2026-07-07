"""Vulnhuntr 式跨文件调用链补全测试（离线，不依赖 LLM）。"""
from pathlib import Path

from backend.dynamic.symbol_resolver import resolve_symbol, extract_referenced_symbols
from backend.agents.audit_agent import AuditAgent
from backend.mcp.audit_mcp_server import AuditMCPServer

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_extract_referenced_symbols_filters_builtins():
    syms = extract_referenced_symbols("x = get_user(uid); print(x); os.system('ping '+host)")
    assert "get_user" in syms
    assert "print" not in syms          # 内置被过滤
    assert "system" in syms


def test_resolve_symbol_finds_definition():
    r = resolve_symbol(DEMO, "get_user")
    assert r["found"] is True
    assert r["count"] >= 1
    assert r["definitions"][0]["file"] == "app.py"
    assert "def get_user" in r["definitions"][0]["code"]


def test_resolve_symbol_missing_returns_not_found():
    r = resolve_symbol(DEMO, "nonexistent_function_xyz")
    assert r["found"] is False
    assert r["count"] == 0


def test_mcp_resolve_symbol_tool():
    srv = AuditMCPServer()
    names = {t["name"] for t in srv.list_tools()}
    assert "resolve_symbol" in names
    out = srv.call_tool("resolve_symbol", {"symbol": "get_user", "code_root": str(DEMO)})["structuredContent"]
    assert out["found"] is True


def test_audit_agent_expand_call_chain():
    hot_files = [{"file": "app.py", "code": "result = get_user(uid)\nreturn result"}]
    chain = AuditAgent._expand_call_chain(hot_files, DEMO)
    # get_user 定义应被跨文件补全进上下文
    assert any(c["symbol"] == "get_user" for c in chain)
    assert all("code" in c for c in chain)
