from pathlib import Path

from backend.agents.static_scan_agent import StaticScanAgent
from backend.agents.verify_agent import VerifyAgent
from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.mcp.audit_mcp_server import AuditMCPServer
from backend.skills.loader import load_skill


def test_static_scan_agent_records_tool_calls(tmp_path: Path):
    agent = StaticScanAgent()
    agent.run(tmp_path, ["custom"])
    tools = {call["tool"] for call in agent.tool_calls}
    assert "run_custom_rules" in tools
    assert any("SQL injection" in call["purpose"] for call in agent.tool_calls)


def test_verify_agent_keeps_unproven_parameter_origin_for_review(monkeypatch, tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "\n".join([
            "def user(uid, cur):",
            "    sql = \"select * from users where id=\" + uid",
            "    return cur.execute(sql)",
        ]),
        encoding="utf-8",
    )
    monkeypatch.setattr(VerifyAgent, "_call", lambda self, content: {"_error": "llm disabled"})

    result = VerifyAgent().run({
        "type": "SQL Injection",
        "file": "app.py",
        "start_line": 2,
        "code_snippet": "sql = \"select * from users where id=\" + uid",
        "confidence": 0.5,
    }, code_root=tmp_path)

    assert result["is_valid"] is None
    assert result["needs_review"] is True
    assert not result.get("source")
    assert not result.get("sink")
    assert result["_tool_evidence"]["code_context"]["found"] is True
    assert result["_tool_evidence"]["heuristic_result"]["is_valid"] is None
    assert "read_code_context" in {tool["name"] for tool in result["_tool_evidence"]["tools_used"]}
    assert "run_sast_replay" in {tool["name"] for tool in result["tool_calls"]}
    assert result.get("call_path") is not None
    assert result["evidence_chain"]["sast_replay"]["matched_rules"]
    assert result["_tool_evidence"]["architecture"] == "MCP+Skill"
    assert result["_tool_evidence"]["skill"]["name"] == "vulnerability-verification"


def test_mcp_server_exposes_verification_tools(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def user(uid, cur):\n    sql = 'select * from users where id=' + uid\n    return cur.execute(sql)\n",
        encoding="utf-8",
    )
    candidate = {
        "type": "SQL Injection",
        "file": "app.py",
        "start_line": 2,
        "code_snippet": "sql = 'select * from users where id=' + uid",
    }

    server = AuditMCPServer()
    tool_names = {tool["name"] for tool in server.list_tools()}
    assert {"read_code_context", "run_sast_replay", "verify_source_sink", "build_evidence_chain"} <= tool_names

    client = AuditMCPClient(server=server)
    skill = load_skill("vulnerability-verification")
    context = client.run_verification_skill(candidate, tmp_path, skill)

    assert context["architecture"] == "MCP+Skill"
    calls = [call["name"] for call in context["tools_used"]]
    assert calls[:2] == ["retrieve_security_knowledge", "retrieve_verification_playbook"]
    assert calls.index("read_code_context") < calls.index("run_sast_replay") < calls.index("verify_source_sink")
    assert "retrieve_remediation_advice" in calls
    assert context["knowledge_result"]["top_result"]["cwe_id"] == "CWE-89"
    assert context["code_context"]["found"] is True
    assert context["heuristic_result"]["is_valid"] is None
    assert "not proven to reach" in context["heuristic_result"]["reason"]
    assert isinstance(context["evidence_chain"]["call_path"], list)


def test_vulnerability_verification_skill_declares_required_tools():
    """v2.0 Skill 保留全部原有工具，并新增动态/harness 工具。"""
    skill = load_skill("vulnerability-verification")
    assert skill["name"] == "vulnerability-verification"
    # 原有 4 个核心工具必须保留（向后兼容）
    core_tools = {
        "read_code_context",
        "run_sast_replay",
        "verify_source_sink",
        "build_evidence_chain",
    }
    assert core_tools <= set(skill["tools"]), "原有核心工具不得删除"
    # v2.0 新增动态/harness 工具
    new_tools = {
        "dynamic_http_verify",
        "extract_target_function",
        "generate_fuzzing_harness",
        "run_fuzzing_harness",
    }
    assert new_tools <= set(skill["tools"]), "v2.0 新增工具必须声明"
    knowledge_tools = {
        "retrieve_security_knowledge",
        "retrieve_verification_playbook",
        "retrieve_remediation_advice",
    }
    assert knowledge_tools <= set(skill["tools"]), "RAG 知识增强工具必须声明"


def test_verify_agent_conflict_parameterized_sql_needs_review(monkeypatch, tmp_path: Path):
    """LLM 确认为漏洞但本地启发式判参数化安全时：不再让启发式静默否决 LLM，
    而是保留 is_valid=True 并标 needs_review + 记录分歧（避免真实漏洞被 naive 正则吞掉）。"""
    (tmp_path / "app.py").write_text(
        "\n".join([
            "def user(uid, cur):",
            "    return cur.execute(\"select * from users where id=?\", (uid,))",
        ]),
        encoding="utf-8",
    )
    monkeypatch.setattr(VerifyAgent, "_call", lambda self, content: {"is_valid": True, "confidence": 0.6})

    result = VerifyAgent().run({
        "type": "SQL Injection",
        "file": "app.py",
        "start_line": 2,
        "code_snippet": "cur.execute(\"select * from users where id=?\", (uid,))",
        "confidence": 0.5,
    }, code_root=tmp_path)

    # LLM 确认不再被静默否决：保留为漏洞、标 needs_review、记录启发式分歧
    assert result["is_valid"] is True
    assert result["needs_review"] is True
    assert "parameterized" in result["heuristic_disagreement"].lower()
    # 本地启发式本身仍然识别出参数化安全（其 is_valid 仍为 False，只是不再拥有否决权）
    assert result["_tool_evidence"]["heuristic_result"]["is_valid"] is False


def test_exploit_fallback_uses_verified_call_path():
    from backend.agents.exploit_agent import ExploitAgent
    from backend.verifier import exploit_templates as tpl

    template = tpl.match_template("SQL Injection")
    finding = {
        "type": "SQL Injection",
        "file": "app.py",
        "line": 21,
        "_verify": {
            "call_path": [
                {"stage": "source", "file": "app.py", "line": 17, "detail": "request.args['id']"},
                {"stage": "sink", "file": "app.py", "line": 21, "detail": "cursor.execute"},
            ]
        },
    }
    result = ExploitAgent._fallback(finding, template)
    assert "source" in result["exploit_path"]
    assert "/user" in result["exploit_code"]
