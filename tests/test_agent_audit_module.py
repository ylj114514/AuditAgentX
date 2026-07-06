from pathlib import Path

from backend.agents.static_scan_agent import StaticScanAgent
from backend.agents.verify_agent import VerifyAgent


def test_static_scan_agent_records_tool_calls(tmp_path: Path):
    agent = StaticScanAgent()
    agent.run(tmp_path, ["custom"])
    tools = {call["tool"] for call in agent.tool_calls}
    assert "custom" in tools
    assert any("SQL injection" in call["purpose"] for call in agent.tool_calls)


def test_verify_agent_confirms_unsafe_sql_with_local_tools(monkeypatch, tmp_path: Path):
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

    assert result["is_valid"] is True
    assert result["source"]
    assert result["sink"]
    assert result["_tool_evidence"]["code_context"]["found"] is True
    assert result["_tool_evidence"]["heuristic_result"]["is_valid"] is True
    assert "code_context_reader" in {tool["name"] for tool in result["_tool_evidence"]["tools_used"]}
    assert "local_sast_replay" in {tool["name"] for tool in result["tool_calls"]}
    assert result["call_path"]
    assert result["evidence_chain"]["sast_replay"]["matched_rules"]


def test_verify_agent_filters_parameterized_sql_false_positive(monkeypatch, tmp_path: Path):
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

    assert result["is_valid"] is False
    assert "parameterized" in result["false_positive_reason"].lower()
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
