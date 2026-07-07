"""验证 ACP 模型真正落地 + Agent×Skill×MCP 统一（离线，monkeypatch 避开 LLM）。"""
from pathlib import Path

from backend.acp.factory import make_message
from backend.acp.models import ACPMessageType, ACPVerification, ACPExploit
from backend.agents.verify_agent import VerifyAgent
from backend.agents.exploit_agent import ExploitAgent
from backend.agents.static_scan_agent import StaticScanAgent
from backend.verifier.harness_verifier import HarnessVerifier

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_agents_load_their_skills():
    """每个该走 Skill 的 Agent 都加载了对应 Skill（孤儿 Skill 落地）。"""
    assert HarnessVerifier().skill.get("name") == "dynamic-exploitation"
    assert StaticScanAgent().skill.get("name") == "static-scanning"
    assert ExploitAgent().skill.get("name") == "exploit-generation"


def test_verify_run_acp_grounds_acpverification(monkeypatch):
    """VerifyAgent.run_acp 的 verification 能被 ACPVerification 反校验 —— 模型真正落地。"""
    monkeypatch.setattr(VerifyAgent, "_call", lambda self, c: {})
    req = make_message(
        sender="orchestrator", receiver="verify_agent",
        message_type=ACPMessageType.VERIFY_REQUEST,
        payload={"finding": {"type": "SQL Injection",
                             "location": {"file": "app.py", "start_line": 21},
                             "code": {"snippet": "cursor.execute('select * from u where id='+uid)"}}},
    )
    res = VerifyAgent().run_acp(req)
    v = res.payload["verification"]
    ACPVerification.model_validate(v)          # 不抛错即证明字段结构合法
    assert v["dynamic_verdict"] == "not_executed"


def test_exploit_run_acp_grounds_acpexploit(monkeypatch):
    """ExploitAgent.run_acp 的 exploit 能被 ACPExploit 反校验 —— 模型真正落地。"""
    monkeypatch.setattr(ExploitAgent, "_call", lambda self, c: {})
    req = make_message(
        sender="orchestrator", receiver="exploit_agent",
        message_type=ACPMessageType.EXPLOIT_GENERATE_REQUEST,
        payload={"finding": {"type": "Command Injection",
                             "location": {"file": "app.py", "start_line": 29}},
                 "verification": {"source": "x", "sink": "os.system"}},
    )
    res = ExploitAgent().run_acp(req)
    ACPExploit.model_validate(res.payload["exploit"])
    assert res.payload["exploit"]["vuln_type"] == "Command Injection"


def test_harness_verifier_uses_mcp_and_skill(monkeypatch):
    """HarnessVerifier 经 MCP 工具执行，并挂载 dynamic-exploitation Skill。"""
    monkeypatch.setattr(HarnessVerifier, "_call", lambda self, c: {})
    r = HarnessVerifier().run(
        {"type": "Command Injection", "file": "app.py", "line": 29,
         "status": "confirmed", "code_snippet": "os.system(...)"},
        DEMO, max_retries=0,
    )
    names = [t["name"] for t in r.get("tool_calls", [])]
    assert "extract_target_function" in names
    assert "run_fuzzing_harness" in names
    assert r["skill"]["name"] == "dynamic-exploitation"
    assert r["verdict"] == "confirmed_dynamic"


def test_verify_dynamic_activation_without_base_url_is_not_executed(monkeypatch):
    """启用动态验证但未配置 base_url -> dynamic_verdict 必须是 not_executed（非 not_reproduced）。"""
    monkeypatch.setattr(VerifyAgent, "_call", lambda self, c: {})
    vr = VerifyAgent().run(
        {"type": "SQL Injection", "file": "app.py", "start_line": 21,
         "code_snippet": "cursor.execute('select * from u where id='+uid)"},
        DEMO, enable_dynamic=True, base_url=None,
    )
    assert vr["dynamic_verdict"] == "not_executed"
