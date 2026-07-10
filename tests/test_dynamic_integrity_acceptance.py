"""动态验证「诚实性」验收测试（对应重构 prompt 第九节反造假验收标准）。

所有断言都建立在【框架侧独立观测的事实】上，绝不采信 Harness 脚本自报、
LLM 自述、字符串 success 或单纯 HTTP 200。
"""
import httpx

from backend.skills.harness_tools import run_harness, scaffold_capability
from backend.mcp.audit_mcp_server import AuditMCPServer


def test_harness_only_prints_success_is_not_confirmed():
    """#4：Harness 仅打印自报 success（不跑真实项目代码）不得 target_confirmed。

    覆盖 llm 源与「持有效 scaffold 令牌但无框架 nonce」两条路径——都不能被自报骗过。
    """
    code = ("import json\n"
            "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({"
            "'triggered': True, 'target_function_called': True, 'sink_called': True}))\n")
    for src, tok in (("llm", None), ("scaffold", scaffold_capability())):
        r = run_harness(code, source=src, scaffold_token=tok, require_docker=False)
        assert r["verdict"] != "target_confirmed", f"{src} 自报不得升级 target_confirmed"
        # 框架 nonce 未出现 -> target_function_called 必须为 False（不采信脚本自报同名字段）
        assert r["target_function_called"] is False


def test_run_fuzzing_harness_and_run_harness_code_are_consistent():
    """#9：run_fuzzing_harness 与 run_harness_code 复用同一实现，行为一致（别名）。"""
    srv = AuditMCPServer()
    tmpl = srv.call_tool("generate_fuzzing_harness",
                         {"vuln_type": "Command Injection"})["structuredContent"]["harness_code"]
    a = srv.call_tool("run_fuzzing_harness",
                      {"harness_code": tmpl, "source": "template"})["structuredContent"]
    b = srv.call_tool("run_harness_code",
                      {"code": tmpl, "source": "template"})["structuredContent"]
    assert a["verdict"] == b["verdict"]
    assert a["triggered"] == b["triggered"]
    assert a["verification_level"] == b["verification_level"]


def test_http_probe_ignores_system_proxy(monkeypatch):
    """#8：HTTP 客户端必须 trust_env=False，忽略 HTTP_PROXY/HTTPS_PROXY，
    避免系统代理劫持本地目标验证。"""
    from backend.verifier.dynamic_verifier import HttpProbe

    captured = {}
    real_client = httpx.Client

    def spy_client(*a, **k):
        captured.update(k)
        return real_client(*a, **k)

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setattr(httpx, "Client", spy_client)
    try:
        HttpProbe(timeout=1).send("http://127.0.0.1:1", "/x", "id", "1")
    except Exception:  # noqa: BLE001  连接失败无所谓，只验证客户端构造参数
        pass
    assert captured.get("trust_env") is False


def test_max_verify_candidates_zero_means_unlimited():
    """#10：max_verify_candidates=0 表示不限，不得回退成 50/500 等默认值。"""
    from backend.agents.orchestrator_agent import OrchestratorAgent
    inst = OrchestratorAgent.__new__(OrchestratorAgent)  # 仅测纯逻辑，不需初始化
    assert OrchestratorAgent._verify_candidate_limit(inst, {"max_verify_candidates": 0}, 1234) == 1234
    assert OrchestratorAgent._verify_candidate_limit(inst, {"max_verify_candidates": -1}, 1234) == 1234
    # 正常上限仍生效
    assert OrchestratorAgent._verify_candidate_limit(inst, {"max_verify_candidates": 50}, 1234) == 50
