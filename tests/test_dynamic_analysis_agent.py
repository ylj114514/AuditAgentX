"""DynamicAnalysisAgent 测试（离线：plan 决策 + harness 执行，不依赖 LLM/靶场）。"""
from pathlib import Path

from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent, _derive_dynamic_verdict, _dynamic_summary

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_plan_detects_launch_and_endpoints():
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 29,
                 "status": "confirmed", "severity": "high"}]
    plan = DynamicAnalysisAgent().plan(findings, DEMO)
    assert plan["launch"]["framework"] == "Flask"
    assert plan["endpoint_count"] >= 1
    assert plan["dynamic_applicable_count"] == 1


def test_plan_marks_secret_not_applicable():
    findings = [{"type": "Hardcoded Secret", "file": "app.py", "start_line": 12,
                 "status": "confirmed", "severity": "high"}]
    plan = DynamicAnalysisAgent().plan(findings, DEMO)
    strat = plan["strategies"][0]
    assert strat["applicable"] is False
    assert strat["strategy"] == "not_applicable"


def test_run_harness_mechanism_confirmed_via_template(monkeypatch):
    """无 LLM 时走模板 Harness：只证明机理 -> mechanism_confirmed，且不标记完全动态确认。"""
    # 强制 LLM 返回空 -> 模板兜底，离线确定性
    monkeypatch.setattr("backend.verifier.harness_verifier.HarnessVerifier._call",
                        lambda self, content: {})
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 38,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(...)"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_exploit=False,
                               enable_dynamic=False, enable_harness=True)
    harness = findings[0].get("_harness") or {}
    assert harness.get("verdict") == "mechanism_confirmed"
    assert harness.get("dynamically_triggered") is False        # 机理级 != 完全动态确认
    assert harness.get("function_mechanism_verified") is True
    # finding 层：机理确认不应把它标记为 dynamically_verified
    assert findings[0].get("dynamically_verified") is not True
    assert findings[0].get("function_mechanism_verified") is True


def test_run_only_touches_confirmed():
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 21,
                 "status": "false_positive", "severity": "high"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_harness=True)
    assert findings[0].get("_harness") is None


def test_mechanism_harness_does_not_count_as_harness_confirmed():
    harness = {
        "verdict": "mechanism_confirmed",
        "dynamically_triggered": True,
        "verification_level": "template_mechanism",
        "function_extracted": False,
        "target_function_called": False,
    }

    assert _derive_dynamic_verdict({}, harness) == "not_executed"
    summary = _dynamic_summary([{"_harness": harness}], None)
    assert summary["harness_confirmed"] == 0
