"""DynamicAnalysisAgent 测试（离线：plan 决策 + harness 执行，不依赖 LLM/靶场）。"""
from pathlib import Path

from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent

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


def test_run_harness_confirms_command_injection():
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 29,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(...)"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_exploit=False,
                               enable_dynamic=False, enable_harness=True)
    harness = findings[0].get("_harness") or {}
    assert harness.get("verdict") == "confirmed_dynamic"
    assert harness.get("dynamically_triggered") is True


def test_run_only_touches_confirmed():
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 21,
                 "status": "false_positive", "severity": "high"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_harness=True)
    assert findings[0].get("_harness") is None
