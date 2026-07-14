"""DynamicAnalysisAgent 测试（离线：plan 决策 + harness 执行，不依赖 LLM/靶场）。"""
from pathlib import Path

from backend.agents.dynamic_analysis_agent import (
    DynamicAnalysisAgent, _derive_dynamic_verdict, _derive_final_verdict, _dynamic_summary,
)

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_plan_detects_launch_and_endpoints():
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 29,
                 "status": "confirmed", "severity": "high"}]
    plan = DynamicAnalysisAgent().plan(findings, DEMO)
    assert plan["launch"]["framework"] == "Flask"
    assert plan["endpoint_count"] >= 1
    assert plan["dynamic_applicable_count"] == 1
    assert plan["strategies"][0]["primary_lane"] == "poc_sandbox"
    assert plan["runtime_plan"]["verification_policy"]["primary"] == "poc_sandbox_harness"


def test_plan_marks_secret_not_applicable():
    findings = [{"type": "Hardcoded Secret", "file": "app.py", "start_line": 12,
                 "status": "confirmed", "severity": "high"}]
    plan = DynamicAnalysisAgent().plan(findings, DEMO)
    strat = plan["strategies"][0]
    assert strat["applicable"] is False
    assert strat["strategy"] == "not_applicable"


def test_plan_builds_executable_target_for_nested_go_dockerfile(tmp_path):
    """计划必须能把仓库证据转成 Pipeline 可消费的 docker_project target。"""
    (tmp_path / "go.mod").write_text("module example.test/service\n", encoding="utf-8")
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    (docker_dir / "Dockerfile").write_text(
        "ARG APP_PORT=80\nENV PORT=$APP_PORT\nEXPOSE $APP_PORT\n"
        "HEALTHCHECK CMD curl --fail http://localhost:$PORT/health\n",
        encoding="utf-8",
    )
    plan = DynamicAnalysisAgent().plan(
        [{"type": "Command Injection", "status": "needs_review"}], tmp_path,
    )

    target = plan["runtime_plan"]["dynamic_target"]
    assert plan["runtime_plan"]["schema_version"] == "dynamic-runtime-plan/v1"
    assert target["mode"] == "docker_project"
    assert target["launch_plan"]["dockerfile"] == "docker/Dockerfile"
    assert target["launch_plan"]["build_context"] == "."
    assert target["launch_plan"]["port"] == 80
    assert target["launch_plan"]["health_path"] == "/health"


def test_run_consumes_the_same_runtime_plan_it_reports(monkeypatch, tmp_path):
    """执行不得绕过 DynamicAnalysisAgent 计划而重新猜测项目启动方式。"""
    (tmp_path / "go.mod").write_text("module example.test/service\n", encoding="utf-8")
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    (docker_dir / "Dockerfile").write_text("EXPOSE 80\n", encoding="utf-8")
    agent = DynamicAnalysisAgent()
    captured = {}
    monkeypatch.setattr(
        agent._pipeline, "run",
        lambda findings, **kwargs: captured.update(kwargs) or findings,
    )

    agent.run(
        [{"type": "Command Injection", "status": "needs_review"}],
        code_root=tmp_path, enable_dynamic=True, enable_harness=False,
        dynamic_target={"mode": "docker_project", "auto_start_docker": True},
    )

    assert captured["dynamic_target"] == agent._last_runtime_plan["dynamic_target"]
    assert captured["dynamic_target"]["launch_plan"]["dockerfile"] == "docker/Dockerfile"


def test_run_harness_command_injection_via_selfcontained_slice(monkeypatch):
    """无 LLM 时命令注入走【自包含切片主力】-> function_reproduced（inline 真实函数体、
    mock 一切外部依赖、桩危险 sink、框架 nonce 证明真实函数被调用），比模板机理更强；
    但仍非入口级完全动态确认（不标记 dynamically_verified）。"""
    # 强制 LLM 返回空；用受控本地执行器模拟 Docker，保证离线确定性
    monkeypatch.setattr("backend.verifier.harness_verifier.HarnessVerifier._call",
                        lambda self, content: {})
    from backend.skills import harness_tools
    monkeypatch.setattr(harness_tools, "_run_in_docker",
                        lambda code, timeout, language, code_root=None, harness_kind=None:
                        harness_tools._run_local(code, timeout, language, "scaffold"))
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 38,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(...)"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_exploit=False,
                               enable_dynamic=False, enable_harness=True)
    harness = findings[0].get("_harness") or {}
    assert harness.get("verdict") == "function_reproduced"       # 切片主力：真实函数级复现
    assert harness.get("dynamically_triggered") is False         # harness 层：函数级 != 入口级
    assert harness.get("function_mechanism_verified") is True
    assert findings[0].get("function_unit_reproduced") is True
    assert findings[0].get("dynamically_verified") is False
    assert findings[0].get("status") == "needs_review"


def test_run_only_touches_confirmed():
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 21,
                 "status": "false_positive", "severity": "high"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_harness=True)
    assert findings[0].get("_harness") is None


def test_function_reproduced_harness_not_masked_by_http_not_executed():
    """核心：harness 函数级复现 + HTTP 那路没起靶场(not_executed) 时，动态裁决必须是
    function_reproduced，绝不能被 HTTP 的 not_executed 覆盖成"未执行"。"""
    harness = {"verdict": "function_reproduced", "dynamically_triggered": False,
               "verification_level": "target_specific", "function_extracted": True,
               "target_function_called": True}
    http_not_run = {"reproduction_status": "not_executed"}
    assert _derive_dynamic_verdict(http_not_run, harness) == "function_reproduced"
    summary = _dynamic_summary([{"_harness": harness, "_dynamic": http_not_run}], None)
    assert summary["function_reproduced"] == 1
    assert summary["not_executed"] == 0


def test_not_executed_only_when_both_channels_idle():
    """只有 HTTP 与 harness 两路都没有任何真实执行结果时，才算 not_executed。"""
    assert _derive_dynamic_verdict({"reproduction_status": "not_executed"}, {}) == "not_executed"
    assert _derive_dynamic_verdict({}, {}) == "not_executed"
    # harness 跑了但未触发 -> harness_not_reproduced，不是 not_executed
    assert _derive_dynamic_verdict(
        {"reproduction_status": "not_executed"},
        {"verdict": "not_reproduced"}) == "harness_not_reproduced"


def test_executed_http_not_reproduced_is_finally_confirmed_without_relabeling_runtime():
    """UI/final confirmation is separate from the honest runtime no-hit verdict."""
    runtime = {"reproduction_status": "not_reproduced", "skipped": False}

    dynamic_verdict = _derive_dynamic_verdict(runtime, {})

    assert dynamic_verdict == "not_reproduced"
    assert _derive_final_verdict("needs_review", dynamic_verdict) == "confirmed"


def test_mechanism_harness_does_not_count_as_harness_confirmed():
    harness = {
        "verdict": "mechanism_confirmed",
        "dynamically_triggered": True,
        "verification_level": "template_mechanism",
        "function_extracted": False,
        "target_function_called": False,
    }

    # mechanism 级 harness 确实【执行过】——只是证据弱，绝不能被打成 not_executed
    # （那正是"把已验证误报成未执行"的 bug）。它返回 mechanism_confirmed，但不计入
    # harness_confirmed（后者要求入口/目标级）。
    assert _derive_dynamic_verdict({}, harness) == "mechanism_confirmed"
    summary = _dynamic_summary([{"_harness": harness}], None)
    assert summary["harness_confirmed"] == 0
    assert summary["not_executed"] == 0   # 跑过 mechanism 的不算未执行
