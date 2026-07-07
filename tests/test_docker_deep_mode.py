"""Docker-first Deep Mode 测试（离线：无 docker 环境验证失败路径不造假）。"""
from pathlib import Path

from backend.dynamic.launch_detector import detect_launch
from backend.dynamic.endpoint_extractor import extract_endpoints
from backend.dynamic.strategy import resolve_strategy
from backend.verifier.docker_project_runner import DockerProjectRunner, build_dockerfile
from backend.verifier.pipeline import ExploitPipeline
from backend.verifier.evidence_collector import EvidenceCollector

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_launch_plan_has_install_and_run():
    plan = detect_launch(DEMO)
    assert plan["framework"] == "Flask"
    assert plan["install_command"]
    assert plan["run_command"]
    assert plan["port"]


def test_build_dockerfile_python_and_node():
    py = build_dockerfile({"framework": "Flask", "run_command": "python app.py",
                           "install_command": "pip install -r requirements.txt"}, 5000)
    assert "FROM python" in py and "EXPOSE 5000" in py and "app.py" in py
    node = build_dockerfile({"framework": "Express", "run_command": "npm start"}, 3000)
    assert "FROM node" in node and "npm" in node


def test_endpoint_extraction_flask():
    eps = extract_endpoints(DEMO)
    assert eps["count"] >= 1
    assert any(e["framework"] == "flask" for e in eps["endpoints"])


def test_strategy_classification():
    assert resolve_strategy("SQL Injection")["strategy"] in ("http", "both")
    assert resolve_strategy("Command Injection")["strategy"] in ("http", "both")
    assert resolve_strategy("Insecure Deserialization")["strategy"] == "harness"
    assert resolve_strategy("Hardcoded Secret")["strategy"] == "not_applicable"


def test_docker_runner_no_docker_returns_sandbox_start_failed():
    """无 docker SDK 环境：应如实返回 sandbox_start_failed，不崩、不造假。"""
    with DockerProjectRunner(DEMO, {"framework": "Flask", "run_command": "python app.py",
                                    "port": 5000}, scan_id="scan_t") as r:
        assert r.base_url is None
        assert r.metadata["status"] in ("sandbox_start_failed", "dependency_install_failed")


def test_pipeline_docker_project_failure_not_faked():
    """docker_project 沙箱失败时，HTTP 类漏洞状态是 sandbox_start_failed，而非 dynamic_confirmed。"""
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 28,
                 "status": "confirmed", "severity": "high", "code_snippet": "...", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=True,
                          dynamic_target={"mode": "docker_project", "scan_id": "scan_x"},
                          code_root=DEMO)
    dyn = findings[0]["_dynamic"]
    assert dyn["reproduction_status"] == "sandbox_start_failed"
    assert dyn["reproducible"] is False


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
