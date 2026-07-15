"""Docker-first Deep Mode 测试（离线：无 docker 环境验证失败路径不造假）。"""
from pathlib import Path

import pytest

from backend.dynamic.launch_detector import detect_launch
from backend.dynamic.endpoint_extractor import extract_endpoints
from backend.dynamic.strategy import resolve_strategy
from backend.verifier.docker_project_runner import (
    DockerProjectRunner,
    _ComposeEnvironmentError,
    build_dockerfile,
)
from backend.verifier.pipeline import ExploitPipeline
from backend.verifier.evidence_collector import EvidenceCollector
from backend.api.routes_scans import resolve_scan_mode
from backend.schemas import ScanCreate
from backend.dynamic.docker_bootstrap import engine_ready

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


@pytest.fixture(autouse=True)
def _route_managed_docker_commands_through_test_subprocess_fakes(monkeypatch):
    """Keep this module Docker-free while preserving its existing subprocess fakes."""
    import subprocess
    import backend.verifier.docker_project_runner as docker_runner
    from backend.runtime.scan_execution import SandboxCommandTimeout

    def _managed(_scan_id, cmd, **kwargs):
        try:
            return docker_runner.subprocess.run(
                cmd,
                cwd=str(kwargs.get("cwd")) if kwargs.get("cwd") is not None else None,
                env=kwargs.get("env"),
                timeout=kwargs.get("timeout"),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxCommandTimeout(
                "managed command timed out",
                phase=kwargs.get("phase") or "unknown",
                timeout_seconds=kwargs.get("timeout"),
            ) from exc

    monkeypatch.setattr(docker_runner, "run_managed_command", _managed)


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
    assert "FROM python" in py and "EXPOSE 5000" in py and "--app app" in py
    node = build_dockerfile({"framework": "Express", "run_command": "npm start"}, 3000)
    assert "FROM node" in node and "npm" in node


def test_generated_flask_entrypoint_binds_outside_container():
    dockerfile = build_dockerfile(
        {"framework": "Flask", "run_command": "python app.py", "install_command": "pip install -r requirements.txt"},
        5000,
    )
    assert "python -m flask --app app run --host 0.0.0.0 --port 5000" in dockerfile


def test_build_dockerfile_php_adds_composer_only_when_install_requires_it():
    composer_php = build_dockerfile(
        {"framework": "PHP", "run_command": "php -S 0.0.0.0:8080 -t .",
         "install_command": "composer install --no-dev"},
        8080,
    )
    assert "FROM composer:2 AS composer" in composer_php
    assert "COPY --from=composer /usr/bin/composer /usr/bin/composer" in composer_php
    assert "FROM php:8.2-cli" in composer_php

    plain_php = build_dockerfile(
        {"framework": "PHP", "run_command": "php -S 0.0.0.0:8080 -t ."},
        8080,
    )
    assert "FROM composer:2 AS composer" not in plain_php


def test_build_dockerfile_preserves_shell_commands():
    """生成 Dockerfile 的 CMD 必须保留通配符/复合命令，避免 JSON argv 模式不展开 target/*.jar。"""
    df = build_dockerfile({"framework": "Spring Boot", "run_command": "java -jar target/*.jar"}, 8080)
    assert 'CMD ["sh", "-c", "java -jar target/*.jar"]' in df


def test_dockerfile_base_images_resolve_safe_args_across_multistage_build(tmp_path):
    from backend.verifier.docker_project_runner import _dockerfile_base_images

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "ARG NODE_TAG=12-alpine\n"
        "ARG RUNTIME=python:3.11-slim\n"
        "FROM --platform=linux/amd64 node:${NODE_TAG} AS assets\n"
        "RUN npm ci\n"
        "FROM ${RUNTIME} AS application\n",
        encoding="utf-8",
    )

    assert _dockerfile_base_images(dockerfile) == ["node:12-alpine", "python:3.11-slim"]


def test_docker_hub_official_image_mirror_uses_immutable_digest_and_records_provenance(tmp_path, monkeypatch):
    calls = []
    mirror_digest = "sha256:" + "a" * 64
    image_id = "sha256:" + "b" * 64

    def _run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            if cmd[-1] == "node:12-alpine":
                return _FakeProc(1, "", "missing")
            if cmd[-1] == "docker.m.daocloud.io/library/node:12-alpine":
                return _FakeProc(
                    0,
                    '[{"RepoDigests":["docker.m.daocloud.io/library/node@'
                    + mirror_digest + '"],"Id":"' + image_id + '"}]',
                    "",
                )
        if cmd == ["docker", "pull", "node:12-alpine"]:
            return _FakeProc(1, "", "registry-1.docker.io: i/o timeout")
        if cmd == ["docker", "pull", "docker.m.daocloud.io/library/node:12-alpine"]:
            return _FakeProc(0, "pulled", "")
        if cmd == [
            "docker", "tag", f"docker.m.daocloud.io/library/node@{mirror_digest}", "node:12-alpine",
        ]:
            return _FakeProc(0, "", "")
        raise AssertionError(f"unexpected Docker command: {cmd}")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="mirror-official")

    runner._prefetch_image("node:12-alpine", source="Dockerfile base")

    assert calls == [
        ["docker", "image", "inspect", "node:12-alpine"],
        ["docker", "pull", "node:12-alpine"],
        ["docker", "pull", "docker.m.daocloud.io/library/node:12-alpine"],
        ["docker", "image", "inspect", "docker.m.daocloud.io/library/node:12-alpine"],
        ["docker", "tag", f"docker.m.daocloud.io/library/node@{mirror_digest}", "node:12-alpine"],
    ]
    assert runner.metadata["image_mirror_provenance"] == [{
        "source": "Dockerfile base",
        "mirror": "docker.m.daocloud.io",
        "canonical": "node:12-alpine",
        "digest": mirror_digest,
        "mirror_reference": f"docker.m.daocloud.io/library/node@{mirror_digest}",
        "image_id": image_id,
        "equivalence_verified": False,
    }]
    runner._cleanup()


def test_docker_hub_namespaced_image_uses_namespaced_mirror_path(tmp_path, monkeypatch):
    calls = []
    mirror_digest = "sha256:" + "c" * 64

    def _run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            if cmd[-1] == "bitnami/nginx:1.27":
                return _FakeProc(1, "", "missing")
            if cmd[-1] == "docker.m.daocloud.io/bitnami/nginx:1.27":
                return _FakeProc(
                    0,
                    '[{"RepoDigests":["docker.m.daocloud.io/bitnami/nginx@'
                    + mirror_digest + '"],"Id":"sha256:' + "d" * 64 + '"}]',
                    "",
                )
        if cmd == ["docker", "pull", "bitnami/nginx:1.27"]:
            return _FakeProc(1, "", "registry-1.docker.io: i/o timeout")
        return _FakeProc(0, "pulled", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="mirror-namespaced")

    runner._prefetch_image("bitnami/nginx:1.27", source="Dockerfile base")

    assert ["docker", "pull", "docker.m.daocloud.io/bitnami/nginx:1.27"] in calls
    assert [
        "docker", "tag", f"docker.m.daocloud.io/bitnami/nginx@{mirror_digest}", "bitnami/nginx:1.27",
    ] in calls
    runner._cleanup()


def test_docker_hub_mirror_without_immutable_digest_fails_closed(tmp_path, monkeypatch):
    calls = []

    def _run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            if cmd[-1] == "node:12-alpine":
                return _FakeProc(1, "", "missing")
            if cmd[-1] == "docker.m.daocloud.io/library/node:12-alpine":
                return _FakeProc(0, '[{"RepoDigests":[],"Id":""}]', "")
        if cmd == ["docker", "pull", "node:12-alpine"]:
            return _FakeProc(1, "", "registry-1.docker.io: i/o timeout")
        if cmd == ["docker", "pull", "docker.m.daocloud.io/library/node:12-alpine"]:
            return _FakeProc(0, "pulled", "")
        raise AssertionError(f"unexpected Docker command: {cmd}")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="mirror-no-digest")

    with pytest.raises(RuntimeError, match="immutable digest"):
        runner._prefetch_image("node:12-alpine", source="Dockerfile base")

    assert not any(cmd[:2] == ["docker", "tag"] for cmd in calls)
    assert runner.metadata.get("image_mirror_provenance", []) == []
    runner._cleanup()


def test_non_hub_image_failure_never_attempts_docker_hub_mirror(tmp_path, monkeypatch):
    calls = []
    environments = []

    def _run(cmd, **kwargs):
        calls.append(cmd)
        environments.append(kwargs["env"])
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _FakeProc(1, "", "missing")
        return _FakeProc(1, "", "denied")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(
        tmp_path, {}, scan_id="mirror-non-hub",
        env={"DOCKER_CONFIG": "host-config", "DOCKER_AUTH_CONFIG": "host-auth"},
    )

    with pytest.raises(RuntimeError, match="ghcr.io/acme/private-app:latest"):
        runner._prefetch_image("ghcr.io/acme/private-app:latest", source="Dockerfile base")

    assert calls == [
        ["docker", "image", "inspect", "ghcr.io/acme/private-app:latest"],
        ["docker", "pull", "ghcr.io/acme/private-app:latest"],
    ]
    assert all(env["DOCKER_CONFIG"] != "host-config" for env in environments)
    assert all("DOCKER_AUTH_CONFIG" not in env for env in environments)
    runner._cleanup()


def test_compose_build_context_prefetches_its_dockerfile_base_images(tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    context = tmp_path / "services" / "web"
    context.mkdir(parents=True)
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: local-web:latest\n"
        "    build:\n"
        "      context: ./services/web\n"
        "      dockerfile: Dockerfile.release\n",
        encoding="utf-8",
    )
    (context / "Dockerfile.release").write_text("FROM golang:1.22-alpine AS build\n", encoding="utf-8")
    calls = []

    def _run(cmd, **_kwargs):
        calls.append(cmd)
        if "config" in cmd:
            return _FakeProc(0, "local-web:latest\n", "")
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _FakeProc(0, "cached", "")
        raise AssertionError(f"unexpected Docker command: {cmd}")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="compose-build-base")
    runner._compose_file = str(compose)

    runner._prefetch_compose_images("project")

    assert runner._compose_needs_build is True
    assert ["docker", "image", "inspect", "golang:1.22-alpine"] in calls
    runner._cleanup()


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


def test_launch_detector_ignores_documentation_compose_in_favor_of_root_dockerfile(tmp_path):
    """Docs installation snippets are not an automatic project runtime target."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\nEXPOSE 8000\n", encoding="utf-8")
    doc_compose = tmp_path / "docs" / "install" / "docker" / "docker-compose.yml"
    doc_compose.parent.mkdir(parents=True)
    doc_compose.write_text("services:\n  proxy:\n    image: nginx\n", encoding="utf-8")

    plan = detect_launch(tmp_path)

    assert plan["compose"] is None
    assert plan["dockerfile"] == "Dockerfile"
    assert plan["source"] == "dockerfile"


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


def test_dependency_failure_records_buildkit_tail(monkeypatch, tmp_path):
    """Long BuildKit output must retain the final actionable dependency error."""
    from backend.verifier.docker_project_runner import _DependencyError

    runner = DockerProjectRunner(tmp_path, {}, scan_id="dependency-tail")

    def fail_start():
        raise _DependencyError("build header\n" + "progress\n" * 300 + "pdo_mysql is missing")

    monkeypatch.setattr(runner, "_start", fail_start)

    with runner:
        assert runner.metadata["status"] == "dependency_install_failed"
        assert "pdo_mysql is missing" in runner.metadata["logs_excerpt"]
        assert "build header" not in runner.metadata["logs_excerpt"]


def test_dependency_failure_keeps_early_pip_diagnostic_and_buildkit_footer(monkeypatch, tmp_path):
    """Plain BuildKit logs must not lose the pip resolver detail before the footer."""
    from backend.verifier.docker_project_runner import _DependencyError

    runner = DockerProjectRunner(tmp_path, {}, scan_id="dependency-diagnostic")
    output = (
        "#9 11.4 ERROR: Cannot install legacy-package==1.0 because it requires Python <3\n"
        + "progress\n" * 30
        + "ERROR: failed to solve: process did not complete successfully: exit code: 1"
    )
    monkeypatch.setattr(runner, "_start", lambda: (_ for _ in ()).throw(_DependencyError(output)))

    with runner:
        assert runner.metadata["status"] == "dependency_install_failed"
        assert "Cannot install legacy-package" in runner.metadata["logs_excerpt"]
        assert "failed to solve" in runner.metadata["logs_excerpt"]
        assert "Cannot install legacy-package" in runner.metadata["reason"]


def test_single_container_build_timeout_never_starts_container(tmp_path, monkeypatch):
    from backend.runtime.scan_execution import SandboxCommandTimeout

    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    class Containers:
        def run(self, **_kwargs):
            raise AssertionError("container must not start after image build timeout")

    fake_client = type("FakeClient", (), {"containers": Containers()})()
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.get_docker_client", lambda: fake_client
    )
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.run_managed_command",
        lambda *_a, **_kw: (_ for _ in ()).throw(
            SandboxCommandTimeout("image build timed out", phase="image_build", timeout_seconds=7)
        ),
    )

    with DockerProjectRunner(
        tmp_path, {"dockerfile": "Dockerfile"}, scan_id="scan_build_timeout",
        trust_project_container_config=True, build_timeout=7,
    ) as runner:
        assert runner.metadata["status"] == "sandbox_build_timeout"
        assert runner.metadata["failure_code"] == "sandbox_build_timeout"
        assert runner.metadata["phase"] == "image_build"
        assert runner.metadata["timeout_seconds"] == 7
        assert runner.metadata["container_start_attempted"] is False


def test_single_container_build_retries_transient_registry_failure(tmp_path, monkeypatch):
    """BuildKit registry EOFs are retried before declaring the sandbox unavailable."""
    import subprocess

    (tmp_path / "Dockerfile").write_text("FROM node:carbon\n", encoding="utf-8")
    calls = []
    container = type("Container", (), {
        "id": "abcdef1234567890", "reload": lambda self: None,
        "remove": lambda self, force=False: None, "logs": lambda self: b"",
    })()
    client = type("Client", (), {
        "containers": type("Containers", (), {"run": lambda self, **_kwargs: container})(),
    })()

    def _run(_scan_id, command, **_kwargs):
        calls.append(command)
        build_calls = [item for item in calls if item[:2] == ["docker", "build"]]
        if command[:2] == ["docker", "build"] and len(build_calls) == 1:
            return subprocess.CompletedProcess(command, 1, "", "failed to fetch anonymous token: EOF")
        return subprocess.CompletedProcess(command, 0, "built", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.get_docker_client", lambda: client)
    monkeypatch.setattr("backend.verifier.docker_project_runner.run_managed_command", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("backend.verifier.docker_project_runner.time.sleep", lambda *_args: None)

    with DockerProjectRunner(
        tmp_path, {"dockerfile": "Dockerfile", "port": 8080}, scan_id="scan_build_retry",
        trust_project_container_config=True,
    ) as runner:
        assert runner.metadata["status"] == "started"
        assert len([item for item in calls if item[:2] == ["docker", "build"]]) == 2
        assert all("--progress=plain" in item for item in calls if item[:2] == ["docker", "build"])
        assert any("build transient failure; retry 1/3" in item for item in runner.metadata["diagnostics"])


def test_generated_python_sandbox_retries_with_newer_compatible_image(tmp_path, monkeypatch):
    """A Python dependency unavailable on 3.11 gets one generic 3.12 retry.

    The fallback applies only to an AuditAgentX-generated Dockerfile, so an
    untrusted project Dockerfile remains disabled when its config is not trusted.
    """
    import subprocess

    generated_images = []
    container = type("Container", (), {
        "id": "abcdef1234567890", "reload": lambda self: None,
        "remove": lambda self, force=False: None, "logs": lambda self: b"",
    })()
    client = type("Client", (), {
        "containers": type("Containers", (), {"run": lambda self, **_kwargs: container})(),
    })()

    def _run(_scan_id, command, **_kwargs):
        generated_images.append((tmp_path / command[command.index("--file") + 1]).read_text())
        if len(generated_images) == 1:
            return subprocess.CompletedProcess(
                command, 1, "", "ERROR: No matching distribution found for demo-package==1.0"
            )
        return subprocess.CompletedProcess(command, 0, "built", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.get_docker_client", lambda: client)
    monkeypatch.setattr("backend.verifier.docker_project_runner.run_managed_command", _run)
    monkeypatch.setattr(DockerProjectRunner, "_prefetch_dockerfile_base_images", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(DockerProjectRunner, "_prefetch_image", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy", lambda *_args, **_kwargs: True)

    with DockerProjectRunner(
        tmp_path, {"framework": "Flask", "run_command": "python app.py", "port": 5000},
        scan_id="python-compat",
        trust_project_container_config=False,
    ) as runner:
        assert runner.metadata["status"] == "started"
        assert len(generated_images) == 2
        assert "FROM python:3.11-slim" in generated_images[0]
        assert "FROM python:3.12-slim" in generated_images[1]
        assert runner.metadata["trust_project_container_config"] is False
        assert runner.metadata["sandbox_compatibility_patches"] == [
            "retried generated Python sandbox with python:3.12-slim after dependency resolution failure"
        ]


def test_python_compatibility_retry_reads_resolver_error_from_buildkit_stdout(tmp_path, monkeypatch):
    """--progress=plain can split the pip error and BuildKit footer across streams."""
    import subprocess

    calls = []
    container = type("Container", (), {
        "id": "abcdef1234567890", "reload": lambda self: None,
        "remove": lambda self, force=False: None, "logs": lambda self: b"",
    })()
    client = type("Client", (), {
        "containers": type("Containers", (), {"run": lambda self, **_kwargs: container})(),
    })()

    def _run(_scan_id, command, **_kwargs):
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 1, "ERROR: No matching distribution found for demo-package==1.0",
                "ERROR: failed to solve: exit code: 1",
            )
        return subprocess.CompletedProcess(command, 0, "built", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.get_docker_client", lambda: client)
    monkeypatch.setattr("backend.verifier.docker_project_runner.run_managed_command", _run)
    monkeypatch.setattr(DockerProjectRunner, "_prefetch_dockerfile_base_images", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(DockerProjectRunner, "_prefetch_image", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy", lambda *_args, **_kwargs: True)

    with DockerProjectRunner(
        tmp_path, {"framework": "Flask", "run_command": "python app.py", "port": 5000},
        scan_id="python-compat-split-stream", trust_project_container_config=False,
    ) as runner:
        assert runner.metadata["status"] == "started"
        assert len(calls) == 2
        assert "python:3.12-slim" in runner.metadata["sandbox_compatibility_patches"][0]


def test_cancel_after_single_container_start_force_removes_once(tmp_path, monkeypatch):
    container = type("Container", (), {
        "id": "abcdef1234567890",
        "remove_calls": 0,
        "remove": lambda self, force=False: setattr(self, "remove_calls", self.remove_calls + 1),
        "reload": lambda self: None,
        "logs": lambda self: b"",
    })()
    client = type("Client", (), {
        "containers": type("Containers", (), {"run": lambda self, **kwargs: container})(),
    })()
    callbacks = []
    monkeypatch.setattr("backend.verifier.docker_project_runner.get_docker_client", lambda: client)
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.run_managed_command",
        lambda *_args, **_kwargs: _FakeProc(0, "", ""),
    )
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy", lambda *_a, **_k: True)
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.register_cleanup_callback",
        lambda _scan_id, callback: callbacks.append(callback) or "token",
    )
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.unregister_cleanup_callback",
        lambda *_args, **_kwargs: None,
    )

    runner = DockerProjectRunner(
        tmp_path, {"framework": "Flask", "run_command": "python app.py", "port": 5000},
        scan_id="cancel-container",
    )
    runner.__enter__()
    assert len(callbacks) == 1
    callbacks[0]()
    runner.__exit__(None, None, None)

    assert container.remove_calls == 1


def test_cancel_after_compose_up_calls_down_once(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n", encoding="utf-8"
    )
    callbacks = []
    down_calls = []

    def fake_run(cmd, **_kwargs):
        if "down" in cmd:
            down_calls.append(cmd)
        return _FakeProc(0, "", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", fake_run)
    monkeypatch.setattr("backend.verifier.docker_project_runner.run_managed_command", lambda *_a, **_k: _FakeProc(0, "", ""))
    monkeypatch.setattr("backend.verifier.docker_project_runner.register_cleanup_callback", lambda _sid, cb: callbacks.append(cb) or "token")
    monkeypatch.setattr("backend.verifier.docker_project_runner.unregister_cleanup_callback", lambda *_a: None)
    monkeypatch.setattr(DockerProjectRunner, "_prefetch_compose_images", lambda self, project: None)
    monkeypatch.setattr(DockerProjectRunner, "_compose_inventory", lambda self: [])
    monkeypatch.setattr(DockerProjectRunner, "_compose_published_port", lambda self, project, hint: 49152)
    monkeypatch.setattr(DockerProjectRunner, "_compose_target_crash_reason", lambda self: None)
    monkeypatch.setattr(DockerProjectRunner, "_wait_compose_healthy", staticmethod(lambda *_a, **_k: (True, [])))

    runner = DockerProjectRunner(tmp_path, {}, scan_id="cancel-compose")
    runner._build_deadline = 999999999.0
    runner._run_compose("docker-compose.yml", 80)
    assert len(callbacks) == 1
    callbacks[0]()
    runner._cleanup()

    assert len(down_calls) == 1


def test_compose_up_managed_timeout_returns_build_timeout(tmp_path, monkeypatch):
    from backend.runtime.scan_execution import SandboxCommandTimeout

    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n", encoding="utf-8"
    )

    def _run(cmd, **_kwargs):
        if "config" in cmd:
            return _FakeProc(0, "", "")
        if "ps" in cmd:
            return _FakeProc(0, "web building", "")
        if "logs" in cmd:
            return _FakeProc(0, "compose build output", "")
        return _FakeProc(0, "", "")

    def _managed(_scan_id, cmd, **_kwargs):
        if "config" in cmd:
            return _FakeProc(0, "nginx\n", "")
        if "inspect" in cmd:
            return _FakeProc(0, "", "")
        assert "up" in cmd
        raise SandboxCommandTimeout(
            "compose up timed out", phase="compose_up", timeout_seconds=9
        )

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner.run_managed_command", _managed)

    with DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml", "port": 8080},
        scan_id="scan_compose_timeout", build_timeout=9,
    ) as runner:
        assert runner.metadata["status"] == "sandbox_build_timeout"
        assert runner.metadata["failure_code"] == "sandbox_build_timeout"
        assert runner.metadata["phase"] == "compose_up"
        assert runner.metadata["timeout_seconds"] == 9
        assert runner.metadata["cleanup_attempted"] is False

    assert runner.metadata["cleanup_attempted"] is True


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


_PS_JSON = ('[{"ID":"abc123","Name":"aax-web-1","Service":"web","Image":"aax-web",'
            '"State":"running","Publishers":['
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
        assert r.metadata["compose_project"] == "aaxscanc"
        assert r.metadata["container_ids"] == ["abc123"]
    assert r.metadata["mode"] == "docker_compose"
    assert r.metadata["cleanup_attempted"] is True
    assert r.metadata["cleanup_succeeded"] is True


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
        assert r.metadata["logs_excerpt"] == "compose logs..."


def test_compose_missing_required_env_file_fails_before_subprocess(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n    env_file: .env\n",
        encoding="utf-8",
    )
    calls = []
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml"}, scan_id="scan_missing_env"
    ) as runner:
        assert runner.metadata["status"] == "sandbox_start_failed"
        assert runner.metadata["failure_code"] == "missing_env_file"
        assert runner.metadata["missing_env_files"] == [".env"]
        assert runner.metadata["environment_precheck"]["status"] == "failed"
        assert "Compose 必需环境文件缺失" in runner.metadata["reason"]
        assert "base_url" not in runner.metadata["reason"]

    assert calls == []


def test_dvna_shape_missing_vars_env_uses_random_isolated_mysql_config(tmp_path):
    """缺失的共享 vars.env 只在可证明的本地 MySQL 依赖图中被安全替代。"""
    import yaml

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  app:\n    image: dvna/app\n    ports: ['9090:9090']\n"
        "    depends_on: [mysql-db]\n    env_file: ./vars.env\n"
        "  mysql-db:\n    image: mysql:8.0\n    env_file: ./vars.env\n",
        encoding="utf-8",
    )
    runner = DockerProjectRunner(tmp_path, {}, scan_id="dvna-safe-env")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    isolated = yaml.safe_load(generated.read_text(encoding="utf-8"))
    assert set(isolated["services"]) == {"app", "mysql-db"}
    app_env = Path(isolated["services"]["app"]["env_file"])
    db_env = Path(isolated["services"]["mysql-db"]["env_file"])
    contents = db_env.read_text(encoding="utf-8")

    assert app_env == db_env
    assert not app_env.is_relative_to(tmp_path)
    assert "MYSQL_HOST=mysql-db" in app_env.read_text(encoding="utf-8")
    assert "MYSQL_PORT=3306" in app_env.read_text(encoding="utf-8")
    assert "MYSQL_USER=aax_" in contents
    assert "MYSQL_DATABASE=aax_" in contents
    assert "MYSQL_PASSWORD=" in contents
    assert "MYSQL_RANDOM_ROOT_PASSWORD=yes" in contents
    assert "MYSQL_HOST=mysql-db" in contents
    assert "MYSQL_PORT=3306" in contents
    assert "MYSQL_PASSWORD=" not in str(runner.metadata)
    temporary_env_dir = app_env.parent
    assert not (tmp_path / "vars.env").exists()
    runner._cleanup()
    assert not app_env.exists()
    assert not temporary_env_dir.exists()
    assert not generated.exists()
    assert not (tmp_path / "vars.env").exists()


def test_unknown_missing_env_file_stays_fail_closed_even_with_sample(tmp_path, monkeypatch):
    """样例、README 或任意文本都不能成为未知 env_file 的配置来源。"""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n    env_file: vars.env\n",
        encoding="utf-8",
    )
    (tmp_path / "vars.env.sample").write_text("TOKEN=do-not-copy\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with DockerProjectRunner(tmp_path, {"compose": "docker-compose.yml"}, scan_id="unknown-env") as runner:
        assert runner.metadata["failure_code"] == "missing_env_file"
        assert runner.metadata["missing_env_files"] == ["vars.env"]
    assert calls == []


def test_missing_env_file_for_non_official_mysql_named_image_fails_closed(tmp_path, monkeypatch):
    """镜像名末尾为 mysql 不足以证明它是 Docker 官方 MySQL 镜像。"""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n    image: example/app\n    ports: ['8080:8080']\n"
        "    depends_on: [db]\n    env_file: vars.env\n"
        "  db:\n    image: registry.example/mysql:8\n    env_file: vars.env\n",
        encoding="utf-8",
    )
    calls = []
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml", "port": 8080}, scan_id="non-official-mysql"
    ) as runner:
        assert runner.metadata["failure_code"] == "missing_env_file"
        assert runner.metadata["missing_env_files"] == ["vars.env"]
    assert calls == []


def test_compose_optional_missing_env_file_does_not_block(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n"
        "    env_file:\n      - path: .env.optional\n        required: false\n",
        encoding="utf-8",
    )
    _install_fake_compose(monkeypatch, ps_json=_PS_JSON, healthy=True)

    with DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml", "port": 8080}, scan_id="scan_optional"
    ) as runner:
        assert runner.metadata["status"] == "started"
        assert runner.metadata["environment_precheck"]["status"] == "passed"


def test_compose_prechecks_env_files_from_selected_service_dependencies(tmp_path, monkeypatch):
    (tmp_path / "web.env").write_bytes(b"WEB=present\n")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n    image: nginx\n    ports: ['8080:80']\n"
        "    depends_on: [db]\n    env_file: [web.env]\n"
        "  db:\n    image: postgres\n    env_file: [db.env]\n"
        "  unrelated:\n    image: busybox\n    env_file: [ignored.env]\n",
        encoding="utf-8",
    )
    calls = []
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml"}, scan_id="scan_dependency_env"
    ) as runner:
        assert runner.metadata["failure_code"] == "missing_env_file"
        assert runner.metadata["missing_env_files"] == ["db.env"]

    assert calls == []


def test_compose_rejects_absolute_and_traversing_env_file_paths(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    for index, env_path in enumerate(("/tmp/secrets.env", "../secrets.env")):
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n"
            f"    env_file: '{env_path}'\n",
            encoding="utf-8",
        )
        with DockerProjectRunner(
            tmp_path, {"compose": "docker-compose.yml"}, scan_id=f"scan_unsafe_{index}"
        ) as runner:
            assert runner.metadata["status"] == "unsafe_project_config"
            assert "env_file" in runner.metadata["reason"]

    assert calls == []


def test_linkding_default_dynamic_bind_volume_is_allowed_then_reaches_env_precheck(tmp_path, monkeypatch):
    """仅含安全默认值的 Linkding bind volume 可通过策略，随后正常做 env_file 预检。"""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: sissbruecker/linkding\n    ports: ['9090:9090']\n"
        "    volumes: ['${LD_DATA_DIR:-./data}:/etc/linkding/data']\n    env_file: .env\n",
        encoding="utf-8",
    )
    calls = []
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with DockerProjectRunner(tmp_path, {"compose": "docker-compose.yml"}, scan_id="linkding") as runner:
        assert runner.metadata["status"] == "sandbox_start_failed"
        assert runner.metadata["failure_code"] == "missing_env_file"
        assert runner.metadata["environment_precheck"]["status"] == "failed"

    assert calls == []


@pytest.mark.parametrize("volume, env", [
    ("${LD_DATA_DIR}:/data", {}),
    ("${LD_DATA_DIR:?required}:/data", {}),
    ("${LD_DATA_DIR:-/tmp/data}:/data", {}),
    ("${LD_DATA_DIR:-../data}:/data", {}),
    ("prefix-${LD_DATA_DIR:-./data}:/data", {}),
    ("${LD_DATA_DIR:-${OTHER:-./data}}:/data", {}),
    ("${LD_DATA_DIR:-./data}${OTHER:-./other}:/data", {}),
    ("${LD_DATA_DIR:-./data}:/data", {"LD_DATA_DIR": "../escape"}),
])
def test_compose_dynamic_bind_volume_rejects_anything_except_safe_single_default(tmp_path, volume, env):
    from backend.verifier.docker_project_runner import _validate_compose_policy

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        f"services:\n  web:\n    image: nginx\n    volumes: ['{volume}']\n",
        encoding="utf-8",
    )

    policy = _validate_compose_policy(compose, code_root=tmp_path, env=env)

    assert policy["allowed"] is False


@pytest.mark.parametrize(("service_config", "top_level", "reason"), [
    ("    network_mode: container:existing-target\n", "", "network_mode"),
    ("    security_opt: ['seccomp=unconfined']\n", "", "security_opt"),
    ("    userns: host\n", "", "userns"),
    ("    devices: ['/dev/kmsg:/dev/kmsg']\n", "", "devices"),
    ("    networks: [shared]\n", "networks:\n  shared:\n    external: true\n", "external network"),
    ("    networks: [shared]\n", "networks:\n  shared:\n    name: shared-host-network\n", "named network"),
    ("    volumes:\n      - type: bind\n        source: .\n        target: /app\n        bind:\n          propagation: rshared\n", "", "mount propagation"),
])
def test_compose_policy_rejects_host_escape_and_cross_project_attachment(
    tmp_path, service_config, top_level, reason
):
    from backend.verifier.docker_project_runner import _validate_compose_policy

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n"
        + service_config + top_level,
        encoding="utf-8",
    )

    policy = _validate_compose_policy(compose, code_root=tmp_path)

    assert policy["allowed"] is False
    assert reason in policy["reason"]


def test_compose_subprocesses_receive_only_explicit_environment(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n",
        encoding="utf-8",
    )
    environments = []

    def _run(cmd, **kwargs):
        environments.append(kwargs.get("env"))
        if "config" in cmd:
            return _FakeProc(0, "", "")
        if "up" in cmd:
            return _FakeProc(0, "", "")
        if "ps" in cmd:
            return _FakeProc(0, _PS_JSON, "")
        return _FakeProc(0, "", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy", lambda *a, **k: True)
    monkeypatch.setenv("AAX_HOST_ONLY_SECRET", "must-not-reach-compose")

    with DockerProjectRunner(
        tmp_path,
        {"compose": "docker-compose.yml", "port": 8080},
        env={"AAX_TEST_ENV": "injected"},
        scan_id="scan_env",
    ):
        pass

    assert environments
    assert all(item is not None and item["AAX_TEST_ENV"] == "injected" for item in environments)
    assert all("AAX_HOST_ONLY_SECRET" not in item for item in environments)
    assert all(item.get("PATH") for item in environments)


def test_compose_commands_disable_automatic_project_dotenv_loading(tmp_path, monkeypatch):
    """显式空 env-file 阻止 Compose 自动读取项目根的 .env。"""
    (tmp_path / ".env").write_text("HOST_SECRET=must-not-be-read\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n",
        encoding="utf-8",
    )
    commands = []

    def _run(cmd, **_kwargs):
        commands.append(cmd)
        if "config" in cmd:
            return _FakeProc(0, "", "")
        if "up" in cmd:
            return _FakeProc(0, "", "")
        if "ps" in cmd:
            return _FakeProc(0, _PS_JSON, "")
        return _FakeProc(0, "", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy", lambda *a, **k: True)
    import backend.verifier.docker_project_runner as runner_module
    compose_prefix = runner_module._compose_cli_prefix()
    prefix_size = len(compose_prefix)

    with DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml", "port": 8080}, scan_id="no-project-dotenv"
    ):
        compose_commands = [cmd for cmd in commands if cmd[:prefix_size] == compose_prefix]
        assert compose_commands
        assert all(cmd[prefix_size] == "--env-file" for cmd in compose_commands)
        isolated_env = Path(compose_commands[0][prefix_size + 1])
        assert not isolated_env.is_relative_to(tmp_path)
        assert isolated_env.read_text(encoding="utf-8") == ""

    compose_commands = [cmd for cmd in commands if cmd[:prefix_size] == compose_prefix]
    option_index = prefix_size + 2
    assert all(cmd[option_index:option_index + 3] == ["-p", "aaxnoprojectdotenv", "-f"] for cmd in compose_commands)
    assert len({cmd[option_index + 3] for cmd in compose_commands}) == 1
    assert {cmd[option_index + 4] for cmd in compose_commands} >= {"config", "up", "ps", "logs", "down"}
    assert not isolated_env.exists()
    assert not isolated_env.parent.exists()


@pytest.mark.parametrize("arguments", [
    ("config", "--images"),
    ("up", "-d"),
    ("ps", "--format", "json"),
    ("logs", "--no-color", "--tail", "50"),
    ("down", "-v"),
    ("port", "web", "8080"),
])
def test_compose_command_builder_places_env_file_after_compose_for_every_subcommand(
    tmp_path, arguments
):
    """所有 Compose 子命令必须使用 ``docker compose --env-file``，而非 Docker 根 CLI flag。"""
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_command_argv")
    runner._compose_file = str(tmp_path / "docker-compose.yml")

    command = runner._compose_command("aaxscan", *arguments)

    import backend.verifier.docker_project_runner as runner_module
    compose_prefix = runner_module._compose_cli_prefix()
    prefix_size = len(compose_prefix)
    assert command[:prefix_size] == compose_prefix
    assert command[prefix_size] == "--env-file"
    assert Path(command[prefix_size + 1]).read_text(encoding="utf-8") == ""
    assert command[prefix_size + 2:prefix_size + 6] == ["-p", "aaxscan", "-f", runner._compose_file]
    assert command[prefix_size + 6:] == list(arguments)
    runner._cleanup()


def test_compose_command_builder_uses_explicit_windows_plugin_when_available(tmp_path, monkeypatch):
    """A sanitized Windows environment must not rely on Docker plugin discovery."""
    import backend.verifier.docker_project_runner as runner_module

    plugin = r"C:\Program Files\Docker\cli-plugins\docker-compose.exe"
    monkeypatch.setattr(runner_module, "_compose_cli_prefix", lambda: [plugin])
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_windows_plugin")
    runner._compose_file = str(tmp_path / "docker-compose.yml")

    command = runner._compose_command("aaxscan", "config", "--images")

    assert command[:3] == [plugin, "--env-file", str(runner._compose_cli_env_file)]
    assert command[3:7] == ["-p", "aaxscan", "-f", runner._compose_file]
    assert command[7:] == ["config", "--images"]
    runner._cleanup()


def test_docker_compose_timeout_captures_ps_and_logs(tmp_path, monkeypatch):
    import subprocess
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n", encoding="utf-8")

    def _run(cmd, **kw):
        if "config" in cmd:
            return _FakeProc(0, "aax-timeout-web\n", "")
        if "up" in cmd:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 1))
        if "ps" in cmd:
            return _FakeProc(0, "web  building", "")
        if "logs" in cmd:
            return _FakeProc(0, "build output", "")
        return _FakeProc(0, "", "")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    with DockerProjectRunner(tmp_path, {"compose": "docker-compose.yml"}, scan_id="scan_timeout") as runner:
        assert runner.metadata["status"] == "sandbox_build_timeout"
        assert runner.metadata["failure_code"] == "sandbox_build_timeout"
        assert runner.metadata["phase"] == "compose_up"
        assert runner.metadata["compose_ps"] == "web  building"
        assert runner.metadata["logs_excerpt"] == "build output"
        assert "SandboxCommandTimeout" in runner.metadata["last_exception"]


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


def test_compose_prefers_http_80_over_tls_443(tmp_path, monkeypatch):
    """同一 Web 服务暴露 80/443 时，http 验证不能误选 8443 TLS 端口。"""
    payload = ('[{"Service":"crapi-web","Publishers":['
               '{"TargetPort":443,"PublishedPort":8443,"Protocol":"tcp"},'
               '{"TargetPort":80,"PublishedPort":8888,"Protocol":"tcp"}]}]')
    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run",
                        lambda cmd, **kw: _FakeProc(0, payload, ""))
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_tls")
    runner._compose_file = str(tmp_path / "docker-compose.yml")
    assert runner._compose_published_port("proj", None) == 8888
    assert runner._compose_selected_target_port == 80


def test_compose_uses_https_for_tls_alternate_port(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  api:\n    image: local/api\n    ports: ['8443:8443']\n", encoding="utf-8")
    observed = {}
    _install_fake_compose(
        monkeypatch,
        ps_json='[{"Service":"api","Publishers":[{"TargetPort":8443,"PublishedPort":49158,"Protocol":"tcp"}]}]',
        healthy=True,
    )
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy",
                        lambda url, *_a, **_kw: observed.setdefault("url", url) is not None)
    with DockerProjectRunner(tmp_path, {"compose": "docker-compose.yml", "port": 8443},
                             scan_id="scan_tls_port") as runner:
        assert runner.base_url == "https://127.0.0.1:49158"
        assert observed["url"].startswith("https://")


def test_compose_logs_prioritizes_selected_web_service_over_noisy_dependency(tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  app:\n    image: example/app\n", encoding="utf-8")
    runner = DockerProjectRunner(tmp_path, {}, scan_id="compose-log-priority")
    runner._compose_project = "project"
    runner._compose_file = str(compose)
    runner._compose_web_service = "app"

    monkeypatch.setattr(runner, "_service_logs", lambda service: "app | startup root cause")
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.subprocess.run",
        lambda *_args, **_kwargs: _FakeProc(0, "mysql | repeated noisy status\n" * 100, ""),
    )

    logs = runner._compose_logs()

    assert logs.startswith("app | startup root cause")
    assert "--- compose tail ---" in logs
    assert "mysql | repeated noisy status" in logs
    runner._cleanup()


def test_isolated_compose_removes_global_names_and_fixed_ports(tmp_path):
    """固定 container_name/network/host port 必须在一次性覆写文件中移除。"""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  db:\n    image: postgres:14\n    container_name: shared-db\n    ports: ['127.0.0.1:5432:5432']\n"
        "  web:\n    image: nginx\n    container_name: shared-web\n    ports: ['127.0.0.1:8888:80', '127.0.0.1:8443:443']\n"
        "networks:\n  default:\n    name: shared-net\n",
        encoding="utf-8")
    runner = DockerProjectRunner(tmp_path, {"port": 3000}, scan_id="scan_isolated")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", 3000)
    import yaml
    data = yaml.safe_load(generated.read_text(encoding="utf-8"))
    assert all("container_name" not in service for service in data["services"].values())
    assert data["networks"]["default"].get("name") is None
    assert "db" not in data["services"]  # unrelated service omitted from isolated target
    assert data["services"]["web"]["ports"] == ["127.0.0.1::80"]


def test_isolated_compose_derives_pinned_nodemon_for_legacy_node_without_mutating_source(tmp_path):
    """Legacy Node images must not resolve today's incompatible global nodemon."""
    import yaml

    source_dockerfile = tmp_path / "Dockerfile-dev"
    source_dockerfile.write_text(
        "FROM node:carbon\nWORKDIR /app\nRUN npm install -g nodemon\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    build:\n      context: .\n      dockerfile: Dockerfile-dev\n"
        "    ports: ['9090:9090']\n"
        "  mysql-db:\n    image: mysql:5.7\n",
        encoding="utf-8",
    )
    runner = DockerProjectRunner(tmp_path, {}, scan_id="legacy-nodemon")

    generated_name = runner._prepare_isolated_compose("docker-compose.yml", 9090)
    generated_path = tmp_path / generated_name
    generated = yaml.safe_load(generated_path.read_text(encoding="utf-8"))
    compat_name = generated["services"]["app"]["build"]["dockerfile"]
    compat_path = tmp_path / compat_name

    assert source_dockerfile.read_text(encoding="utf-8") == (
        "FROM node:carbon\nWORKDIR /app\nRUN npm install -g nodemon\n"
    )
    assert "RUN npm install -g nodemon@1.19.4" in compat_path.read_text(encoding="utf-8")
    assert runner.metadata["sandbox_compatibility_patches"] == [{
        "kind": "legacy_node_unpinned_nodemon",
        "service": "app",
        "source_dockerfile": "Dockerfile-dev",
        "replacement": "nodemon@1.19.4",
        "source_preserved": True,
    }]

    runner._cleanup()
    assert not compat_path.exists()
    assert not generated_path.exists()


def test_isolated_compose_hardens_selected_web_service_without_restricting_database(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  web:\n    image: example/nodegoat\n    ports: ['3000:3000']\n    depends_on: [mongo]\n"
        "  mongo:\n    image: mongo:7\n",
        encoding="utf-8",
    )
    runner = DockerProjectRunner(tmp_path, {}, scan_id="compose-hardening")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    import yaml
    services = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]

    web = services["web"]
    assert web["cap_drop"] == ["ALL"]
    assert web["security_opt"] == ["no-new-privileges:true"]
    assert web["read_only"] is True
    assert web["tmpfs"] == ["/tmp:rw,noexec,nosuid,size=64m"]
    assert web["mem_limit"] == "512m"
    assert web["pids_limit"] == 256
    assert services["mongo"]["mem_limit"] == "512m"
    assert services["mongo"]["pids_limit"] == 256
    assert "read_only" not in services["mongo"]
    runner._cleanup()


def test_isolated_compose_removes_baked_source_bind_without_masking_runtime_or_named_storage(tmp_path):
    """A local-build source bind must not hide image-installed dependencies at runtime."""
    import yaml

    (tmp_path / "Dockerfile").write_text(
        "FROM node:8\nWORKDIR /app\nCOPY package.json ./\nRUN npm install\nCOPY . .\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    build: .\n"
        "    ports: ['9090:9090']\n"
        "    depends_on: [db]\n"
        "    volumes:\n"
        "      - .:/app\n"
        "      - app_node_modules:/app/node_modules\n"
        "      - ./runtime:/app/runtime\n"
        "  db:\n"
        "    image: mysql:8\n"
        "    volumes:\n"
        "      - type: volume\n"
        "        source: db_data\n"
        "        target: /var/lib/mysql\n"
        "volumes:\n"
        "  app_node_modules: {}\n"
        "  db_data: {}\n",
        encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="source-bind-mask")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    services = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]

    assert services["app"]["volumes"] == [
        "app_node_modules:/app/node_modules",
        "./runtime:/app/runtime",
    ]
    assert services["db"]["volumes"] == [{
        "type": "volume", "source": "db_data", "target": "/var/lib/mysql",
    }]
    assert any("removed baked source bind mounts: app:/app" in item
               for item in runner.metadata["diagnostics"])
    runner._cleanup()


def test_isolated_compose_leaves_source_binds_for_prebuilt_images_unchanged(tmp_path):
    """Without a local build, the image may rely on its declared bind and is not rewritten."""
    import yaml

    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    image: example/app\n"
        "    working_dir: /app\n"
        "    ports: ['9090:9090']\n"
        "    volumes: ['.:/app']\n",
        encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="prebuilt-source-bind")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    app = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]["app"]

    assert app["volumes"] == [".:/app"]
    runner._cleanup()


def test_isolated_compose_mounts_declared_relative_sqlite_storage_on_tmpfs(tmp_path):
    """A declared project-relative SQLite directory stays writable per scan."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim\nWORKDIR /srv/application\n", encoding="utf-8",
    )
    (tmp_path / "settings.py").write_text(
        "import sqlite3\nDATABASE = 'runtime/state.sqlite3'\n", encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports: ['8000:8000']\n", encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="sqlite-runtime")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    import yaml
    web = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]["web"]

    assert web["read_only"] is True
    assert web["tmpfs"] == [
        "/tmp:rw,noexec,nosuid,size=64m",
        "/srv/application/runtime:rw,noexec,nosuid,nodev,size=64m,mode=1777",
    ]
    runner._cleanup()


def test_isolated_compose_does_not_add_sqlite_tmpfs_without_a_declaration(tmp_path):
    """Non-SQLite projects retain the existing single writable /tmp mount."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim\nWORKDIR /srv/application\n", encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("print('no local database')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Example only: sqlite3.connect('/var/lib/example.db')\n", encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports: ['8000:8000']\n", encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="no-sqlite-runtime")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    import yaml
    web = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]["web"]

    assert web["tmpfs"] == ["/tmp:rw,noexec,nosuid,size=64m"]
    runner._cleanup()


@pytest.mark.parametrize("sqlite_path", ["/var/lib/app.db", "../outside/app.db"])
def test_isolated_compose_rejects_absolute_or_traversing_sqlite_storage(tmp_path, sqlite_path):
    """SQLite declarations must not turn arbitrary paths into writable mounts."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim\nWORKDIR /srv/application\n", encoding="utf-8",
    )
    (tmp_path / "settings.py").write_text(
        f"import sqlite3\nDATABASE = {sqlite_path!r}\n", encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports: ['8000:8000']\n", encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="unsafe-sqlite-runtime")
    with pytest.raises(_ComposeEnvironmentError, match="SQLite.*路径") as exc_info:
        runner._prepare_isolated_compose("docker-compose.yml", None)
    assert exc_info.value.failure_code == "unsafe_sqlite_storage_path"


def test_compose_prefers_explicit_vulnerable_variant_for_vampi_style_target(tmp_path):
    from backend.verifier.docker_project_runner import _select_compose_web_service
    service, port = _select_compose_web_service({
        "vampi-secure": {"ports": ["5001:5000"], "environment": ["vulnerable=0"]},
        "vampi-vulnerable": {"ports": ["5002:5000"], "environment": ["vulnerable=1"]},
    }, None)
    assert (service, port) == ("vampi-vulnerable", 5000)


def test_compose_prefers_published_application_port_over_database_expose_port():
    """DVNA's app port is the HTTP entrypoint; MySQL's internal expose is not."""
    from backend.verifier.docker_project_runner import _select_compose_web_service

    service, port = _select_compose_web_service({
        "app": {"ports": ["9090:9090"], "depends_on": ["mysql-db"]},
        "mysql-db": {"image": "mysql:5.7", "expose": ["3306"]},
    }, 3306)

    assert (service, port) == ("app", 9090)


def test_isolated_compose_keeps_only_web_dependency_closure(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  secure:\n    image: example/secure\n    ports: ['5001:5000']\n"
        "  vulnerable-api:\n    build: .\n    ports: ['5002:5000']\n    depends_on: [db]\n"
        "  db:\n    image: postgres:16\n"
        "  mailhog:\n    image: mailhog/mailhog\n",
        encoding="utf-8",
    )
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_closure")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    import yaml
    services = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]
    assert set(services) == {"vulnerable-api", "db"}
    assert any("secure" in entry and "mailhog" in entry for entry in runner.metadata["diagnostics"])


def test_isolated_compose_keeps_services_referenced_by_web_environment_or_command(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: example/web\n"
        "    ports: ['3000:3000']\n"
        "    environment:\n"
        "      MONGODB_URI: mongodb://mongo:27017/nodegoat\n"
        "    command: node app.js --cache redis://redis:6379/0\n"
        "  mongo:\n"
        "    image: mongo:7\n"
        "  redis:\n"
        "    image: redis:7\n"
        "  mailhog:\n"
        "    image: mailhog/mailhog\n",
        encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_service_refs")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    import yaml
    services = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]

    assert set(services) == {"web", "mongo", "redis"}
    assert "mailhog" not in services


def test_isolated_compose_keeps_explicit_dependencies_without_service_references(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: example/web\n"
        "    ports: ['3000:3000']\n"
        "    depends_on: [mongo]\n"
        "  mongo:\n"
        "    image: mongo:7\n"
        "  redis:\n"
        "    image: redis:7\n",
        encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_explicit_dependency")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    import yaml
    services = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]

    assert set(services) == {"web", "mongo"}


def test_isolated_compose_does_not_expand_unresolved_service_variables(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: example/web\n"
        "    ports: ['3000:3000']\n"
        "    environment:\n"
        "      MONGODB_URI: $MONGODB_URI\n"
        "    command: node $APP_COMMAND\n"
        "  mongo:\n"
        "    image: mongo:7\n"
        "  redis:\n"
        "    image: redis:7\n",
        encoding="utf-8",
    )

    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_unresolved_variable")
    generated = tmp_path / runner._prepare_isolated_compose("docker-compose.yml", None)
    import yaml
    services = yaml.safe_load(generated.read_text(encoding="utf-8"))["services"]

    assert set(services) == {"web"}


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


def test_compose_does_not_pull_image_built_by_the_project(tmp_path, monkeypatch):
    """VAmPI-style ``image`` + ``build`` names a local build output, not a registry image."""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: vampi_docker:latest\n"
        "    build: .\n"
        "    ports: ['5002:5002']\n",
        encoding="utf-8",
    )
    calls = []

    def _run(cmd, **kw):
        calls.append(cmd)
        if "config" in cmd:
            return _FakeProc(0, "vampi_docker:latest\n", "")
        raise AssertionError(f"locally built image must not be inspected or pulled: {cmd}")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_vampi")
    runner._compose_file = str(compose)

    runner._prefetch_compose_images("proj")

    assert not [cmd for cmd in calls if cmd[:2] == ["docker", "pull"]]
    assert any("will be built locally: vampi_docker:latest" in item
                for item in runner.metadata["diagnostics"])


def test_compose_does_not_pull_unnamed_build_service_image(tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  vampi-vulnerable:\n    build: .\n", encoding="utf-8")
    calls = []

    def _run(cmd, **kw):
        calls.append(cmd)
        if "config" in cmd:
            return _FakeProc(0, "aaxscan-vampi-vulnerable\n", "")
        raise AssertionError(f"unnamed local build must not be inspected or pulled: {cmd}")

    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan")
    runner._compose_file = str(compose)
    runner._prefetch_compose_images("aaxscan")

    assert not [cmd for cmd in calls if cmd[:2] == ["docker", "pull"]]


def test_isolated_nested_compose_stays_beside_source_file(tmp_path):
    compose = tmp_path / "deploy" / "docker" / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text("services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n", encoding="utf-8")
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_nested")
    generated = tmp_path / runner._prepare_isolated_compose("deploy/docker/docker-compose.yml", None)
    assert generated.parent == compose.parent
    assert generated.name.startswith("docker-compose.auditagentx.")


def test_compose_image_pull_timeout_is_reported(tmp_path, monkeypatch):
    from backend.runtime.scan_execution import SandboxCommandTimeout

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
    except SandboxCommandTimeout as exc:
        assert exc.phase == "image_pull"


def test_compose_image_discovery_uses_managed_deadline(tmp_path, monkeypatch):
    """Compose image discovery must not outlive the scan's build deadline."""
    from backend.runtime.scan_execution import SandboxCommandTimeout

    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n", encoding="utf-8"
    )
    runner = DockerProjectRunner(
        tmp_path, {"compose": "docker-compose.yml"}, scan_id="scan_config_timeout"
    )
    runner._compose_file = str(tmp_path / "docker-compose.yml")
    runner._build_deadline = 1.0
    calls = []

    def _managed(_scan_id, cmd, **_kwargs):
        calls.append(cmd)
        raise SandboxCommandTimeout(
            "compose config timed out", phase="compose_config", timeout_seconds=60
        )

    monkeypatch.setattr("backend.verifier.docker_project_runner.run_managed_command", _managed)

    with pytest.raises(SandboxCommandTimeout) as exc_info:
        runner._prefetch_compose_images("project")

    assert exc_info.value.phase == "compose_config"
    import backend.verifier.docker_project_runner as runner_module
    assert calls == [[*runner_module._compose_cli_prefix(), "--env-file", str(runner._compose_cli_env_file),
                      "-p", "project", "-f", runner._compose_file, "config", "--images"]]


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


def test_pipeline_function_harness_stays_review_only_when_http_sandbox_fails(monkeypatch):
    """函数切片保留取证价值，但没有 HTTP/入口证据时不得升级确认。"""
    _force_no_docker(monkeypatch)
    monkeypatch.setattr(
        "backend.verifier.harness_verifier.HarnessVerifier.run",
        lambda self, f, code_root, **_kwargs: {"dynamically_triggered": False, "verdict": "function_reproduced",
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
    assert f["function_unit_reproduced"] is True
    assert f["runtime_verification_status"] == "function_reproduced"
    assert f["_evidence"]["verification"]["entrypoint_confirmed"] is False


def test_pipeline_mechanism_harness_not_fully_dynamic(monkeypatch):
    """模板机理级 Harness(mechanism_confirmed) 不应把 finding 标记为完全 dynamically_verified。"""
    _force_no_docker(monkeypatch)
    monkeypatch.setattr(
        "backend.verifier.harness_verifier.HarnessVerifier.run",
        lambda self, f, code_root, **_kwargs: {"dynamically_triggered": False, "verdict": "mechanism_confirmed",
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
    """Exploit lane failure is isolated and retains a deterministic fallback plan."""
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
    assert findings[1]["_exploit"]["_from_template"] is True
    assert findings[1]["_exploit"]["payloads"]
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
