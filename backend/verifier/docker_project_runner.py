"""DockerProjectRunner —— Docker-first Deep Mode 沙箱：在容器内启动 GitHub 项目。

流程：code_root + launch_plan → 生成/复用 Dockerfile → build → run → 健康检查 → base_url。
退出时自动 docker rm -f 清理容器，并采集 docker logs 摘要。

安全边界：仅用于本地 Docker 沙箱 / 授权目标；容器限内存，扫描后即销毁。
失败时如实返回状态（sandbox_start_failed / health_check_failed / dependency_install_failed），
绝不造假复现结果。

复用：端口分配 / 健康检查复用 app_runner 的 _free_port / _wait_healthy，不重复实现。
"""
from __future__ import annotations

import json as _json
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from backend.config import settings
from backend.runtime.scan_execution import (
    SandboxCommandCancelled,
    SandboxCommandTimeout,
    is_cancelled,
    register_cleanup_callback,
    run_managed_command,
    unregister_cleanup_callback,
)
from backend.verifier.app_runner import _free_port, _wait_healthy, get_docker_client

logger = logging.getLogger(__name__)

# 沙箱状态
STARTED = "started"
SANDBOX_START_FAILED = "sandbox_start_failed"
HEALTH_CHECK_FAILED = "health_check_failed"
DEPENDENCY_INSTALL_FAILED = "dependency_install_failed"
LAUNCH_NOT_DETECTED = "launch_not_detected"   # 预检：无法自动识别启动方式，未尝试构建
NOT_WEB_TARGET = "not_web_target"             # 原生 CLI/系统项目：HTTP 项目沙箱不适用
UNSAFE_PROJECT_CONFIG = "unsafe_project_config"  # 项目容器配置违反沙箱策略
SANDBOX_BUILD_TIMEOUT = "sandbox_build_timeout"
SANDBOX_CANCELLED = "sandbox_cancelled"


def _first_line(text: str, limit: int = 200) -> str:
    """取错误信息的首个有效行，便于生成可读 reason。"""
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return str(text)[:limit]


def _diagnostic_tail(text: str, limit: int = 1200) -> str:
    """保留 Compose 错误末尾；真正原因通常在大量 Pulling/Waiting 输出之后。"""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    return "\n".join(lines[-12:])[-limit:]


_DEPENDENCY_DIAGNOSTIC = re.compile(
    r"(?:^|\b)(?:cannot install|resolutionimpossible|no matching distribution|"
    r"failed building wheel|subprocess-exited-with-error|could not build wheels|"
    r"package .*? has no installation candidate)",
    re.IGNORECASE,
)
_PYTHON_RESOLUTION_FAILURE = re.compile(
    r"(?:no matching distribution found|could not find a version that satisfies the requirement)",
    re.IGNORECASE,
)
_DEFAULT_PYTHON_SANDBOX_IMAGE = "python:3.11-slim"
_PYTHON_COMPATIBILITY_IMAGE = "python:3.12-slim"


def _dependency_diagnostic(text: str, limit: int = 1200) -> tuple[str, str]:
    """Keep a meaningful dependency error as well as the final BuildKit footer."""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    detail = next((line for line in reversed(lines) if _DEPENDENCY_DIAGNOSTIC.search(line)), "")
    if not detail:
        detail = next((line for line in reversed(lines) if "error:" in line.lower()), "")
    tail = _diagnostic_tail(text, limit)
    if not detail or detail in tail:
        return detail or _first_line(text), tail
    excerpt = f"{detail}\n--- BuildKit tail ---\n{tail}"
    return detail[:400], excerpt[-limit:]


def _transient_pull_failure(text: str) -> bool:
    lower = str(text).lower()
    return any(token in lower for token in (
        " eof", "context canceled", "tls handshake timeout", "i/o timeout",
        "connection reset", "temporary failure", "unexpected status from head request",
        "auth.docker.io", "registry-1.docker.io",
    ))


_DOCKER_HUB_REGISTRIES = frozenset({
    "docker.io", "index.docker.io", "registry-1.docker.io",
})
_DOCKER_HUB_MIRRORS = ("docker.m.daocloud.io",)
_IMMUTABLE_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
_SIMPLE_DOCKERFILE_ARG_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
_DOCKERFILE_ARG = re.compile(
    r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*([^\s#]+))?\s*(?:#.*)?$", re.IGNORECASE,
)
_DOCKERFILE_FROM = re.compile(r"^\s*FROM\s+(?:--[^\s]+\s+)*([^\s]+)", re.IGNORECASE)
_DOCKERFILE_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _dockerfile_base_images(path: Path) -> list[str]:
    """Return resolvable base images from Dockerfile ``FROM`` statements.

    Only simple ``ARG name=value`` defaults are expanded.  Shell expressions,
    unresolved variables and arbitrary Dockerfile instructions remain Docker's
    responsibility rather than becoming an input to an image-pull command.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    arguments: dict[str, str] = {}
    images: list[str] = []
    instruction = ""
    for raw_line in lines:
        stripped = raw_line.strip()
        if not instruction and (not stripped or stripped.startswith("#")):
            continue
        if raw_line.rstrip().endswith("\\"):
            instruction += raw_line.rstrip()[:-1] + " "
            continue
        instruction += raw_line
        arg_match = _DOCKERFILE_ARG.match(instruction)
        if arg_match:
            name, default = arg_match.groups()
            if default and _SIMPLE_DOCKERFILE_ARG_VALUE.fullmatch(default):
                arguments[name] = default
        else:
            from_match = _DOCKERFILE_FROM.match(instruction)
            if from_match:
                image = _DOCKERFILE_VARIABLE.sub(
                    lambda match: arguments.get(match.group(1) or match.group(2), match.group(0)),
                    from_match.group(1),
                )
                if "$" not in image and image.lower() != "scratch":
                    images.append(image)
        instruction = ""
    return list(dict.fromkeys(images))


def _docker_hub_repository(image: str) -> str | None:
    """Return the mirror repository for a public Docker Hub image, else ``None``."""
    reference = str(image or "").strip()
    if not reference or any(char in reference for char in ("$", "\\", " ")):
        return None
    parts = reference.split("/")
    if any(not part for part in parts):
        return None
    first = parts[0].lower()
    if first in _DOCKER_HUB_REGISTRIES:
        parts = parts[1:]
    elif len(parts) > 1 and ("." in first or ":" in first or first == "localhost"):
        return None
    if not parts:
        return None
    if len(parts) == 1:
        parts.insert(0, "library")
    return "/".join(parts)


def _docker_hub_mirror_reference(image: str, mirror: str) -> str | None:
    """Build a candidate image reference using a trusted Docker Hub mirror."""
    repository = _docker_hub_repository(image)
    if not repository or mirror not in _DOCKER_HUB_MIRRORS:
        return None
    return f"{mirror}/{repository}"


def _image_reference_repository(reference: str) -> str:
    """Return an image reference without a tag or digest."""
    repository = str(reference or "").split("@", 1)[0]
    final_component = repository.rsplit("/", 1)[-1]
    if ":" in final_component:
        repository = repository.rsplit(":", 1)[0]
    return repository


def build_dockerfile(launch_plan: dict, port: int, *, python_image: str = _DEFAULT_PYTHON_SANDBOX_IMAGE) -> str:
    """SandboxBuilder：按 launch_plan 生成最小 Dockerfile（无项目 Dockerfile 时）。"""
    framework = (launch_plan.get("framework") or "").lower()
    install = launch_plan.get("install_command")
    run = launch_plan.get("run_command") or launch_plan.get("command") or ""
    run = run.replace("{port}", str(port))
    workdir = _safe_workdir(launch_plan.get("working_dir"))
    app_workdir = "/app" + ("/" + workdir if workdir else "")

    if "node" in framework or "express" in framework:
        install = install or "npm install"
        return (
            "FROM node:20-slim\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            f"RUN {install}\n"
            f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "php" in framework:
        # The PHP CLI image intentionally contains only PHP.  When launch
        # detection infers ``composer install`` from composer.json, provide the
        # pinned Composer binary through a separate official stage rather than
        # assuming Composer happens to be installed in php:*-cli.
        composer_stage = (
            "FROM composer:2 AS composer\n"
            if _install_invokes_composer(install) else ""
        )
        composer_copy = (
            "COPY --from=composer /usr/bin/composer /usr/bin/composer\n"
            if composer_stage else ""
        )
        return (
            composer_stage
            + "FROM php:8.2-cli\n"
            "WORKDIR /app\n"
            + composer_copy
            + "COPY . /app\n"
            + f"WORKDIR {app_workdir}\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "spring" in framework or "java" in framework:
        return (
            "FROM eclipse-temurin:17-jdk\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    # 默认 Python
    install = install or "pip install --no-cache-dir -r requirements.txt"
    return (
        f"FROM {python_image}\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        f"WORKDIR {app_workdir}\n"
        # 不能用 `|| pip install flask ...` 吞掉真实依赖失败；否则容器“构建成功”但实际
        # 项目依赖缺失，最终把问题伪装成无意义的健康检查失败。
        f"RUN {install}\n"
        f"EXPOSE {port}\n"
        f"CMD {_cmd_json(run)}\n"
    )


def _uses_generated_python_image(launch_plan: dict) -> bool:
    """Whether ``build_dockerfile`` selects its Python branch for this plan."""
    framework = str(launch_plan.get("framework") or "").lower()
    return not any(runtime in framework for runtime in ("node", "express", "php", "spring", "java"))


def _should_retry_python_dependency_resolution(build_error: str, launch_plan: dict) -> bool:
    """Allow one newer-interpreter retry for generated Python dependency resolution.

    This deliberately keys off the generic pip resolver error rather than a
    package name. Project Dockerfiles never reach this path, and a failed retry
    remains an honest ``dependency_install_failed`` result.
    """
    return bool(
        _uses_generated_python_image(launch_plan)
        and _PYTHON_RESOLUTION_FAILURE.search(str(build_error or ""))
    )


def _safe_workdir(value: str | None) -> str:
    """把源码识别出的相对工作目录转为 Docker 内安全路径。"""
    raw = str(value or ".").replace("\\", "/").strip("/")
    if not raw or raw == ".":
        return ""
    parts = [part for part in raw.split("/") if part and part not in {".", ".."}]
    return "/".join(parts)


def _install_invokes_composer(command: str | None) -> bool:
    """Return whether a generated PHP dependency command requires Composer.

    Launch-plan commands are separately allowlisted before Docker execution;
    this helper only selects the generated image capability.  Matching the
    command token avoids adding another base image for PHP projects that do not
    use Composer.
    """
    return bool(re.match(r"^\s*composer(?:\s|$)", str(command or ""), re.IGNORECASE))


def _safe_project_dockerfile(root: Path, value: str | None) -> str | None:
    """Return a repository-relative Dockerfile path, rejecting traversal/absolute paths."""
    raw = str(value or "Dockerfile").replace("\\", "/").strip()
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        return None
    candidate = (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return path.as_posix() if candidate.is_file() else None


def _cmd_json(run_command: str) -> str:
    """把启动命令转成 Dockerfile CMD。

    使用 ``sh -c`` 而不是简单 split 成 argv，原因：
    - Java/Spring 常见 ``target/*.jar`` 需要 shell 展开通配符；
    - 用户手动填写的命令可能包含引号、环境变量或 ``&&``；
    - npm/pip 等命令以 shell 运行更贴近日常启动方式。
    """
    return _json.dumps(["sh", "-c", run_command or "true"], ensure_ascii=False)


def _compose_cli_prefix() -> list[str]:
    """Return a Compose v2 entrypoint that works with a scrubbed environment.

    Docker Desktop discovers its Compose plugin through Windows profile/config
    variables. The sandbox intentionally strips those variables, which makes
    ``docker compose`` forward Compose flags to Docker's root parser. When the
    Desktop plugin exists at its trusted machine location, invoke it directly;
    Unix installations retain the normal v2 subcommand.
    """
    if os.name == "nt":
        candidates: list[Path] = []
        for variable in ("ProgramW6432", "ProgramFiles"):
            root = os.environ.get(variable)
            if root:
                candidates.append(Path(root) / "Docker" / "cli-plugins" / "docker-compose.exe")
        docker_cli = shutil.which("docker")
        if docker_cli:
            docker_path = Path(docker_cli).resolve()
            # Docker Desktop places docker.exe at Docker/Docker/resources/bin
            # and the Compose plugin at Docker/cli-plugins.
            if len(docker_path.parents) >= 4:
                candidates.append(docker_path.parents[3] / "cli-plugins" / "docker-compose.exe")
        for candidate in candidates:
            if candidate.is_file():
                return [str(candidate)]
    return ["docker", "compose"]


class DockerProjectRunner:
    """上下文管理器：进入返回 self（含 base_url / metadata），退出清理容器。"""

    def __init__(self, code_root: Path, launch_plan: dict | None = None,
                 *, env: dict | None = None, scan_id: str | None = None,
                 trust_project_container_config: bool = False,
                 build_timeout: int | None = None, health_timeout: int | None = None) -> None:
        # 未显式传入时读配置：单容器项目默认 90s，镜像构建 900s；compose 另有更长超时。
        if build_timeout is None:
            build_timeout = int(getattr(settings, "sandbox_build_timeout", 900))
        if health_timeout is None:
            health_timeout = int(getattr(settings, "sandbox_project_health_timeout", 90))
        # Compose 命令会以 code_root 作为 cwd；这里必须先绝对化，否则 `-f` 收到相对
        # 路径时会被 cwd 再拼接一次（data/projects/.../data/projects/...）。
        self.code_root = Path(code_root).resolve()
        self.launch_plan = launch_plan or {}
        self.env = env or {}
        self.scan_id = scan_id or "adhoc"
        self.trust_project_container_config = bool(trust_project_container_config)
        self.build_timeout = build_timeout
        self.health_timeout = health_timeout

        self.base_url: str | None = None
        self.metadata: dict = {
            "mode": "docker_project",
            "code_root": str(self.code_root),
            "launch_plan": self.launch_plan,
            "image": f"auditagentx-{re.sub(r'[^a-z0-9]', '', self.scan_id.lower())[:20] or 'scan'}",
            "container_id": None,
            "container_ids": [],
            "compose_project": None,
            "cleanup_attempted": False,
            "cleanup_succeeded": None,
            "base_url": None,
            "port": self.launch_plan.get("port") or 8000,
            "health_path": self.launch_plan.get("health_path") or "/",
            "working_dir": _safe_workdir(self.launch_plan.get("working_dir")) or ".",
            "health_check": "failed",
            "launch_command": (self.launch_plan.get("run_command")
                               or self.launch_plan.get("command")),
            "image_build_attempted": False,
            "container_start_attempted": False,
            "logs_excerpt": "",
            "status": SANDBOX_START_FAILED,
            "reason": "",
            "diagnostics": [],
            "image_mirror_provenance": [],
            "sandbox_compatibility_patches": [],
            "trust_project_container_config": self.trust_project_container_config,
        }
        self._client = None
        self._container = None
        # docker compose 编排（多服务项目）时记录，供清理使用
        self._compose_project: str | None = None
        self._compose_file: str | None = None
        self._generated_compose_file_name: str | None = None
        self._generated_compat_dockerfiles: list[Path] = []
        self._compose_selected_target_port: int | None = None
        self._compose_web_service: str | None = None
        self._compose_environment_temp_dir: Path | None = None
        self._compose_cli_env_file: Path | None = None
        # 是否有 build 型服务的镜像无法拉取、必须本地构建（决定 up 是否加 --build）。
        self._compose_needs_build: bool = False
        self._generated_dockerfile_name: str | None = None
        self._build_deadline: float | None = None
        self._cleanup_lock = threading.RLock()
        self._cleanup_done = False
        self._cleanup_token: int | None = None

    def __enter__(self) -> "DockerProjectRunner":
        try:
            self._start()
        except SandboxCommandTimeout as e:
            self.metadata["status"] = SANDBOX_BUILD_TIMEOUT
            self.metadata["failure_code"] = SANDBOX_BUILD_TIMEOUT
            self.metadata["phase"] = e.phase
            self.metadata["timeout_seconds"] = e.timeout_seconds
            if e.stderr or e.stdout:
                self.metadata["logs_excerpt"] = _diagnostic_tail(e.stderr or e.stdout)
            self.metadata["reason"] = f"沙箱命令超时（phase={e.phase}）"
            logger.warning("沙箱命令超时: phase=%s", e.phase)
        except SandboxCommandCancelled as e:
            self.metadata["status"] = SANDBOX_CANCELLED
            self.metadata["failure_code"] = SANDBOX_CANCELLED
            self.metadata["phase"] = e.phase
            if e.stderr or e.stdout:
                self.metadata["logs_excerpt"] = _diagnostic_tail(e.stderr or e.stdout)
            self.metadata["reason"] = "扫描取消，沙箱命令已终止并回收"
            logger.info("沙箱命令已取消: phase=%s", e.phase)
        except _ComposeEnvironmentError as e:
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["failure_code"] = e.failure_code
            self.metadata["missing_env_files"] = e.missing_env_files
            self.metadata["reason"] = str(e)
            logger.warning("Compose 环境预检失败: %s", e)
        except _DependencyError as e:
            self.metadata["status"] = DEPENDENCY_INSTALL_FAILED
            detail, excerpt = _dependency_diagnostic(str(e), 1200)
            self.metadata["logs_excerpt"] = excerpt
            self.metadata["reason"] = "镜像构建时依赖安装失败：" + detail
            logger.warning("沙箱依赖安装失败: %s", e)
        except Exception as e:  # noqa: BLE001
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata.setdefault("failure_code", SANDBOX_START_FAILED)
            # _run_compose already captured compose logs/ps before raising. Preserve
            # that primary evidence; only fall back to exception text when no runtime
            # logs were obtainable.
            if not self.metadata.get("logs_excerpt"):
                self.metadata["logs_excerpt"] = _diagnostic_tail(str(e), 1200)
            self.metadata["reason"] = "沙箱构建/启动失败：" + _diagnostic_tail(str(e), 500)
            logger.warning("沙箱启动失败: %s", e)
        return self

    def __exit__(self, *exc) -> None:
        unregister_cleanup_callback(self.scan_id, self._cleanup_token)
        self._cleanup_token = None
        self._cleanup()

    # ---------- 内部 ----------
    def _start(self) -> None:
        if not self.code_root.exists() or not self.code_root.is_dir():
            raise RuntimeError(f"code_root 不存在或不是目录: {self.code_root}")
        internal_port = int(self.metadata["port"])
        host_port = _free_port()
        base_url = f"http://127.0.0.1:{host_port}"
        image_tag = self.metadata["image"]
        self._build_deadline = time.monotonic() + max(0, self.build_timeout)

        if self.launch_plan.get("runtime_kind") == "native_cli":
            self.metadata["status"] = NOT_WEB_TARGET
            self.metadata["reason"] = (
                "项目被识别为原生 CLI/系统软件，不存在可自动健康检查的 HTTP 服务；"
                "HTTP 项目沙箱不适用，已保留静态验证与函数级 Harness 结果。"
            )
            self.metadata["diagnostics"].append(
                f"non-web runtime detected from {self.launch_plan.get('source_evidence') or 'project structure'}"
            )
            return

        configured_dockerfile = _safe_project_dockerfile(
            self.code_root, self.launch_plan.get("dockerfile"))
        project_dockerfile = configured_dockerfile is not None
        has_dockerfile = project_dockerfile and self.trust_project_container_config
        run_command = self.launch_plan.get("run_command") or self.launch_plan.get("command")
        compose = self.launch_plan.get("compose")

        if project_dockerfile and not self.trust_project_container_config:
            self.metadata["diagnostics"].append(
                "ignored untrusted project Dockerfile; using generated restricted Dockerfile"
            )

        # 0) 多服务项目：若检测到 docker-compose，优先按项目既定方式编排启动
        #    （单容器无法提供 DB/Redis 等依赖服务，这是真实开源项目动态验证失败的高频原因）。
        if compose and (self.code_root / compose).exists():
            policy = _validate_compose_policy(
                self.code_root / compose, code_root=self.code_root, env=self.env,
            )
            if not policy["allowed"]:
                self.metadata["status"] = UNSAFE_PROJECT_CONFIG
                self.metadata["reason"] = "项目 docker-compose 被安全策略阻止：" + policy["reason"]
                self.metadata["diagnostics"].extend(policy["checks"])
                return
            if not self.trust_project_container_config:
                self.metadata["diagnostics"].append(
                    "compose configuration auto-approved by restricted policy; direct project Dockerfile remains disabled"
                )
            self.metadata["diagnostics"].append(f"using docker compose file: {compose}")
            # `-p` 只能隔离 Compose 自动生成的名称。项目若写死
            # container_name / networks.*.name / host ports，仍会和现有靶场冲突。
            # 生成一次性覆写配置，保留服务依赖但移除这些跨项目全局名称。
            isolated_compose = self._prepare_isolated_compose(
                compose, self.launch_plan.get("port")
            )
            self.metadata["container_start_attempted"] = True
            self._run_compose(isolated_compose, self.launch_plan.get("port"))
            return

        # 1) 启动预检：既没有项目自带 Dockerfile，也没识别到启动命令 —— 无法自动容器化。
        #    直接如实返回 launch_not_detected（附手动步骤），避免生成 CMD 为空的坏容器
        #    再报出不可诊断的 "no command specified"（旧 bug 根因）。
        if not has_dockerfile and not run_command:
            self.metadata["status"] = LAUNCH_NOT_DETECTED
            steps = self.launch_plan.get("manual_steps") or []
            hint = "；".join(steps) if steps else "未在项目中识别到 Web 服务的启动方式"
            compose_note = (
                "（检测到 docker-compose，属多服务编排，当前单容器沙箱不自动编排；"
                "请先手动 `docker compose up`，再用 url 模式指定 base_url）"
                if compose else ""
            )
            self.metadata["reason"] = (
                f"无法自动识别项目启动方式：{hint}{compose_note}。"
                "可在动态验证选项中手动提供启动命令（run_command），"
                "或改用 url 模式指定一个已运行的授权靶场 base_url。"
                "界面输入框中的灰色文字只是示例 placeholder，不会作为实际命令提交。"
            )
            logger.info("沙箱预检未通过（不构建）：%s", self.metadata["reason"])
            return

        # 未安装 docker SDK / 引擎不可用时抛异常 -> sandbox_start_failed
        self._client = get_docker_client()

        # 1) 构建镜像：优先项目 Dockerfile，否则生成临时 Dockerfile
        if not has_dockerfile:
            command_policy = _validate_generated_launch_plan(self.launch_plan)
            if not command_policy["allowed"]:
                self.metadata["status"] = UNSAFE_PROJECT_CONFIG
                self.metadata["reason"] = "自动启动命令被安全策略阻止：" + command_policy["reason"]
                self.metadata["diagnostics"].extend(command_policy["checks"])
                return
            dockerfile = build_dockerfile(self.launch_plan, internal_port)
            dockerfile_name = self._next_generated_dockerfile_name()
            (self.code_root / dockerfile_name).write_text(dockerfile, encoding="utf-8")
            self._generated_dockerfile_name = dockerfile_name
            self.metadata["diagnostics"].append(f"generated {dockerfile_name} from launch_plan")
        else:
            dockerfile_name = configured_dockerfile
            self.metadata["diagnostics"].append("using project Dockerfile")
        self.metadata["dockerfile"] = dockerfile_name
        self._prefetch_dockerfile_base_images(
            self.code_root / dockerfile_name, source="Dockerfile base"
        )

        try:
            self.metadata["image_build_attempted"] = True
            build_command = [
                "docker", "build", "--progress=plain", "--file", str(dockerfile_name), "--tag", image_tag,
                "--rm", "--force-rm", ".",
            ]
            built = None
            for attempt in range(1, 4):
                built = run_managed_command(
                    self.scan_id, build_command, cwd=self.code_root,
                    env=self._compose_subprocess_env(), timeout=self.build_timeout,
                    deadline=self._build_deadline, phase="image_build",
                )
                build_error = (built.stderr or built.stdout or "").strip()
                if built.returncode == 0 or not _transient_pull_failure(build_error) or attempt == 3:
                    break
                self.metadata["diagnostics"].append(
                    "build transient failure; retry "
                    f"{attempt}/3: {_diagnostic_tail(build_error, 240)}"
                )
                time.sleep(attempt * 2)
            if built is None:
                raise RuntimeError("docker build 未返回结果")
            # A generated Python 3.11 image is a conservative default, but a
            # project dependency can legitimately require a newer interpreter.
            # Retry exactly once with the next supported image only for pip's
            # generic resolution failure; never reinterpret or execute a
            # project Dockerfile while trust_project_container_config is false.
            if (built.returncode != 0 and not has_dockerfile
                    and _should_retry_python_dependency_resolution(build_error, self.launch_plan)):
                compatibility_dockerfile = build_dockerfile(
                    self.launch_plan, internal_port,
                    python_image=_PYTHON_COMPATIBILITY_IMAGE,
                )
                (self.code_root / dockerfile_name).write_text(
                    compatibility_dockerfile, encoding="utf-8"
                )
                self._prefetch_image(
                    _PYTHON_COMPATIBILITY_IMAGE,
                    source="Python dependency compatibility fallback",
                )
                self.metadata["sandbox_compatibility_patches"].append(
                    "retried generated Python sandbox with python:3.12-slim after dependency resolution failure"
                )
                self.metadata["diagnostics"].append(
                    "generated Python dependency compatibility retry: python:3.11-slim -> python:3.12-slim"
                )
                for attempt in range(1, 4):
                    built = run_managed_command(
                        self.scan_id, build_command, cwd=self.code_root,
                        env=self._compose_subprocess_env(), timeout=self.build_timeout,
                        deadline=self._build_deadline, phase="image_build",
                    )
                    build_error = (built.stderr or built.stdout or "").strip()
                    if built.returncode == 0 or not _transient_pull_failure(build_error) or attempt == 3:
                        break
                    self.metadata["diagnostics"].append(
                        "compatibility build transient failure; retry "
                        f"{attempt}/3: {_diagnostic_tail(build_error, 240)}"
                    )
                    time.sleep(attempt * 2)
            if built.returncode != 0:
                raise RuntimeError(built.stderr or built.stdout or "docker build 失败")
        except FileNotFoundError as e:
            raise RuntimeError("docker CLI 不可用，无法执行受管沙箱构建") from e
        except Exception as e:  # noqa: BLE001
            if isinstance(e, (SandboxCommandTimeout, SandboxCommandCancelled)):
                raise
            msg = str(e).lower()
            if any(k in msg for k in ("pip install", "npm install", "composer",
                                      "could not find", "no matching distribution")):
                raise _DependencyError(str(e)) from e
            raise

        # 2) 启动容器（注入默认监听环境变量，确保服务绑定 0.0.0.0 可被端口映射访问）
        run_env = {
            "APP_HOST": "0.0.0.0", "HOST": "0.0.0.0", "FLASK_RUN_HOST": "0.0.0.0",
            "PORT": str(internal_port), "FLASK_RUN_PORT": str(internal_port),
            **self.env,
        }
        self.metadata["container_start_attempted"] = True
        self._container = self._client.containers.run(
            image=image_tag, detach=True, remove=False,
            ports={f"{internal_port}/tcp": host_port},
            environment=run_env, mem_limit="512m",
            pids_limit=256,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
        )
        self.metadata["container_id"] = self._container.id[:12]
        self._register_cancel_cleanup()

        # 3) 健康检查
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        if self._wait_single_container_healthy(health_url):
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "health_check": "passed",
                "status": STARTED, "reason": "",
            })
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = (
                f"容器已启动但 {self.health_timeout}s 内健康检查未通过"
                f"（health_path={self.metadata['health_path']}，容器端口 {internal_port}）："
                "可能应用未监听 0.0.0.0、实际端口与探测端口不一致、启动过慢或已崩溃，"
                "详见 logs_excerpt。"
            )
        self.metadata["logs_excerpt"] = self._logs()

    def _wait_single_container_healthy(self, health_url: str) -> bool:
        deadline = time.monotonic() + self.health_timeout
        while time.monotonic() < deadline:
            if is_cancelled(self.scan_id):
                raise SandboxCommandCancelled(
                    "scan cancellation requested", phase="health_check"
                )
            remaining = max(1, min(3, int(deadline - time.monotonic()) + 1))
            if _wait_healthy(health_url, remaining):
                return True
        return False

    def _logs(self) -> str:
        if not self._container:
            return ""
        try:
            self._container.reload()
            return self._container.logs().decode("utf-8", errors="ignore")[-3000:]
        except Exception:  # noqa: BLE001
            return ""

    def runtime_logs(self) -> str:
        """返回运行中容器/Compose 的最新日志，供动态判据做请求前后差分。

        仅作为已运行本地沙箱的辅助证据，不能单独把日志出现当成漏洞确认；调用方仍须
        保存对应 HTTP 请求、良性基线和漏洞类型专用判据。
        """
        return self._compose_logs() if self._compose_project else self._logs()

    # ---------- docker compose 多服务编排 ----------
    def _compose_subprocess_env(self) -> dict:
        """Return a scrubbed but viable OS environment for Docker subprocesses."""
        # Never inherit the parent process environment wholesale: Compose must not
        # receive developer credentials, proxy settings, or arbitrary CI secrets.
        # Windows Docker/BuildKit still requires a small set of OS variables for
        # DNS, process creation, temporary files and Desktop plugin execution.
        docker_cli = shutil.which("docker")
        docker_directory = str(Path(docker_cli).parent) if docker_cli else os.defpath
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        path_entries = [docker_directory]
        if system_root:
            path_entries.extend([str(Path(system_root) / "System32"), system_root])
        environment = {"PATH": os.pathsep.join(dict.fromkeys(path_entries))}
        for key in (
            "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA",
            "ProgramData", "ProgramFiles", "ProgramW6432", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        ):
            value = os.environ.get(key)
            if value:
                environment[key] = value
        # Do not let Docker read host ~/.docker credentials or contexts.  The
        # per-scan empty config keeps registry access anonymous and target-local.
        docker_config = self._compose_environment_dir() / "docker-config"
        docker_config.mkdir(parents=True, exist_ok=True)
        environment["DOCKER_CONFIG"] = str(docker_config)
        environment.update({
            str(key): str(value)
            for key, value in self.env.items()
            if str(key) not in {"DOCKER_CONFIG", "DOCKER_AUTH_CONFIG"}
        })
        environment.pop("DOCKER_AUTH_CONFIG", None)
        return environment

    def _compose_environment_dir(self) -> Path:
        if self._compose_environment_temp_dir is None:
            safe_scan_id = re.sub(r"[^A-Za-z0-9_.-]", "", self.scan_id)[:16] or "scan"
            self._compose_environment_temp_dir = Path(tempfile.mkdtemp(
                prefix=f"auditagentx-{safe_scan_id}-env-"
            ))
        return self._compose_environment_temp_dir

    def _ensure_compose_cli_env_file(self) -> None:
        """Prevent Compose from implicitly loading a project or host ``.env`` file."""
        if self._compose_cli_env_file is None:
            self._compose_cli_env_file = self._compose_environment_dir() / "compose-cli.env"
            self._compose_cli_env_file.write_text("", encoding="utf-8")

    def _compose_command(self, project: str, *arguments: str) -> list[str]:
        """Build an isolated Compose argv with only explicit project inputs.

        ``--env-file`` belongs to the Compose subcommand, not Docker's root CLI:
        ``docker compose --env-file <empty-file> ...``.  Keep this invariant in
        the single command builder so diagnostic calls (ps/logs/down) cannot
        accidentally re-enable implicit project ``.env`` loading.
        """
        self._ensure_compose_cli_env_file()
        if not self._compose_file:
            raise RuntimeError("Compose command requires an explicit compose file")
        return [
            *_compose_cli_prefix(), "--env-file", str(self._compose_cli_env_file),
            "-p", project, "-f", self._compose_file, *arguments,
        ]

    def _run_compose(self, compose_file: str, port_hint) -> None:
        """用 `docker compose up` 启动多服务项目，探测对外发布端口并健康检查。

        失败时如实返回状态与 reason，绝不造假复现结果。退出时 `docker compose down` 清理。
        """
        project = "aax" + (re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:20] or "scan")
        self._compose_project = project
        self._compose_file = str(self.code_root / compose_file)
        self.metadata["mode"] = "docker_compose"
        self.metadata["compose_project"] = project
        # Docker Desktop 的内部代理在 Compose 并发拉取多个镜像时容易出现 auth.docker.io
        # EOF。先解析镜像清单并逐个顺序预拉取，既能复用缓存，也避免并发鉴权风暴。
        self._prefetch_compose_images(project)

        # 只有确有 build 型服务的镜像拉不到、必须本地构建时才加 --build；否则用已拉取/缓存
        # 的官方镜像（如 DVWA），避免无谓本地重建触发构建期错误（apt-get 失败等）。
        up_cmd = self._compose_command(project, "up", "-d")
        if self._compose_needs_build:
            up_cmd.append("--build")
        up_cmd += ["--pull", "never"]
        self.metadata["launch_command"] = (
            f"docker compose -f {compose_file} up -d"
            + (" --build" if self._compose_needs_build else "") + " --pull never")
        proc = None
        for attempt in range(1, 4):
            try:
                proc = run_managed_command(
                    self.scan_id, up_cmd, cwd=self.code_root,
                    env=self._compose_subprocess_env(), timeout=self.build_timeout,
                    deadline=self._build_deadline, phase="compose_up",
                )
            except FileNotFoundError as e:
                raise RuntimeError("docker compose CLI 不可用（需 Docker Compose v2）") from e
            except (SandboxCommandTimeout, SandboxCommandCancelled) as e:
                self.metadata["compose_ps"] = self._compose_ps()
                self.metadata["logs_excerpt"] = self._compose_logs()
                self.metadata["last_exception"] = f"{type(e).__name__}: {e}"
                raise
            err = (proc.stderr or proc.stdout or "").strip()
            if proc.returncode == 0 or not _transient_pull_failure(err) or attempt == 3:
                break
            self.metadata["diagnostics"].append(
                f"compose image pull transient failure; retry {attempt}/3: {_diagnostic_tail(err, 240)}"
            )
            time.sleep(attempt * 2)

        if proc is None or proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            self.metadata["compose_ps"] = self._compose_ps()
            self.metadata["logs_excerpt"] = self._compose_logs()
            low = err.lower()
            if any(k in low for k in ("pip install", "npm install", "could not find",
                                      "no matching distribution", "failed to solve")):
                raise _DependencyError(err)
            raise RuntimeError(_diagnostic_tail(err) or "docker compose up 失败")

        # `up -d` 已创建资源；后续 inventory/端口/健康检查期间也必须可立即取消回收。
        self._register_cancel_cleanup()

        inventory = self._compose_inventory()
        self.metadata["compose_containers"] = inventory
        self.metadata["container_ids"] = [
            str(item.get("id")) for item in inventory if item.get("id")
        ]

        # 探测对外发布的 HTTP 端口
        host_port = self._compose_published_port(project, port_hint)
        if not host_port:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["reason"] = (
                "docker compose 已启动，但未找到对外发布的 HTTP 端口，无法探测："
                "请在 compose 文件里为 Web 服务映射端口（ports: '<host>:<container>'）。"
            )
            self.metadata["logs_excerpt"] = self._compose_logs()
            return

        scheme = _scheme_for_port(self._compose_selected_target_port, self.launch_plan)
        base_url = f"{scheme}://127.0.0.1:{host_port}"
        self.metadata["scheme"] = scheme
        self.metadata["selected_service_port"] = self._compose_selected_target_port
        self.metadata["health_url"] = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        # 多服务 compose 首启动依赖 DB/迁移，动辄数分钟；用更长的 compose 专用超时，
        # 避免把“仍在启动”误判为“沙箱健康检查失败”。
        compose_health_timeout = max(self.health_timeout,
                                     int(getattr(settings, "sandbox_compose_health_timeout", 300)))
        # 边等健康边盯目标容器是否已崩溃退出：容器 exit(1) 后再干等满超时是纯浪费，
        # 且真实原因（启动 traceback）远比“Ns 内未通过健康检查”有用。
        crash = self._compose_target_crash_reason()
        if crash:
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = crash
            self.metadata["logs_excerpt"] = self._compose_logs()
            self.metadata["compose_ps"] = self._compose_ps()
            return
        healthy, attempts = self._wait_compose_healthy(
            base_url, compose_health_timeout,
            crash_probe=self._compose_target_crash_reason,
            cancel_probe=lambda: is_cancelled(self.scan_id),
        )
        self.metadata["health_attempts"] = attempts
        crash = crash or self._compose_target_crash_reason()
        if healthy:
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "port": host_port,
                "health_check": "passed", "status": STARTED, "reason": "",
            })
        elif crash:
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = crash
            self.metadata["logs_excerpt"] = self._compose_logs()
            self.metadata["compose_ps"] = self._compose_ps()
            return
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = (
                f"docker compose 服务已启动但 {compose_health_timeout}s 内健康检查未通过"
                f"（探测端口 {host_port}，health_path={self.metadata['health_path']}）："
                "可能 Web 服务尚未就绪、端口映射不对或依赖服务未启动，详见 logs_excerpt。"
            )
        self.metadata["logs_excerpt"] = self._compose_logs()

    def _prefetch_image(self, image: str, *, source: str) -> None:
        """Prepare an image without changing a project's image references.

        Docker Hub references get one canonical anonymous pull, then only the
        explicitly allowlisted mirrors. A mirror fallback is inspected after
        pull and tagged from an immutable mirror digest (or image ID) so
        BuildKit and Compose can consume project references unchanged. Its
        provenance explicitly states that Docker Hub content equivalence was
        not verified while the canonical registry was unavailable. Other
        registries never receive a mirror candidate or host Docker credentials.
        """
        reference = str(image or "").strip()
        pull_timeout = min(
            self.build_timeout, int(getattr(settings, "sandbox_image_pull_timeout", 600)),
        )
        try:
            cached = run_managed_command(
                self.scan_id, ["docker", "image", "inspect", reference],
                cwd=self.code_root, env=self._compose_subprocess_env(), timeout=30,
                deadline=self._build_deadline, phase="image_inspect",
            )
            if cached.returncode == 0:
                self.metadata["diagnostics"].append(f"{source} cached: {reference}")
                return

            canonical = run_managed_command(
                self.scan_id, ["docker", "pull", reference], cwd=self.code_root,
                env=self._compose_subprocess_env(), timeout=pull_timeout,
                deadline=self._build_deadline, phase="image_pull",
            )
        except FileNotFoundError as exc:
            raise RuntimeError("docker CLI 不可用，无法拉取镜像") from exc

        if canonical.returncode == 0:
            self.metadata["diagnostics"].append(f"{source} pulled: {reference}")
            return

        canonical_error = (canonical.stderr or canonical.stdout or "").strip()
        mirror_errors: list[str] = []
        for mirror in _DOCKER_HUB_MIRRORS:
            mirror_reference = _docker_hub_mirror_reference(reference, mirror)
            if not mirror_reference:
                continue
            mirrored = run_managed_command(
                self.scan_id, ["docker", "pull", mirror_reference], cwd=self.code_root,
                env=self._compose_subprocess_env(), timeout=pull_timeout,
                deadline=self._build_deadline, phase="image_mirror_pull",
            )
            if mirrored.returncode != 0:
                mirror_errors.append(
                    f"{mirror}: {_diagnostic_tail(mirrored.stderr or mirrored.stdout, 180)}"
                )
                continue
            provenance = self._mirror_image_provenance(
                mirror_reference, mirror=mirror, canonical=reference, source=source,
            )
            if provenance is None:
                mirror_errors.append(f"{mirror}: immutable digest unavailable after mirror pull")
                continue
            tagged = run_managed_command(
                self.scan_id, ["docker", "tag", provenance["mirror_reference"], reference],
                cwd=self.code_root,
                env=self._compose_subprocess_env(), timeout=30,
                deadline=self._build_deadline, phase="image_mirror_tag",
            )
            if tagged.returncode == 0:
                self.metadata["image_mirror_provenance"].append(provenance)
                self.metadata["diagnostics"].append(
                    f"{source} mirror fallback via {mirror}: resolved {provenance['digest']} and "
                    f"provided locally for {reference}; Docker Hub content equivalence was not verified"
                )
                return
            mirror_errors.append(
                f"{mirror} tag: {_diagnostic_tail(tagged.stderr or tagged.stdout, 180)}"
            )

        detail = _diagnostic_tail(canonical_error, 300)
        if mirror_errors:
            detail += "; mirror failures: " + "; ".join(mirror_errors)
        raise RuntimeError(f"拉取 {source} 镜像失败 ({reference})：{detail}")

    def _mirror_image_provenance(
        self, mirror_reference: str, *, mirror: str, canonical: str, source: str,
    ) -> dict | None:
        """Return immutable, allowlisted provenance for a mirror image, if available.

        A mirror tag is mutable and cannot be used as the source of a local
        retag. RepoDigests identify the registry manifest and are preferred;
        Docker's immutable image ID is an acceptable local fallback when the
        mirror does not publish a repo digest. The digest must describe this
        exact allowlisted mirror repository, not merely any alias on the image.
        """
        try:
            inspected = run_managed_command(
                self.scan_id, ["docker", "image", "inspect", mirror_reference],
                cwd=self.code_root, env=self._compose_subprocess_env(), timeout=30,
                deadline=self._build_deadline, phase="image_mirror_inspect",
            )
        except FileNotFoundError as exc:
            raise RuntimeError("docker CLI 不可用，无法检查镜像摘要") from exc
        if inspected.returncode != 0:
            return None
        try:
            records = _json.loads(inspected.stdout or "")
            record = records[0] if isinstance(records, list) and records else None
        except (_json.JSONDecodeError, IndexError, TypeError):
            return None
        if not isinstance(record, dict):
            return None

        image_id = str(record.get("Id") or "")
        if not _IMMUTABLE_IMAGE_DIGEST.fullmatch(image_id):
            image_id = ""
        expected_repository = _image_reference_repository(mirror_reference)
        expected_prefix = f"{expected_repository}@" if expected_repository else ""
        mirror_digest_reference = ""
        mirror_digest = ""
        for candidate in record.get("RepoDigests") or []:
            candidate = str(candidate or "")
            if not candidate.startswith(expected_prefix):
                continue
            digest = candidate[len(expected_prefix):]
            if _IMMUTABLE_IMAGE_DIGEST.fullmatch(digest):
                mirror_digest_reference = candidate
                mirror_digest = digest
                break
        if not mirror_digest and not image_id:
            return None

        # Use the registry manifest digest whenever the mirror exposes one;
        # image IDs remain an immutable local selector for mirrors that omit it.
        resolved_reference = mirror_digest_reference or image_id
        return {
            "source": source,
            "mirror": mirror,
            "canonical": canonical,
            "digest": mirror_digest or image_id,
            "mirror_reference": resolved_reference,
            "image_id": image_id,
            "equivalence_verified": False,
        }

    def _prefetch_dockerfile_base_images(self, dockerfile: Path, *, source: str) -> None:
        """Prefetch all resolvable stages before a Docker build starts."""
        images = _dockerfile_base_images(dockerfile)
        if images:
            self.metadata["diagnostics"].append(
                f"{source} images discovered: {len(images)}"
            )
        for image in images:
            self._prefetch_image(image, source=source)

    def _prefetch_compose_images(self, project: str) -> None:
        """Prepare Compose images, and build bases when local builds are required."""
        # `image` and `build` may intentionally coexist: `image` names the result
        # of the local build. Pulling that name first turns valid projects such as
        # VAmPI into a false sandbox_start_failed when the tag is not published.
        locally_built = self._compose_locally_built_images(project)
        cmd = self._compose_command(project, "config", "--images")
        proc = run_managed_command(
            self.scan_id, cmd, cwd=self.code_root,
            env=self._compose_subprocess_env(), timeout=60,
            deadline=self._build_deadline, phase="compose_config",
        )
        if proc.returncode != 0:
            raise RuntimeError("无法解析 Compose 镜像清单：" + _diagnostic_tail(proc.stderr or proc.stdout))
        images = list(dict.fromkeys(
            line.strip() for line in (proc.stdout or "").splitlines() if line.strip()
        ))
        self.metadata["diagnostics"].append(f"compose images discovered: {len(images)}")

        needs_build = False
        for index, image in enumerate(images, start=1):
            is_build_service = image in locally_built
            if is_build_service and "/" not in image:
                needs_build = True
                self.metadata["diagnostics"].append(
                    f"compose image {index}/{len(images)} will be built locally: {image}"
                )
                continue
            try:
                self._prefetch_image(image, source=f"compose image {index}/{len(images)}")
            except (SandboxCommandTimeout, SandboxCommandCancelled):
                raise
            except RuntimeError as exc:
                if not is_build_service:
                    raise
                needs_build = True
                self.metadata["diagnostics"].append(
                    f"compose image {index}/{len(images)} 无法拉取，改本地构建: {image} "
                    f"（拉取失败原因: {_diagnostic_tail(str(exc), 200)}）"
                )
        self._compose_needs_build = needs_build
        if needs_build:
            self._prefetch_compose_build_base_images()

    def _prefetch_compose_build_base_images(self) -> None:
        """Find Dockerfiles used by Compose build services and prefetch their bases."""
        if not self._compose_file:
            return
        try:
            import yaml
            compose_path = Path(self._compose_file).resolve()
            data = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
            services = data.get("services") or {}
        except Exception as exc:  # noqa: BLE001
            self.metadata["diagnostics"].append(
                f"compose build base discovery skipped: {type(exc).__name__}"
            )
            return
        if not isinstance(services, dict):
            return

        images: list[str] = []
        for name, service in services.items():
            build = service.get("build") if isinstance(service, dict) else None
            if isinstance(build, str):
                context_value, dockerfile_value = build, "Dockerfile"
            elif isinstance(build, dict):
                context_value = build.get("context", ".")
                dockerfile_value = build.get("dockerfile") or "Dockerfile"
            else:
                continue
            if "$" in str(context_value) or "$" in str(dockerfile_value):
                self.metadata["diagnostics"].append(
                    f"compose build base discovery skipped unresolved path for service {name}"
                )
                continue
            dockerfile = (compose_path.parent / str(context_value) / str(dockerfile_value)).resolve()
            try:
                dockerfile.relative_to(self.code_root)
            except ValueError:
                self.metadata["diagnostics"].append(
                    f"compose build base discovery skipped unsafe path for service {name}"
                )
                continue
            images.extend(_dockerfile_base_images(dockerfile))

        images = list(dict.fromkeys(images))
        if images:
            self.metadata["diagnostics"].append(
                f"compose build base images discovered: {len(images)}"
            )
        for image in images:
            self._prefetch_image(image, source="compose build base")

    def _compose_locally_built_images(self, project: str) -> set[str]:
        """Return explicit image tags produced by services that declare ``build``.

        Failure to parse is deliberately non-fatal: Compose remains the source of
        truth and the existing prefetch path still handles genuinely pullable images.
        """
        try:
            import yaml
            compose_text = Path(self._compose_file).read_text(encoding="utf-8", errors="ignore")
            data = yaml.safe_load(compose_text) or {}
            services = data.get("services") or {}
            images: set[str] = set()
            for name, service in services.items():
                if not isinstance(service, dict) or service.get("build") is None:
                    continue
                explicit = str(service.get("image") or "").strip()
                if explicit:
                    images.add(explicit)
                else:
                    # Compose names an unnamed build image <project>-<service>.
                    # ``config --images`` returns that generated tag, which is still
                    # a local build output and must never be sent to docker pull.
                    images.add(f"{project}-{str(name).lower()}")
            # Keep a conservative text fallback as a second source. Test and
            # plugin environments can replace YAML loaders, while Compose's
            # common top-level service form remains unambiguous here.
            for match in re.finditer(
                r"(?ms)^  ([A-Za-z0-9_.-]+):\s*\n((?:    .*?(?:\n|$))*)",
                compose_text,
            ):
                name, body = match.group(1), match.group(2)
                if not re.search(r"(?m)^    build\s*:", body):
                    continue
                image_match = re.search(r"(?m)^    image\s*:\s*['\"]?([^\s'\"]+)", body)
                images.add(image_match.group(1) if image_match else f"{project}-{name.lower()}")
            return images
        except Exception as exc:  # noqa: BLE001
            self.metadata["diagnostics"].append(
                f"compose local-build image detection skipped: {type(exc).__name__}"
            )
            self.metadata["compose_ps"] = self._compose_ps()
            return set()

    def _compose_published_port(self, project: str, port_hint) -> int | None:
        """解析 `docker compose ps --format json`，返回一个对外发布的 TCP 端口。

        兼容两种输出：整体 JSON 数组，或每行一个 JSON 对象（不同 compose 版本）。
        优先匹配 port_hint（容器内目标端口），否则取第一个已发布端口。
        """
        try:
            cmd = self._compose_command(project, "ps", "--format", "json")
            proc = subprocess.run(
                cmd,
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
        except Exception:  # noqa: BLE001
            return None
        raw = (proc.stdout or "").strip()
        if not raw:
            return None
        services: list = []
        try:
            parsed = _json.loads(raw)
            services = parsed if isinstance(parsed, list) else [parsed]
        except Exception:  # noqa: BLE001
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    services.append(_json.loads(line))
                except Exception:  # noqa: BLE001
                    continue
        published: list[dict] = []
        for svc in services:
            for pub in (svc.get("Publishers") or []):
                pp = pub.get("PublishedPort")
                if pp and str(pub.get("Protocol", "tcp")) == "tcp":
                    published.append({
                        "service": str(svc.get("Service") or svc.get("Name") or "").lower(),
                        "target": int(pub.get("TargetPort") or 0),
                        "host": int(pp),
                    })
        if not published:
            return None
        if port_hint:
            for item in published:
                if item["target"] == int(port_hint) or item["host"] == int(port_hint):
                    self._compose_selected_target_port = item["target"]
                    return item["host"]

        # 多服务 Compose 不能取“第一个已发布端口”：它可能是 Postgres、Mailhog 或 MCP。
        # 优先选择名称像 Web/API/Gateway 的服务，再参考常见 HTTP 端口。
        web_words = ("web", "gateway", "frontend", "api", "nginx", "proxy")
        common_http = {80, 443, 3000, 5000, 8000, 8080, 8081, 8888}
        published.sort(key=lambda item: (
            0 if any(word in item["service"] for word in web_words) else 1,
            # 同一个 Web 服务同时映射 80/443 时，优先未加密 HTTP；否则不能把
            # httpx 的 http:// 请求误送到 TLS 端口（crAPI 的 8443 就是该反例）。
            0 if item["target"] == 80 else 1 if item["target"] in common_http else 2,
            item["host"],
        ))
        self.metadata["diagnostics"].append(
            "compose published ports: "
            + ", ".join(f"{item['service']}:{item['host']}->{item['target']}" for item in published[:12])
        )
        self._compose_selected_target_port = published[0]["target"]
        return published[0]["host"]

    def _prepare_isolated_compose(self, compose_file: str, port_hint) -> str:
        """生成一次性 Compose 配置，避免不可信项目配置占用全局 Docker 名称。

        原始 Compose 只读不修改。覆写版移除 ``container_name``、顶层网络的
        显式 ``name`` 与所有固定宿主端口；然后仅为最可能的 Web 服务创建一个
        随机宿主端口映射。这样既能保持服务间依赖，也不会碰用户已运行的靶场。
        """
        try:
            import yaml
            source = self.code_root / compose_file
            data = yaml.safe_load(source.read_text(encoding="utf-8", errors="ignore")) or {}
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"无法生成隔离 Compose 配置: {exc}") from exc

        services = data.get("services") or {}
        if not isinstance(services, dict) or not services:
            raise RuntimeError("Compose 未定义 services，无法生成隔离配置")

        web_service, target_port = _select_compose_web_service(services, port_hint)
        if not web_service or not target_port:
            raise RuntimeError("Compose 中无法识别可发布的 Web 服务端口")

        # A target Compose may intentionally ship secure and vulnerable variants
        # (VAmPI), or unrelated developer tools. Start only the selected HTTP service
        # and its declared dependency closure; this preserves required DB/queue
        # services while avoiding unrelated containers, image builds and state bleed.
        referenced_services = _compose_service_reference_closure(services, web_service)
        selected_services = _compose_dependency_closure(services, referenced_services)
        inferred_services = sorted(referenced_services - {web_service})
        if inferred_services:
            self.metadata["diagnostics"].append(
                "isolated compose retained service references: " + ", ".join(inferred_services)
            )
        # 通用规则（不针对任何具体项目）：多服务 Web 部署常把浏览器/API 流量经一个单独
        # 命名的网关/反向代理转发，而该网关未必写进 depends_on。当所选目标或任一服务看起来
        # 是 web/前端/网关/鉴权/身份类时，一并保留同族服务，避免漏起真正对外的入口。
        _WEB_FAMILY = ("gateway", "proxy", "nginx", "web", "frontend", "api", "identity", "auth")
        target_is_web = any(tok in web_service.lower() for tok in _WEB_FAMILY)
        has_gateway = any(
            any(tok in str(name).lower() for tok in ("gateway", "proxy", "nginx"))
            for name in services
        )
        if target_is_web or has_gateway:
            selected_services.update(
                name for name in services
                if any(tok in str(name).lower() for tok in _WEB_FAMILY)
            )
        if len(selected_services) < len(services):
            skipped = sorted(set(services) - selected_services)
            data["services"] = {name: services[name] for name in selected_services}
            services = data["services"]
            self.metadata["diagnostics"].append(
                "isolated compose omitted unrelated services: " + ", ".join(skipped)
            )

        # The selected web service is needed to decide whether a missing shared
        # env_file is the narrowly supported local MySQL/MariaDB dependency case.
        self._compose_web_service = web_service
        self._precheck_compose_environment_files(services, source.parent)
        self._stabilize_legacy_node_nodemon_build(services, web_service, source.parent)

        removed_names = 0
        removed_ports = 0
        for service in services.values():
            if not isinstance(service, dict):
                continue
            if service.pop("container_name", None) is not None:
                removed_names += 1
            if service.pop("ports", None) is not None:
                removed_ports += 1

        networks = data.get("networks") or {}
        if isinstance(networks, dict):
            for network in networks.values():
                if isinstance(network, dict) and network.pop("name", None) is not None:
                    self.metadata["diagnostics"].append("removed fixed Compose network name")

        services[web_service]["ports"] = [f"127.0.0.1::{target_port}"]
        self._harden_isolated_compose_services(services, web_service)
        suffix = re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:12] or "scan"
        generated_name = f"docker-compose.auditagentx.{suffix}.yml"
        # Keep the isolated file next to the source Compose file. Compose resolves
        # relative build contexts, env_file, configs and bind mounts relative to this
        # directory; relocating it to repository root breaks nested deployments.
        target = (self.code_root / compose_file).parent / generated_name
        target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        self._generated_compose_file_name = str(target.relative_to(self.code_root))
        self.metadata["diagnostics"].append(
            f"isolated compose generated: removed container_name={removed_names}, "
            f"fixed ports={removed_ports}, exposed {web_service}:*->{target_port}"
        )
        return str(target.relative_to(self.code_root))

    def _stabilize_legacy_node_nodemon_build(self, services: dict, web_service: str,
                                             compose_dir: Path) -> None:
        """Create a deterministic sandbox-only Dockerfile for a known legacy mismatch.

        Some historical Node 8 projects install ``nodemon`` globally without a
        version.  That command resolves today's nodemon dependency graph, which
        no longer parses on Node 8.  Preserve source evidence and the original
        Dockerfile untouched; only the generated isolated Compose file points at
        a per-scan derived Dockerfile with the last Node-8-compatible nodemon.
        """
        service = services.get(web_service)
        if not isinstance(service, dict):
            return
        build = service.get("build")
        if isinstance(build, str):
            context_value, dockerfile_value = build, "Dockerfile"
            build_config = {"context": context_value, "dockerfile": dockerfile_value}
        elif isinstance(build, dict):
            build_config = dict(build)
            context_value = build_config.get("context", ".")
            dockerfile_value = build_config.get("dockerfile") or "Dockerfile"
        else:
            return
        if "$" in str(context_value) or "$" in str(dockerfile_value):
            return
        context_dir = (compose_dir / str(context_value)).resolve()
        dockerfile = (context_dir / str(dockerfile_value)).resolve()
        try:
            context_dir.relative_to(self.code_root)
            dockerfile.relative_to(context_dir)
            source = dockerfile.read_text(encoding="utf-8", errors="ignore")
        except (OSError, ValueError):
            return

        legacy_node = re.search(
            r"(?mi)^\s*FROM\s+node:(?:carbon|8(?:[.\-][^\s]*)?)\b", source,
        )
        unpinned_nodemon = re.search(
            r"(?mi)(\bnpm\s+(?:install|i)\s+-g\s+)nodemon(?!@)(?=\s|$)", source,
        )
        if not legacy_node or not unpinned_nodemon:
            return

        patched = source[:unpinned_nodemon.start(1)] + unpinned_nodemon.group(1) + "nodemon@1.19.4" + source[unpinned_nodemon.end():]
        suffix = re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:12] or "scan"
        derived = dockerfile.with_name(f"{dockerfile.name}.auditagentx.{suffix}.compat")
        derived.write_text(patched, encoding="utf-8")
        self._generated_compat_dockerfiles.append(derived)
        build_config["context"] = str(context_value)
        build_config["dockerfile"] = derived.relative_to(context_dir).as_posix()
        service["build"] = build_config
        self.metadata["sandbox_compatibility_patches"].append({
            "kind": "legacy_node_unpinned_nodemon",
            "service": web_service,
            "source_dockerfile": dockerfile.relative_to(self.code_root).as_posix(),
            "replacement": "nodemon@1.19.4",
            "source_preserved": True,
        })
        self.metadata["diagnostics"].append(
            f"generated deterministic Node 8 nodemon compatibility Dockerfile for {web_service}"
        )

    def _harden_isolated_compose_services(self, services: dict, web_service: str) -> None:
        """Apply controls that do not prevent ordinary stateful dependencies from starting.

        Every selected service receives bounded memory, CPU and process resources.  The
        HTTP target additionally gets a read-only root filesystem, a small writable
        ``/tmp``, no Linux capabilities and no privilege escalation.  Databases and
        queues are intentionally not made read-only or capability-free: common
        NodeGoat-like stacks initialize data directories as their entrypoint user.
        """
        for name, service in services.items():
            if not isinstance(service, dict):
                continue
            service["mem_limit"] = "512m"
            service["pids_limit"] = 256
            service["cpus"] = 1.0
            if name != web_service:
                continue
            service["cap_drop"] = ["ALL"]
            service["security_opt"] = ["no-new-privileges:true"]
            service["read_only"] = True
            tmpfs = service.get("tmpfs")
            tmpfs_entries = [tmpfs] if isinstance(tmpfs, str) else list(tmpfs or [])
            safe_tmp = "/tmp:rw,noexec,nosuid,size=64m"
            if not any(str(entry).split(":", 1)[0] == "/tmp" for entry in tmpfs_entries):
                tmpfs_entries.append(safe_tmp)
            service["tmpfs"] = tmpfs_entries
        self.metadata["diagnostics"].append(
            "isolated compose hardened selected web service and applied resource limits"
        )

    def _precheck_compose_environment_files(self, services: dict, compose_dir: Path) -> None:
        """Fail closed for missing env files, except one deterministic local DB shape.

        We never copy a sample, parse a README, or consult an ambient host env file.
        The sole recovery is a selected web service whose dependency closure contains
        exactly one official ``mysql``/``mariadb`` image and shares the same missing
        relative env_file.  Its values are per-scan random test values in a temp dir.
        """
        entries_by_path: dict[str, list[tuple[str, object, bool]]] = {}
        optional_missing: list[str] = []
        for name, service in services.items():
            if not isinstance(service, dict) or "env_file" not in service:
                continue
            original = service.get("env_file")
            for entry in (original if isinstance(original, list) else [original]):
                raw_path = entry.get("path") if isinstance(entry, dict) else entry
                required = entry.get("required", True) is not False if isinstance(entry, dict) else True
                relative_name, source_path = self._safe_compose_env_path(raw_path, compose_dir)
                if source_path.is_file() or not required:
                    if not required and not source_path.is_file():
                        optional_missing.append(relative_name)
                    continue
                entries_by_path.setdefault(relative_name, []).append((str(name), entry, required))

        replacements: dict[str, str] = {}
        generated: list[dict] = []
        missing: list[str] = []
        for relative_name, refs in entries_by_path.items():
            db_name = self._safe_local_mysql_dependency(services, [name for name, _, _ in refs])
            if not db_name:
                missing.append(relative_name)
                continue
            artifact = self._write_isolated_mysql_env(relative_name, db_name)
            replacements[relative_name] = str(artifact)
            # Do not record generated values or filesystem paths in persisted metadata.
            generated.append({"kind": "isolated_local_mysql", "temporary_artifact_generated": True,
                              "services": sorted(name for name, _, _ in refs)})

        if missing:
            missing = sorted(set(missing))
            self.metadata["environment_precheck"] = {
                "status": "failed", "failure_code": "missing_env_file", "missing_env_files": missing,
            }
            raise _ComposeEnvironmentError(
                "missing_env_file", missing,
                "Compose 必需环境文件缺失；仅可为可证明的本地 MySQL/MariaDB 依赖生成隔离测试配置："
                + ", ".join(missing),
            )

        for service in services.values():
            if not isinstance(service, dict) or "env_file" not in service:
                continue
            original = service.get("env_file")
            rewritten = []
            for entry in (original if isinstance(original, list) else [original]):
                raw_path = entry.get("path") if isinstance(entry, dict) else entry
                relative_name, _ = self._safe_compose_env_path(raw_path, compose_dir)
                replacement = replacements.get(relative_name, str(raw_path))
                if isinstance(entry, dict):
                    updated = dict(entry)
                    updated["path"] = replacement
                    rewritten.append(updated)
                else:
                    rewritten.append(replacement)
            service["env_file"] = rewritten if isinstance(original, list) else rewritten[0]

        self.metadata["environment_precheck"] = {
            "status": "generated_isolated_local_db" if generated else "passed",
            "generated_files": generated,
            "optional_missing_env_files": sorted(set(optional_missing)),
        }

    def _safe_local_mysql_dependency(self, services: dict, referencing_services: list[str]) -> str | None:
        web = self._compose_web_service
        if not web or web not in services:
            return None
        closure = _compose_dependency_closure(services, web)
        databases = [
            name for name in closure
            if _is_official_mysql_family((services.get(name) or {}).get("image"))
        ]
        # More than one database or an env file that is not used by that exact DB
        # is ambiguous configuration; do not guess credentials or connection names.
        if len(databases) != 1 or databases[0] not in referencing_services:
            return None
        return databases[0]

    def _write_isolated_mysql_env(self, relative_name: str, db_service: str) -> Path:
        environment_dir = self._compose_environment_dir()
        token = secrets.token_urlsafe(18).replace("-", "a").replace("_", "b")
        filename = f"{len(list(environment_dir.iterdir()))}-{Path(relative_name).name}"
        artifact = environment_dir / filename
        artifact.write_text(
            f"MYSQL_USER=aax_{token[:12]}\n"
            f"MYSQL_DATABASE=aax_{token[12:24]}\n"
            f"MYSQL_PASSWORD={token}\n"
            "MYSQL_RANDOM_ROOT_PASSWORD=yes\n"
            f"MYSQL_HOST={db_service}\nMYSQL_PORT=3306\n",
            encoding="utf-8",
        )
        return artifact.resolve()

    def _safe_compose_env_path(self, value, compose_dir: Path) -> tuple[str, Path]:
        raw = str(value or "").strip()
        normalized = raw.replace("\\", "/")
        parts = normalized.split("/")
        if (not normalized or normalized.startswith(("/", "~"))
                or re.match(r"^[A-Za-z]:/", normalized)
                or ".." in parts or "$" in normalized):
            self.metadata["environment_precheck"] = {
                "status": "failed", "failure_code": "unsafe_env_file_path"
            }
            raise _ComposeEnvironmentError(
                "unsafe_env_file_path", [],
                "Compose env_file 路径不安全；拒绝绝对路径、路径穿越或动态路径",
            )
        candidate = (compose_dir / Path(*parts)).resolve()
        try:
            relative = candidate.relative_to(self.code_root).as_posix()
        except ValueError as exc:
            self.metadata["environment_precheck"] = {
                "status": "failed", "failure_code": "unsafe_env_file_path"
            }
            raise _ComposeEnvironmentError(
                "unsafe_env_file_path", [], "Compose env_file 路径位于 code_root 外，已拒绝"
            ) from exc
        return relative, candidate

    def _compose_logs(self) -> str:
        if not (self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                self._compose_command(self._compose_project, "logs", "--no-color", "--tail", "50"),
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
            compose_tail = _diagnostic_tail(proc.stdout or proc.stderr or "", 600)
            # A noisy DB can push the selected HTTP service out of a combined
            # Compose tail. Keep that service's startup output first so runtime
            # failures remain attributable after the sandbox is cleaned up.
            target_logs = self._service_logs(self._compose_web_service or "")
            target_tail = _diagnostic_tail(target_logs, 1200)
            if target_tail and target_tail != compose_tail:
                return target_tail + ("\n--- compose tail ---\n" + compose_tail if compose_tail else "")
            return compose_tail
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _wait_compose_healthy(base_url: str, timeout: int,
                              crash_probe=None, cancel_probe=None) -> tuple[bool, list[dict]]:
        """轮询直到就绪或超时；就绪判据复用 _wait_healthy（2xx–4xx 即服务已在处理 HTTP，
        且可被测试注入）。每隔几秒调 crash_probe 检查目标容器是否已崩溃退出，崩溃则立即
        停止等待（不干等满超时），由调用方带真实日志报 sandbox_start_failed。

        循环同时受**墙钟 deadline** 与**迭代次数上限**双重约束：前者保证生产环境不超时，
        后者保证测试把 time.sleep patch 成 no-op 时也能有限次退出，不忙等满超时。"""
        import httpx
        base = base_url.rstrip("/")
        attempts: list[dict] = []
        extra_paths = ("/health", "/actuator/health", "/identity/health_check")
        deadline = time.time() + timeout
        next_crash_check = 0.0
        for _ in range(int(timeout) + 5):
            if cancel_probe is not None and cancel_probe():
                raise SandboxCommandCancelled(
                    "scan cancellation requested", phase="health_check"
                )
            if time.time() >= deadline:
                break
            now = time.time()
            if crash_probe is not None and now >= next_crash_check:
                if crash_probe():
                    return False, attempts or [{"note": "target container exited during startup"}]
                next_crash_check = now + 4.0
            # 主路径：复用 _wait_healthy（根路径，短超时，可被测试注入其返回值）
            if _wait_healthy(base + "/", 3):
                return True, [{"url": base + "/", "status": "healthy"}]
            # 备用健康路径：根路径不可健康检查的项目（真实 HTTP，2xx–4xx 即就绪）
            round_attempts = []
            for path in extra_paths:
                url = base + path
                try:
                    resp = httpx.get(url, timeout=3, trust_env=False, follow_redirects=False)
                    round_attempts.append({"url": url, "status": resp.status_code})
                    if 200 <= resp.status_code < 500:
                        return True, round_attempts
                except httpx.HTTPError as exc:
                    round_attempts.append({"url": url, "error": type(exc).__name__})
            attempts = round_attempts or attempts
            time.sleep(1)
        return False, attempts

    def _compose_target_crash_reason(self) -> "str | None":
        """目标 Web 服务容器是否已异常退出。是则返回含真实启动错误的原因，否则 None。

        用 `compose ps --format json` 读各服务状态：目标服务（或任一构建型服务）处于
        exited 且退出码非 0，说明应用启动即崩溃（如上游依赖未锁版本导致 import 失败）——
        应立刻带真实 traceback 报 sandbox_start_failed，而不是干等满健康超时。
        """
        if not (self._compose_project and self._compose_file):
            return None
        try:
            proc = subprocess.run(
                self._compose_command(self._compose_project, "ps", "--all", "--format", "json"),
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20,
                env=self._compose_subprocess_env())
        except Exception:  # noqa: BLE001
            return None
        out = (proc.stdout or "").strip()
        if not out:
            return None
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(_json.loads(line))
            except Exception:  # noqa: BLE001  某些版本输出单个 JSON 数组
                try:
                    rows.extend(_json.loads(line))
                except Exception:  # noqa: BLE001
                    pass
        target = (self._compose_web_service or "").lower()
        for row in rows:
            if not isinstance(row, dict):
                continue
            svc = str(row.get("Service") or row.get("Name") or "").lower()
            state = str(row.get("State") or "").lower()
            exit_code = row.get("ExitCode")
            is_target = (target and target in svc) or True  # 任一服务崩溃都值得暴露
            if is_target and state == "exited" and exit_code not in (0, None):
                svc_logs = self._service_logs(row.get("Service") or row.get("Name") or "")
                tail = _diagnostic_tail(svc_logs) or (svc_logs[-400:] if svc_logs else "")
                return (f"目标容器 {svc or '?'} 启动即退出(exit={exit_code})——应用自身崩溃"
                        f"（常见：上游依赖未锁版本/缺环境变量/迁移失败）。真实错误：{tail}")
        return None

    def _service_logs(self, service: str) -> str:
        if not (service and self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                self._compose_command(
                    self._compose_project, "logs", "--no-color", "--tail", "40", str(service)
                ),
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20,
                env=self._compose_subprocess_env())
            return (proc.stdout or proc.stderr or "")[-2000:]
        except Exception:  # noqa: BLE001
            return ""

    def _compose_ps(self) -> str:
        if not (self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                self._compose_command(self._compose_project, "ps", "--all"),
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
            return (proc.stdout or proc.stderr or "")[-1200:]
        except Exception:  # noqa: BLE001
            return ""

    def _compose_inventory(self) -> list[dict]:
        """Capture stable container identity before teardown for audit evidence."""
        if not (self._compose_project and self._compose_file):
            return []
        try:
            proc = subprocess.run(
                self._compose_command(self._compose_project, "ps", "--all", "--format", "json"),
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
            raw = (proc.stdout or "").strip()
            if not raw:
                return []
            try:
                parsed = _json.loads(raw)
                rows = parsed if isinstance(parsed, list) else [parsed]
            except Exception:  # noqa: BLE001
                rows = []
                for line in raw.splitlines():
                    try:
                        rows.append(_json.loads(line))
                    except Exception:  # noqa: BLE001
                        continue
            return [{
                "id": row.get("ID") or row.get("Id"),
                "name": row.get("Name"),
                "service": row.get("Service"),
                "image": row.get("Image"),
                "state": row.get("State"),
                "exit_code": row.get("ExitCode"),
            } for row in rows if isinstance(row, dict)]
        except Exception as exc:  # noqa: BLE001
            self.metadata["diagnostics"].append(
                f"compose inventory capture failed: {type(exc).__name__}"
            )
            return []

    def _cleanup(self) -> None:
        with self._cleanup_lock:
            if self._cleanup_done:
                return
            self._cleanup_done = True
            self.metadata["cleanup_attempted"] = True
            cleanup_ok = True
            if self._container is not None:
                try:
                    self._container.remove(force=True)
                except Exception as e:  # noqa: BLE001
                    cleanup_ok = False
                    logger.warning("清理容器失败: %s", e)
            if self._compose_project and self._compose_file:
                try:
                    proc = subprocess.run(
                        self._compose_command(self._compose_project, "down", "-v"),
                        cwd=str(self.code_root), capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=30,
                        env=self._compose_subprocess_env())
                    if proc.returncode != 0:
                        cleanup_ok = False
                        self.metadata["diagnostics"].append(
                            "compose cleanup failed: " + _diagnostic_tail(proc.stderr or proc.stdout, 240)
                        )
                except Exception as e:  # noqa: BLE001
                    cleanup_ok = False
                    logger.warning("清理 compose 项目失败: %s", e)
            tmp = self.code_root / self._generated_dockerfile_name if self._generated_dockerfile_name else None
            if tmp and tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
            generated_compose = (self.code_root / self._generated_compose_file_name
                                 if self._generated_compose_file_name else None)
            if generated_compose and generated_compose.exists():
                try:
                    generated_compose.unlink()
                except OSError:
                    pass
            for compat_dockerfile in self._generated_compat_dockerfiles:
                try:
                    compat_dockerfile.unlink(missing_ok=True)
                except OSError:
                    cleanup_ok = False
            self._generated_compat_dockerfiles = []
            if self._compose_environment_temp_dir is not None:
                try:
                    shutil.rmtree(self._compose_environment_temp_dir)
                except OSError:
                    cleanup_ok = False
                self._compose_environment_temp_dir = None
                self._compose_cli_env_file = None
            self.metadata["cleanup_succeeded"] = cleanup_ok

    def _register_cancel_cleanup(self) -> None:
        if self._cleanup_token is None and not self._cleanup_done:
            self._cleanup_token = register_cleanup_callback(self.scan_id, self._cleanup)

    def _next_generated_dockerfile_name(self) -> str:
        stem = "Dockerfile.auditagentx"
        suffix = re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:12] or "scan"
        candidate = f"{stem}.{suffix}"
        index = 1
        while (self.code_root / candidate).exists():
            index += 1
            candidate = f"{stem}.{suffix}.{index}"
        return candidate


class _DependencyError(Exception):
    """依赖安装失败的内部异常。"""


class _ComposeEnvironmentError(Exception):
    """Structured Compose env_file preflight failure raised before Docker is touched."""

    def __init__(self, failure_code: str, missing_env_files: list[str], reason: str) -> None:
        super().__init__(reason)
        self.failure_code = failure_code
        self.missing_env_files = missing_env_files


def _select_compose_web_service(services: dict, port_hint) -> tuple[str | None, int | None]:
    """从原始 Compose 中选择一个适合动态 HTTP 验证的服务与容器端口。

    不信任原有的宿主发布端口：它可能已被另一个靶场占用。仅读取容器目标端口，
    并偏好名字像 Web/API 的服务和 80/8080 等 HTTP 端口。
    """
    web_words = ("web", "gateway", "frontend", "api", "nginx", "proxy")
    common_http = (80, 8080, 8000, 8001, 5000, 3000)
    candidates: list[tuple[tuple, str, int]] = []
    fallback_candidates: list[tuple[tuple, str, int]] = []
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        ports = service.get("ports") or []
        targets: list[tuple[int, int]] = []
        for port in ports:
            target = _compose_port_target(port)
            if target:
                # A published port is an explicit host-facing entrypoint. It is
                # stronger evidence than an internal ``expose`` declaration.
                targets.append((target, 0))
        # 无 ports 但明确 expose 的项目也可作为单一 HTTP 服务。
        for port in service.get("expose") or []:
            try:
                targets.append((int(str(port).split("/")[0]), 1))
            except (TypeError, ValueError):
                pass
        for target, internal_only in dict.fromkeys(targets):
            score = (
                0 if any(word in str(name).lower() for word in web_words) else 1,
                internal_only,
                _vulnerable_service_priority(name, service),
                0 if port_hint and target == int(port_hint) else 1,
                0 if target in common_http else 1,
                common_http.index(target) if target in common_http else target,
                str(name),
            )
            candidates.append((score, str(name), target))
        # 有些 Compose 只依赖 Dockerfile EXPOSE 或服务默认端口，不写 ports。
        # 隔离覆写正是要补一个随机宿主端口，因此对明显的 Web 服务可以采用启动
        # 计划的端口；没有计划时用 HTTP 的保守默认 80。
        if not targets and any(word in str(name).lower() for word in web_words):
            target = int(port_hint) if port_hint else 80
            fallback_candidates.append(((0, 0, 0 if target in common_http else 1,
                                         common_http.index(target) if target in common_http else target,
                                         str(name)), str(name), target))
    if not candidates:
        candidates = fallback_candidates
    if not candidates:
        return None, None
    candidates.sort(key=lambda item: item[0])
    _, name, target = candidates[0]
    return name, target


def _vulnerable_service_priority(name: str, service: dict) -> int:
    """Prefer an explicitly vulnerable target when an educational Compose ships both modes.

    VAmPI intentionally publishes secure and vulnerable instances on the same container
    port. Choosing the lexical first service silently turns an authorized vulnerability
    verification campaign into a scan of the secure variant.
    """
    if "vulnerable" in str(name).lower():
        return 0
    values = service.get("environment") or []
    if isinstance(values, dict):
        values = [f"{key}={value}" for key, value in values.items()]
    return 0 if any(str(item).replace(" ", "").lower() in {"vulnerable=1", "vuln=1"}
                    for item in values) else 1


def _compose_service_reference_closure(services: dict, root: str) -> set[str]:
    """Return services named by explicit runtime URLs in selected Compose services.

    This intentionally inspects only parsed ``environment`` values and ``command`` entries.
    It accepts exact current service keys only when they appear as URI hosts or ``host:port``;
    unresolved shell/Compose variables are ignored rather than guessed.
    """
    selected: set[str] = set()
    pending = [root]
    while pending:
        name = pending.pop()
        if name in selected or name not in services:
            continue
        selected.add(name)
        definition = services.get(name) or {}
        if not isinstance(definition, dict):
            continue
        pending.extend(_compose_service_references(definition, services))
    return selected


def _compose_service_references(definition: dict, services: dict) -> set[str]:
    """Find exact Compose service-name hosts in supported runtime configuration fields."""
    references: set[str] = set()
    for value in _compose_runtime_config_values(definition):
        # ``$MONGODB_URI`` and `${MONGODB_URI}` are not resolved configuration. Do
        # not infer a target from a shell expression or substitute host environment.
        if "$" in value:
            continue
        for name in services:
            service_name = str(name)
            escaped = re.escape(service_name)
            host = rf"(?<![A-Za-z0-9_.-]){escaped}(?=[:/?#\s'\"]|$)"
            uri = rf"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/@\s]+@)?{host}"
            host_port = rf"(?<![A-Za-z0-9_.-]){escaped}:\d{{1,5}}(?=[/?#\s'\"]|$)"
            if re.search(uri, value) or re.search(host_port, value):
                references.add(service_name)
    return references


def _compose_runtime_config_values(definition: dict) -> list[str]:
    """Return strings from Compose runtime fields, never Dockerfiles or arbitrary text."""
    values: list[str] = []
    environment = definition.get("environment")
    if isinstance(environment, dict):
        values.extend(str(value) for value in environment.values() if value is not None)
    elif isinstance(environment, list):
        for entry in environment:
            if isinstance(entry, str) and "=" in entry:
                values.append(entry.split("=", 1)[1])

    command = definition.get("command")
    if isinstance(command, str):
        values.append(command)
    elif isinstance(command, list):
        values.extend(item for item in command if isinstance(item, str))
    return values


def _compose_dependency_closure(services: dict, roots: str | set[str]) -> set[str]:
    """Return roots plus declared depends_on services, without following arbitrary links."""
    selected: set[str] = set()
    pending = [roots] if isinstance(roots, str) else list(roots)
    while pending:
        name = pending.pop()
        if name in selected or name not in services:
            continue
        selected.add(name)
        definition = services.get(name) or {}
        dependencies = definition.get("depends_on") if isinstance(definition, dict) else []
        if isinstance(dependencies, dict):
            pending.extend(str(item) for item in dependencies)
        elif isinstance(dependencies, list):
            pending.extend(str(item) for item in dependencies)
    return selected


def _is_official_mysql_family(image: object) -> bool:
    """Accept official Docker Hub MySQL/MariaDB names, including tags/digests.

    A repository such as ``registry.example/mysql`` is not equivalent to Docker
    Hub's official image.  Keep this recovery path conservative because it
    creates credentials and changes a missing-env failure into a runnable app.
    """
    raw = str(image or "").strip().lower().split("@", 1)[0]
    if not raw:
        return False
    parts = raw.split("/")
    leaf = parts[-1].split(":", 1)[0]
    if leaf not in {"mysql", "mariadb"}:
        return False
    namespaces = tuple(parts[:-1])
    return namespaces in {
        (),
        ("library",),
        ("docker.io",),
        ("docker.io", "library"),
        ("index.docker.io", "library"),
        ("registry-1.docker.io", "library"),
    }


def _compose_port_target(value) -> int | None:
    """解析 Compose 短/长端口语法的容器目标端口。"""
    if isinstance(value, dict):
        try:
            return int(value.get("target"))
        except (TypeError, ValueError):
            return None
    raw = str(value or "").strip()
    if not raw:
        return None
    raw = raw.rsplit("/", 1)[0]
    try:
        return int(raw.rsplit(":", 1)[-1])
    except ValueError:
        return None


def _scheme_for_port(target_port: int | None, launch_plan: dict | None = None) -> str:
    configured = str((launch_plan or {}).get("scheme") or "").lower()
    if configured in {"http", "https"}:
        return configured
    return "https" if int(target_port or 0) in {443, 8443, 9443} else "http"


@contextmanager
def docker_project_sandbox(code_root: Path, launch_plan: dict | None = None,
                           *, env: dict | None = None, scan_id: str | None = None,
                           trust_project_container_config: bool = False):
    """便捷上下文管理器，yield DockerProjectRunner 实例。"""
    runner = DockerProjectRunner(
        code_root, launch_plan, env=env, scan_id=scan_id,
        trust_project_container_config=trust_project_container_config,
    )
    with runner:
        yield runner


_SAFE_DYNAMIC_BIND_DEFAULT_RE = re.compile(
    r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(:-|-)([^${}]+)\}$"
)


def _compose_short_volume_source(value) -> str:
    """Extract a short-syntax volume source without splitting ``:-`` in ${...}."""
    raw = str(value or "").strip()
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        return raw  # absolute Windows paths are rejected by the normal policy
    depth = 0
    for index, char in enumerate(raw):
        if char == "{" and index and raw[index - 1] == "$":
            depth += 1
        elif char == "}" and depth:
            depth -= 1
        elif char == ":" and depth == 0:
            return raw[:index]
    return raw


def _validate_compose_policy(path: Path, *, code_root: Path | None = None,
                             env: dict | None = None) -> dict:
    """Reject Compose capabilities and host paths that escape the project root."""
    root = Path(code_root or path.parent).resolve()
    compose_path = Path(path).resolve()
    try:
        compose_path.relative_to(root)
    except ValueError:
        return {
            "allowed": False,
            "reason": "compose file is outside code_root",
            "checks": ["compose file is outside code_root"],
        }
    try:
        import yaml
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception as exc:  # noqa: BLE001
        return {"allowed": False, "reason": f"无法安全解析 Compose: {exc}", "checks": []}

    services = data.get("services") or {}
    if not isinstance(services, dict) or not services:
        return {"allowed": False, "reason": "Compose 未定义 services", "checks": []}

    blocked: list[str] = []
    compose_dir = compose_path.parent
    explicit_env = env or {}

    def validate_host_path(value, label: str, *, base: Path = compose_dir,
                           named_volume_allowed: bool = False) -> Path | None:
        raw = str(value or "").strip()
        if not raw:
            blocked.append(f"{label}: empty or unresolved host path")
            return None
        normalized = raw.replace("\\", "/")
        if named_volume_allowed and "$" not in raw and _is_compose_named_volume(raw):
            return None
        if "$" in raw:
            match = _SAFE_DYNAMIC_BIND_DEFAULT_RE.fullmatch(raw)
            if not match:
                blocked.append(f"{label}: dynamic host path is not allowed")
                return None
            name, operator, default = match.groups()
            # Exact full-match plus this guard excludes mixed text, multiple
            # variables, :? forms and nested substitutions without reading .env.
            if not default or "${" in default:
                blocked.append(f"{label}: dynamic host path default is unsafe")
                return None
            provided = explicit_env.get(name)
            effective = default if provided is None or (operator == ":-" and provided == "") else str(provided)
            raw = effective
            normalized = raw.replace("\\", "/")
        if ("{{" in raw or "}}" in raw or raw.startswith("~") or "$" in raw):
            blocked.append(f"{label}: dynamic host path is not allowed")
            return None
        if (normalized.startswith("/") or raw.startswith("\\")
                or re.match(r"^[A-Za-z]:", raw)):
            blocked.append(f"{label}: absolute host path is not allowed")
            return None
        if ".." in normalized.split("/") or ":" in normalized:
            blocked.append(f"{label}: host path escapes code_root")
            return None
        candidate = (base / Path(*normalized.split("/"))).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            blocked.append(f"{label}: host path escapes code_root")
            return None
        return candidate

    dangerous_keys = {
        "privileged", "devices", "device_cgroup_rules", "gpus", "cap_add",
        "pid", "ipc", "uts", "userns", "userns_mode",
    }
    for name, service in services.items():
        if not isinstance(service, dict):
            blocked.append(f"service {name}: invalid definition")
            continue
        for key in dangerous_keys:
            value = service.get(key)
            if value not in (None, False, [], ""):
                blocked.append(f"service {name}: forbidden {key}")
        network_mode = str(service.get("network_mode") or "").strip().lower()
        if network_mode not in {"", "default", "none"}:
            blocked.append(f"service {name}: forbidden network_mode={network_mode}")
        security_options = service.get("security_opt")
        if security_options not in (None, False, [], ""):
            values = [security_options] if isinstance(security_options, str) else security_options
            if not isinstance(values, list) or any(
                str(value).strip().lower() not in {
                    "no-new-privileges", "no-new-privileges:true",
                }
                for value in values
            ):
                blocked.append(f"service {name}: forbidden security_opt")
        service_volumes = service.get("volumes") or []
        if not isinstance(service_volumes, list):
            blocked.append(f"service {name}: invalid volumes definition")
            service_volumes = []
        for volume in service_volumes:
            if isinstance(volume, dict):
                source = volume.get("source") or ""
                volume_type = str(volume.get("type") or "").lower()
                if volume_type not in {"bind", "volume"}:
                    blocked.append(f"service {name} volume: unsupported mount type")
                    continue
                named_allowed = volume_type == "volume" and _is_compose_named_volume(str(source))
                if volume_type == "volume" and not named_allowed:
                    blocked.append(f"service {name} volume: unsafe named volume source")
                    continue
                if volume_type == "bind":
                    bind_options = volume.get("bind") or {}
                    if not isinstance(bind_options, dict):
                        blocked.append(f"service {name} volume: invalid bind options")
                        continue
                    propagation = str(bind_options.get("propagation") or "").lower()
                    if propagation not in {"", "private", "rprivate"}:
                        blocked.append(f"service {name} volume: mount propagation is forbidden")
            else:
                raw = str(volume or "")
                source = _compose_short_volume_source(raw)
                if source == raw and raw.startswith("/"):
                    # A target-only short mount (for example ``/app/node_modules``)
                    # is an anonymous volume, not a host bind.
                    continue
                named_allowed = _is_compose_named_volume(source)
            if "docker.sock" in str(source).lower():
                blocked.append(f"service {name} volume: docker.sock is forbidden")
            else:
                validate_host_path(
                    source, f"service {name} host volume", named_volume_allowed=named_allowed,
                )

        build = service.get("build")
        if build is not None:
            if isinstance(build, str):
                context_value = build
                dockerfile_value = None
            elif isinstance(build, dict):
                context_value = build.get("context", ".")
                dockerfile_value = build.get("dockerfile")
            else:
                blocked.append(f"service {name} build: invalid definition")
                context_value = None
                dockerfile_value = None
            context_path = None
            if context_value is not None:
                context_path = validate_host_path(context_value, f"service {name} build.context")
            if dockerfile_value is not None:
                validate_host_path(
                    dockerfile_value, f"service {name} build.dockerfile",
                    base=context_path or compose_dir,
                )

        env_files = service.get("env_file")
        if env_files is not None:
            for entry in env_files if isinstance(env_files, list) else [env_files]:
                value = entry.get("path") if isinstance(entry, dict) else entry
                validate_host_path(value, f"service {name} env_file")

    networks = data.get("networks") or {}
    if not isinstance(networks, dict):
        blocked.append("networks: invalid definition")
        networks = {}
    for network_name, definition in networks.items():
        if definition is None:
            continue
        if not isinstance(definition, dict):
            blocked.append(f"network {network_name}: invalid definition")
            continue
        if definition.get("external") not in (None, False):
            blocked.append(f"external network attachment is forbidden: {network_name}")
        if definition.get("name") not in (None, ""):
            blocked.append(f"named network attachment is forbidden: {network_name}")
        driver = str(definition.get("driver") or "").lower()
        if driver and driver != "bridge":
            blocked.append(f"network {network_name}: non-bridge driver is forbidden")
        if definition.get("driver_opts") not in (None, {}, []):
            blocked.append(f"network {network_name}: driver_opts are forbidden")

    defined_networks = set(networks) | {"default"}
    for service_name, service in services.items():
        if not isinstance(service, dict) or "networks" not in service:
            continue
        attachments = service.get("networks")
        if isinstance(attachments, dict):
            attachment_names = attachments.keys()
        elif isinstance(attachments, list):
            attachment_names = attachments
        else:
            blocked.append(f"service {service_name}: invalid networks attachment")
            continue
        for network_name in attachment_names:
            if str(network_name) not in defined_networks:
                blocked.append(f"service {service_name}: unknown network attachment {network_name}")

    volumes = data.get("volumes") or {}
    if not isinstance(volumes, dict):
        blocked.append("volumes: invalid definition")
    else:
        for volume_name, definition in volumes.items():
            if definition is None:
                continue
            if not isinstance(definition, dict):
                blocked.append(f"volume {volume_name}: invalid definition")
                continue
            if definition.get("external") not in (None, False):
                blocked.append(f"external volume is forbidden: {volume_name}")
            if definition.get("name") not in (None, ""):
                blocked.append(f"named volume is forbidden: {volume_name}")
            if definition.get("driver_opts") not in (None, {}, []):
                blocked.append(f"volume {volume_name}: driver_opts are forbidden")

    for section in ("configs", "secrets"):
        definitions = data.get(section) or {}
        if not isinstance(definitions, dict):
            blocked.append(f"{section}: invalid definition")
            continue
        for name, definition in definitions.items():
            if isinstance(definition, dict) and "file" in definition:
                validate_host_path(definition.get("file"), f"{section}.{name}.file")
    return {
        "allowed": not blocked,
        "reason": "; ".join(blocked) if blocked else "",
        "checks": blocked or ["compose policy passed"],
    }


def _is_compose_named_volume(value: str) -> bool:
    raw = str(value or "").strip()
    return bool(raw and "/" not in raw and "\\" not in raw and not raw.startswith("."))


def _validate_generated_launch_plan(plan: dict) -> dict:
    """只允许已知的依赖安装器和 Web 服务启动命令进入 Docker build/CMD。"""
    from backend.dynamic.launch_detector import README_INSTALL_PATTERNS, README_RUN_PATTERNS

    install = str(plan.get("install_command") or "").strip()
    run = str(plan.get("run_command") or plan.get("command") or "").strip()
    workdir = _safe_workdir(plan.get("working_dir"))
    checks: list[str] = []
    normalized_run = run.replace("{port}", str(plan.get("port") or 8000))
    if install and not any(pattern.fullmatch(install) for pattern in README_INSTALL_PATTERNS):
        checks.append(f"unapproved install_command: {install[:160]}")
    if normalized_run and not any(pattern.fullmatch(normalized_run) for pattern in README_RUN_PATTERNS):
        checks.append(f"unapproved run_command: {run[:160]}")
    raw_workdir = str(plan.get("working_dir") or ".")
    if ".." in raw_workdir.replace("\\", "/").split("/"):
        checks.append(f"unsafe working_dir: {raw_workdir[:160]}")
    elif raw_workdir not in {"", "."} and not workdir:
        checks.append(f"invalid working_dir: {raw_workdir[:160]}")
    return {
        "allowed": not checks,
        "reason": "; ".join(checks),
        "checks": checks or ["generated launch command policy passed"],
    }
