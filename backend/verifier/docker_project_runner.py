"""DockerProjectRunner —— Docker-first Deep Mode 沙箱：在容器内启动 GitHub 项目。

流程：code_root + launch_plan → 生成/复用 Dockerfile → build → run → 健康检查 → base_url。
退出时自动 docker rm -f 清理容器，并采集 docker logs 摘要。

安全边界：仅用于本地 Docker 沙箱 / 授权目标；容器限内存，扫描后即销毁。
失败时如实返回状态（sandbox_start_failed / health_check_failed / dependency_install_failed），
绝不造假复现结果。

复用：端口分配 / 健康检查复用 app_runner 的 _free_port / _wait_healthy，不重复实现。
"""
from __future__ import annotations

import logging
import re
from contextlib import contextmanager
from pathlib import Path

from backend.verifier.app_runner import _free_port, _wait_healthy

logger = logging.getLogger(__name__)

# 沙箱状态
STARTED = "started"
SANDBOX_START_FAILED = "sandbox_start_failed"
HEALTH_CHECK_FAILED = "health_check_failed"
DEPENDENCY_INSTALL_FAILED = "dependency_install_failed"


def build_dockerfile(launch_plan: dict, port: int) -> str:
    """SandboxBuilder：按 launch_plan 生成最小 Dockerfile（无项目 Dockerfile 时）。"""
    framework = (launch_plan.get("framework") or "").lower()
    install = launch_plan.get("install_command")
    run = launch_plan.get("run_command") or launch_plan.get("command") or ""
    run = run.replace("{port}", str(port))

    if "node" in framework or "express" in framework:
        install = install or "npm install"
        return (
            "FROM node:20-slim\n"
            "WORKDIR /app\n"
            "COPY package*.json ./\n"
            f"RUN {install}\n"
            "COPY . .\n"
            f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "php" in framework:
        return (
            "FROM php:8.2-cli\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "spring" in framework or "java" in framework:
        return (
            "FROM eclipse-temurin:17-jdk\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    # 默认 Python
    install = install or "pip install --no-cache-dir -r requirements.txt"
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        f"RUN {install} || pip install --no-cache-dir flask fastapi uvicorn\n"
        f"EXPOSE {port}\n"
        f"CMD {_cmd_json(run)}\n"
    )


def _cmd_json(run_command: str) -> str:
    """把 run_command 转成 Dockerfile CMD 的 JSON 数组形式。"""
    parts = run_command.split()
    return "[" + ", ".join(f'"{p}"' for p in parts) + "]"


class DockerProjectRunner:
    """上下文管理器：进入返回 self（含 base_url / metadata），退出清理容器。"""

    def __init__(self, code_root: Path, launch_plan: dict | None = None,
                 *, env: dict | None = None, scan_id: str | None = None,
                 build_timeout: int = 600, health_timeout: int = 40) -> None:
        self.code_root = Path(code_root)
        self.launch_plan = launch_plan or {}
        self.env = env or {}
        self.scan_id = scan_id or "adhoc"
        self.build_timeout = build_timeout
        self.health_timeout = health_timeout

        self.base_url: str | None = None
        self.metadata: dict = {
            "mode": "docker_project",
            "image": f"auditagentx-{re.sub(r'[^a-z0-9]', '', self.scan_id.lower())[:20] or 'scan'}",
            "container_id": None,
            "base_url": None,
            "port": self.launch_plan.get("port") or 8000,
            "health_path": self.launch_plan.get("health_path") or "/",
            "health_check": "failed",
            "launch_command": (self.launch_plan.get("run_command")
                               or self.launch_plan.get("command")),
            "logs_excerpt": "",
            "status": SANDBOX_START_FAILED,
        }
        self._client = None
        self._container = None

    def __enter__(self) -> "DockerProjectRunner":
        try:
            self._start()
        except _DependencyError as e:
            self.metadata["status"] = DEPENDENCY_INSTALL_FAILED
            self.metadata["logs_excerpt"] = str(e)[:800]
            logger.warning("沙箱依赖安装失败: %s", e)
        except Exception as e:  # noqa: BLE001
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["logs_excerpt"] = str(e)[:800]
            logger.warning("沙箱启动失败: %s", e)
        return self

    def __exit__(self, *exc) -> None:
        self._cleanup()

    # ---------- 内部 ----------
    def _start(self) -> None:
        import docker  # 未安装 docker SDK 时抛 ImportError -> sandbox_start_failed

        from backend.config import settings
        self._client = docker.DockerClient(base_url=settings.docker_host)

        internal_port = int(self.metadata["port"])
        host_port = _free_port()
        base_url = f"http://127.0.0.1:{host_port}"
        image_tag = self.metadata["image"]

        # 1) 构建镜像：优先项目 Dockerfile，否则生成临时 Dockerfile
        has_dockerfile = (self.code_root / "Dockerfile").exists()
        if not has_dockerfile:
            dockerfile = build_dockerfile(self.launch_plan, internal_port)
            (self.code_root / "Dockerfile.auditagentx").write_text(dockerfile, encoding="utf-8")
            dockerfile_name = "Dockerfile.auditagentx"
        else:
            dockerfile_name = "Dockerfile"

        try:
            self._client.images.build(
                path=str(self.code_root), dockerfile=dockerfile_name,
                tag=image_tag, rm=True, forcerm=True,
            )
        except Exception as e:  # noqa: BLE001
            msg = str(e).lower()
            if any(k in msg for k in ("pip install", "npm install", "composer",
                                      "could not find", "no matching distribution")):
                raise _DependencyError(str(e)) from e
            raise

        # 2) 启动容器
        self._container = self._client.containers.run(
            image=image_tag, detach=True, remove=False,
            ports={f"{internal_port}/tcp": host_port},
            environment=self.env, mem_limit="512m",
        )
        self.metadata["container_id"] = self._container.id[:12]

        # 3) 健康检查
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        if _wait_healthy(health_url, self.health_timeout):
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "health_check": "passed", "status": STARTED,
            })
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
        self.metadata["logs_excerpt"] = self._logs()

    def _logs(self) -> str:
        if not self._container:
            return ""
        try:
            return self._container.logs().decode("utf-8", errors="ignore")[-1500:]
        except Exception:  # noqa: BLE001
            return ""

    def _cleanup(self) -> None:
        if self._container is not None:
            try:
                self._container.remove(force=True)
            except Exception as e:  # noqa: BLE001
                logger.warning("清理容器失败: %s", e)
        # 清理临时 Dockerfile
        tmp = self.code_root / "Dockerfile.auditagentx"
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


class _DependencyError(Exception):
    """依赖安装失败的内部异常。"""


@contextmanager
def docker_project_sandbox(code_root: Path, launch_plan: dict | None = None,
                           *, env: dict | None = None, scan_id: str | None = None):
    """便捷上下文管理器，yield DockerProjectRunner 实例。"""
    runner = DockerProjectRunner(code_root, launch_plan, env=env, scan_id=scan_id)
    with runner:
        yield runner
