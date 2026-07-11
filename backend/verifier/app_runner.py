"""靶场应用启动器：为动态验证提供一个正在运行的目标 base_url。

两种 provider：
- LocalAppRunner：在本机子进程启动靶场（仅限隔离实验环境 / 虚拟机，含风险，默认需显式开启）
- DockerAppRunner：在 Docker 容器内启动靶场并映射端口（推荐，隔离更强）

均实现为上下文管理器：进入返回 base_url，退出自动清理。
"""
from __future__ import annotations

import logging
import socket
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)


class DockerTargetStartError(RuntimeError):
    """Docker 目标未进入可探测状态；metadata 可安全进入动态证据链。"""

    def __init__(self, metadata: dict) -> None:
        self.metadata = metadata
        super().__init__(str(metadata.get("reason") or "Docker target failed to start"))


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get_docker_client():
    """返回 docker 客户端，自动适配平台。

    - docker_host 显式配置 -> 直接用。
    - 否则 Windows 用 named pipe，其余交给 from_env（读 DOCKER_HOST / unix socket）。
    """
    import os
    import sys
    import docker

    from backend.config import settings
    host = (settings.docker_host or "").strip()
    # Windows 上忽略 unix:// 配置（无效），改用 named pipe
    if sys.platform == "win32" and host.startswith("unix://"):
        host = ""
    if not host and sys.platform == "win32" and not os.environ.get("DOCKER_HOST"):
        host = "npipe:////./pipe/docker_engine"
    if host:
        return docker.DockerClient(base_url=host)
    return docker.from_env()


def _wait_healthy(base_url: str, timeout: int = 20, *, extra_paths=None) -> bool:
    """就绪探测：只要 Web 服务开始处理 HTTP 请求即视为就绪。

    关键修正：真实项目的根路径经常返回 401/403/404/405（VAmPI 的 `/` 就是 404，
    crAPI 的 nginx 常返回 401/403）——这说明**服务已经在监听并处理请求**，只是根路径
    不是 2xx。此前只认 2xx/3xx，会把大量已就绪的真实靶场误判成“沙箱健康检查失败”。
    因此：任何 2xx–4xx 都算就绪；只有连接失败、或 5xx 网关（502/503/504，后端仍在启动）
    才继续等待。为兼顾“根路径 404 但某常见路径已可用”的项目，可多探几个常见路径。
    """
    import httpx

    paths = [""] + list(extra_paths or [])
    deadline = time.time() + timeout
    last_status = None
    while time.time() < deadline:
        reachable_5xx = False
        for suffix in paths:
            url = base_url.rstrip("/") + suffix if suffix else base_url
            try:
                # trust_env=False：绕过系统代理，确保直连本地容器端口
                response = httpx.get(url, timeout=3, trust_env=False, follow_redirects=False)
                last_status = response.status_code
                # 服务已在处理 HTTP 请求（含 401/403/404/405）即就绪。
                if 200 <= response.status_code < 500:
                    return True
                # 502/503/504：反向代理在、但后端仍在启动 -> 继续等。
                if response.status_code in (502, 503, 504):
                    reachable_5xx = True
            except Exception:  # noqa: BLE001  连接被拒/超时：服务还没起
                continue
        time.sleep(1.0 if reachable_5xx else 0.5)
    logger.info("健康检查未通过（最后状态=%s，超时=%ss）", last_status, timeout)
    return False


@contextmanager
def LocalAppRunner(command: list[str], cwd: str | Path, *,
                   env: dict | None = None, health_timeout: int = 20):
    """在本机子进程启动靶场。

    ⚠️ 安全警告：命令注入等载荷会在本机执行。仅限隔离虚拟机/实验环境使用。
    command 中用 {port} 占位符表示监听端口。
    """
    import os

    port = _free_port()
    cmd = [c.format(port=port) for c in command]
    base_url = f"http://127.0.0.1:{port}"
    run_env = {**os.environ, **(env or {}), "PORT": str(port), "FLASK_RUN_PORT": str(port)}

    logger.info("LocalAppRunner 启动: %s (cwd=%s) -> %s", cmd, cwd, base_url)
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), env=run_env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not _wait_healthy(base_url, health_timeout):
            logger.warning("靶场未在 %ds 内就绪", health_timeout)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logger.info("LocalAppRunner 已停止 (port=%s)", port)


@contextmanager
def DockerAppRunner(image: str, *, internal_port: int = 80,
                    build_context: str | Path | None = None,
                    health_timeout: int = 30):
    """在 Docker 容器内启动靶场并映射到本机随机端口。"""
    client = get_docker_client()
    host_port = _free_port()
    base_url = f"http://127.0.0.1:{host_port}"

    if build_context:
        logger.info("构建靶场镜像 %s (context=%s)", image, build_context)
        client.images.build(path=str(build_context), tag=image)

    container = client.containers.run(
        image=image, detach=True, remove=False,
        ports={f"{internal_port}/tcp": host_port},
        mem_limit="512m",
        # 容器可访问回环即可；如需完全断网可加 network_mode="none"（但会无法探测）
    )
    try:
        if not _wait_healthy(base_url, health_timeout):
            try:
                container.reload()
            except Exception:  # noqa: BLE001
                pass
            try:
                logs = container.logs(stdout=True, stderr=True).decode(
                    "utf-8", errors="replace")[-4000:]
            except Exception as exc:  # noqa: BLE001
                logs = f"container logs unavailable: {type(exc).__name__}: {exc}"
            status = str(getattr(container, "status", None) or "unknown")
            raise DockerTargetStartError({
                "status": "health_check_failed",
                "mode": "docker",
                "image": image,
                "internal_port": internal_port,
                "container_status": status,
                "health_check": "failed",
                "reason": (
                    f"Docker target did not become healthy within {health_timeout}s "
                    f"(container_status={status})"
                ),
                "logs_excerpt": logs,
            })
        yield base_url
    finally:
        try:
            container.remove(force=True)
        except Exception as e:  # noqa: BLE001
            logger.warning("清理容器失败: %s", e)
