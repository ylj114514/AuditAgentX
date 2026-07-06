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


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_healthy(base_url: str, timeout: int = 20) -> bool:
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(base_url, timeout=2)
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
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
    import docker

    from backend.config import settings

    client = docker.DockerClient(base_url=settings.docker_host)
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
        _wait_healthy(base_url, health_timeout)
        yield base_url
    finally:
        try:
            container.remove(force=True)
        except Exception as e:  # noqa: BLE001
            logger.warning("清理容器失败: %s", e)
