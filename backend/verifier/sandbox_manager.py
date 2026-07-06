"""Docker 沙箱管理器（进阶功能）。

默认关闭（ENABLE_SANDBOX=false）。开启后在隔离容器内运行 PoC，
不接触真实第三方系统（对应 md 文档合规与沙箱验证要求）。
"""
from __future__ import annotations

import logging
import uuid

from backend.config import settings

logger = logging.getLogger(__name__)


class SandboxManager:
    def __init__(self) -> None:
        self.enabled = settings.enable_sandbox

    def available(self) -> bool:
        if not self.enabled:
            return False
        try:
            import docker  # noqa: F401
            return True
        except ImportError:
            logger.warning("未安装 docker SDK，沙箱不可用")
            return False

    def run_script(self, image: str, script: str, timeout: int | None = None) -> dict:
        """在一次性容器中执行脚本，返回 {sandbox_id, exit_code, stdout, stderr}。"""
        sandbox_id = f"sandbox_{uuid.uuid4().hex[:8]}"
        if not self.available():
            return {
                "sandbox_id": sandbox_id,
                "skipped": True,
                "reason": "沙箱未启用或 docker 不可用",
            }
        import docker

        client = docker.DockerClient(base_url=settings.docker_host)
        timeout = timeout or settings.sandbox_timeout
        try:
            container = client.containers.run(
                image=image,
                command=["sh", "-c", script],
                detach=True,
                network_disabled=True,   # 断网，杜绝外联真实系统
                mem_limit="512m",
                remove=False,
            )
            result = container.wait(timeout=timeout)
            logs = container.logs().decode("utf-8", errors="ignore")
            container.remove(force=True)
            return {
                "sandbox_id": sandbox_id,
                "exit_code": result.get("StatusCode", -1),
                "stdout": logs,
                "stderr": "",
            }
        except Exception as e:  # noqa: BLE001
            logger.exception("沙箱执行失败: %s", e)
            return {"sandbox_id": sandbox_id, "error": str(e)}
