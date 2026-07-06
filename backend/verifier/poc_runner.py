"""PoC 运行器：调度 PocAgent 生成方案，可选在沙箱内执行。"""
from __future__ import annotations

import logging

from backend.agents.poc_agent import PocAgent
from backend.verifier.sandbox_manager import SandboxManager

logger = logging.getLogger(__name__)


class PocRunner:
    def __init__(self, scan_id: str | None = None) -> None:
        self.poc_agent = PocAgent(scan_id=scan_id)
        self.sandbox = SandboxManager()

    def run(self, verified_finding: dict, *, use_sandbox: bool = False) -> dict:
        poc = self.poc_agent.run(verified_finding)
        sandbox_result: dict | None = None

        script = poc.get("verification_script")
        if use_sandbox and script and self.sandbox.available():
            # 默认使用轻量 python 镜像；真实靶场应指定对应镜像
            sandbox_result = self.sandbox.run_script("python:3.11-slim", script)

        return {
            "poc": poc,
            "poc_executed": bool(sandbox_result and not sandbox_result.get("skipped")),
            "sandbox_result": sandbox_result,
        }
