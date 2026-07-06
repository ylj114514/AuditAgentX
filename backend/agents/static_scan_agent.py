"""StaticScanAgent —— 静态扫描智能体。

调度 scanners 注册表，产出归一化 RawFinding 列表。
"""
from __future__ import annotations

from pathlib import Path

from backend.scanners.registry import run_scanners
from backend.scanners.base import RawFinding


class StaticScanAgent:
    name = "static_scan_agent"

    def run(self, code_root: Path, enabled_tools: list[str]) -> list[RawFinding]:
        return run_scanners(code_root, enabled_tools)
