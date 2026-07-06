"""扫描器注册表 —— 按启用工具集合统一调度。"""
from __future__ import annotations

import logging
from pathlib import Path

from backend.scanners.base import RawFinding
from backend.scanners.semgrep_runner import SemgrepScanner
from backend.scanners.bandit_runner import BanditScanner
from backend.scanners.gitleaks_runner import GitleaksScanner
from backend.scanners.trivy_runner import TrivyScanner
from backend.scanners.custom_rules import CustomRuleScanner

logger = logging.getLogger(__name__)

_SCANNERS = {
    "semgrep": SemgrepScanner,
    "bandit": BanditScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
    "custom": CustomRuleScanner,
}


def run_scanners(target: Path, enabled_tools: list[str]) -> list[RawFinding]:
    """运行选定的扫描器；始终附加 custom 规则作为兜底。"""
    tools = list(dict.fromkeys(enabled_tools + ["custom"]))
    all_findings: list[RawFinding] = []
    for tool in tools:
        cls = _SCANNERS.get(tool)
        if not cls:
            logger.warning("未知扫描器: %s", tool)
            continue
        scanner = cls()
        if not scanner.available():
            logger.warning("扫描器 %s 未安装，跳过", tool)
            continue
        try:
            results = scanner.run(target)
            logger.info("扫描器 %s 发现 %d 条", tool, len(results))
            all_findings.extend(results)
        except Exception as e:  # noqa: BLE001  单个工具失败不影响整体
            logger.exception("扫描器 %s 执行失败: %s", tool, e)
    return all_findings
