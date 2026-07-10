"""扫描器注册表 —— 按启用工具集合统一调度（多扫描器并行执行）。"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from backend.scanners.base import RawFinding
from backend.scanners.semgrep_runner import SemgrepScanner
from backend.scanners.bandit_runner import BanditScanner
from backend.scanners.gitleaks_runner import GitleaksScanner
from backend.scanners.custom_rules import CustomRuleScanner

logger = logging.getLogger(__name__)

_SCANNERS = {
    "semgrep": SemgrepScanner,
    "bandit": BanditScanner,
    "gitleaks": GitleaksScanner,
    "custom": CustomRuleScanner,
}


def _run_one(tool: str, target: Path) -> tuple[list[RawFinding], dict]:
    """运行单个扫描器（独立进程/纯计算，可并行）；失败不影响其它扫描器。"""
    cls = _SCANNERS.get(tool)
    if not cls:
        logger.warning("未知扫描器: %s", tool)
        return [], {"tool": tool, "available": False, "executed": False,
                    "success": False, "error": "unknown_scanner", "finding_count": 0}
    scanner = cls()
    if not scanner.available():
        logger.warning("扫描器 %s 未安装，跳过", tool)
        return [], {"tool": tool, "available": False, "executed": False,
                    "success": False, "error": "not_installed", "finding_count": 0}
    try:
        results = scanner.run(target)
        logger.info("扫描器 %s 发现 %d 条", tool, len(results))
        return results, {"tool": tool, "available": True, "executed": True,
                         "success": True, "error": None, "finding_count": len(results)}
    except Exception as e:  # noqa: BLE001  单个工具失败不影响整体
        logger.exception("扫描器 %s 执行失败: %s", tool, e)
        return [], {"tool": tool, "available": True, "executed": True,
                    "success": False, "error": str(e)[:300], "finding_count": 0}


def run_scanners(target: Path, enabled_tools: list[str]) -> list[RawFinding]:
    """并行运行选定的扫描器；始终附加 custom 规则作为兜底。

    各扫描器相互独立（semgrep/bandit/gitleaks 是子进程、custom 是纯计算），
    并行后总耗时≈最慢的那个（通常是 semgrep），而非各工具耗时累加。
    结果按工具顺序拼接，保证确定性。
    """
    findings, _ = run_scanners_detailed(target, enabled_tools)
    return findings


def run_scanners_detailed(target: Path, enabled_tools: list[str]) -> tuple[list[RawFinding], list[dict]]:
    """运行扫描器并同时返回逐工具健康状态，避免“未安装”和“零发现”混为一谈。"""
    tools = list(dict.fromkeys(enabled_tools + ["custom"]))
    results_by_tool: dict[str, list[RawFinding]] = {}
    status_by_tool: dict[str, dict] = {}
    workers = max(1, min(len(tools), 5))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
        futures = {pool.submit(_run_one, t, target): t for t in tools}
        for fut in as_completed(futures):
            tool = futures[fut]
            results, status = fut.result()
            results_by_tool[tool] = results
            status_by_tool[tool] = status

    all_findings: list[RawFinding] = []
    for tool in tools:                       # 按输入顺序拼接，确定性
        all_findings.extend(results_by_tool.get(tool, []))
    return all_findings, [status_by_tool.get(tool, {"tool": tool, "success": False,
                                                     "error": "missing_status"}) for tool in tools]
