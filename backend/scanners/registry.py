"""扫描器注册表 —— 按启用工具集合统一调度（多扫描器并行执行）。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path

from backend.scanners.base import RawFinding, scanner_process_context
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
_TOOL_SEMAPHORES = {
    # These scanners are CPU/IO heavy and maintain shared caches. Running two
    # repository scans concurrently caused both Semgrep jobs to hit 15-minute
    # timeouts on real projects, so serialize them across scan tasks.
    "semgrep": threading.Semaphore(1),
    "trivy": threading.Semaphore(1),
}


def _run_one(tool: str, target: Path, max_files: int,
             scan_id: str | None = None) -> tuple[list[RawFinding], dict]:
    """运行单个扫描器（独立进程/纯计算，可并行）；失败不影响其它扫描器。"""
    cls = _SCANNERS.get(tool)
    if not cls:
        logger.warning("未知扫描器: %s", tool)
        return [], {"tool": tool, "available": False, "executed": False,
                    "success": False, "error": "unknown_scanner", "finding_count": 0}
    scanner = cls()
    scanner.max_files = max_files
    if not scanner.available():
        logger.warning("扫描器 %s 未安装，跳过", tool)
        return [], {"tool": tool, "available": False, "executed": False,
                    "success": False, "error": "not_installed", "finding_count": 0}
    try:
        gate = _TOOL_SEMAPHORES.get(tool)
        with scanner_process_context(scan_id):
            if gate is None:
                results = scanner.run(target)
            else:
                acquired = gate.acquire(timeout=1800)
                if not acquired:
                    raise TimeoutError(f"timed out waiting for global {tool} scanner slot")
                try:
                    results = scanner.run(target)
                finally:
                    gate.release()
        if not isinstance(results, list):
            raise RuntimeError(
                f"scanner {tool} returned {type(results).__name__}, expected list[RawFinding]"
            )
        degraded = getattr(scanner, "degraded_reason", None)
        logger.info("扫描器 %s 发现 %d 条", tool, len(results))
        return results, {"tool": tool, "available": True, "executed": True,
                         "success": not bool(degraded), "error": degraded,
                         "finding_count": len(results), "partial_results": bool(degraded)}
    except Exception as e:  # noqa: BLE001  单个工具失败不影响整体
        logger.exception("扫描器 %s 执行失败: %s", tool, e)
        return [], {"tool": tool, "available": True, "executed": True,
                    "success": False, "error": str(e)[:300], "finding_count": 0}


def run_scanner_tool(tool: str, target: Path, *, max_files: int = 20000,
                     scan_id: str | None = None) -> tuple[list[RawFinding], dict]:
    """MCP-facing single scanner entrypoint.

    StaticScanAgent should call scanners through MCP tools, not by reaching into
    subprocess wrappers directly.  This thin public wrapper keeps the actual
    scanner execution semantics centralized in one place, including availability
    checks, global heavy-tool semaphores, scan cancellation context, and
    structured per-tool status.
    """
    try:
        max_files = max(1, min(int(max_files), 200000))
    except (TypeError, ValueError):
        max_files = 20000
    return _run_one(tool, target, max_files, scan_id)


def static_tool_preflight(enabled_tools: list[str] | None = None) -> list[dict]:
    """Return availability for static scanner tools without executing scans."""
    tools = list(dict.fromkeys(list(enabled_tools or _SCANNERS.keys()) + ["custom"]))
    checks: list[dict] = []
    for tool in tools:
        cls = _SCANNERS.get(tool)
        if not cls:
            checks.append({"tool": tool, "available": False, "error": "unknown_scanner"})
            continue
        scanner = cls()
        checks.append({
            "tool": tool,
            "available": bool(scanner.available()),
            "cli": getattr(scanner, "cli", ""),
            "error": None if scanner.available() else "not_installed",
        })
    return checks


def run_scanners(target: Path, enabled_tools: list[str]) -> list[RawFinding]:
    """并行运行选定的扫描器；始终附加 custom 规则作为兜底。

    各扫描器相互独立（semgrep/bandit/gitleaks 是子进程、custom 是纯计算），
    并行后总耗时≈最慢的那个（通常是 semgrep），而非各工具耗时累加。
    结果按工具顺序拼接，保证确定性。
    """
    findings, _ = run_scanners_detailed(target, enabled_tools)
    return findings


def run_scanners_detailed(target: Path, enabled_tools: list[str], *, max_files: int = 20000,
                          severity_threshold: str = "low", scan_id: str | None = None,
                          ) -> tuple[list[RawFinding], list[dict]]:
    """运行扫描器并同时返回逐工具健康状态，避免“未安装”和“零发现”混为一谈。"""
    tools = list(dict.fromkeys(enabled_tools + ["custom"]))
    results_by_tool: dict[str, list[RawFinding]] = {}
    status_by_tool: dict[str, dict] = {}
    workers = max(1, min(len(tools), 5))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
        futures = {pool.submit(_run_one, t, target, max_files, scan_id): t for t in tools}
        for fut in as_completed(futures):
            tool = futures[fut]
            results, status = fut.result()
            results_by_tool[tool] = results
            status_by_tool[tool] = status

    all_findings: list[RawFinding] = []
    for tool in tools:                       # 按输入顺序拼接，确定性
        all_findings.extend(results_by_tool.get(tool, []))
    consolidated = consolidate_findings(all_findings)
    threshold = _SEVERITY.get(str(severity_threshold or "low").lower(), 1)
    consolidated = [f for f in consolidated if _SEVERITY.get(str(f.severity).lower(), 1) >= threshold]
    return consolidated, [
        status_by_tool.get(tool, {"tool": tool, "success": False, "error": "missing_status"})
        for tool in tools
    ]


_SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _canonical_type(value: str) -> str:
    text = (value or "").lower().replace("_", "-")
    if "nosql" in text and "inject" in text:
        return "nosql-injection"
    if ("weak" in text and "hash" in text) or text.strip("- ") == "hashlib":
        return "weak-hash"
    aliases = [
        (("sql", "inject"), "sql-injection"), (("command", "inject"), "command-injection"),
        (("path", "travers"), "path-traversal"), (("hardcoded", "secret"), "hardcoded-secret"),
        (("cross-site", "script"), "xss"), (("insecure", "deserial"), "insecure-deserialization"),
        (("open", "redirect"), "open-redirect"), (("server-side", "request"), "ssrf"),
    ]
    for terms, canonical in aliases:
        if all(term in text for term in terms):
            return canonical
    return "".join(ch for ch in text if ch.isalnum())


def _confidence(finding: RawFinding) -> float:
    try:
        return max(0.0, min(float((finding.extra or {}).get("confidence", 0.5)), 1.0))
    except (TypeError, ValueError):
        return 0.5


def _safe_rel_key(value: str) -> str:
    text = str(value or "").replace("\\", "/").lower()
    while text.startswith("./"):
        text = text[2:]
    return text


def consolidate_findings(findings: list[RawFinding]) -> list[RawFinding]:
    """合并同一 file:line 的同类工具命中，并保留交叉佐证而不是静默丢证据。"""
    groups: dict[tuple, RawFinding] = {}
    order: list[tuple] = []
    for finding in findings:
        file_key = _safe_rel_key(finding.file)
        type_key = _canonical_type(finding.type or finding.rule_id)
        # SCA 一份清单可有多个 CVE，不能仅按 line=0 合并。
        discriminator = finding.rule_id if finding.line <= 0 else ""
        key = (type_key, file_key, int(finding.line or 0), discriminator)
        if key not in groups:
            copied = replace(finding, extra=dict(finding.extra or {}))
            copied.extra.setdefault("corroborating_sources", [finding.source])
            copied.extra.setdefault("corroborating_rules", [finding.rule_id] if finding.rule_id else [])
            copied.extra.setdefault("duplicate_count", 1)
            groups[key] = copied
            order.append(key)
            continue
        current = groups[key]
        sources = list(dict.fromkeys((current.extra.get("corroborating_sources") or []) + [finding.source]))
        rules = list(dict.fromkeys((current.extra.get("corroborating_rules") or []) +
                                   ([finding.rule_id] if finding.rule_id else [])))
        best = finding if _confidence(finding) > _confidence(current) else current
        merged = replace(best, extra=dict(best.extra or {}))
        merged.severity = max((current.severity, finding.severity), key=lambda v: _SEVERITY.get(v, 0))
        merged.extra["corroborating_sources"] = sources
        merged.extra["corroborating_rules"] = rules
        merged.extra["duplicate_count"] = int(current.extra.get("duplicate_count", 1)) + 1
        merged.extra["corroborating_evidence"] = _merge_evidence(current, finding)
        _preserve_flow_fields(merged.extra, current.extra or {})
        _preserve_flow_fields(merged.extra, finding.extra or {})
        if len(sources) > 1:
            merged.extra["confidence"] = min(0.98, max(_confidence(current), _confidence(finding)) + 0.05)
        groups[key] = merged
    return [groups[key] for key in order]


def _merge_evidence(*findings: RawFinding) -> list[dict]:
    evidence: list[dict] = []
    seen: set[tuple] = set()
    for finding in findings:
        item = {
            "source": finding.source,
            "rule_id": finding.rule_id,
            "confidence": _confidence(finding),
            "analysis": (finding.extra or {}).get("analysis"),
            "taint_flow": (finding.extra or {}).get("taint_flow"),
            "source_line": (finding.extra or {}).get("source_line"),
            "sink_line": finding.line,
        }
        key = (item["source"], item["rule_id"], item["sink_line"])
        if key not in seen:
            seen.add(key)
            evidence.append({k: v for k, v in item.items() if v not in (None, "", [])})
    return evidence


def _preserve_flow_fields(target: dict, source: dict) -> None:
    for key in ("analysis", "taint_flow", "source_line", "sanitized", "dynamic_verification"):
        if key not in target and source.get(key) not in (None, "", []):
            target[key] = source[key]
