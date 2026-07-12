"""报告生成器：汇总扫描结果 -> Markdown / HTML / JSON。"""
from __future__ import annotations

import json
import re
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.config import settings
from backend.verifier.evidence_collector import apply_product_evidence_policy

TEMPLATE_DIR = Path(__file__).resolve().parent
REPORT_SCHEMA_VERSION = "1.0.0"
SUPPORTED_FORMATS = {"markdown", "html", "json", "pdf"}
_SENSITIVE_KEY = re.compile(
    r"authorization|cookie|password|passwd|secret|token|api[_-]?key|private[_-]?key|credential",
    re.I,
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_LOCAL_PATH = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+\\[^\s\"']+")


def severity_stats(findings: list[dict]) -> dict[str, int]:
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "low")
        stats[sev] = stats.get(sev, 0) + 1
    return stats


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _confidence_value(f: dict) -> float:
    try:
        return float(f.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def sort_findings(findings: list[dict]) -> list[dict]:
    """按“动态确认 > 严重级 > 置信度”排序，让最可信、最严重的漏洞排在前面，
    使报告阅读顺序与风险优先级一致。"""
    def key(f: dict):
        ev = f.get("evidence") or {}
        ver = ev.get("verification") or {}
        status_order = {
            "confirmed": 0, "needs_review": 1, "unverified": 2, "candidate": 2,
            "informational": 3, "out_of_scope": 4, "false_positive": 5,
        }.get(str(f.get("status") or "unverified"), 3)
        dyn = 0 if ver.get("dynamically_verified") else 1
        sev = _SEVERITY_ORDER.get(f.get("severity", "low"), 4)
        return (status_order, dyn, sev, -_confidence_value(f), str(f.get("finding_id") or ""))

    return sorted(findings, key=key)


def evidence_stats(findings: list[dict]) -> dict[str, int]:
    """统计证据链维度覆盖情况，用于报告头部概览，突出证据链的完整度。"""
    stats = {
        "with_evidence": 0,
        "with_static_chain": 0,
        "with_runtime": 0,
        "with_harness": 0,
        "with_exploit": 0,
        "dynamically_verified": 0,
        "http_reproduced": 0,
    }
    for f in findings:
        ev = f.get("evidence") or {}
        if ev:
            stats["with_evidence"] += 1
        sec = ev.get("static_evidence_chain") or {}
        if sec.get("checks"):
            stats["with_static_chain"] += 1
        runtime = ev.get("runtime") or {}
        runtime_status = str(runtime.get("reproduction_status") or runtime.get("status") or "")
        if runtime and runtime_status not in {"", "not_executed"}:
            stats["with_runtime"] += 1
        harness = ev.get("harness") or {}
        if harness and str(harness.get("verdict") or "") not in {"", "not_executed"}:
            stats["with_harness"] += 1
        if ev.get("exploit"):
            stats["with_exploit"] += 1
        ver = ev.get("verification") or {}
        if ver.get("dynamically_verified"):
            stats["dynamically_verified"] += 1
            if ver.get("dynamic_method") == "http_dynamic":
                stats["http_reproduced"] += 1
    return stats


def build_context(project: dict, scan: dict, findings: list[dict],
                  summary: dict, *, report_id: str | None = None,
                  options: dict[str, Any] | None = None) -> dict:
    report_options = {
        "include_poc": True,
        "include_fix": True,
        "profile": "technical_full",
    }
    report_options.update(options or {})
    normalized = []
    for finding in findings:
        item = dict(finding)
        # ExploitPipeline 即时结果使用 _evidence，数据库/API 结果使用 evidence。
        # 两者都接受，避免动态扫描结束后直接生成报告时整条证据链为空。
        evidence = deepcopy(item.get("evidence") or item.get("_evidence") or {})
        for internal_key in [key for key in item if str(key).startswith("_")]:
            item.pop(internal_key, None)
        if not item.get("fix_suggestion"):
            remediation = (evidence.get("knowledge") or {}).get("remediation") or []
            if remediation:
                item["fix_suggestion"] = "；".join(str(value) for value in remediation)
        if not report_options["include_fix"]:
            item["fix_suggestion"] = None
        if not report_options["include_poc"]:
            evidence.pop("poc_file", None)
            exploit = dict(evidence.get("exploit") or {})
            for key in ("exploit_code", "payloads", "payload", "poc"):
                exploit.pop(key, None)
            if exploit:
                evidence["exploit"] = exploit
            attack_plan = dict(evidence.get("attack_plan") or {})
            attack_plan.pop("code", None)
            if attack_plan:
                evidence["attack_plan"] = attack_plan
            harness = dict(evidence.get("harness") or {})
            harness.pop("harness_code", None)
            if harness:
                evidence["harness"] = harness
        evidence = apply_product_evidence_policy(
            _redact_value(evidence),
            status=item.get("status"), verified=item.get("verified"),
            file=item.get("file"), line=item.get("start_line") or item.get("line"),
        )
        if not evidence["actionable"]:
            exploit = dict(evidence.get("exploit") or {})
            for key in ("exploit_code", "payloads", "payload", "poc"):
                exploit.pop(key, None)
            evidence["exploit"] = exploit
        item["evidence"] = evidence
        item["classification"] = _classification(evidence)
        item["location"] = {
            "file": item.get("file") or "not_available",
            "start_line": item.get("start_line") or item.get("line"),
            "end_line": item.get("end_line") or item.get("start_line") or item.get("line"),
            "symbol": item.get("symbol") or (evidence.get("sink") or {}).get("symbol")
            if isinstance(evidence.get("sink"), dict) else item.get("symbol"),
        }
        item["exploit_chain"] = _build_exploit_chain(item)
        item["evidence_availability"] = _evidence_availability(evidence)
        normalized.append(item)
    ordered = sort_findings(normalized)
    metrics = _metrics(ordered)
    scope = _scope(scan)
    methodology = _methodology(scan)
    limitations = _limitations(scan, methodology, scope)
    generated_at = datetime.now(timezone.utc).isoformat()
    completeness = _completeness(scan)
    return _redact_value({
        "schema_version": REPORT_SCHEMA_VERSION,
        "report": {
            "id": report_id or f"report-{scan.get('id', 'unknown')}",
            "generated_at": generated_at,
            "generator": {"name": "AuditAgentX", "version": "1"},
            "completeness": completeness,
            "options": report_options,
        },
        "project": project,
        "scan": scan,
        "scope": scope,
        "methodology": methodology,
        "findings": ordered,
        "stats": severity_stats(ordered),
        "metrics": metrics,
        "evidence_stats": evidence_stats(ordered),
        "summary": summary,
        "limitations": limitations,
        "appendices": {
            "tool_status": methodology["tools"],
            "finding_index": [
                {"id": f.get("finding_id"), "type": f.get("type"), "severity": f.get("severity"),
                 "status": f.get("status"), "file": f.get("file"), "line": f.get("start_line")}
                for f in ordered
            ],
            "status_glossary": {
                "confirmed": "Evidence supports the vulnerability.",
                "needs_review": "Additional human or runtime verification is required.",
                "false_positive": "Evidence indicates the candidate is not exploitable.",
                "out_of_scope": "The finding is outside the configured production scope.",
                "unverified": "Static candidate not independently verified.",
            },
        },
        "redaction": {
            "applied": True,
            "policy_version": "1",
            "categories": ["credentials", "authorization", "tokens", "local_paths"],
        },
        "generated_at": generated_at,
        "tool": "AuditAgentX",
    })


def _classification(evidence: dict) -> dict:
    knowledge = evidence.get("knowledge") or {}
    metadata = evidence.get("semgrep_metadata") or {}
    return {
        "cwe": knowledge.get("cwe_id") or metadata.get("cwe") or "not_available",
        "owasp": knowledge.get("owasp") or metadata.get("owasp") or [],
    }


def _build_exploit_chain(finding: dict) -> dict:
    evidence = finding.get("evidence") or {}
    exploit = evidence.get("exploit") or {}
    runtime = evidence.get("runtime") or {}
    verification = evidence.get("verification") or {}
    stages: list[dict[str, Any]] = []
    source = evidence.get("source")
    if source:
        stages.append(_chain_stage("source", source))
    for index, hop in enumerate(evidence.get("call_path") or [], start=1):
        stages.append(_chain_stage("call", hop, sequence=index))
    sink = evidence.get("sink")
    if sink:
        stages.append(_chain_stage("sink", sink))
    path = exploit.get("exploit_path") or []
    if isinstance(path, str):
        path = [path]
    for index, step in enumerate(path, start=1):
        stages.append({"stage": "exploit", "sequence": index, "detail": step})
    for name in ("setup_record", "baseline_record", "attack_record", "confirmation_record"):
        if runtime.get(name):
            stages.append(_chain_stage(name.removesuffix("_record"), runtime[name]))
    if verification.get("dynamically_verified"):
        status = "confirmed"
    elif exploit:
        status = "planned"
    else:
        status = "not_available"
    return {
        "status": status,
        "preconditions": exploit.get("preconditions") or [],
        "entry_point": exploit.get("trigger_location") or finding.get("file"),
        "stages": stages,
        "verification_method": exploit.get("verification_method") or verification.get("dynamic_method"),
        "observed_result": runtime.get("confirmation_record") or runtime.get("matched_indicator"),
        "impact": exploit.get("impact") or "not_available",
        "artifact": evidence.get("poc_file"),
    }


def _chain_stage(stage: str, evidence: Any, *, sequence: int | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"stage": stage}
    if sequence is not None:
        item["sequence"] = sequence
    if isinstance(evidence, dict):
        for key in ("file", "line", "symbol", "status", "method", "url"):
            if evidence.get(key) is not None:
                item[key] = evidence[key]
        item["detail"] = (
            evidence.get("detail") or evidence.get("node") or evidence.get("matched_indicator")
            or evidence.get("response_excerpt") or json.dumps(evidence, ensure_ascii=False, default=str)
        )
    else:
        item["detail"] = str(evidence)
    return item


def _evidence_availability(evidence: dict) -> dict:
    return {
        "static_chain": "available" if evidence.get("data_flow") or evidence.get("call_path") else "not_available",
        "exploit": "available" if evidence.get("exploit") else "not_available",
        "runtime": str((evidence.get("runtime") or {}).get("reproduction_status") or "not_executed"),
        "harness": str((evidence.get("harness") or {}).get("verdict") or "not_executed"),
    }


def _metrics(findings: list[dict]) -> dict:
    statuses = Counter(str(f.get("status") or "unverified") for f in findings)
    sources = Counter(str(f.get("source") or "unknown") for f in findings)
    types = Counter(str(f.get("type") or "unknown") for f in findings)
    verification_levels = Counter()
    dynamically_verified = 0
    for finding in findings:
        verification = (finding.get("evidence") or {}).get("verification") or {}
        level = str(verification.get("verification_level") or verification.get("dynamic_method") or "static_only")
        verification_levels[level] += 1
        dynamically_verified += int(bool(verification.get("dynamically_verified")))
    return {
        "total": len(findings),
        "actionable_total": sum(
            1 for finding in findings
            if bool((finding.get("evidence") or {}).get("actionable"))
        ),
        "by_severity": severity_stats(findings),
        "by_status": dict(statuses),
        "by_source": dict(sources),
        "by_type": dict(types),
        "by_verification_level": dict(verification_levels),
        "dynamically_verified": dynamically_verified,
    }


def _scope(scan: dict) -> dict:
    config = scan.get("config") or {}
    options = config.get("options") or {}
    include_tests = bool(options.get("include_test_findings", False))
    excluded = [] if include_tests else [
        {"path": name, "reason": "non-production code excluded by configuration"}
        for name in ("tests", "samples", "examples", "docs")
    ]
    return {
        "included_paths": ["project_root"],
        "excluded_paths": excluded,
        "limits": {
            "max_files": options.get("max_files"),
            "max_verify_candidates": options.get("max_verify_candidates"),
            "severity_threshold": options.get("severity_threshold"),
        },
        "include_test_findings": include_tests,
        "scan_mode": config.get("scan_mode") or scan.get("scan_type"),
        "enabled_agents": config.get("enabled_agents") or [],
    }


def _methodology(scan: dict) -> dict:
    config = scan.get("config") or {}
    requested = set(config.get("enabled_tools") or [])
    tools = []
    seen = set()
    for item in config.get("scanner_status") or []:
        tool = str(item.get("tool") or "unknown")
        seen.add(tool)
        if item.get("partial_results"):
            status = "partial"
        elif item.get("executed") and item.get("success"):
            status = "executed"
        elif not item.get("available"):
            status = "unavailable"
        elif item.get("executed"):
            status = "failed"
        else:
            status = "skipped"
        tools.append({**item, "name": tool, "requested": tool in requested, "status": status})
    for tool in sorted(requested - seen):
        tools.append({
            "name": tool, "tool": tool, "requested": True, "status": "not_recorded",
            "success": False, "partial_results": False, "finding_count": 0,
            "error": "scanner status was not recorded",
        })
    return {"stages": ["parse", "static_scan", "audit", "verify", "exploit", "summary"], "tools": tools}


def _limitations(scan: dict, methodology: dict, scope: dict) -> list[dict]:
    limitations = []
    status = str(scan.get("status") or "unknown")
    if status != "done":
        limitations.append({
            "category": "scan_completeness", "detail": f"scan status is {status}",
            "impact": "coverage may be incomplete",
        })
    for tool in methodology["tools"]:
        if tool["status"] not in {"executed"}:
            limitations.append({
                "category": "tool_coverage", "tool": tool["name"],
                "detail": tool.get("error") or tool["status"],
                "impact": "findings from this tool may be incomplete or unavailable",
            })
    if scope["limits"].get("max_files"):
        limitations.append({
            "category": "file_limit", "detail": f"max_files={scope['limits']['max_files']}",
            "impact": "files beyond the configured limit are not analyzed",
        })
    return limitations


def _completeness(scan: dict) -> str:
    status = str(scan.get("status") or "unknown")
    if status == "done":
        return "complete"
    if status in {"partial_completed", "running", "queued"}:
        return "partial"
    return "failed"


def _redact_value(value: Any, key: str = "") -> Any:
    if _SENSITIVE_KEY.search(str(key)):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): _redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        text = _JWT.sub("<redacted-jwt>", value)
        text = _BEARER.sub("Bearer <redacted>", text)
        text = _LOCAL_PATH.sub("<local-path>", text)
        return text
    return value


def render_markdown(ctx: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    return env.get_template("markdown_template.md").render(**ctx)


def render_html(ctx: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    return env.get_template("html_template.html").render(**ctx)


def save_report(scan_id: str, fmt: str, content: str, *, report_id: str | None = None) -> Path:
    out_dir = settings.data_path / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported report format: {fmt}")
    ext = {"markdown": "md", "html": "html", "json": "json", "pdf": "pdf"}[fmt]
    artifact_id = report_id or f"{scan_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}"
    fp = out_dir / f"{artifact_id}.{ext}"
    fp.write_text(content, encoding="utf-8")
    return fp


def generate(project: dict, scan: dict, findings: list[dict],
             summary: dict, fmt: str = "html", *, report_id: str | None = None,
             options: dict[str, Any] | None = None) -> Path:
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported report format: {fmt}")
    ctx = build_context(
        project, scan, findings, summary, report_id=report_id, options=options,
    )
    ctx["report"]["format"] = fmt
    if fmt == "markdown":
        content = render_markdown(ctx)
    elif fmt == "json":
        content = json.dumps(ctx, ensure_ascii=False, indent=2)
    else:  # html / pdf 先渲染 html
        content = render_html(ctx)
    if fmt == "pdf":
        from backend.report.pdf_exporter import html_to_pdf
        out_dir = settings.data_path / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        artifact_id = report_id or f"{scan['id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}"
        return html_to_pdf(content, out_dir / f"{artifact_id}.pdf")
    return save_report(scan_id=scan["id"], fmt=fmt, content=content, report_id=report_id)
