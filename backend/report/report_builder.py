"""报告生成器：汇总扫描结果 -> Markdown / HTML / JSON。"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.config import settings

TEMPLATE_DIR = Path(__file__).resolve().parent


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
        dyn = 0 if ver.get("dynamically_verified") else 1
        sev = _SEVERITY_ORDER.get(f.get("severity", "low"), 4)
        return (dyn, sev, -_confidence_value(f))

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
        if ev.get("runtime"):
            stats["with_runtime"] += 1
        if ev.get("harness"):
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
                  summary: dict) -> dict:
    ordered = sort_findings(findings)
    return {
        "project": project,
        "scan": scan,
        "findings": ordered,
        "stats": severity_stats(ordered),
        "evidence_stats": evidence_stats(ordered),
        "summary": summary,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "tool": "AuditAgentX",
    }


def render_markdown(ctx: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    return env.get_template("markdown_template.md").render(**ctx)


def render_html(ctx: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    return env.get_template("html_template.html").render(**ctx)


def save_report(scan_id: str, fmt: str, content: str) -> Path:
    out_dir = settings.data_path / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    ext = {"markdown": "md", "html": "html", "json": "json", "pdf": "pdf"}.get(fmt, "txt")
    fp = out_dir / f"{scan_id}.{ext}"
    fp.write_text(content, encoding="utf-8")
    return fp


def generate(project: dict, scan: dict, findings: list[dict],
             summary: dict, fmt: str = "html") -> Path:
    ctx = build_context(project, scan, findings, summary)
    if fmt == "markdown":
        content = render_markdown(ctx)
    elif fmt == "json":
        content = json.dumps(ctx, ensure_ascii=False, indent=2)
    else:  # html / pdf 先渲染 html
        content = render_html(ctx)
    fp = save_report(scan_id=scan["id"], fmt=fmt, content=content)
    if fmt == "pdf":
        from backend.report.pdf_exporter import html_to_pdf
        fp = html_to_pdf(content, fp.with_suffix(".pdf"))
    return fp
