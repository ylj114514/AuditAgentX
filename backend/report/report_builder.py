"""报告生成器：汇总扫描结果 -> Markdown / HTML / JSON。"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.config import settings

TEMPLATE_DIR = Path(__file__).resolve().parent


def severity_stats(findings: list[dict]) -> dict[str, int]:
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        stats[sev] = stats.get(sev, 0) + 1
    return stats


def build_context(project: dict, scan: dict, findings: list[dict],
                  summary: dict) -> dict:
    return {
        "project": project,
        "scan": scan,
        "findings": findings,
        "stats": severity_stats(findings),
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
