"""跨项目 / 跨扫描的漏洞统计聚合。

从 projects / scans / findings 表聚合，支撑：
- 全局概览（项目数、扫描数、漏洞总数、严重级分布、Top 漏洞类型）
- 被测项目横向对比（每个项目最新扫描的漏洞画像）
用于课件要求的「≥20 款开源项目检测」量化展示。
"""
from __future__ import annotations

import json
from collections import Counter

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models import Project, Scan, Finding

SEVERITY_KEYS = ["critical", "high", "medium", "low", "info"]


def _empty_severity() -> dict:
    return {k: 0 for k in SEVERITY_KEYS}


def _severity_dist(findings: list[Finding]) -> dict:
    dist = _empty_severity()
    for f in findings:
        sev = (f.severity or "low").lower()
        dist[sev] = dist.get(sev, 0) + 1
    return dist


def overview(db: Session) -> dict:
    """全局概览统计。"""
    project_count = db.query(func.count(Project.id)).scalar() or 0
    scan_count = db.query(func.count(Scan.id)).scalar() or 0
    done_scans = db.query(func.count(Scan.id)).filter(Scan.status == "done").scalar() or 0

    findings = db.query(Finding).all()
    total = len(findings)
    verified = sum(1 for f in findings if f.verified)
    confirmed = sum(1 for f in findings if f.status == "confirmed")

    type_counter: Counter[str] = Counter(f.type or "Unknown" for f in findings)
    top_types = [{"type": t, "count": c} for t, c in type_counter.most_common(10)]

    return {
        "projects": project_count,
        "scans": scan_count,
        "scans_done": done_scans,
        "findings_total": total,
        "findings_verified": verified,
        "findings_confirmed": confirmed,
        "severity_distribution": _severity_dist(findings),
        "top_vulnerability_types": top_types,
    }


def _latest_scan(db: Session, project_id: str) -> Scan | None:
    return (db.query(Scan)
            .filter(Scan.project_id == project_id)
            .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
            .first())


def project_comparison(db: Session) -> list[dict]:
    """每个项目取最新扫描，输出横向对比行。"""
    rows: list[dict] = []
    for project in db.query(Project).order_by(Project.created_at.desc()).all():
        meta = {}
        try:
            meta = json.loads(project.metadata_json or "{}")
        except json.JSONDecodeError:
            meta = {}
        scan = _latest_scan(db, project.id)
        findings = (db.query(Finding).filter(Finding.scan_id == scan.id).all()
                    if scan else [])
        dist = _severity_dist(findings)
        rows.append({
            "project_id": project.id,
            "name": project.name,
            "source_type": project.source_type,
            "languages": meta.get("languages", []),
            "loc": meta.get("loc", 0),
            "file_count": meta.get("file_count", 0),
            "latest_scan_id": scan.id if scan else None,
            "scan_status": scan.status if scan else "none",
            "findings_total": len(findings),
            "severity_distribution": dist,
            "verified": sum(1 for f in findings if f.verified),
            "reproducible": sum(1 for f in findings
                                if f.status == "confirmed" and f.verified),
            "risk_score": _risk_score(dist),
        })
    return rows


def _risk_score(dist: dict) -> int:
    """简单加权风险分：critical×10 + high×5 + medium×2 + low×1；info 不计风险分。"""
    return (dist.get("critical", 0) * 10 + dist.get("high", 0) * 5
            + dist.get("medium", 0) * 2 + dist.get("low", 0))
