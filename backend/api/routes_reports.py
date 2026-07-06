"""报告生成 / 下载接口（md 7.10 / 7.11）。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.core import ids
from backend.models import Scan, Finding, Report
from backend.schemas import ReportCreate, ReportOut
from backend.report import report_builder
from backend.agents.report_agent import ReportAgent

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("", response_model=ReportOut)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)) -> ReportOut:
    scan = db.get(Scan, payload.scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    project = scan.project
    meta = json.loads(project.metadata_json or "{}")
    rows = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    findings = [{
        "type": f.type, "severity": f.severity, "file": f.file_path,
        "start_line": f.start_line, "line": f.start_line,
        "code_snippet": f.code_snippet, "confidence": f.confidence,
        "verified": f.verified, "status": f.status,
        "fix_suggestion": f.fix_suggestion,
    } for f in rows]

    stats = report_builder.severity_stats(findings)
    # 调用报告智能体生成摘要（失败自动降级为占位）
    summary = ReportAgent(scan_id=scan.id).run(meta, {"stats": stats, "total": len(findings)})

    project_ctx = {
        "name": project.name, "url": project.url, "local_path": project.local_path,
        "languages": meta.get("languages", []), "frameworks": meta.get("frameworks", []),
        "file_count": meta.get("file_count", 0), "loc": meta.get("loc", 0),
    }
    scan_ctx = {"id": scan.id, "scan_type": scan.scan_type, "status": scan.status}

    fp = report_builder.generate(project_ctx, scan_ctx, findings, summary, fmt=payload.format)

    rid = ids.report_id()
    db.add(Report(id=rid, scan_id=scan.id, format=payload.format, file_path=str(fp)))
    db.commit()
    return ReportOut(report_id=rid, status="generated",
                     download_url=f"/api/reports/{rid}/download")


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report or not report.file_path:
        raise HTTPException(404, "report not found")
    return FileResponse(report.file_path, filename=report.file_path.split("/")[-1])
