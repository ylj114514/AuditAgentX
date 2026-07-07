"""Report generation and download routes."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.agents.summary_agent import SummaryAgent
from backend.core import ids
from backend.database import get_db
from backend.models import Evidence, Finding, Report, Scan
from backend.report import report_builder
from backend.schemas import ReportCreate, ReportOut

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("", response_model=ReportOut)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)) -> ReportOut:
    scan = db.get(Scan, payload.scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")

    project = scan.project
    meta = _decode_json(project.metadata_json) or {}
    rows = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    findings = []
    for f in rows:
        detail = _decode_json(f.detail_json) or {}
        verify_detail = detail.get("_verify") or {}
        ev = (db.query(Evidence)
              .filter(Evidence.finding_id == f.id)
              .order_by(Evidence.created_at.desc())
              .first())
        evidence = _decode_report_evidence(ev) if ev else None
        tool_calls = (
            verify_detail.get("tool_calls")
            or (verify_detail.get("_tool_evidence") or {}).get("tools_used")
            or []
        )
        if evidence is not None:
            evidence["tool_calls"] = tool_calls
            evidence["static_evidence_chain"] = verify_detail.get("evidence_chain")
        findings.append({
            "finding_id": f.id,
            "type": f.type,
            "severity": f.severity,
            "file": f.file_path,
            "start_line": f.start_line,
            "line": f.start_line,
            "code_snippet": f.code_snippet,
            "confidence": f.confidence,
            "source": f.source,
            "verified": f.verified,
            "status": f.status,
            "fix_suggestion": f.fix_suggestion,
            "tool_calls": tool_calls,
            "evidence": evidence,
        })

    project_ctx = {
        "name": project.name,
        "url": project.url,
        "local_path": project.local_path,
        "languages": meta.get("languages", []),
        "frameworks": meta.get("frameworks", []),
        "file_count": meta.get("file_count", 0),
        "loc": meta.get("loc", 0),
    }
    scan_ctx = {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "config": _decode_json(scan.config_json) or {},
    }
    stats = report_builder.severity_stats(findings)
    summary = SummaryAgent(scan_id=scan.id).run(project_ctx, scan_ctx, findings, stats)

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


def _decode_json(value: str | None):
    return json.loads(value or "null")


def _decode_report_evidence(ev: Evidence) -> dict:
    poc = _decode_json(ev.poc_result)
    if isinstance(poc, dict) and ("exploit" in poc or "runtime" in poc):
        exploit = poc.get("exploit")
        runtime = poc.get("runtime")
    else:
        exploit = None
        runtime = None
    return {
        "source": _decode_json(ev.source),
        "sink": _decode_json(ev.sink),
        "data_flow": _decode_json(ev.data_flow),
        "call_path": poc.get("call_path") if isinstance(poc, dict) else None,
        "exploit": exploit,
        "runtime": runtime,
        "harness": poc.get("harness") if isinstance(poc, dict) else None,
        "poc_result": poc.get("poc_result") if isinstance(poc, dict) else None,
        "logs": _decode_json(ev.logs),
    }
