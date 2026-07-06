"""扫描任务接口（md 7.4 / 7.5 / 7.6）。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from backend.database import get_db, SessionLocal
from backend.core import ids
from backend.models import Project, Scan, Finding
from backend.schemas import ScanCreate, ScanOut, ScanStatus, FindingBrief
from backend.agents.orchestrator_agent import OrchestratorAgent

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _run_scan_task(scan_id: str) -> None:
    """后台任务入口：使用独立 DB 会话运行编排器。"""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan:
            OrchestratorAgent(db, scan).run()
    finally:
        db.close()


@router.post("", response_model=ScanOut)
def create_scan(payload: ScanCreate, background: BackgroundTasks,
                db: Session = Depends(get_db)) -> ScanOut:
    project = db.get(Project, payload.project_id)
    if not project:
        raise HTTPException(404, "project not found")
    sid = ids.scan_id()
    scan = Scan(
        id=sid, project_id=payload.project_id, scan_type=payload.scan_type,
        status="queued", progress=0,
        config_json=json.dumps({
            "enabled_tools": payload.enabled_tools,
            "enabled_agents": payload.enabled_agents,
            "options": payload.options.model_dump(),
        }, ensure_ascii=False),
    )
    db.add(scan)
    db.commit()
    background.add_task(_run_scan_task, sid)
    return ScanOut(scan_id=sid, status="queued")


@router.get("/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanStatus:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return ScanStatus(
        scan_id=scan.id, project_id=scan.project_id, status=scan.status,
        progress=scan.progress, current_stage=scan.current_stage,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        error=scan.error,
    )


@router.get("/{scan_id}/findings")
def get_scan_findings(scan_id: str, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings = [FindingBrief(
        finding_id=f.id, type=f.type, severity=f.severity, file=f.file_path,
        line=f.start_line, confidence=f.confidence, verified=f.verified, status=f.status,
    ).model_dump() for f in rows]
    return {"scan_id": scan_id, "total": len(findings), "findings": findings}
