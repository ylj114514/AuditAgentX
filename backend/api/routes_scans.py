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
from backend.acp.trace import ACPTracer

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


def resolve_scan_mode(payload: ScanCreate) -> dict:
    """把 scan_mode（quick/standard/deep）映射为 enabled_agents + options。

    - quick    ：仅静态扫描，不审计/不复核/不动态。
    - standard ：+ AuditAgent 语义审计 + VerifyAgent 复核 + 误报过滤 + 报告；不主动动态验证。
    - deep     ：+ Docker-first 动态验证（exploit + HTTP + harness），dynamic_target 默认 docker_project。

    未显式传 scan_mode 时，沿用 payload 里的 enabled_agents/options（向后兼容）。
    """
    mode = (payload.scan_mode or "").lower()
    agents = list(payload.enabled_agents)
    opts = payload.options.model_dump()

    if mode == "quick":
        agents = []
        opts.update(enable_exploit=False, enable_dynamic=False, enable_harness=False)
    elif mode == "standard":
        agents = ["audit", "verify"]
        opts.update(enable_exploit=False, enable_dynamic=False, enable_harness=False)
    elif mode == "deep":
        agents = ["audit", "verify", "exploit", "harness"]
        opts.update(enable_exploit=True, enable_dynamic=True, enable_harness=True)
        # Deep 默认 Docker-first：未显式指定动态目标时用 docker_project
        if not opts.get("dynamic_target"):
            opts["dynamic_target"] = {"mode": "docker_project", "scan_id": None}
    return {"enabled_agents": agents, "options": opts, "scan_mode": mode or None}


@router.post("", response_model=ScanOut)
def create_scan(payload: ScanCreate, background: BackgroundTasks,
                db: Session = Depends(get_db)) -> ScanOut:
    project = db.get(Project, payload.project_id)
    if not project:
        raise HTTPException(404, "project not found")
    sid = ids.scan_id()
    resolved = resolve_scan_mode(payload)
    # Deep 模式把 scan_id 补进 docker_project 目标，便于容器命名
    dt = resolved["options"].get("dynamic_target")
    if isinstance(dt, dict) and dt.get("mode") == "docker_project" and not dt.get("scan_id"):
        dt["scan_id"] = sid
    scan = Scan(
        id=sid, project_id=payload.project_id, scan_type=payload.scan_type,
        status="queued", progress=0,
        config_json=json.dumps({
            "scan_mode": resolved["scan_mode"],
            "enabled_tools": payload.enabled_tools,
            "enabled_agents": resolved["enabled_agents"],
            "options": resolved["options"],
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


@router.get("/{scan_id}/agent-messages")
def get_scan_agent_messages(scan_id: str, full: bool = False,
                            db: Session = Depends(get_db)) -> dict:
    """返回该扫描的 ACP Agent 通信流，用于前端展示审计过程。"""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")

    tracer = ACPTracer(scan_id=scan_id)
    messages = tracer.load_all()
    response = {
        "scan_id": scan_id,
        "total": len(messages),
        "messages": tracer.summary(),
    }
    if full:
        response["full_messages"] = [msg.to_dict() for msg in messages]
    return response


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
