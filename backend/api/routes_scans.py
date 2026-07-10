"""扫描任务接口（md 7.4 / 7.5 / 7.6）。"""
from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.config import settings
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
        if opts.get("max_verify_candidates") is None:
            opts["max_verify_candidates"] = settings.max_verify_candidates
    elif mode == "deep":
        agents = ["audit", "verify", "exploit", "harness"]
        # Deep：沙箱全开——HTTP 项目沙箱 + 函数级 Harness(Docker) + PoC 沙箱 一并启用
        opts.update(enable_exploit=True, enable_dynamic=True, enable_harness=True,
                    enable_sandbox=True)
        if opts.get("max_verify_candidates") is None:
            opts["max_verify_candidates"] = settings.max_verify_candidates
        # Deep 默认 Docker-first：未显式指定动态目标时用 docker_project
        if not opts.get("dynamic_target"):
            opts["dynamic_target"] = {
                "mode": "docker_project",
                "scan_id": None,
                "auto_start_docker": True,
            }
        elif opts["dynamic_target"].get("mode") == "docker_project":
            # 前端 build 模式与后端 Docker 自启建立明确契约；显式 false 才关闭。
            opts["dynamic_target"].setdefault("auto_start_docker", True)
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


@router.get("")
def list_scans(q: str | None = None, limit: int = 50,
              db: Session = Depends(get_db)) -> dict:
    """列出扫描任务（历史记录的后端真实数据源）。

    前端历史查询原本仅依赖浏览器 localStorage，一旦清缓存/换浏览器/经脚本跑扫描，
    就会「查不到」。本接口以数据库为准，支持按 scan_id / 项目 id / 项目名模糊搜索，
    让前端在 localStorage 无命中时可回退到后端查询。
    """
    query = db.query(Scan, Project).join(Project, Scan.project_id == Project.id)
    if q and q.strip():
        like = f"%{q.strip()}%"
        query = query.filter(or_(
            Scan.id.ilike(like),
            Project.id.ilike(like),
            Project.name.ilike(like),
        ))
    # 排序：未开始（排队/进行中，started_at 为空）视为最新排最前，其余按最近开始时间倒序。
    # 用布尔表达式而非 NULLS FIRST，保证跨 SQLite 版本可移植。
    rows = (query.order_by((Scan.started_at.is_(None)).desc(), Scan.started_at.desc())
            .limit(max(1, min(limit, 200))).all())
    scans = [{
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "project_name": project.name,
        "target": project.url or project.local_path,
        "source_type": project.source_type,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "progress": scan.progress,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    } for scan, project in rows]
    return {"total": len(scans), "scans": scans}


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
        stage_detail=_scan_stage_detail(scan),
    )


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)) -> dict:
    """删除扫描及其级联数据（findings → evidence、reports），供历史记录页真正移除记录。

    模型关系已配置 cascade="all, delete-orphan"，删除 Scan 会一并清除其 findings、
    每条 finding 的 evidence，以及关联 reports。
    """
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: str, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan.status in {"done", "finished", "failed", "cancelled"}:
        return {"scan_id": scan.id, "status": scan.status}
    scan.status = "cancelled"
    scan.error = "用户已请求停止扫描"
    scan.finished_at = datetime.utcnow()
    db.commit()
    return {"scan_id": scan.id, "status": "cancelled"}


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


def _scan_stage_detail(scan: Scan) -> dict:
    try:
        config = json.loads(scan.config_json or "{}")
    except json.JSONDecodeError:
        config = {}
    opts = config.get("options") or {}
    detail = {
        "scan_mode": config.get("scan_mode"),
        "max_verify_candidates": opts.get("max_verify_candidates"),
        "max_verify_workers": opts.get("max_verify_workers") or settings.verify_workers,
        "dynamic_target_mode": (opts.get("dynamic_target") or {}).get("mode"),
        "docker_autostart_requested": bool(
            (opts.get("dynamic_target") or {}).get("auto_start_docker")
        ),
        "launch_plan": (opts.get("dynamic_target") or {}).get("launch_plan") or {},
        "elapsed_seconds": None,
    }
    if scan.started_at:
        end = scan.finished_at or datetime.utcnow()
        detail["elapsed_seconds"] = max(0, int((end - scan.started_at).total_seconds()))
    try:
        tracer = ACPTracer(scan_id=scan.id)
        messages = tracer.summary()
        full_messages = tracer.load_all()
        verify_requests = sum(1 for m in messages if m.get("message_type") == "verify.request")
        verify_results = sum(1 for m in messages if m.get("message_type") == "verify.result")
        progress_events = [
            (msg.payload.get("progress") or {}) for msg in full_messages
            if getattr(msg.header.message_type, "value", msg.header.message_type)
            == "dynamic.progress"
        ]
        latest_progress = progress_events[-1] if progress_events else {}
        detail.update({
            "agent_message_total": len(messages),
            "verify_requests": verify_requests,
            "verify_results": verify_results,
            "verify_pending": max(0, verify_requests - verify_results),
            "dynamic_phase": latest_progress.get("phase"),
            "dynamic_completed": latest_progress.get("completed"),
            "dynamic_total": latest_progress.get("total"),
            "dynamic_detail": latest_progress.get("detail"),
            "dynamic_target_status": latest_progress.get("target_status"),
        })
    except Exception:
        detail.update({
            "agent_message_total": 0,
            "verify_requests": 0,
            "verify_results": 0,
            "verify_pending": 0,
            "dynamic_phase": None,
            "dynamic_completed": 0,
            "dynamic_total": 0,
            "dynamic_detail": None,
            "dynamic_target_status": None,
        })
    return detail
