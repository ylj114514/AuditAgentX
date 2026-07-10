"""AuditAgentX FastAPI 应用入口。

启动：
    uvicorn backend.main:app --reload --port 8000
文档：
    http://localhost:8000/docs
"""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.database import init_db
from backend.api import (
    routes_projects, routes_scans, routes_findings, routes_reports, routes_agents,
    routes_analytics, routes_acp,
)

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

app = FastAPI(
    title="AuditAgentX",
    description="基于大模型智能体的开源项目安全缺陷自动审计与验证系统",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[item.strip() for item in settings.cors_allow_origins.split(",") if item.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_projects.router)
app.include_router(routes_scans.router)
app.include_router(routes_findings.router)
app.include_router(routes_reports.router)
app.include_router(routes_agents.router)
app.include_router(routes_analytics.router)
app.include_router(routes_acp.router)


def _bootstrap_docker() -> None:
    """后台线程：确保 Docker 引擎在线，供动态验证使用。失败不影响后端运行。"""
    try:
        from backend.dynamic.docker_bootstrap import ensure_docker_running
        result = ensure_docker_running()
        logging.getLogger(__name__).info("Docker 自启结果：%s", result)
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).exception("Docker 自启过程异常（已忽略，不影响后端）。")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    logging.getLogger(__name__).info("AuditAgentX 已启动，数据库初始化完成。")
    # 项目启动即在后台预热 Docker 引擎（引擎冷启动较慢，用独立线程避免阻塞服务就绪）。
    if settings.docker_autostart:
        import threading
        threading.Thread(target=_bootstrap_docker, name="docker-bootstrap",
                         daemon=True).start()


@app.get("/")
def root() -> dict:
    return {
        "app": "AuditAgentX",
        "desc": "开源项目智能安全审计与验证系统",
        "docs": "/docs",
        "health": "ok",
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
