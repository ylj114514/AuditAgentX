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
    allow_origins=["*"],
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


@app.on_event("startup")
def _startup() -> None:
    init_db()
    logging.getLogger(__name__).info("AuditAgentX 已启动，数据库初始化完成。")


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
