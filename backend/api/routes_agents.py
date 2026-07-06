"""智能体信息接口 —— 列出系统内置智能体及其职责。"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/agents", tags=["agents"])

AGENTS = [
    {"name": "OrchestratorAgent", "role": "总控调度，串联完整审计链路"},
    {"name": "RepoParserAgent", "role": "仓库解析：语言/框架/依赖/入口/目录树"},
    {"name": "StaticScanAgent", "role": "静态扫描：Semgrep/Bandit/Gitleaks/Trivy/自定义规则"},
    {"name": "AuditAgent", "role": "LLM 语义安全审计，发现工具漏报"},
    {"name": "VerifyAgent", "role": "独立交叉验证，降低误报"},
    {"name": "ExploitAgent", "role": "漏洞自动利用：生成利用代码/触发位置/利用路径/验证方法"},
    {"name": "PocAgent", "role": "生成本地沙箱 PoC 验证方案"},
    {"name": "ReportAgent", "role": "生成结构化审计报告摘要"},
]


@router.get("")
def list_agents() -> dict:
    return {"total": len(AGENTS), "agents": AGENTS}
