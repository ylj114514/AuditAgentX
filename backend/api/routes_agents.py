"""Agent information route."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/agents", tags=["agents"])

AGENTS = [
    {"name": "OrchestratorAgent", "role": "总控调度，串联完整审计链路"},
    {"name": "RepoParserAgent", "role": "仓库解析：识别语言、框架、依赖、入口和目录结构"},
    {"name": "StaticScanAgent", "role": "静态扫描：调用 Semgrep、Gitleaks、自定义规则等工具生成候选漏洞"},
    {"name": "AuditAgent", "role": "LLM 语义安全审计，补充传统工具可能漏报的风险"},
    {"name": "VerifyAgent", "role": "独立复核候选漏洞，调用本地分析工具过滤误报"},
    {"name": "ExploitAgent", "role": "为已确认漏洞生成授权 PoC、触发位置、利用路径和验证方法"},
    {"name": "DynamicAnalysisAgent", "role": "动态分析调度：识别项目启动方式、提取攻击面端点、按漏洞类型选择动态策略，委托 HTTP/Harness 验证器执行并汇总运行时证据"},
    {"name": "HarnessVerifier", "role": "DeepAudit 式 Fuzzing Harness 动态验证：生成 mock 验证脚本、沙箱执行、自我修正，动态确认漏洞可利用性"},
    {"name": "PocAgent", "role": "生成本地沙箱 PoC 验证方案"},
    {"name": "SummaryAgent", "role": "汇总项目概况、静态/动态验证结果和证据链，生成执行摘要与修改建议"},
    {"name": "ReportAgent", "role": "负责结构化报告渲染与导出"},
]


@router.get("")
def list_agents() -> dict:
    return {"total": len(AGENTS), "agents": AGENTS}
