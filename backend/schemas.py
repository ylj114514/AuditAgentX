"""Pydantic 请求/响应模型（对应 md 文档第 7 节接口设计）。"""
from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


# ---------- Project ----------
class ProjectCreate(BaseModel):
    name: str
    source_type: str = Field("git", description="git | local")
    url: str | None = None
    local_path: str | None = None
    branch: str | None = "main"
    description: str | None = None


class ProjectOut(BaseModel):
    project_id: str
    status: str
    message: str | None = None


class ProjectMetadata(BaseModel):
    languages: list[str] = []
    frameworks: list[str] = []
    dependencies: list[str] = []
    entrypoints: list[str] = []
    file_count: int = 0
    loc: int = 0


# ---------- Scan ----------
class ScanOptions(BaseModel):
    enable_poc: bool = False
    enable_sandbox: bool = False
    enable_exploit: bool = False           # 是否生成漏洞利用方案（模块③）
    enable_dynamic: bool = False           # 是否执行 HTTP 动态验证
    enable_harness: bool = False           # 是否执行 Fuzzing Harness 动态验证（DeepAudit 式）
    dynamic_target: dict[str, Any] | None = None  # 动态靶场配置 {mode,...}
    max_verify_workers: int | None = None  # VerifyAgent 静态复核并发数；为空则使用后端配置
    max_verify_candidates: int | None = None  # 最多送入 VerifyAgent LLM 复核的候选数
    # 最多对多少条候选执行「生成利用 + 动态验证」；为空则用后端默认(20)。用户可按需
    # 调大以覆盖更多注入类候选（代价：更多 HTTP/Harness 执行，扫描更慢）。
    max_dynamic_candidates: int | None = None
    include_test_findings: bool = False  # 默认只审计生产代码；需要时显式纳入 sample/tests/docs
    max_files: int = 20000
    severity_threshold: str = "low"


class ScanCreate(BaseModel):
    project_id: str
    scan_type: str = "full"
    # 扫描模式：quick（仅静态）| standard（+语义审计+复核）| deep（+Docker 沙箱动态验证）
    scan_mode: str | None = None
    enabled_tools: list[str] = ["semgrep", "bandit", "gitleaks", "trivy"]
    enabled_agents: list[str] = ["audit", "verify"]
    options: ScanOptions = ScanOptions()


class ScanOut(BaseModel):
    scan_id: str
    status: str


class ScanStatus(BaseModel):
    scan_id: str
    project_id: str
    status: str
    progress: int
    current_stage: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    stage_detail: dict[str, Any] | None = None


# ---------- Finding ----------
class FindingBrief(BaseModel):
    finding_id: str
    type: str | None
    severity: str
    file: str | None
    line: int | None
    confidence: float
    verified: bool
    status: str


class FindingDetail(BaseModel):
    finding_id: str
    type: str | None
    severity: str
    file: str | None
    start_line: int | None
    end_line: int | None
    vulnerable_code: str | None
    source: str | None = None
    sink: str | None = None
    data_flow: list[dict[str, Any]] = []
    verification: dict[str, Any] = {}
    fix_suggestion: str | None = None


# ---------- 动态验证（md 7.8）----------
class VerifyRequest(BaseModel):
    mode: str = "sandbox"                   # sandbox | local | url
    timeout: int = 60
    base_url: str | None = None             # mode=url 时的已运行靶场地址
    endpoints: list[str] | None = None      # 指定探测端点
    dynamic_target: dict[str, Any] | None = None  # mode=local/docker 时的启动配置


class VerifyResponse(BaseModel):
    finding_id: str
    verified: bool
    reproducible: bool
    matched_indicator: str | None = None
    evidence_id: str | None = None
    message: str


# ---------- Report ----------
class ReportCreate(BaseModel):
    scan_id: str
    format: Literal["html", "markdown", "pdf", "json"] = "html"
    include_poc: bool = True
    include_fix: bool = True


class ReportOut(BaseModel):
    report_id: str
    status: str
    download_url: str | None = None
