"""ACP（AuditAgentX-ACP）通信协议数据模型。

按北邮 ACP 字段思想定义 Agent 间通信的统一消息结构。
Python 3.9 兼容：ORM 层 Optional[X]，Pydantic 模型层 X | None。
"""
from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, field_validator


class ACPMessageType(str, Enum):
    """消息类型枚举：粒度为 {阶段}.{动作}。"""
    # 扫描生命周期
    SCAN_START = "scan.start"
    SCAN_COMPLETE = "scan.complete"
    SCAN_FAILED = "scan.failed"

    # 解析 / 静态扫描
    PARSE_REQUEST = "parse.request"
    PARSE_RESULT = "parse.result"
    STATIC_SCAN_REQUEST = "static_scan.request"
    STATIC_SCAN_RESULT = "static_scan.result"

    # 审计
    AUDIT_REQUEST = "audit.request"
    AUDIT_RESULT = "audit.result"

    # 验证
    VERIFY_REQUEST = "verify.request"
    VERIFY_RESULT = "verify.result"

    # 漏洞利用生成
    EXPLOIT_GENERATE_REQUEST = "exploit.generate.request"
    EXPLOIT_GENERATE_RESULT = "exploit.generate.result"

    # 动态验证
    DYNAMIC_VERIFY_REQUEST = "dynamic.verify.request"
    DYNAMIC_VERIFY_RESULT = "dynamic.verify.result"
    DYNAMIC_PROGRESS = "dynamic.progress"

    # Harness 验证
    HARNESS_VERIFY_REQUEST = "harness.verify.request"
    HARNESS_VERIFY_RESULT = "harness.verify.result"

    # 报告
    REPORT_REQUEST = "report.request"
    REPORT_RESULT = "report.result"

    # 通用
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class ACPState(str, Enum):
    """消息状态枚举。"""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    PENDING = "pending"


class ACPVerdict(str, Enum):
    """裁决结果枚举。

    完整取值集合——每个值的语义必须严格区分：
      not_executed   : 未曾尝试执行（如未配置 base_url）
      not_reproduced : 执行了但载荷未命中成功特征
      model_gap      : Harness 已执行，但受控模型或本地导入无法代表目标代码
    """
    # 静态层
    CANDIDATE = "candidate"
    STATICALLY_VERIFIED = "statically_verified"
    FALSE_POSITIVE = "false_positive"

    # 利用层
    EXPLOIT_GENERATED = "exploit_generated"

    # 动态 HTTP 层
    DYNAMIC_CONFIRMED = "dynamic_confirmed"
    NOT_REPRODUCED = "not_reproduced"          # 执行了但未命中
    NOT_EXECUTED = "not_executed"              # 未执行（未配置目标）
    CONNECTION_FAILED = "connection_failed"
    ENDPOINT_NOT_FOUND = "endpoint_not_found"
    REQUEST_TIMEOUT = "request_timeout"
    PAYLOAD_NOT_MATCHED = "payload_not_matched"
    MODEL_GAP = "model_gap"

    # Harness 层
    HARNESS_CONFIRMED = "harness_confirmed"
    HARNESS_INCONCLUSIVE = "harness_inconclusive"

    # 综合
    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs_review"


class ACPHeader(BaseModel):
    """ACP 消息头：标识消息的元信息与路由信息。"""
    protocol: str = "AuditAgentX-ACP"
    version: str = "1.0"
    message_id: str
    conversation_id: str = ""
    task_id: str = ""
    sender: str                        # 发送方 Agent 名称
    receiver: str                      # 接收方 Agent 名称
    message_type: ACPMessageType | str
    intent: str = ""                   # 人类可读的意图描述
    timestamp: str                     # ISO 8601
    trace_id: str = ""                 # 跨多条消息的追踪 ID
    in_reply_to: str | None = None     # 被回复消息的 message_id


class ACPContext(BaseModel):
    """ACP 上下文：任务级元信息，所有消息共享一套 context。"""
    project_id: str = ""
    scan_id: str = ""
    code_root: str | None = None
    enabled_tools: list[str] = Field(default_factory=list)
    enabled_agents: list[str] = Field(default_factory=list)
    options: dict[str, Any] = Field(default_factory=dict)


class ACPStatus(BaseModel):
    """ACP 状态：本条消息的执行结果。"""
    state: ACPState = ACPState.SUCCESS
    verdict: ACPVerdict | str | None = None
    confidence: float | None = None
    detail: str = ""


class ACPFinding(BaseModel):
    """统一 finding 字段结构（Payload 内部）。

    所有 Agent 的 finding 都使用此结构，废弃旧散字段写法。
    """
    finding_id: str = ""
    type: str | None = None
    severity: str = "medium"
    location: dict[str, Any] = Field(default_factory=dict)   # {file, start_line, end_line}
    code: dict[str, Any] = Field(default_factory=dict)        # {snippet}
    source: dict[str, Any] = Field(default_factory=dict)      # {agent, tool, rule_id}
    description: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class ACPVerification(BaseModel):
    """VerifyAgent 输出的核查结果（Payload 内部）。"""
    static_verdict: str = "uncertain"      # confirmed | false_positive | uncertain
    dynamic_verdict: str = "not_executed"  # dynamic_confirmed|not_reproduced|not_executed|...
    final_verdict: str = "needs_review"    # statically_verified|dynamic_confirmed|harness_confirmed|false_positive|needs_review
    source: str | None = None
    sink: str | None = None
    call_path: list[dict[str, Any]] = Field(default_factory=list)
    evidence_chain: dict[str, Any] = Field(default_factory=dict)
    false_positive_reason: str | None = None
    recommended_poc_strategy: str | None = None
    confidence: float = 0.5

    @field_validator("call_path", mode="before")
    @classmethod
    def _coerce_call_path(cls, v: Any) -> list:
        """LLM 有时把 call_path 输出成字符串（如 "a.py:63-65"），这里统一转成 list[dict]。"""
        if v is None:
            return []
        if isinstance(v, list):
            return [hop if isinstance(hop, dict) else {"stage": "path", "detail": str(hop)}
                    for hop in v]
        if isinstance(v, str):
            return [{"stage": "path", "detail": v}] if v.strip() else []
        if isinstance(v, dict):
            return [v]
        return [{"stage": "path", "detail": str(v)}]

    @field_validator("evidence_chain", mode="before")
    @classmethod
    def _coerce_evidence_chain(cls, v: Any) -> dict:
        """LLM 有时把 evidence_chain 输出成字符串描述，这里统一转成 dict。"""
        if v is None:
            return {}
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            return {"summary": v} if v.strip() else {}
        if isinstance(v, list):
            return {"items": v}
        return {"summary": str(v)}


class ACPExploit(BaseModel):
    """ExploitAgent 输出的利用方案（Payload 内部）。"""
    vuln_type: str | None = None
    trigger_location: str | None = None
    exploit_path: str | None = None
    attack_vector: str | None = None
    payloads: list[str] = Field(default_factory=list)
    exploit_code: str | None = None
    success_indicators: list[str] = Field(default_factory=list)
    safety_notes: str = "仅限本地授权沙箱环境，禁止攻击真实第三方系统。"

    @field_validator("payloads", "success_indicators", mode="before")
    @classmethod
    def _coerce_str_list(cls, v: Any) -> list:
        """LLM 有时把列表字段输出成单个字符串，这里统一转成 list[str]。"""
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            return [v] if v.strip() else []
        return [str(v)]


class ACPToolCall(BaseModel):
    """单个 MCP tool 调用记录。"""
    tool_name: str
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    error: str | None = None


class ACPArtifact(BaseModel):
    """消息附带的制品（代码、文件、截图等）。"""
    artifact_id: str = ""
    artifact_type: str = ""     # exploit_code | harness_code | report | screenshot
    name: str = ""
    content: str = ""           # 文本内容，大文件用路径代替
    path: str | None = None
    mime_type: str = "text/plain"


class ACPMessage(BaseModel):
    """AuditAgentX-ACP 统一消息结构。

    所有 Agent 间通信均使用此结构，确保字段接口一致。
    """
    header: ACPHeader
    context: ACPContext = Field(default_factory=ACPContext)
    payload: dict[str, Any] = Field(default_factory=dict)
    tools: list[ACPToolCall] = Field(default_factory=list)
    artifacts: list[ACPArtifact] = Field(default_factory=list)
    status: ACPStatus = Field(default_factory=ACPStatus)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """序列化为可落盘的纯 dict。"""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ACPMessage":
        """从 dict 反序列化（读取 trace 文件用）。"""
        return cls.model_validate(data)
