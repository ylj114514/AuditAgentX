"""ACP 适配器：legacy dict ↔ ACPMessage 互转 + finding 字段统一。

关键原则：保证向后兼容。
  - legacy -> ACP：取旧字段映射到 ACPFinding / ACPMessage
  - ACP -> legacy：能还原成系统其他模块期望的旧字段 dict

finding 统一结构：
  {
    finding_id, type, severity,
    location:  {file, start_line, end_line},
    code:      {snippet},
    source:    {agent, tool, rule_id},
    description,
    extra: {}
  }
"""
from __future__ import annotations

import uuid
from typing import Any

from backend.acp.models import (
    ACPMessage, ACPFinding, ACPContext,
    ACPMessageType, ACPState, ACPVerdict,
)
from backend.acp.factory import make_message


# ---------------------------------------------------------------------------
# Finding 字段统一转换
# ---------------------------------------------------------------------------

def raw_finding_to_acp(rf: Any) -> dict[str, Any]:
    """RawFinding dataclass → 统一 ACP finding dict。

    RawFinding 字段：type, file, line, severity, source, code_snippet,
                     message, rule_id, extra
    """
    # 兼容 dataclass 和 dict 两种输入
    if hasattr(rf, "type"):
        d = {
            "type": rf.type,
            "file": rf.file,
            "line": rf.line,
            "severity": rf.severity,
            "source": rf.source,
            "code_snippet": getattr(rf, "code_snippet", ""),
            "message": getattr(rf, "message", ""),
            "rule_id": getattr(rf, "rule_id", ""),
            "extra": getattr(rf, "extra", {}),
        }
    else:
        d = dict(rf)

    finding = ACPFinding(
        finding_id=str(uuid.uuid4()),
        type=d.get("type"),
        severity=d.get("severity", "medium"),
        location={
            "file": d.get("file"),
            "start_line": d.get("line"),
            "end_line": d.get("line"),
        },
        code={"snippet": d.get("code_snippet", "")},
        source={
            "agent": "static_scan_agent",
            "tool": d.get("source", ""),
            "rule_id": d.get("rule_id", ""),
        },
        description=d.get("message", ""),
        extra=d.get("extra") or {},
    )
    return finding.model_dump()


def audit_finding_to_acp(lf: dict[str, Any]) -> dict[str, Any]:
    """AuditAgent LLM finding dict → 统一 ACP finding dict。

    AuditAgent finding 字段：vulnerability_type, severity, file_path,
                              start_line, end_line, vulnerable_code,
                              confidence, fix_suggestion, ...
    """
    finding = ACPFinding(
        finding_id=str(uuid.uuid4()),
        type=lf.get("vulnerability_type") or lf.get("type"),
        severity=lf.get("severity", "medium"),
        location={
            "file": lf.get("file_path") or lf.get("file"),
            "start_line": lf.get("start_line") or lf.get("line"),
            "end_line": lf.get("end_line"),
        },
        code={"snippet": lf.get("vulnerable_code") or lf.get("code_snippet", "")},
        source={
            "agent": "audit_agent",
            "tool": "llm",
            "rule_id": "",
        },
        description=lf.get("description") or lf.get("message", ""),
        extra={
            k: v for k, v in lf.items()
            if k not in (
                "vulnerability_type", "type", "severity", "file_path", "file",
                "start_line", "end_line", "line", "vulnerable_code", "code_snippet",
                "description", "message",
            )
        },
    )
    return finding.model_dump()


def legacy_finding_to_acp(f: dict[str, Any]) -> dict[str, Any]:
    """Orchestrator 候选 finding dict（散字段）→ 统一 ACP finding dict。

    旧字段：type, severity, file, start_line, line, end_line,
            code_snippet, confidence, source, status, message, detail
    """
    extra = {
        k: v for k, v in f.items()
        if k not in (
            "type", "severity", "file", "file_path", "start_line", "line",
            "end_line", "code_snippet", "source", "message", "extra",
        )
    }
    extra.update(f.get("extra") or {})
    finding = ACPFinding(
        finding_id=f.get("finding_id") or str(uuid.uuid4()),
        type=f.get("type"),
        severity=f.get("severity", "medium"),
        location={
            "file": f.get("file") or f.get("file_path"),
            "start_line": f.get("start_line") or f.get("line"),
            "end_line": f.get("end_line"),
        },
        code={"snippet": f.get("code_snippet", "")},
        source={
            "agent": f.get("source", ""),
            "tool": f.get("source", ""),
            "rule_id": f.get("rule_id", ""),
        },
        description=f.get("message", ""),
        extra=extra,
    )
    return finding.model_dump()


def acp_to_legacy_finding(acp_finding: dict[str, Any]) -> dict[str, Any]:
    """统一 ACP finding dict → 旧散字段 dict（向后兼容）。"""
    location = acp_finding.get("location") or {}
    code = acp_finding.get("code") or {}
    source = acp_finding.get("source") or {}
    extra = acp_finding.get("extra") or {}

    legacy = {
        "type": acp_finding.get("type"),
        "severity": acp_finding.get("severity", "medium"),
        "file": location.get("file"),
        "start_line": location.get("start_line"),
        "end_line": location.get("end_line"),
        "line": location.get("start_line"),
        "code_snippet": code.get("snippet", ""),
        "source": source.get("tool") or source.get("agent", ""),
        "message": acp_finding.get("description", ""),
        "confidence": extra.get("confidence", 0.5),
        "verified": extra.get("verified", False),
        "status": extra.get("status", "candidate"),
    }
    # 保留 extra 中的其他字段
    for k, v in extra.items():
        if k not in legacy:
            legacy[k] = v
    return legacy


# ---------------------------------------------------------------------------
# ACPMessage ↔ legacy dict
# ---------------------------------------------------------------------------

def legacy_dict_to_message(
    d: dict[str, Any],
    *,
    sender: str,
    receiver: str,
    message_type: ACPMessageType | str = ACPMessageType.AUDIT_REQUEST,
    intent: str = "",
    scan_id: str = "",
    project_id: str = "",
) -> ACPMessage:
    """把任意旧格式 dict 包装成 ACPMessage（payload = 原始 dict）。

    用于将旧接口的输入/输出纳入 ACP 通信体系，保证向后兼容。
    """
    context = ACPContext(
        scan_id=scan_id,
        project_id=project_id,
    )
    return make_message(
        sender=sender,
        receiver=receiver,
        message_type=message_type,
        intent=intent,
        context=context,
        payload=d,
    )


def message_to_legacy_dict(msg: ACPMessage) -> dict[str, Any]:
    """把 ACPMessage 还原为 payload dict（向下兼容旧代码读取）。

    若 payload 不为空则直接返回 payload，否则返回整条消息的 dict 摘要。
    """
    if msg.payload:
        return dict(msg.payload)
    return {
        "message_id": msg.header.message_id,
        "message_type": msg.header.message_type,
        "sender": msg.header.sender,
        "receiver": msg.header.receiver,
        "status": msg.status.state,
        "verdict": msg.status.verdict,
    }
