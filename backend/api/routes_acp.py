"""ACP 通信端点 —— 让外部系统的 Agent 经标准 ACP 协议驱动本系统。

这是 ACP「可扩展为跨系统 Agent 通信」的真实落地：
  外部 Agent → POST /api/acp/message（一条 ACPMessage）→ ACPDispatcher
    → 路由到本系统 verify/exploit/report Agent 的 run_acp() → 返回回复 ACPMessage

配合 backend/mcp/stdio_server.py（MCP 工具通道），本系统对外同时提供
「MCP 工具」与「ACP 消息」两种标准协作接口。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from backend.acp.models import ACPMessage
from backend.acp.dispatcher import ACPDispatcher
from backend.acp.trace import ACPTracer

router = APIRouter(prefix="/api/acp", tags=["acp"])


@router.get("/message-types")
def list_message_types() -> dict:
    """列出本系统可受理的 ACP 请求消息类型（供外部 Agent 发现能力）。"""
    d = ACPDispatcher()
    return {
        "protocol": "AuditAgentX-ACP",
        "version": "1.0",
        "supported_request_types": d.supported_request_types(),
        "endpoint": "POST /api/acp/message",
    }


@router.post("/message")
def post_message(message: dict[str, Any]) -> dict:
    """接收一条 ACPMessage（JSON），分发处理后返回回复 ACPMessage（JSON）。

    请求体即一条 ACPMessage 的 dict 表示（含 header/context/payload/status）。
    可选 header.task_id 作为 scan_id，用于把往返消息落盘到该 scan 的通信流。
    """
    try:
        request = ACPMessage.from_dict(message)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"invalid ACPMessage: {exc}")

    scan_id = request.header.task_id or None
    reply = ACPDispatcher(scan_id=scan_id).dispatch(request)

    # 若带 task_id，则把外部请求与回复一并记入该 scan 的 ACP 通信流，便于回放展示
    if scan_id:
        try:
            tracer = ACPTracer(scan_id=scan_id)
            tracer.save(request)
            tracer.save(reply)
        except Exception:  # noqa: BLE001
            pass

    return reply.to_dict()
