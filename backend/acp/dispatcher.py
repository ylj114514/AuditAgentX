"""ACP 消息分发中枢 —— 把 ACP 从"旁路记录"升级为"真正驱动 Agent 通信"。

职责：接收一条 ACPMessage（可来自内部编排，也可来自外部系统的 Agent），
按 header.message_type 路由到对应 Agent 的 run_acp()，返回回复 ACPMessage。

这使 ACP 不再只是"消息格式定义"：
  - 内部：编排器可通过 dispatch() 以消息驱动方式调用各 Agent；
  - 外部：其他系统的 Agent 可经 HTTP 端点（routes_acp）发 ACP 消息进来，
    驱动本系统的 verify / exploit / report，实现跨系统 Agent 协作。
"""
from __future__ import annotations

import logging

from backend.acp.factory import make_reply
from backend.acp.models import ACPMessage, ACPMessageType, ACPState

logger = logging.getLogger(__name__)


class ACPDispatcher:
    """按 message_type 把请求消息分发到对应 Agent 的 run_acp()。"""

    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id

    def supported_request_types(self) -> list[str]:
        return [
            ACPMessageType.PARSE_REQUEST.value,
            ACPMessageType.STATIC_SCAN_REQUEST.value,
            ACPMessageType.AUDIT_REQUEST.value,
            ACPMessageType.VERIFY_REQUEST.value,
            ACPMessageType.EXPLOIT_GENERATE_REQUEST.value,
            ACPMessageType.DYNAMIC_VERIFY_REQUEST.value,
        ]

    def dispatch(self, request: ACPMessage) -> ACPMessage:
        """把一条请求消息路由到目标 Agent，返回其回复消息。"""
        mtype = request.header.message_type
        mtype_val = mtype.value if hasattr(mtype, "value") else str(mtype)

        try:
            # 解析 / 静态扫描：对应 Agent 不接受 scan_id（无 LLM trace 需求）
            if mtype_val == ACPMessageType.PARSE_REQUEST.value:
                from backend.agents.repo_parser_agent import RepoParserAgent
                return RepoParserAgent().run_acp(request)
            if mtype_val == ACPMessageType.STATIC_SCAN_REQUEST.value:
                from backend.agents.static_scan_agent import StaticScanAgent
                return StaticScanAgent().run_acp(request)
            if mtype_val == ACPMessageType.AUDIT_REQUEST.value:
                from backend.agents.audit_agent import AuditAgent
                return AuditAgent(scan_id=self.scan_id).run_acp(request)
            if mtype_val == ACPMessageType.VERIFY_REQUEST.value:
                from backend.agents.verify_agent import VerifyAgent
                return VerifyAgent(scan_id=self.scan_id).run_acp(request)
            if mtype_val == ACPMessageType.EXPLOIT_GENERATE_REQUEST.value:
                from backend.agents.exploit_agent import ExploitAgent
                return ExploitAgent(scan_id=self.scan_id).run_acp(request)
            if mtype_val == ACPMessageType.DYNAMIC_VERIFY_REQUEST.value:
                from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent
                return DynamicAnalysisAgent(scan_id=self.scan_id).run_acp(request)
        except Exception as exc:  # noqa: BLE001
            logger.exception("ACP dispatch 处理 %s 失败: %s", mtype_val, exc)
            return make_reply(
                request, sender="acp_dispatcher",
                message_type=ACPMessageType.ERROR,
                intent=f"处理 {mtype_val} 时发生错误",
                state=ACPState.FAILED, error=str(exc),
            )

        # 未知/不支持的消息类型
        return make_reply(
            request, sender="acp_dispatcher",
            message_type=ACPMessageType.ERROR,
            intent=f"不支持的 message_type: {mtype_val}",
            state=ACPState.FAILED,
            error=f"unsupported message_type '{mtype_val}'. "
                  f"supported: {', '.join(self.supported_request_types())}",
        )


def dispatch(request: ACPMessage, scan_id: str | None = None) -> ACPMessage:
    """便捷函数：分发一条 ACP 请求消息。"""
    return ACPDispatcher(scan_id=scan_id).dispatch(request)
