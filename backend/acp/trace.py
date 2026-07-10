"""ACP 消息追踪器：持久化与回放 ACPMessage。

消息保存路径：data/scans/{scan_id}/agent_messages/{timestamp}_{message_type}.json
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.acp.models import ACPMessage

logger = logging.getLogger(__name__)


class ACPTracer:
    """把 ACPMessage 保存到 scan 目录，并能读回。

    用法：
        tracer = ACPTracer(scan_id="abc123", data_path=settings.data_path)
        tracer.save(msg)
        messages = tracer.load_all()
    """

    def __init__(self, scan_id: str, data_path: Optional[Path] = None) -> None:
        self.scan_id = scan_id
        if data_path is None:
            # 延迟导入避免循环依赖
            from backend.config import settings
            data_path = settings.data_path
        self.base_dir: Path = data_path / "scans" / scan_id / "agent_messages"

    def _ensure_dir(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save(self, msg: ACPMessage) -> Path:
        """将一条 ACPMessage 序列化并写入 JSON 文件，返回文件路径。"""
        self._ensure_dir()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        # 消息类型中的点替换为下划线，用作文件名一部分
        mtype = str(msg.header.message_type).replace(".", "_")
        filename = f"{ts}_{mtype}_{msg.header.message_id}.json"
        fp = self.base_dir / filename
        try:
            fp.write_text(
                json.dumps(msg.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ACPTracer 保存消息失败: %s", exc)
        return fp

    def load_all(self) -> list[ACPMessage]:
        """读取该 scan 目录下所有 agent_messages/*.json，按时间戳排序返回。"""
        if not self.base_dir.exists():
            return []
        msgs: list[ACPMessage] = []
        for fp in sorted(self.base_dir.glob("*.json")):
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
                msgs.append(ACPMessage.from_dict(data))
            except Exception as exc:  # noqa: BLE001
                logger.warning("ACPTracer 读取消息失败 %s: %s", fp.name, exc)
        return msgs

    def load_by_type(self, message_type: str) -> list[ACPMessage]:
        """仅返回指定 message_type 的消息列表。"""
        return [m for m in self.load_all()
                if getattr(m.header.message_type, "value", m.header.message_type) == message_type]

    def summary(self) -> list[dict[str, Any]]:
        """返回所有消息的摘要列表（message_id / sender / receiver / type / state / verdict）。"""
        result = []
        for msg in self.load_all():
            mtype = msg.header.message_type
            mtype_str = mtype.value if hasattr(mtype, "value") else str(mtype)
            state = msg.status.state
            state_str = state.value if hasattr(state, "value") else str(state)
            verdict = msg.status.verdict
            verdict_str = (verdict.value if hasattr(verdict, "value") else str(verdict)) if verdict else None
            result.append({
                "message_id": msg.header.message_id,
                "timestamp": msg.header.timestamp,
                "sender": msg.header.sender,
                "receiver": msg.header.receiver,
                "message_type": mtype_str,
                "intent": msg.header.intent,
                "state": state_str,
                "verdict": verdict_str,
                "confidence": msg.status.confidence,
            })
        return result
