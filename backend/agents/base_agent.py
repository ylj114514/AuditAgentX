"""智能体基类：加载提示词 + 调用 LLM + 记录可复现日志。"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from backend.config import settings
from backend.core.llm_client import llm

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


class BaseAgent:
    name: str = "base_agent"
    prompt_file: str = ""

    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id
        self.system_prompt = self._load_prompt()

    def _load_prompt(self) -> str:
        if not self.prompt_file:
            return ""
        fp = PROMPTS_DIR / self.prompt_file
        return fp.read_text(encoding="utf-8") if fp.exists() else ""

    def _call(self, user_content: str) -> object:
        """调用 LLM 并返回解析后的 JSON，同时落盘原始输入输出以保证可复现。"""
        raw_text = ""
        try:
            raw_text = llm.chat(self.system_prompt, user_content, json_mode=True)
            result = llm.safe_parse_json(raw_text)
        except Exception as e:  # noqa: BLE001
            logger.exception("%s 调用 LLM 失败: %s", self.name, e)
            result = {"_error": str(e)}
        self._trace(user_content, raw_text, result)
        return result

    def _trace(self, user_content: str, raw_text: str, result: object) -> None:
        """保存 prompt / 模型输出，对应 md 文档"结果可复现"创新点。"""
        if not self.scan_id:
            return
        trace_dir = settings.data_path / "scans" / self.scan_id / "agent_traces"
        trace_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        (trace_dir / f"{self.name}_{ts}.json").write_text(
            json.dumps({
                "agent": self.name,
                "model": settings.llm_model,
                "temperature": settings.llm_temperature,
                "system_prompt": self.system_prompt,
                "user_content": user_content,
                "raw_output": raw_text,
                "parsed": result,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
