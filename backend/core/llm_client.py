"""大模型统一调用封装（OpenAI 兼容接口）。

设计要点（对应 md 文档第 16 节"LLM 输出不稳定"风险）：
- 统一入口，方便替换 DeepSeek/Qwen/OpenAI/本地模型；
- 强制 JSON 输出 + 容错解析；
- 记录 prompt 与原始输出，保证可复现。
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)


class LLMClient:
    def __init__(self) -> None:
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(
                api_key=settings.llm_api_key,
                base_url=settings.llm_base_url,
                timeout=settings.llm_timeout,
            )
        return self._client

    def chat(self, system_prompt: str, user_content: str, *, json_mode: bool = True) -> str:
        """返回模型原始文本。"""
        client = self._get_client()
        kwargs: dict[str, Any] = {
            "model": settings.llm_model,
            "temperature": settings.llm_temperature,
            "max_tokens": settings.llm_max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        }
        if json_mode:
            # 多数 OpenAI 兼容服务支持；不支持时靠下面的正则兜底
            kwargs["response_format"] = {"type": "json_object"}
        resp = client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""

    def chat_json(self, system_prompt: str, user_content: str) -> Any:
        """调用并解析为 JSON 对象；解析失败返回 {'_raw': ...}。"""
        raw = self.chat(system_prompt, user_content, json_mode=True)
        return self.safe_parse_json(raw)

    @staticmethod
    def safe_parse_json(text: str) -> Any:
        """从可能包含 markdown 代码块的文本中提取 JSON。"""
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # 去掉 ```json ... ``` 包裹
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        # 尝试截取第一个 { 到最后一个 }
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
        logger.warning("LLM 输出无法解析为 JSON，返回原文。")
        return {"_raw": text}


# 全局单例
llm = LLMClient()
