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
import time
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)

# 不值得重试的错误关键词（鉴权/额度类，重试也没用，快速失败）
_NON_RETRYABLE = ("api key", "unauthorized", "permission", "usage limit",
                  "quota", "invalid_api_key", "401", "403")


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
                # Retry exactly once in this wrapper. The SDK's hidden retries
                # otherwise multiply with our loop (3 x 3 attempts per finding)
                # and make a four-worker verification stage appear frozen.
                max_retries=0,
            )
        return self._client

    def chat(self, system_prompt: str, user_content: str, *, json_mode: bool = True) -> str:
        """返回模型原始文本。

        健壮性增强：
        - 指数退避重试（llm_max_retries / llm_retry_backoff）；
        - 鉴权/额度类错误不重试，快速失败；
        - json_mode 被服务拒绝（部分模型不支持 response_format）时，自动降级为普通模式重发一次。
        """
        client = self._get_client()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        def _do(use_json: bool) -> str:
            kwargs: dict[str, Any] = {
                "model": settings.llm_model,
                "temperature": settings.llm_temperature,
                "max_tokens": settings.llm_max_tokens,
                "messages": messages,
            }
            if use_json:
                kwargs["response_format"] = {"type": "json_object"}
            resp = client.chat.completions.create(**kwargs)
            choice = resp.choices[0]
            # 推理模型（deepseek-v4-flash 等）会先耗掉一部分 completion 预算做隐藏推理，
            # 输出较长时会撞上 max_tokens 上限被从中间截断，导致 JSON 解析失败、结论被静默丢弃。
            # 这里显式暴露截断，便于定位「明明有 key 却拿不到有效结论」的问题（对应调大 llm_max_tokens）。
            if getattr(choice, "finish_reason", None) == "length":
                logger.warning(
                    "LLM 输出因 max_tokens=%s 上限被截断(finish_reason=length)，"
                    "JSON 可能不完整、解析失败后结论会被丢弃；建议调大 llm_max_tokens。",
                    settings.llm_max_tokens,
                )
            return choice.message.content or ""

        max_retries = int(getattr(settings, "llm_max_retries", 2))
        backoff = float(getattr(settings, "llm_retry_backoff", 1.5))
        json_downgraded = False
        last_exc: Exception | None = None

        for attempt in range(max_retries + 1):
            try:
                return _do(json_mode and not json_downgraded)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                msg = str(exc).lower()
                # 鉴权/额度类：重试无意义，直接抛
                if any(k in msg for k in _NON_RETRYABLE):
                    logger.warning("LLM 调用不可重试错误（鉴权/额度）: %s", exc)
                    raise
                # json_mode 不被支持：降级为普通模式再试（不计入退避）
                if (json_mode and not json_downgraded
                        and ("response_format" in msg or "json" in msg)):
                    logger.info("模型不支持 json_mode，降级为普通模式重试")
                    json_downgraded = True
                    continue
                if attempt < max_retries:
                    wait = backoff * (2 ** attempt)
                    logger.warning("LLM 调用失败（第 %d 次），%.1fs 后重试: %s",
                                   attempt + 1, wait, exc)
                    time.sleep(wait)
                else:
                    logger.error("LLM 调用重试 %d 次仍失败: %s", max_retries, exc)
        raise last_exc  # type: ignore[misc]

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
