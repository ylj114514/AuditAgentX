"""HarnessVerifier —— 动态验证智能体（DeepAudit 式 Fuzzing Harness 闭环）。

闭环流程（ReAct 思路）：
  1. 提取目标漏洞函数（extract_function）
  2. LLM 生成 Fuzzing Harness（harness_agent_prompt）
  3. 沙箱执行 Harness（run_harness）
  4. 未触发/报错 -> 把执行输出回喂 LLM 自我修正，重试（最多 max_retries 次）
  5. 输出 verdict：confirmed_dynamic / not_reproduced / inconclusive + harness_code + 执行日志

作用：把"生成利用脚本"升级为"生成并真跑，跑通才算数"，是模块③真正的自动化利用验证。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from backend.agents.base_agent import BaseAgent
from backend.config import settings
from backend.skills.harness_tools import extract_function, run_harness, build_template_harness
from backend.mcp.audit_mcp_server import AuditMCPServer
from backend.skills.loader import load_skill

logger = logging.getLogger(__name__)


class HarnessVerifier(BaseAgent):
    name = "harness_verifier"
    prompt_file = "harness_agent_prompt.md"

    def __init__(self, scan_id: "str | None" = None) -> None:
        super().__init__(scan_id=scan_id)
        # 经 MCP 工具边界执行「提取函数 / 运行 Harness」，并加载 dynamic-exploitation Skill
        self.mcp = AuditMCPServer()
        try:
            self.skill = load_skill("dynamic-exploitation")
        except Exception:  # noqa: BLE001
            self.skill = {}
        self._tool_calls: list[dict] = []

    def run(self, finding: dict, code_root: Path | None = None,
            *, max_retries: int | None = None) -> dict:
        max_retries = (max_retries if max_retries is not None
                       else int(getattr(settings, "harness_max_retries", 2)))
        self._tool_calls = []

        func = self._mcp_extract(finding, code_root)
        attempts: list[dict] = []
        last_exec: dict = {}
        harness_code = ""
        harness_source = "llm"

        for attempt in range(max_retries + 1):
            gen = self._generate(finding, func, previous=last_exec if attempt else None)
            harness_code = gen.get("harness_code") or ""
            harness_source = gen.get("_source", "llm")
            if not harness_code.strip():
                attempts.append({"attempt": attempt + 1, "error": "no_harness_generated"})
                break

            last_exec = self._mcp_run(harness_code)
            attempts.append({
                "attempt": attempt + 1,
                "source": harness_source,
                "triggered": last_exec.get("triggered", False),
                "backend": last_exec.get("backend"),
                "stdout": (last_exec.get("stdout") or "")[:400],
                "reason": last_exec.get("reason"),
            })
            # 触发成功，或用的是模板兜底（重试同一模板无意义）-> 停止
            if last_exec.get("triggered") or harness_source == "template":
                break

        verdict = self._verdict(harness_code, last_exec, attempts, func)
        verdict["harness_source"] = harness_source
        verdict["skill"] = {
            "name": self.skill.get("name"),
            "version": self.skill.get("version"),
            "workflow": self.skill.get("workflow", []),
        }
        verdict["tool_calls"] = self._tool_calls
        return verdict

    # ---------- MCP 工具调用（经 AuditMCPServer 边界）----------
    def _mcp_extract(self, finding: dict, code_root: Path | None) -> dict:
        candidate = {
            "file": finding.get("file"),
            "start_line": finding.get("start_line") or finding.get("line"),
            "line": finding.get("line"),
        }
        out = self.mcp.call_tool("extract_target_function", {
            "candidate": candidate,
            "code_root": str(code_root) if code_root else None,
        })["structuredContent"]
        self._tool_calls.append({
            "name": "extract_target_function",
            "purpose": "Extract vulnerable function via MCP for harness building.",
            "success": bool(out.get("found")),
        })
        return out

    def _mcp_run(self, harness_code: str) -> dict:
        out = self.mcp.call_tool("run_fuzzing_harness", {
            "harness_code": harness_code,
        })["structuredContent"]
        self._tool_calls.append({
            "name": "run_fuzzing_harness",
            "purpose": "Execute fuzzing harness in sandbox via MCP.",
            "success": bool(out.get("triggered")),
        })
        return out

    # ---------- 内部 ----------
    def _generate(self, finding: dict, func: dict, previous: dict | None) -> dict:
        payload = {
            "vulnerability": {
                "type": finding.get("type"),
                "file": finding.get("file"),
                "line": finding.get("start_line") or finding.get("line"),
                "code_snippet": finding.get("code_snippet"),
            },
            "target_function": func.get("function_code") or finding.get("code_snippet"),
        }
        if previous:
            # 自我修正：把上一次执行结果回喂，要求改进 Harness
            payload["previous_attempt"] = {
                "triggered": previous.get("triggered"),
                "stdout": (previous.get("stdout") or "")[:600],
                "stderr": (previous.get("stderr") or "")[:400],
                "reason": previous.get("reason"),
                "instruction": ("上一次未触发或报错，请修正 Harness：确认已正确 mock 危险 sink、"
                                "目标函数被真实调用、payload 覆盖更全，并保证打印触发标记。"),
            }
        result = self._call(json.dumps(payload, ensure_ascii=False))
        harness_code = result.get("harness_code") if isinstance(result, dict) else None
        if harness_code:
            return result
        # LLM 不可用/未产出 -> 用按类型的模板 Harness 兜底（离线也能动态验证）
        logger.info("HarnessVerifier 使用模板兜底 Harness (type=%s)", finding.get("type"))
        return {
            "harness_code": build_template_harness(finding.get("type"), finding.get("code_snippet")),
            "_source": "template",
        }

    @staticmethod
    def _verdict(harness_code: str, last_exec: dict, attempts: list[dict],
                 func: dict) -> dict:
        triggered = bool(last_exec.get("triggered"))
        executed = bool(last_exec.get("executed"))
        if triggered:
            verdict, confidence = "confirmed_dynamic", 0.97
        elif executed:
            verdict, confidence = "not_reproduced", 0.5
        else:
            verdict, confidence = "inconclusive", 0.4
        return {
            "verdict": verdict,
            "dynamically_triggered": triggered,
            "confidence": confidence,
            "harness_code": harness_code,
            "trigger_detail": last_exec.get("trigger_detail", ""),
            "execution_backend": last_exec.get("backend"),
            "attempts": attempts,
            "function_extracted": func.get("found", False),
            "execution_log": {
                "stdout": last_exec.get("stdout", ""),
                "stderr": last_exec.get("stderr", ""),
                "reason": last_exec.get("reason"),
            },
        }
