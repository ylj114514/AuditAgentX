"""HarnessVerifier —— 动态验证智能体（DeepAudit 式 Fuzzing Harness 闭环）。

闭环流程（ReAct 思路）：
  1. 提取目标漏洞函数（extract_function）
  2. LLM 生成 Fuzzing Harness（harness_agent_prompt）
  3. 沙箱执行 Harness（run_harness）
  4. 未触发/报错 -> 把执行输出回喂 LLM 自我修正，重试（最多 max_retries 次）
  5. 输出 verdict：dynamic_confirmed / not_reproduced / inconclusive + harness_code + 执行日志

作用：把"生成利用脚本"升级为"生成并真跑，跑通才算数"，是模块③真正的自动化利用验证。
"""
from __future__ import annotations

import json
import hashlib
import logging
from pathlib import Path

from backend.agents.base_agent import BaseAgent
from backend.config import settings
from backend.skills.harness_tools import (
    extract_function, run_harness, build_template_harness, normalize_language,
    build_target_scaffold_harness, build_import_scaffold_harness,
    build_route_testclient_harness, build_django_classview_harness,
    build_selfcontained_slice_harness, build_selfcontained_slice_harness_multilang,
    scaffold_capability,
)
from backend.mcp.audit_mcp_server import AuditMCPServer
from backend.skills.loader import load_skill
from backend.dynamic.strategy import is_harness_applicable, resolve_strategy

logger = logging.getLogger(__name__)

# HarnessVerifier 输出的 finding 级 verdict -> (dynamically_triggered, function_mechanism_verified, confidence)
_VERDICT_EFFECT = {
    "target_confirmed":       (True,  True,  0.97),   # 需额外具备真实入口可达性证明
    "function_reproduced":    (False, True,  0.85),   # 真实函数单元触发，不等价端到端可利用
    "mechanism_confirmed":    (False, True,  0.75),   # 仅模板机理，封顶 0.75，不算完全动态确认
    "synthetic_demo_only":    (False, False, 0.40),   # 玩具程序触发，不是项目漏洞证据
    "not_reproduced":         (False, False, 0.50),
    "inconclusive":           (False, False, 0.40),
    "sandbox_failed":         (False, False, 0.40),
    "unsafe_harness_blocked": (False, False, 0.40),
    "not_applicable":         (False, False, 0.40),
}


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

        # 0) 不适合函数级 Harness 的类型（硬编码密钥/弱加密/配置类）直接判 not_applicable
        strategy = resolve_strategy(finding.get("type"))
        if not is_harness_applicable(finding.get("type")):
            return self._finalize_verdict(
                "not_applicable", {}, [], {"found": False}, "n/a", "n/a",
                reason=f"{strategy.get('reason_code')}: {strategy.get('reason')}")

        func = self._mcp_extract(finding, code_root)
        target_lang = normalize_language(func.get("language"))
        attempts: list[dict] = []
        last_exec: dict = {}
        harness_source = "llm"
        harness_lang = target_lang

        for attempt in range(max_retries + 1):
            gen = self._generate(finding, func, target_lang,
                                 previous=last_exec if attempt else None, code_root=code_root)
            harness_code = gen.get("harness_code") or ""
            harness_source = gen.get("_source", "llm")
            harness_lang = gen.get("_language", target_lang)
            if not harness_code.strip():
                attempts.append({"attempt": attempt + 1, "error": "no_harness_generated"})
                last_exec = {"verdict": "inconclusive", "reason": "no_harness_generated"}
                break

            trusted_scaffold = harness_source == "scaffold"
            last_exec = self._mcp_run(
                harness_code, harness_lang, harness_source,
                code_root=str(code_root) if (trusted_scaffold and code_root) else None,
                harness_kind=gen.get("_kind") if trusted_scaffold else None,
            )
            last_exec["harness_kind"] = gen.get("_kind") or harness_source
            last_exec["attempt"] = attempt + 1
            attempts.append({
                "attempt": attempt + 1, "source": harness_source, "language": harness_lang,
                "verdict": last_exec.get("verdict"),
                "triggered": last_exec.get("triggered", False),
                "verification_level": last_exec.get("verification_level"),
                "backend": last_exec.get("backend"),
                "sink_name": last_exec.get("sink_name"),
                "reason": last_exec.get("reason"),
                "stdout": (last_exec.get("stdout") or "")[:400],
            })
            # 停止条件：已证明目标级、被安全阻止或沙箱失败。route/import 型
            # scaffold 若连真实调用都没有证明（典型为 import 依赖失败），不能把一次失败
            # 当作结论；下一轮强制尝试不 import 应用的自包含切片。
            exec_verdict = last_exec.get("verdict")
            if (exec_verdict in ("target_confirmed", "mechanism_confirmed", "synthetic_demo_only",
                                 "unsafe_harness_blocked", "sandbox_failed")):
                break
            failed_route_or_import = (
                harness_source == "scaffold"
                and last_exec.get("harness_kind") in ("testclient_route", "django_class_view", "import_module")
                and (not last_exec.get("target_function_called")
                     or bool(last_exec.get("import_error")))
            )
            if failed_route_or_import:
                continue
            # 切片、模板及其它确定性脚手架的失败不会靠相同生成器的重试变好。
            if harness_source in ("template", "scaffold"):
                break

        # 执行级 verdict -> finding 级 verdict
        finding_verdict = self._map_finding_verdict(last_exec, harness_source)
        return self._finalize_verdict(finding_verdict, last_exec, attempts, func,
                                      harness_source, harness_lang)

    @staticmethod
    def _map_finding_verdict(last_exec: dict, harness_source: str) -> str:
        """run_harness 的执行级 verdict -> HarnessVerifier 的 finding 级 verdict。"""
        ev = last_exec.get("verdict") or "inconclusive"
        if ev in ("unsafe_harness_blocked", "sandbox_failed", "not_reproduced",
                  "target_confirmed", "function_reproduced", "mechanism_confirmed",
                  "synthetic_demo_only"):
            return ev
        return "inconclusive"

    def _finalize_verdict(self, verdict: str, last_exec: dict, attempts: list,
                          func: dict, harness_source: str, harness_lang: str,
                          *, reason: str | None = None) -> dict:
        confirmed_blockers: list[str] = []
        if verdict == "target_confirmed":
            if not func.get("found"):
                confirmed_blockers.append("function_extracted=false: target project function was not extracted")
            if not last_exec.get("target_function_called"):
                confirmed_blockers.append("target_function_called=false: harness did not prove real target invocation")
            if last_exec.get("verification_level") not in ("target_specific", "entrypoint_reproduced"):
                confirmed_blockers.append("verification_level is not target/entrypoint level")
            if harness_source == "template":
                confirmed_blockers.append("template harness is mechanism-only")
            if harness_source != "scaffold":
                confirmed_blockers.append(
                    "target confirmation requires a backend-generated scaffold; LLM self-report is untrusted"
                )
            # 入口级可达性：框架经真实路由 test-client 调到真实 handler（nonce 证明），
            # 且用户输入送达 sink（marker 证明）——「路由入口→处理函数→危险 sink」可审计关联齐全。
            entrypoint_ok = bool(
                last_exec.get("entrypoint_reachable")
                and last_exec.get("verification_level") == "entrypoint_reproduced"
            )
            if confirmed_blockers:
                verdict = "mechanism_confirmed" if last_exec.get("triggered") else "inconclusive"
                reason = "; ".join(confirmed_blockers)
            elif entrypoint_ok:
                # 端到端动态确认：真实入口 -> 真实源码 -> 危险 sink 可达性成立，保持 target_confirmed。
                reason = ("真实路由入口经框架 test-client 调用真实 handler（nonce 证明），"
                          "用户输入送达危险 sink（marker 证明）；入口→源码→sink 可达性成立。")
            else:
                # nonce 只证明框架强制调用了抽取函数；尚未证明真实 HTTP/CLI/消息入口
                # 能把攻击输入送到该函数。因此诚实标记为函数单元复现。
                verdict = "function_reproduced"
                reason = (
                    "真实目标函数在隔离 Harness 中把攻击 payload 送达 sink；"
                    "尚缺少 entrypoint-to-source-to-function 可达性证据，不能升级端到端动态确认。"
                )
        triggered, mechanism_verified, confidence = _VERDICT_EFFECT.get(
            verdict, (False, False, 0.40))
        return {
            "verdict": verdict,
            "dynamically_triggered": triggered,           # 仅 target_confirmed 为 True
            "function_mechanism_verified": mechanism_verified,
            "confidence": confidence,
            "verification_level": last_exec.get("verification_level", "none"),
            "harness_source": harness_source,
            "harness_kind": last_exec.get("harness_kind") or harness_source,
            "harness_language": harness_lang,
            "harness_code": last_exec.get("_harness_code") or "",
            "sink_name": last_exec.get("sink_name"),
            "captured_argument": last_exec.get("captured_argument"),
            "payload": last_exec.get("payload"),
            "target_function_called": last_exec.get("target_function_called", False),
            "entrypoint_reachable": bool(last_exec.get("entrypoint_reachable")),
            "trigger_detail": last_exec.get("trigger_detail", ""),
            "execution_backend": last_exec.get("backend"),
            "sandbox_image": last_exec.get("sandbox_image"),
            "nonce_attestation": last_exec.get("nonce_attestation"),
            "function_extracted": func.get("found", False),
            "function_name": func.get("function_name"),
            "function_location": {
                "file": func.get("file"),
                "start_line": func.get("start_line") or func.get("line"),
                "end_line": func.get("end_line") or func.get("start_line") or func.get("line"),
                "function_name": func.get("function_name"),
                "class_name": func.get("class_name"),
                "module_path": func.get("module_path"),
            },
            "function_code_sha256": (
                hashlib.sha256(str(func.get("function_code")).encode("utf-8", "ignore")).hexdigest()
                if func.get("function_code") else None
            ),
            "harness_code_sha256": (
                hashlib.sha256(str(last_exec.get("_harness_code")).encode("utf-8", "ignore")).hexdigest()
                if last_exec.get("_harness_code") else None
            ),
            "confirmed_blockers": confirmed_blockers,
            "safety": last_exec.get("safety", {"allowed": True, "blocked_reason": None, "checks": []}),
            "attempts": attempts,
            "reason": reason or last_exec.get("reason"),
            "execution_log": {
                "stdout": last_exec.get("stdout", ""),
                "stderr": last_exec.get("stderr", ""),
                "reason": last_exec.get("reason"),
            },
            "skill": {"name": self.skill.get("name"), "version": self.skill.get("version"),
                      "workflow": self.skill.get("workflow", [])},
            "tool_calls": self._tool_calls,
        }

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

    def _mcp_run(self, harness_code: str, language: str = "python",
                 source: str = "llm", code_root: str | None = None,
                 harness_kind: str | None = None) -> dict:
        out = self.mcp.call_tool("run_harness_code", {
            "code": harness_code,
            "language": language,
            "source": source,
            "scaffold_token": scaffold_capability() if source == "scaffold" else None,
            # 仅 scaffold 挂载项目真实源码供 import；LLM 代码不可信，不挂载。
            "code_root": code_root if source == "scaffold" else None,
            # harness 种类由框架决定（非脚本自报）：testclient_route 表示经真实路由入口调用。
            "harness_kind": harness_kind if source == "scaffold" else None,
        })["structuredContent"]
        out["_harness_code"] = harness_code   # 供上层保留完整 harness 源码
        self._tool_calls.append({
            "name": "run_harness_code",
            "purpose": "Execute fuzzing harness in Docker sandbox via MCP.",
            # function_reproduced is a successful execution-level result even
            # though it intentionally remains below endpoint/entrypoint confirmation.
            "success": out.get("verdict") in (
                "target_confirmed", "function_reproduced", "mechanism_confirmed",
            ),
        })
        return out

    # ---------- 内部 ----------
    def _generate(self, finding: dict, func: dict, target_lang: str,
                  previous: dict | None, code_root=None) -> dict:
        # 【主力：DeepAudit 式自包含切片】inline 真实函数体、mock 一切外部依赖、桩危险 sink，
        # **不 import 整个 app、不装依赖、不起服务**，因此对任何可抽取函数都鲁棒可跑，是动态
        # 验证主力——完全绕开"整项目起 Docker/装依赖/健康检查"这些脆弱环节，稳定产出
        # function_reproduced（函数级复现，nonce 证明真实函数被调用）。
        # 整项目 route/import 脚手架需真实导入应用、脆弱，仅作**可选增强**：切片无法构建
        # （如对象方法 SQLi 需真实 DB、Django 类视图）时才兜底，用于争取入口级证据。
        if func.get("found"):
            if code_root:
                previous_kind = (previous or {}).get("harness_kind")
                slice_h = build_selfcontained_slice_harness(func, finding.get("type"))
                if slice_h:
                    logger.info("HarnessVerifier 使用【自包含切片·主力】脚手架 (func=%s)",
                                func.get("function_name"))
                    return {"harness_code": slice_h, "_source": "scaffold", "_language": "python",
                            "_kind": "selfcontained_slice"}
                # 切片不适用 → 可选增强：真实路由 test-client（入口级）。
                if not previous:
                    route = build_route_testclient_harness(func, finding.get("type"))
                    if route:
                        logger.info("切片不适用，改用【框架 test-client 真实路由】脚手架 (func=%s)",
                                    func.get("function_name"))
                        return {"harness_code": route, "_source": "scaffold", "_language": "python",
                                "_kind": "testclient_route"}
                    django_view = build_django_classview_harness(func, finding.get("type"))
                    if django_view:
                        logger.info("切片不适用，改用【Django 真实类视图】脚手架 (func=%s)",
                                    func.get("function_name"))
                        return {"harness_code": django_view, "_source": "scaffold", "_language": "python",
                                "_kind": "django_class_view"}
                # 再兜底：import 真实模块（import 本身可行时才值得试）。
                prev_import_failed = bool((previous or {}).get("import_error"))
                if previous_kind not in {"import_module", "selfcontained_slice"} and not prev_import_failed:
                    imp = build_import_scaffold_harness(func, finding.get("type"))
                    if imp:
                        logger.info("切片不适用，改用【import 真实模块】脚手架 (func=%s)",
                                    func.get("function_name"))
                        return {"harness_code": imp, "_source": "scaffold", "_language": "python",
                                "_kind": "import_module"}
            # 【多语言自包含切片·主力】PHP/JS 等解释型语言：同样 inline 真实函数体、
            # 运行时遮蔽/mock 危险 sink，不 import 整个 app、不起服务，稳定产出 function_reproduced。
            ml_slice = build_selfcontained_slice_harness_multilang(func, finding.get("type"))
            if ml_slice:
                ml_code, ml_lang = ml_slice
                logger.info("HarnessVerifier 使用【自包含切片·主力·%s】脚手架 (func=%s)",
                            ml_lang, func.get("function_name"))
                return {"harness_code": ml_code, "_source": "scaffold", "_language": ml_lang,
                        "_kind": "selfcontained_slice"}
            # 再次选：内联函数体脚手架（无源码/import 不适用时）。
            scaffold = build_target_scaffold_harness(func, finding.get("type"))
            if scaffold:
                logger.info("HarnessVerifier 使用【内联函数体】脚手架 (func=%s)", func.get("function_name"))
                return {"harness_code": scaffold, "_source": "scaffold", "_language": "python"}

        payload = {
            "vulnerability": {
                "type": finding.get("type"),
                "file": finding.get("file"),
                "line": finding.get("start_line") or finding.get("line"),
                "code_snippet": finding.get("code_snippet"),
            },
            "target_function": {
                "function_name": func.get("function_name"),
                "class_name": func.get("class_name"),
                "module_path": func.get("module_path"),
                "imports": func.get("imports"),
                "function_code": func.get("function_code") or finding.get("code_snippet"),
                "found": func.get("found", False),
                "extract_reason": func.get("reason"),
            },
            "target_language": target_lang,
            "instruction": (
                f"用 {target_lang} 编写一个【目标函数级】Fuzzing Harness（DeepAudit 式）：\n"
                "1) 尽量 import 项目真实模块/函数（module_path/function_name）；无法 import 则内联 function_code；\n"
                "2) 必须 mock 掉危险 sink（os.system/subprocess/cursor.execute/open/pickle.loads/"
                "render_template_string 等），mock 只记录被调用的参数，绝不真实执行/联网/删文件；\n"
                "3) 必须真实调用目标函数，喂多个恶意 payload；\n"
                "4) 最后一行必须打印结构化结果（单行）：\n"
                "   AUDITAGENTX_RESULT_JSON={\"triggered\":true,\"target_function_called\":true,"
                "\"sink_called\":true,\"sink_name\":\"os.system\",\"captured_argument\":\"...\",\"payload\":\"...\","
                "\"trigger_detail\":\"...\"}\n"
                "   （未触发则 triggered=false；同时兼容保留 AUDITAGENTX_VULN_TRIGGERED / "
                "AUDITAGENTX_NO_TRIGGER 旧标记）。\n"
                "严禁真实网络请求、删除文件、反射逃逸（__subclasses__/ctypes 等）——违规会被安全策略拦截。"
            ),
        }
        if previous:
            # DeepAudit 式 self-correction：把上一次执行结果回喂，要求修正
            payload["previous_attempt"] = {
                "verdict": previous.get("verdict"),
                "triggered": previous.get("triggered"),
                "target_function_called": previous.get("target_function_called"),
                "stdout": (previous.get("stdout") or "")[:600],
                "stderr": (previous.get("stderr") or "")[:400],
                "reason": previous.get("reason"),
                "instruction": ("上一次未复现或未真正调用目标函数，请修正：确认目标函数被真实调用、"
                                "危险 sink 已被 mock 且被触发、payload 更全，并输出 AUDITAGENTX_RESULT_JSON。"),
            }
        result = self._call(json.dumps(payload, ensure_ascii=False))
        harness_code = result.get("harness_code") if isinstance(result, dict) else None
        if harness_code:
            # LLM output crosses a trust boundary. It may not grant itself a scaffold
            # capability, source mount, route-level provenance, or language override by
            # returning private metadata fields. Only builders in this module create
            # trusted scaffold records.
            return {
                "harness_code": harness_code,
                "_source": "llm",
                "_language": target_lang,
            }
        # 兜底：类型模板（仅证明漏洞机理，非真实可利用；标 template）
        logger.info("HarnessVerifier 使用模板兜底 Harness (type=%s)", finding.get("type"))
        return {
            "harness_code": build_template_harness(finding.get("type"), finding.get("code_snippet")),
            "_source": "template",
            "_language": "python",
        }
