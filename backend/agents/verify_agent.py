"""VerifyAgent: independent MCP+Skill review agent for candidate findings.

新增 run_acp() 方法，输入/输出符合 AuditAgentX-ACP 协议：
  输入：message_type="verify.request"，payload.finding 为统一 finding 结构
  输出：message_type="verify.result"，payload.verification 含静/动/综合裁决
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.agents.verification_tools import build_verification_context
from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.skills.harness_tools import is_target_harness_confirmed
from backend.skills.loader import load_skill


logger = logging.getLogger(__name__)


class VerifyAgent(BaseAgent):
    name = "verify_agent"
    prompt_file = "verify_agent_prompt.md"

    def run(self, candidate: dict[str, Any], code_root: Path | None = None,
            *, enable_dynamic: bool = False, enable_harness: bool = False,
            base_url: str | None = None,
            endpoints: list[str] | None = None) -> dict[str, Any]:
        """Review one candidate finding and return a normalized verdict.

        动态开关（默认关闭，向后兼容）：开启后经 vulnerability-verification Skill
        额外调用 dynamic_http_verify / harness MCP 工具，产出 dynamic_verdict。
        """
        tool_context = self._build_mcp_skill_context(
            candidate, code_root, enable_dynamic=enable_dynamic,
            enable_harness=enable_harness, base_url=base_url, endpoints=endpoints)
        user_content = json.dumps({
            "candidate_finding": candidate,
            "tool_evidence": tool_context,
            "instruction": (
                "Use the MCP+Skill tool_evidence to independently confirm or reject the finding. "
                "Return JSON with is_valid, false_positive_reason, confidence, source, "
                "sink, propagation_path, call_path, tool_calls, evidence_chain, "
                "required_runtime_conditions, recommended_poc_strategy, cwe_id, "
                "owasp_category, knowledge_refs, verification_guidance, and remediation_guidance."
            ),
        }, ensure_ascii=False)

        llm_result = self._call(user_content)
        if not isinstance(llm_result, dict):
            llm_result = {"_error": "verify_agent returned non-dict output"}

        return self._merge_verdict(candidate, tool_context, llm_result)

    def run_batch(self, candidates: list[dict[str, Any]],
                  code_root: Path | None = None) -> list[dict[str, Any]]:
        return [self.run(c, code_root=code_root) for c in candidates]

    @staticmethod
    def _build_mcp_skill_context(candidate: dict[str, Any], code_root: Path | None,
                                 *, enable_dynamic: bool = False, enable_harness: bool = False,
                                 base_url: str | None = None,
                                 endpoints: list[str] | None = None) -> dict[str, Any]:
        try:
            skill = load_skill("vulnerability-verification")
            return AuditMCPClient().run_verification_skill(
                candidate, code_root, skill,
                base_url=base_url, endpoints=endpoints,
                enable_dynamic=enable_dynamic, enable_harness=enable_harness)
        except Exception as exc:  # noqa: BLE001
            logger.exception("MCP+Skill verification failed, falling back to local tools: %s", exc)
            context = build_verification_context(candidate, code_root)
            context["architecture"] = "local-tool-fallback"
            context["mcp_error"] = str(exc)
            return context

    @staticmethod
    def _merge_verdict(candidate: dict[str, Any], tool_context: dict[str, Any],
                       llm_result: dict[str, Any]) -> dict[str, Any]:
        heuristic = tool_context.get("heuristic_result", {}) or {}
        local_valid = _normalize_bool(heuristic.get("is_valid"))
        llm_valid = _normalize_bool(llm_result.get("is_valid") if isinstance(llm_result, dict) else None)

        verdict = dict(llm_result)
        verdict["is_valid"] = llm_valid
        if local_valid is False and llm_valid is True:
            # 冲突：LLM 明确确认为漏洞，本地启发式却判为"安全模式"。
            # 安全审计中"漏报"比"误报"更危险，故不让 naive 正则静默否决 LLM——
            # 保留为待人工复核并记录分歧，而不是直接丢成 false_positive。
            if _strong_local_rejection(heuristic):
                verdict["is_valid"] = False
                verdict["needs_review"] = False
                verdict["false_positive_reason"] = (
                    heuristic.get("false_positive_reason") or heuristic.get("reason")
                )
            else:
                verdict["is_valid"] = True
                verdict["needs_review"] = True
                verdict["heuristic_disagreement"] = (
                    heuristic.get("false_positive_reason") or heuristic.get("reason")
                    or "本地启发式判为安全，但 LLM 判为漏洞，需人工复核。"
                )
        elif local_valid is None and llm_valid is False:
            # A model/service-layer parameter can have a concrete source-to-sink
            # chain while route binding is still unresolved.  An LLM rejection
            # based only on that missing HTTP origin must not erase a high-value
            # runtime candidate before endpoint extraction gets a chance to bind it.
            source = heuristic.get("source") or candidate.get("source")
            sink = heuristic.get("sink") or candidate.get("sink")
            severity = str(candidate.get("severity") or "").lower()
            if source and sink and severity in {"critical", "high", "medium"}:
                verdict["is_valid"] = None
                verdict["needs_review"] = True
                verdict["static_rejection"] = "inconclusive_source_sink"
                verdict["heuristic_disagreement"] = (
                    heuristic.get("false_positive_reason") or heuristic.get("reason")
                    or verdict.get("false_positive_reason")
                    or "Source-to-sink evidence requires runtime route binding."
                )
        elif local_valid is False:
            # A machine heuristic is weaker than a concrete source→sink/route trail.
            # Preserve high-value candidates for runtime verification rather than
            # permanently writing false_positive when the LLM is unavailable.
            source = heuristic.get("source") or candidate.get("source")
            sink = heuristic.get("sink") or candidate.get("sink")
            severity = str(candidate.get("severity") or "").lower()
            # 只有**弱**机器启发式（如通用窗口正则）才保留为 needs_review 交动态复核；
            # 确定性安全判定（参数化查询/已净化路径/安全反序列化等）是强否决，即便有
            # source/sink、即便 LLM 不可用，也应直接判 false_positive，不灌爆复核队列。
            if (source and sink and severity in {"critical", "high", "medium"}
                    and not _definitive_local_safety(heuristic)):
                verdict["is_valid"] = None
                verdict["needs_review"] = True
                verdict["static_rejection"] = "machine_heuristic"
                verdict["heuristic_disagreement"] = (
                    heuristic.get("false_positive_reason") or heuristic.get("reason")
                    or "Machine static rejection retained for dynamic source-to-sink review."
                )
            else:
                # No high-value runtime evidence: retain the existing conservative FP path.
                verdict["is_valid"] = False
                verdict["false_positive_reason"] = (
                    heuristic.get("false_positive_reason")
                    or verdict.get("false_positive_reason")
                    or heuristic.get("reason")
                    or "Local verification tools rejected this candidate."
                )
        elif local_valid is True and llm_valid is False:
            verdict["is_valid"] = True
            # Independent verifiers disagree. Only an exact weak hash used in
            # password/authentication state is deterministic enough to prevail;
            # generic window heuristics remain reviewable.
            verdict["needs_review"] = heuristic.get("evidence_strength") not in {
                "authentication_hash", "server_route_sink",
            }
            verdict["heuristic_disagreement"] = (
                verdict.get("false_positive_reason") or
                "本地静态验证确认漏洞，但 LLM 判为误报，保留本地证据并标记分歧。"
            )
            verdict["confidence"] = min(_bounded_float(verdict.get("confidence"), default=0.5), 0.75)
        elif local_valid is True:
            verdict["is_valid"] = True
        elif verdict.get("_error") or llm_valid is None:
            verdict["is_valid"] = None
            verdict["needs_review"] = True

        if not verdict.get("confidence"):
            verdict["confidence"] = heuristic.get("confidence", candidate.get("confidence", 0.5))
        verdict["confidence"] = _bounded_float(verdict.get("confidence"), default=0.5)

        context = tool_context.get("context_classification") or {
            "context": heuristic.get("context"),
            "risk_modifier": heuristic.get("risk_modifier"),
            "allow_confirmed": heuristic.get("allow_confirmed", True),
            "confirmed_blockers": heuristic.get("confirmed_blockers") or [],
            "reason": heuristic.get("downgrade_reason") or heuristic.get("false_positive_reason"),
        }
        if context.get("context"):
            verdict["context"] = context.get("context")
            verdict["risk_modifier"] = context.get("risk_modifier")
            verdict["allow_confirmed"] = context.get("allow_confirmed", True)
        if not context.get("allow_confirmed", True):
            blockers = context.get("confirmed_blockers") or [context.get("reason") or "context blocks automated confirmation"]
            verdict["confirmed_blockers"] = _dedupe_list(blockers)
            verdict["downgrade_reason"] = context.get("reason") or blockers[0]
            verdict["confidence"] = min(verdict["confidence"], 0.65)
            if context.get("risk_modifier") == "false_positive":
                verdict["is_valid"] = False
                verdict["false_positive_reason"] = verdict.get("downgrade_reason")
            else:
                verdict["needs_review"] = True

        for field in ("source", "sink", "propagation_path", "recommended_poc_strategy", "call_path"):
            if not verdict.get(field) and heuristic.get(field):
                verdict[field] = heuristic[field]

        tool_evidence_chain = tool_context.get("evidence_chain") or {
            "tool_calls": tool_context.get("tools_used", []),
            "call_path": verdict.get("call_path", []),
            "checks": heuristic.get("checks", []),
            "sast_replay": tool_context.get("sast_replay", {}),
        }
        if verdict.get("evidence_chain") and isinstance(verdict.get("evidence_chain"), dict):
            verdict["evidence_chain"] = {
                **tool_evidence_chain,
                "llm_assessment": verdict.get("evidence_chain"),
            }
        else:
            verdict["evidence_chain"] = tool_evidence_chain
        verdict["tool_calls"] = tool_context.get("tools_used", [])

        knowledge = _knowledge_from_tool_context(tool_context)
        verdict["knowledge"] = knowledge
        if knowledge:
            verdict.setdefault("cwe_id", knowledge.get("cwe_id"))
            verdict.setdefault("owasp_category", ", ".join(knowledge.get("owasp") or []))
            verdict.setdefault("knowledge_refs", knowledge.get("references") or [])
            verdict.setdefault("verification_guidance", knowledge.get("verification_checks") or [])
            verdict.setdefault("remediation_guidance", knowledge.get("remediation") or [])
            if isinstance(verdict.get("evidence_chain"), dict):
                verdict["evidence_chain"]["knowledge"] = knowledge

        # 动态裁决：由 dynamic_http_verify / harness MCP 工具结果推导
        dynamic_result = tool_context.get("dynamic_result") or {}
        harness_result = tool_context.get("harness_result") or {}
        dynamic_verdict = dynamic_result.get("reproduction_status") or "not_executed"
        if heuristic.get("runtime_verification_status") == "not_runtime_verifiable":
            dynamic_verdict = "not_runtime_verifiable"
        if is_target_harness_confirmed(harness_result):
            dynamic_verdict = "harness_confirmed"
        elif harness_result.get("verdict") in {"function_reproduced", "mechanism_confirmed"}:
            dynamic_verdict = harness_result.get("verdict")
        elif dynamic_verdict == "not_executed" and harness_result.get("executed"):
            dynamic_verdict = "harness_inconclusive"
        verdict["dynamic_verdict"] = dynamic_verdict
        verdict["runtime_verification_status"] = dynamic_verdict
        verdict["_dynamic_result"] = dynamic_result
        verdict["_harness_result"] = harness_result

        if _requires_manual_review(candidate, tool_context, heuristic, verdict):
            blocker = "No deterministic local verifier or SAST replay matched this finding; LLM-only confirmation remains needs_review."
            verdict["needs_review"] = True
            verdict["confidence"] = min(verdict["confidence"], 0.75)
            verdict["confirmed_blockers"] = _dedupe_list(
                list(verdict.get("confirmed_blockers") or []) + [blocker]
            )
            verdict.setdefault("downgrade_reason", blocker)

        if not verdict.get("required_runtime_conditions"):
            verdict["required_runtime_conditions"] = _runtime_conditions(candidate, heuristic)

        verdict.setdefault("mcp_server", tool_context.get("mcp_server"))
        verdict.setdefault("skill", tool_context.get("skill"))
        verdict["_tool_evidence"] = tool_context
        verdict["_llm_result"] = llm_result
        return verdict


    # ------------------------------------------------------------------ #
    # ACP 接口（新增）                                                     #
    # ------------------------------------------------------------------ #
    def run_acp(self, request: "ACPMessage") -> "ACPMessage":  # noqa: F821
        """ACP 接口：输入 verify.request，输出 verify.result。

        Parameters
        ----------
        request : ACPMessage
            message_type = "verify.request"
            payload.finding = 统一 ACP finding dict

        Returns
        -------
        ACPMessage
            message_type = "verify.result"
            payload.verification = ACPVerification 结构
            status.verdict = 综合裁决
            status.confidence = 置信度
        """
        # 延迟导入避免循环依赖
        from backend.acp.factory import make_reply
        from backend.acp.models import ACPMessageType, ACPState, ACPVerdict
        from backend.acp.adapters import acp_to_legacy_finding
        from backend.acp.models import ACPToolCall

        acp_finding = request.payload.get("finding") or {}
        legacy = acp_to_legacy_finding(acp_finding)
        code_root_str = (request.context.code_root or
                         acp_finding.get("extra", {}).get("code_root"))
        code_root = Path(code_root_str) if code_root_str else None

        # 从 ACP context.options 读取动态验证开关（真正激活 MCP 动态工具）
        opts = request.context.options or {}
        dyn_target = opts.get("dynamic_target") or {}
        base_url = opts.get("base_url") or dyn_target.get("base_url")
        endpoints = opts.get("endpoints") or dyn_target.get("endpoints")
        enable_dynamic = bool(opts.get("enable_dynamic", False))
        enable_harness = bool(opts.get("enable_harness", False))

        # 调用验证逻辑（按需激活动态/harness MCP 工具）
        vr = self.run(legacy, code_root=code_root, enable_dynamic=enable_dynamic,
                      enable_harness=enable_harness, base_url=base_url, endpoints=endpoints)

        # 静态裁决 + 动态裁决 -> 综合裁决
        is_valid = _normalize_bool(vr.get("is_valid"))
        needs_review = bool(vr.get("needs_review"))
        if is_valid is False:
            static_verdict = "false_positive"
        elif needs_review or is_valid is not True:
            static_verdict = "needs_review"   # LLM 确认但本地启发式有异议，交人工复核（不静默丢弃）
        else:
            static_verdict = "confirmed"
        dynamic_verdict = vr.get("dynamic_verdict", "not_executed")
        state = ACPState.SUCCESS
        if static_verdict == "false_positive":
            final_verdict = "false_positive"
            verdict_enum = ACPVerdict.FALSE_POSITIVE
        elif dynamic_verdict == "dynamic_confirmed":
            final_verdict = "dynamic_confirmed"
            verdict_enum = ACPVerdict.DYNAMIC_CONFIRMED
        elif dynamic_verdict == "harness_confirmed":
            final_verdict = "harness_confirmed"
            verdict_enum = ACPVerdict.HARNESS_CONFIRMED
        elif (dynamic_verdict == "not_reproduced"
              and not (vr.get("_dynamic_result") or {}).get("skipped")):
            # Preserve the runtime no-hit verdict while exposing the completed
            # verification as confirmed at the product/ACP verdict layer.
            final_verdict = "confirmed"
            verdict_enum = ACPVerdict.CONFIRMED
        elif dynamic_verdict == "function_reproduced":
            final_verdict = "needs_review"
            verdict_enum = ACPVerdict.NEEDS_REVIEW
        elif static_verdict == "needs_review":
            final_verdict = "needs_review"
            verdict_enum = ACPVerdict.NEEDS_REVIEW
        else:
            final_verdict = "statically_verified"
            verdict_enum = ACPVerdict.STATICALLY_VERIFIED

        # 用 ACPVerification 模型实例化（字段校验 + 默认值统一），再序列化为 dict
        from backend.acp.models import ACPVerification
        verification = ACPVerification(
            static_verdict=static_verdict,
            dynamic_verdict=dynamic_verdict,
            final_verdict=final_verdict,
            source=_as_text(vr.get("source")),
            sink=_as_text(vr.get("sink")),
            call_path=vr.get("call_path") or [],
            evidence_chain=vr.get("evidence_chain") or {},
            # false_positive_reason 复用为"裁决说明"：误报时是误报原因，needs_review 时是启发式分歧说明
            false_positive_reason=vr.get("false_positive_reason") or vr.get("heuristic_disagreement"),
            recommended_poc_strategy=_as_text(vr.get("recommended_poc_strategy")),
            confidence=float(vr.get("confidence") or 0.5),
        ).model_dump()
        verification.update({
            "context": vr.get("context"),
            "risk_modifier": vr.get("risk_modifier"),
            "downgrade_reason": vr.get("downgrade_reason"),
            "verification_level": vr.get("verification_level"),
            "harness_kind": vr.get("harness_kind"),
            "dynamic_applicable": vr.get("dynamic_applicable"),
            "confirmed_blockers": vr.get("confirmed_blockers") or [],
        })

        # 构建 tool_calls 列表
        tool_calls = [
            ACPToolCall(
                tool_name=tc.get("name", ""),
                input={},
                output=tc.get("result_summary") or {},
                success=tc.get("success", True),
            )
            for tc in (vr.get("tool_calls") or [])
        ]

        return make_reply(
            request,
            sender=self.name,
            message_type=ACPMessageType.VERIFY_RESULT,
            intent="漏洞静态验证完成，返回裁决结果",
            payload={
                "finding": acp_finding,
                "verification": verification,
                "knowledge": vr.get("knowledge") or {},
            },
            tools=tool_calls,
            state=state,
            verdict=verdict_enum,
            confidence=verification["confidence"],
        )


def _as_text(value: Any) -> "str | None":
    """把 source/sink 等值统一成字符串（兼容 dict/None），供 ACPVerification 字段使用。"""
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


def _bounded_float(value: Any, *, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0.0, min(parsed, 1.0))


def _normalize_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "yes", "y", "1", "valid", "confirmed"}:
            return True
        if text in {"false", "no", "n", "0", "invalid", "false_positive", "fp"}:
            return False
    return None


def _strong_local_static_evidence(heuristic: dict[str, Any]) -> bool:
    if heuristic.get("deterministic_flow"):
        return True
    if heuristic.get("verification_level") == "local_static_verified":
        return True
    if heuristic.get("is_valid") is True and heuristic.get("source") and heuristic.get("sink"):
        return bool(heuristic.get("propagation_path") or heuristic.get("call_path"))
    return False


def _strong_local_rejection(heuristic: dict[str, Any]) -> bool:
    # 用于「LLM 确认为漏洞、本地判安全」的冲突场景：只有这些高确定性否决才允许否决 LLM
    # 的正向确认（漏报比误报危险，故不含参数化查询等——那类仍应保留人工复核）。
    return heuristic.get("evidence_strength") in {
        "no_hardcoded_literal", "non_credential_literal", "protocol_nonce",
        "non_security_random_use", "safe_deserialization_loader",
    }


def _definitive_local_safety(heuristic: dict[str, Any]) -> bool:
    # 用于「LLM 未确认/不可用、本地判安全」场景：结构上确定性安全（参数化查询、已净化
    # 路径等）即便有 source/sink 也应直接判 false_positive，不灌进人工复核队列。
    return _strong_local_rejection(heuristic) or heuristic.get("evidence_strength") in {
        "parameterized_query",
    }


def _knowledge_from_tool_context(tool_context: dict[str, Any]) -> dict[str, Any]:
    knowledge = tool_context.get("knowledge_result") or {}
    playbook = tool_context.get("playbook_result") or {}
    remediation = tool_context.get("remediation_result") or {}

    top = knowledge.get("top_result") or playbook.get("top_result") or {}
    summary = knowledge.get("summary") or {}
    playbook_summary = playbook.get("summary") or {}
    remediation_summary = remediation.get("summary") or {}

    cwe_id = top.get("cwe_id") or summary.get("cwe_id") or playbook_summary.get("cwe_id")
    owasp = _dedupe_list((summary.get("owasp") or []) + (playbook_summary.get("owasp") or []))
    verification_checks = _dedupe_list(
        (summary.get("verification_checks") or []) +
        (playbook_summary.get("verification_checks") or [])
    )
    false_positive_signals = _dedupe_list(
        (summary.get("false_positive_signals") or []) +
        (playbook_summary.get("false_positive_signals") or [])
    )
    remediation_items = _dedupe_list(
        (summary.get("remediation") or []) +
        (remediation_summary.get("remediation") or [])
    )
    references = _dedupe_list(
        (summary.get("references") or []) +
        (playbook_summary.get("references") or []) +
        (remediation_summary.get("references") or [])
    )

    if not any([cwe_id, owasp, verification_checks, false_positive_signals, remediation_items, references]):
        return {}
    return {
        "cwe_id": cwe_id,
        "owasp": owasp,
        "dynamic_strategy": summary.get("dynamic_strategy") or playbook_summary.get("dynamic_strategy"),
        "verification_checks": verification_checks,
        "false_positive_signals": false_positive_signals,
        "remediation": remediation_items,
        "references": references,
        "retrieval": {
            "security_knowledge": knowledge.get("results") or [],
            "verification_playbooks": playbook.get("results") or [],
            "remediation_guides": remediation.get("results") or [],
        },
    }


def _requires_manual_review(candidate: dict[str, Any], tool_context: dict[str, Any],
                            heuristic: dict[str, Any], verdict: dict[str, Any]) -> bool:
    if verdict.get("is_valid") is not True or verdict.get("needs_review"):
        return False
    dynamic_verdict = verdict.get("dynamic_verdict") or verdict.get("runtime_verification_status")
    if dynamic_verdict in {
        "dynamic_confirmed", "harness_confirmed", "harness_target_confirmed", "not_reproduced",
    }:
        return False
    if _strong_local_static_evidence(heuristic):
        return False
    extra = candidate.get("extra") or {}
    analysis = str(extra.get("analysis") or candidate.get("analysis") or "")
    taint_flow = extra.get("taint_flow") or candidate.get("taint_flow") or []
    if analysis in {"taint", "interproc-taint", "java-taint"} and len(taint_flow) >= 2:
        return False
    # SAST/局部正则重放是支持性证据，不是独立验证器；即使命中也不能阻止人工复核。
    return True


def _dedupe_list(items: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        text = str(item)
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
    return result


def _runtime_conditions(candidate: dict[str, Any], heuristic: dict[str, Any]) -> list[str]:
    vuln_type = str(candidate.get("type") or "").lower()
    if "secret" in vuln_type:
        return ["Confirm whether the literal credential is real and reachable by runtime code."]
    if heuristic.get("is_valid") is False:
        return ["No runtime verification required unless a new unsafe path is identified."]
    return ["Run only against a local authorized target or sandbox.", "Use the recommended PoC strategy if dynamic validation is enabled."]
