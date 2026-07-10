"""证据链采集：把 source→sink→exploit→dynamic runtime 汇总为可追溯结构。

对应 md「证据链可追溯」创新点 & PDF「给出触发文件位置、利用路径、验证方法」。

新增 build_from_acp()：从 ACP messages 列表中提取证据链，兼容 ACP 协议。
"""
from __future__ import annotations

import re

from backend.skills.harness_tools import is_target_harness_confirmed


def _build_call_path(verify_result: dict, exploit: dict) -> list[dict]:
    """把 source→传播→sink 整理为逐跳「调用路径」（结构化，便于证据链展示）。

    兼容 propagation_path 为字符串（-> / → / => 分隔）或列表；
    静态信息缺失时用 exploit 的触发位置与利用路径兜底。
    """
    hops: list[dict] = []
    source = verify_result.get("source")
    sink = verify_result.get("sink")
    prop = verify_result.get("propagation_path")
    structured = verify_result.get("call_path")

    if isinstance(structured, list) and structured:
        return structured

    if source:
        hops.append({"stage": "source", "detail": str(source)})

    if isinstance(prop, str) and prop.strip():
        for part in re.split(r"->|→|=>", prop):
            step = part.strip()
            if step and step != str(source) and step != str(sink):
                hops.append({"stage": "propagation", "detail": step})
    elif isinstance(prop, (list, tuple)):
        for step in prop:
            hops.append({"stage": "propagation",
                         "detail": step if isinstance(step, str) else str(step)})

    if sink:
        hops.append({"stage": "sink", "detail": str(sink)})

    # 缺少静态数据流时，用利用证据兜底，保证「调用路径」始终有内容
    if not hops and exploit:
        if exploit.get("trigger_location"):
            hops.append({"stage": "trigger", "detail": str(exploit["trigger_location"])})
        if exploit.get("exploit_path"):
            hops.append({"stage": "exploit_path", "detail": str(exploit["exploit_path"])})
    return hops


class EvidenceCollector:
    @staticmethod
    def build(verify_result: dict, exploit: dict | None = None,
              dynamic: dict | None = None, poc_result: dict | None = None,
              harness: dict | None = None, sandbox: dict | None = None) -> dict:
        """组装写入 evidence 表的证据结构（md 7.9 证据链格式 + 动态利用/Harness/Docker 沙箱证据）。"""
        exploit = exploit or {}
        dynamic = dynamic or {}
        harness = harness or {}
        knowledge = _normalize_knowledge(verify_result)
        tool_calls = _normalize_tool_calls(verify_result)
        # 沙箱元信息可能已由 pipeline 塞进 dynamic，优先用显式参数
        sandbox = sandbox or (dynamic.get("sandbox") if isinstance(dynamic, dict) else None)
        logs = ["候选漏洞由 AuditAgent 产生", "VerifyAgent 独立复核通过"]

        if exploit:
            logs.append(f"ExploitAgent 生成利用方案: {exploit.get('vuln_type', '')}")
        if dynamic:
            if dynamic.get("skipped"):
                logs.append(f"HTTP 动态验证跳过: {dynamic.get('reason', '')}")
            elif dynamic.get("reproducible"):
                logs.append(f"HTTP 动态验证成功，命中特征: {dynamic.get('matched_indicator', '')}")
            else:
                logs.append("HTTP 动态验证执行，但未复现")
            logs.extend(dynamic.get("logs", [])[:5])
        else:
            logs.append("HTTP 动态验证未执行")
        if harness:
            logs.append(f"Fuzzing Harness 验证: {harness.get('verdict', '')}"
                        + (f"（{harness.get('trigger_detail', '')}）"
                           if harness.get('dynamically_triggered') else ""))
        else:
            logs.append("Fuzzing Harness 未执行")
        if sandbox:
            logs.append(f"Docker 沙箱: {sandbox.get('status', '')}"
                        f"（健康检查 {sandbox.get('health_check', '')}）")
        if knowledge:
            logs.append(f"安全知识增强: {knowledge.get('cwe_id') or 'N/A'}")

        confirmed = dynamic.get("confirmed_record") or {}
        sample_record = confirmed or ((dynamic.get("records") or [{}])[0] if dynamic.get("records") else {})
        call_path = _build_call_path(verify_result, exploit)
        runtime = _build_runtime_evidence(verify_result, exploit, dynamic, sample_record, sandbox)
        harness_evidence = _build_harness_evidence(harness)
        verification = _build_verification_evidence(verify_result, runtime, harness_evidence)
        exploit_evidence = _redact_sensitive({
            "trigger_location": exploit.get("trigger_location"),
            "exploit_path": exploit.get("exploit_path"),
            "attack_vector": exploit.get("attack_vector"),
            "payloads": exploit.get("payloads"),
            "exploit_code": exploit.get("exploit_code"),
            "verification_method": exploit.get("verification_method"),
            "impact": exploit.get("impact"),
        })
        runtime = _redact_sensitive(runtime)
        harness_evidence = _redact_sensitive(harness_evidence)
        sandbox = _redact_sensitive(sandbox)
        logs = _redact_sensitive(logs)

        return {
            # 静态数据流证据
            "source": verify_result.get("source"),
            "sink": verify_result.get("sink"),
            "data_flow": verify_result.get("propagation_path"),
            # 结构化调用路径：source -> 传播 -> sink，逐跳可追溯
            "call_path": call_path,
            # 利用证据（PDF 模块③要求）
            "exploit": exploit_evidence,
            # 动态运行时证据
            "runtime": runtime,
            # Docker 沙箱环境证据（Deep 模式 docker_project）
            "sandbox": sandbox,
            "poc_result": {
                "poc": (poc_result or {}).get("poc"),
                "executed": (poc_result or {}).get("poc_executed", False),
                "sandbox": (poc_result or {}).get("sandbox_result") or {},
            },
            # Fuzzing Harness 动态验证证据（DeepAudit 式）
            "harness": harness_evidence,
            # VerifyAgent / MCP / Skill 工具证据，供前端和报告回放 Agent 做了什么
            "tool_calls": tool_calls,
            "static_evidence_chain": verify_result.get("evidence_chain") or {},
            # RAG / Security Knowledge 证据：CWE、OWASP、验证条件、误报信号、修复建议
            "knowledge": knowledge,
            "verification": verification,
            "logs": logs,
        }

    @classmethod
    def build_from_acp(cls, messages: list) -> dict:
        """从 ACP messages 列表中构建证据链。

        处理以下消息类型：
          verify.result            → source / sink / call_path / evidence_chain
          exploit.generate.result  → exploit 字段
          dynamic.verify.result    → runtime 字段
          harness.verify.result    → harness 字段

        Parameters
        ----------
        messages : list[ACPMessage]
            ACPTracer.load_all() 返回的消息列表，或手动构造的 ACPMessage 列表

        Returns
        -------
        dict
            与 build() 格式兼容的证据链 dict
        """
        verify_result: dict = {}
        exploit: dict = {}
        dynamic: dict = {}
        harness: dict = {}
        knowledge: dict = {}
        tool_calls: list = []
        agent_messages: list = []
        logs: list = ["证据链由 ACP messages 重建"]

        for msg in messages:
            # 兼容 ACPMessage 对象和普通 dict
            if hasattr(msg, "header"):
                # 取 enum value（str），兼容 Python 3.9 的 str(enum) 返回 "Name.VALUE" 问题
                mtype_raw = msg.header.message_type
                mtype = mtype_raw.value if hasattr(mtype_raw, "value") else str(mtype_raw)
                payload = msg.payload or {}
                tools = [t.model_dump() if hasattr(t, "model_dump") else t for t in (msg.tools or [])]
                sender = msg.header.sender
                receiver = msg.header.receiver
                verdict_raw = msg.status.verdict
                verdict = (verdict_raw.value if hasattr(verdict_raw, "value") else str(verdict_raw)) if verdict_raw else None
                confidence = msg.status.confidence
            else:
                mtype = str(msg.get("header", {}).get("message_type", ""))
                payload = msg.get("payload") or {}
                tools = msg.get("tools") or []
                sender = (msg.get("header") or {}).get("sender", "")
                receiver = (msg.get("header") or {}).get("receiver", "")
                verdict = (msg.get("status") or {}).get("verdict")
                confidence = (msg.get("status") or {}).get("confidence")

            # 收集 agent 消息摘要
            agent_messages.append({
                "message_type": mtype,
                "sender": sender,
                "receiver": receiver,
                "verdict": verdict,
                "confidence": confidence,
            })
            tool_calls.extend(tools)

            # 注意：dynamic.verify.result / harness.verify.result 都含子串 "verify.result"，
            # 必须显式排除，否则会被这个分支截胡、走不到各自的解析分支。
            if ("verify.result" in mtype
                    and "dynamic.verify.result" not in mtype
                    and "harness.verify.result" not in mtype):
                vinfo = payload.get("verification") or {}
                knowledge = payload.get("knowledge") or vinfo.get("knowledge") or knowledge
                verify_result = {
                    "source": vinfo.get("source"),
                    "sink": vinfo.get("sink"),
                    "call_path": vinfo.get("call_path") or [],
                    "propagation_path": None,
                    "evidence_chain": vinfo.get("evidence_chain") or {},
                    "mcp_server": vinfo.get("mcp_server"),
                    "skill": vinfo.get("skill"),
                    "static_verdict": vinfo.get("static_verdict"),
                    "dynamic_verdict": vinfo.get("dynamic_verdict"),
                    "final_verdict": vinfo.get("final_verdict"),
                    "false_positive_reason": vinfo.get("false_positive_reason"),
                    "is_valid": vinfo.get("final_verdict") in ("confirmed",),
                    "confidence": vinfo.get("confidence", 0.5),
                    "knowledge": knowledge,
                    "tool_calls": tool_calls,
                }
                logs.append(
                    f"VerifyAgent 裁决: static={vinfo.get('static_verdict')} "
                    f"dynamic={vinfo.get('dynamic_verdict')} "
                    f"final={vinfo.get('final_verdict')}"
                )

            elif "exploit.generate.result" in mtype:
                ep = payload.get("exploit") or {}
                exploit = {
                    "trigger_location": ep.get("trigger_location"),
                    "exploit_path": ep.get("exploit_path"),
                    "attack_vector": ep.get("attack_vector"),
                    "payloads": ep.get("payloads") or [],
                    "exploit_code": ep.get("exploit_code"),
                    "verification_method": "ACP exploit",
                    "impact": ep.get("vuln_type"),
                    "vuln_type": ep.get("vuln_type"),
                }
                logs.append(f"ExploitAgent 生成利用方案: {ep.get('vuln_type', '')}")

            elif "dynamic.verify.result" in mtype:
                # DynamicAnalysisAgent 发的是 payload["runtime"]（扁平 dyn_result）；
                # MCP dynamic_http_verify 工具则是嵌套 runtime_evidence。两种结构都兼容。
                dp = payload.get("runtime") or payload.get("dynamic") or payload
                status = dp.get("reproduction_status", "not_executed")
                runtime_ev = dp.get("runtime_evidence") or {}
                dynamic = {
                    "reproduction_status": status,
                    "reproducible": dp.get("reproducible", status == "dynamic_confirmed"),
                    "verified": dp.get("verified", status == "dynamic_confirmed"),
                    "reason": dp.get("reason", ""),
                    "error": dp.get("error", ""),
                    "matched_indicator": dp.get("matched_indicator") or runtime_ev.get("matched_indicator"),
                    "confirmed_record": dp.get("confirmed_record") or runtime_ev.get("request"),
                    "records": dp.get("records") or runtime_ev.get("records") or [],
                    "skipped": dp.get("skipped", status == "not_executed"),
                }
                logs.append(f"动态 HTTP 验证: {status}")

            elif "harness.verify.result" in mtype:
                hp = payload.get("harness") or payload
                harness = {
                    "verdict": hp.get("verdict"),
                    "dynamically_triggered": hp.get("dynamically_triggered", False),
                    "reason": hp.get("reason", ""),
                    "harness_code": hp.get("harness_code"),
                    "trigger_detail": hp.get("trigger_detail"),
                    "execution_backend": hp.get("execution_backend"),
                    "attempts": hp.get("attempts"),
                    "execution_log": hp.get("execution_log"),
                }
                logs.append(f"Harness 验证: {hp.get('verdict', '')}")

        # 调用原有 build() 组装最终证据链
        evidence = cls.build(
            verify_result,
            exploit=exploit or None,
            dynamic=dynamic or None,
            harness=harness or None,
        )
        # 附加 ACP 专属字段
        evidence["tool_calls"] = tool_calls
        evidence["agent_messages"] = agent_messages
        if knowledge:
            evidence["knowledge"] = _normalize_knowledge({"knowledge": knowledge})
        evidence["logs"] = evidence.get("logs", []) + logs
        return evidence


def _legacy_runtime_status(dynamic: dict) -> str:
    if dynamic.get("reproducible"):
        return "dynamic_confirmed"
    if dynamic.get("skipped"):
        return "not_executed"
    reason = dynamic.get("reason")
    if reason == "payload_not_matched":
        return "not_reproduced"
    return reason or "not_executed"


def _normalize_knowledge(verify_result: dict) -> dict:
    knowledge = dict(verify_result.get("knowledge") or {})

    if not knowledge.get("cwe_id") and verify_result.get("cwe_id"):
        knowledge["cwe_id"] = verify_result.get("cwe_id")

    owasp = knowledge.get("owasp") or knowledge.get("owasp_category") or verify_result.get("owasp_category")
    if isinstance(owasp, str):
        owasp = [item.strip() for item in re.split(r",|、", owasp) if item.strip()]
    knowledge["owasp"] = owasp or []

    field_map = {
        "verification_checks": "verification_guidance",
        "false_positive_signals": "false_positive_signals",
        "remediation": "remediation_guidance",
        "references": "knowledge_refs",
    }
    for target, source in field_map.items():
        value = knowledge.get(target)
        if not value and verify_result.get(source):
            value = verify_result.get(source)
        if isinstance(value, str):
            value = [value]
        knowledge[target] = value or []

    if verify_result.get("recommended_poc_strategy") and not knowledge.get("dynamic_strategy"):
        knowledge["dynamic_strategy"] = verify_result.get("recommended_poc_strategy")

    return knowledge


def _normalize_tool_calls(verify_result: dict) -> list:
    tool_calls = verify_result.get("tool_calls") or []
    if not tool_calls:
        tool_calls = (verify_result.get("_tool_evidence") or {}).get("tools_used") or []
    return list(tool_calls) if isinstance(tool_calls, list) else []


def _build_runtime_evidence(verify_result: dict, exploit: dict, dynamic: dict,
                            sample_record: dict, sandbox: dict | None) -> dict:
    if not dynamic:
        status = "not_executed"
        reason = "未执行动态 HTTP 验证"
    else:
        status = dynamic.get("reproduction_status") or _legacy_runtime_status(dynamic)
        reason = dynamic.get("reason", "")

    return {
        "reproduction_status": status,
        "reproducible": dynamic.get("reproducible", False),
        "verified": dynamic.get("verified", False),
        "skipped": dynamic.get("skipped", not bool(dynamic)),
        "reason": reason,
        "error": dynamic.get("error", ""),
        "matched_indicator": dynamic.get("matched_indicator"),
        "verification_level": dynamic.get("verification_level", "not_executed"),
        "oracle": dynamic.get("oracle", ""),
        "request": {
            "url": sample_record.get("url"),
            "method": sample_record.get("method"),
            "params": sample_record.get("params"),
            "payload": sample_record.get("payload"),
            "transport": sample_record.get("transport"),
        },
        "baseline": dynamic.get("baseline_record") or {},
        "response_status": sample_record.get("status_code") or sample_record.get("status"),
        "response_excerpt": (sample_record.get("response_excerpt") or "")[:400],
        "runtime_log_excerpt": (sample_record.get("runtime_log_excerpt") or "")[:1200],
        "elapsed_ms": sample_record.get("elapsed_ms"),
        "records": dynamic.get("records", [])[:10],
        "baseline_records": dynamic.get("baseline_records", [])[:10],
        "candidate_endpoints": dynamic.get("candidate_endpoints") or [],
        "surfaces": dynamic.get("surfaces", [])[:40],
        "evidence_flow": _build_runtime_flow(verify_result, exploit, sample_record, dynamic),
        "sandbox": sandbox,
    }


def _build_harness_evidence(harness: dict) -> dict:
    if not harness:
        return {
            "verdict": "not_executed",
            "dynamically_triggered": False,
            "reason": "未执行 Fuzzing Harness 验证",
            "harness_code": None,
            "trigger_detail": None,
            "execution_backend": None,
            "attempts": None,
            "execution_log": None,
        }
    return {
        "verdict": harness.get("verdict") or "not_executed",
        "dynamically_triggered": harness.get("dynamically_triggered", False),
        "function_mechanism_verified": harness.get("function_mechanism_verified", False),
        "verification_level": harness.get("verification_level"),
        "reason": harness.get("reason", ""),
        "harness_code": harness.get("harness_code"),
        "harness_source": harness.get("harness_source"),
        "harness_kind": harness.get("harness_kind") or harness.get("harness_source"),
        "harness_language": harness.get("harness_language"),
        "sink_name": harness.get("sink_name"),
        "captured_argument": harness.get("captured_argument"),
        "payload": harness.get("payload"),
        "function_extracted": harness.get("function_extracted", False),
        "target_function_called": harness.get("target_function_called", False),
        "entrypoint_reachable": harness.get("entrypoint_reachable", False),
        "function_unit_reproduced": harness.get("verdict") == "function_reproduced",
        "function_name": harness.get("function_name"),
        "trigger_detail": harness.get("trigger_detail"),
        "execution_backend": harness.get("execution_backend"),
        "confirmed_blockers": harness.get("confirmed_blockers") or [],
        "safety": harness.get("safety"),
        "attempts": harness.get("attempts"),
        "execution_log": harness.get("execution_log"),
    }


def _normalize_skill(skill):
    if isinstance(skill, dict):
        return {
            "name": skill.get("name") or skill.get("id") or "",
            "version": skill.get("version"),
        }
    if isinstance(skill, str) and skill:
        return {"name": skill, "version": None}
    return {"name": "", "version": None}


def _build_verification_evidence(verify_result: dict, runtime: dict, harness: dict) -> dict:
    static_verdict = verify_result.get("static_verdict")
    dynamic_verdict = verify_result.get("dynamic_verdict") or runtime.get("reproduction_status") or "not_executed"
    final_verdict = verify_result.get("final_verdict")

    harness_verdict = harness.get("verdict")
    http_reproduced = (runtime.get("reproduction_status") == "dynamic_confirmed"
                       or runtime.get("reproducible"))
    # 目标级动态确认判据统一走 canonical（框架 nonce 证明真实调用，非脚本自报）。
    harness_target = is_target_harness_confirmed(harness)
    function_reproduced = harness_verdict == "function_reproduced"
    mechanism_only = harness_verdict == "mechanism_confirmed" or (
        bool(harness.get("function_mechanism_verified")) and not function_reproduced
    )

    if http_reproduced:
        dynamic_verdict = "dynamic_confirmed"
        final_verdict = "dynamic_confirmed"
        dynamic_method = "http_dynamic"
    elif harness_target:
        dynamic_verdict = "harness_confirmed"
        final_verdict = "dynamic_confirmed"
        dynamic_method = "target_harness"
    else:
        dynamic_method = None
        if not final_verdict:
            if static_verdict == "false_positive":
                final_verdict = "false_positive"
            elif static_verdict in ("confirmed", "statically_verified"):
                final_verdict = "statically_verified"
            else:
                final_verdict = "needs_review"

    # 是否经运行时证据（HTTP 复现 / 目标函数级 Harness）动态确认——供报告如实展示。
    dynamically_verified = bool(http_reproduced or harness_target)
    if http_reproduced:
        evidence_level = "http_reproduced"
    elif harness_target:
        evidence_level = "target_harness"
    elif function_reproduced:
        evidence_level = "function_unit_reproduced"
    elif mechanism_only:
        evidence_level = "mechanism_only"
    elif runtime.get("skipped") and harness_verdict in {None, "not_executed"}:
        evidence_level = "not_executed"
    else:
        evidence_level = "not_reproduced"

    return {
        "mcp_server": verify_result.get("mcp_server"),
        "skill": _normalize_skill(verify_result.get("skill")),
        "static_verdict": static_verdict,
        "dynamic_verdict": dynamic_verdict,
        "final_verdict": final_verdict,
        "false_positive_reason": verify_result.get("false_positive_reason"),
        "context": verify_result.get("context"),
        "risk_modifier": verify_result.get("risk_modifier"),
        "downgrade_reason": verify_result.get("downgrade_reason"),
        "verification_level": harness.get("verification_level") or verify_result.get("verification_level"),
        "harness_kind": harness.get("harness_kind") or harness.get("harness_source") or verify_result.get("harness_kind"),
        "dynamic_applicable": verify_result.get("dynamic_applicable"),
        "confirmed_blockers": verify_result.get("confirmed_blockers") or harness.get("confirmed_blockers") or [],
        # 动态验证透出：报告/前端可据此展示「经动态确认」标记与方法
        "dynamically_verified": dynamically_verified,
        "dynamic_method": dynamic_method,
        "evidence_level": evidence_level,
        "runtime_verification_status": runtime.get("reproduction_status"),
        "harness_verdict": harness_verdict,
        "harness_dynamically_triggered": bool(harness.get("dynamically_triggered")),
        "function_mechanism_verified": bool(harness.get("function_mechanism_verified")),
    }


def _build_runtime_flow(verify_result: dict, exploit: dict,
                        record: dict, dynamic: dict) -> list[dict]:
    flow: list[dict] = []
    if verify_result.get("source"):
        flow.append({"stage": "source", "detail": verify_result.get("source")})
    if verify_result.get("sink"):
        flow.append({"stage": "sink", "detail": verify_result.get("sink")})
    payload = record.get("payload")
    if not payload and exploit.get("payloads"):
        payload = exploit.get("payloads", [None])[0]
    if payload:
        flow.append({"stage": "payload", "detail": payload})
    if record.get("url"):
        flow.append({
            "stage": "request",
            "detail": record.get("url"),
            "method": record.get("method"),
            "params": record.get("params"),
        })
    response_detail = {
        "status": record.get("status_code") or record.get("status"),
        "matched_indicator": dynamic.get("matched_indicator"),
        "reason": dynamic.get("reason"),
    }
    if response_detail["status"] or response_detail["matched_indicator"] or response_detail["reason"]:
        flow.append({"stage": "response", "detail": response_detail})
    return flow


_SENSITIVE_KEY_RE = re.compile(r"(password|passwd|secret|api[_-]?key|token|authorization|cookie)", re.I)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret(?:[_-]?key)?|api[_-]?key|token|authorization|cookie)\b\s*[:=]\s*([^\n,;]+)"
)
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+\-/=]{6,}")


def _redact_sensitive(value):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _SENSITIVE_KEY_RE.search(str(key)):
                out[key] = "<redacted>" if item not in (None, "") else item
            else:
                out[key] = _redact_sensitive(item)
        return out
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_sensitive(item) for item in value)
    if isinstance(value, str):
        text = _SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", value)
        return _BEARER_RE.sub("Bearer <redacted>", text)
    return value
