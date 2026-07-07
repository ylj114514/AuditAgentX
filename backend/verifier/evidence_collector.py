"""证据链采集：把 source→sink→exploit→dynamic runtime 汇总为可追溯结构。

对应 md「证据链可追溯」创新点 & PDF「给出触发文件位置、利用路径、验证方法」。

新增 build_from_acp()：从 ACP messages 列表中提取证据链，兼容 ACP 协议。
"""
from __future__ import annotations

import re


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
        if harness:
            logs.append(f"Fuzzing Harness 验证: {harness.get('verdict', '')}"
                        + (f"（{harness.get('trigger_detail', '')}）"
                           if harness.get('dynamically_triggered') else ""))
        if sandbox:
            logs.append(f"Docker 沙箱: {sandbox.get('status', '')}"
                        f"（健康检查 {sandbox.get('health_check', '')}）")

        confirmed = dynamic.get("confirmed_record") or {}
        sample_record = confirmed or ((dynamic.get("records") or [{}])[0] if dynamic.get("records") else {})
        call_path = _build_call_path(verify_result, exploit)
        runtime = None
        if dynamic:
            runtime = {
                "reproduction_status": dynamic.get("reproduction_status") or _legacy_runtime_status(dynamic),
                "reproducible": dynamic.get("reproducible", False),
                "verified": dynamic.get("verified", False),
                "skipped": dynamic.get("skipped", False),
                "reason": dynamic.get("reason", ""),
                "error": dynamic.get("error", ""),
                "matched_indicator": dynamic.get("matched_indicator"),
                "request": {
                    "url": sample_record.get("url"),
                    "method": sample_record.get("method"),
                    "params": sample_record.get("params"),
                    "payload": sample_record.get("payload"),
                },
                "response_status": sample_record.get("status_code") or sample_record.get("status"),
                "response_excerpt": (sample_record.get("response_excerpt") or "")[:400],
                "elapsed_ms": sample_record.get("elapsed_ms"),
                "records": dynamic.get("records", [])[:10],
                "candidate_endpoints": dynamic.get("candidate_endpoints") or [],
                "evidence_flow": _build_runtime_flow(verify_result, exploit, sample_record, dynamic),
                "sandbox": sandbox,
            }

        return {
            # 静态数据流证据
            "source": verify_result.get("source"),
            "sink": verify_result.get("sink"),
            "data_flow": verify_result.get("propagation_path"),
            # 结构化调用路径：source -> 传播 -> sink，逐跳可追溯
            "call_path": call_path,
            # 利用证据（PDF 模块③要求）
            "exploit": {
                "trigger_location": exploit.get("trigger_location"),
                "exploit_path": exploit.get("exploit_path"),
                "attack_vector": exploit.get("attack_vector"),
                "payloads": exploit.get("payloads"),
                "exploit_code": exploit.get("exploit_code"),
                "verification_method": exploit.get("verification_method"),
                "impact": exploit.get("impact"),
            },
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
            "harness": {
                "verdict": harness.get("verdict"),
                "dynamically_triggered": harness.get("dynamically_triggered", False),
                "harness_code": harness.get("harness_code"),
                "trigger_detail": harness.get("trigger_detail"),
                "execution_backend": harness.get("execution_backend"),
                "attempts": harness.get("attempts"),
                "execution_log": harness.get("execution_log"),
            } if harness else None,
            # VerifyAgent / MCP / Skill 工具证据，供前端和报告回放 Agent 做了什么
            "tool_calls": verify_result.get("tool_calls") or [],
            "static_evidence_chain": verify_result.get("evidence_chain") or {},
            "verification": {
                "mcp_server": verify_result.get("mcp_server"),
                "skill": verify_result.get("skill"),
                "static_verdict": verify_result.get("static_verdict"),
                "dynamic_verdict": verify_result.get("dynamic_verdict"),
                "final_verdict": verify_result.get("final_verdict"),
                "false_positive_reason": verify_result.get("false_positive_reason"),
            },
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

            if "verify.result" in mtype:
                vinfo = payload.get("verification") or {}
                verify_result = {
                    "source": vinfo.get("source"),
                    "sink": vinfo.get("sink"),
                    "call_path": vinfo.get("call_path") or [],
                    "propagation_path": None,
                    "evidence_chain": vinfo.get("evidence_chain") or {},
                    "is_valid": vinfo.get("final_verdict") in ("confirmed",),
                    "confidence": vinfo.get("confidence", 0.5),
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
                dp = payload.get("dynamic") or payload
                status = dp.get("reproduction_status", "not_executed")
                runtime_ev = dp.get("runtime_evidence") or {}
                dynamic = {
                    "reproducible": status == "dynamic_confirmed",
                    "verified": status == "dynamic_confirmed",
                    "reason": dp.get("reason", ""),
                    "error": dp.get("error", ""),
                    "matched_indicator": runtime_ev.get("matched_indicator"),
                    "confirmed_record": runtime_ev.get("request"),
                    "records": runtime_ev.get("records") or [],
                    "skipped": status == "not_executed",
                }
                logs.append(f"动态 HTTP 验证: {status}")

            elif "harness.verify.result" in mtype:
                hp = payload.get("harness") or payload
                harness = {
                    "verdict": hp.get("verdict"),
                    "dynamically_triggered": hp.get("dynamically_triggered", False),
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
