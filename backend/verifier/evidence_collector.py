"""证据链采集：把 source→sink→exploit→dynamic runtime 汇总为可追溯结构。

对应 md「证据链可追溯」创新点 & PDF「给出触发文件位置、利用路径、验证方法」。

新增 build_from_acp()：从 ACP messages 列表中提取证据链，兼容 ACP 协议。
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy

from backend.skills.harness_tools import is_target_harness_confirmed


# 用户可控输入（source）识别：跨 PHP/Python/Node/Java 常见入口
_SOURCE_RX = [
    re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[\s*['\"]?[\w-]+['\"]?\s*\]"),
    re.compile(r"request\.(?:args|form|values|json|GET|POST|cookies|data)(?:\.get)?\s*[\(\[]\s*['\"]?[\w-]+"),
    re.compile(r"req\.(?:query|body|params|cookies)\.[\w]+"),
    re.compile(r"getParameter\s*\(\s*[\"'][\w-]+"),
    re.compile(r"input\s*\(\s*\)"),
]
# 危险汇聚（sink）识别：按漏洞类型给出该类的危险函数关键字
_SINK_KEYWORDS = {
    "sql injection": ["mysqli_query", "mysql_query", "pg_query", "->query(", "->execute(",
                      "cursor.execute", "db.execute", "session.execute", "sqlite3", "executeQuery"],
    "command injection": ["shell_exec", "system(", "exec(", "popen", "passthru", "proc_open",
                          "os.system", "subprocess", "Runtime.getRuntime", "os.popen"],
    "path traversal": ["file_get_contents", "fopen(", "readfile", "include ", "require ",
                       "open(", "Files.read", "sendFile", "fs.readFile"],
    "code injection": ["eval(", "assert(", "create_function", "compile(", "exec("],
    "server-side template injection": ["render_template_string", "Template(", ".render(", "from_string"],
    "insecure deserialization": ["unserialize", "pickle.loads", "yaml.load", "ObjectInputStream", "marshal.loads"],
    "xss": ["echo ", "print(", "innerHTML", "document.write", "response.getWriter", "res.send"],
    "ssrf": ["curl_exec", "requests.get", "urlopen", "file_get_contents", "fetch(", "HttpURLConnection"],
}


def _derive_static_flow(finding: dict) -> dict:
    """从 finding 自身派生 source→sink→数据流：优先用 interproc 已产出的 taint_flow，
    否则从代码片段识别用户输入(source)与危险函数(sink)，至少给出 2 跳可读数据流。

    让**每一条** finding（不只是动态候选）都有完整可追溯的纵向数据流证据链。"""
    extra = finding.get("extra") or {}
    taint_flow = extra.get("taint_flow")
    file = finding.get("file") or finding.get("file_path")
    line = finding.get("start_line") or finding.get("line")
    code = (finding.get("code_snippet")
            or (finding.get("detail") or {}).get("vulnerable_code") or "")
    vtype = str(finding.get("type") or "")

    # 1) 跨函数污点分析已产出真实数据流：直接采用
    if isinstance(taint_flow, list) and taint_flow:
        return {"source": taint_flow[0], "sink": taint_flow[-1], "data_flow": list(taint_flow)}

    # 2) 从代码片段派生用户输入（source）
    src_var = None
    for rx in _SOURCE_RX:
        m = rx.search(code)
        if m:
            src_var = m.group(0).strip()
            break
    source = {"file": file, "line": line, "variable": src_var or "用户可控输入"}

    # 3) 从代码片段派生危险汇聚（sink）
    sink_fn = None
    for kw in _SINK_KEYWORDS.get(vtype.lower(), []):
        if kw.strip().rstrip("(") and kw.strip().rstrip("(") in code:
            sink_fn = kw.strip().rstrip("(")
            break
    sink = {"file": file, "line": line, "function": sink_fn or f"{vtype} 危险汇聚点"}

    # 4) 组装 2 跳可读数据流
    data_flow = [
        {"stage": "source", "file": file, "line": line,
         "detail": f"用户可控输入{('：' + src_var) if src_var else ''}"},
        {"stage": "sink", "file": file, "line": line,
         "detail": (f"流入危险操作：{sink_fn}()" if sink_fn else f"流入 {vtype} 危险汇聚点")},
    ]
    return {"source": source, "sink": sink, "data_flow": data_flow}


def build_static_evidence_chain(finding: dict) -> dict:
    """为任意 finding 构建完整静态证据链（source→sink→数据流→验证结果），
    即使它没进动态验证队列。用 _verify 已有字段优先，缺失处从代码/taint_flow 派生。"""
    verify_result = dict(finding.get("_verify") or {})
    derived = _derive_static_flow(finding)
    if not verify_result.get("source"):
        verify_result["source"] = derived["source"]
    if not verify_result.get("sink"):
        verify_result["sink"] = derived["sink"]
    if not verify_result.get("propagation_path"):
        verify_result["propagation_path"] = derived["data_flow"]
    return EvidenceCollector.build(verify_result, exploit=finding.get("_exploit") or {})


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
        logs = ["候选漏洞由 AuditAgent 产生", _static_verdict_log(verify_result)]

        if exploit:
            logs.append(f"ExploitAgent 生成利用方案: {exploit.get('vuln_type', '')}")
        if dynamic:
            if dynamic.get("skipped"):
                logs.append(f"HTTP 动态验证跳过: {dynamic.get('reason', '')}")
            elif dynamic.get("reproducible"):
                logs.append(f"HTTP 动态验证成功，命中特征: {dynamic.get('matched_indicator', '')}")
            elif dynamic.get("reproduction_status") == "blocked":
                logs.append(f"HTTP 动态验证被前置条件阻断: {dynamic.get('blocker_reason') or dynamic.get('reason', '')}")
            elif dynamic.get("reproduction_status") in {"inconclusive", "connection_failed", "request_timeout", "setup_failed"}:
                logs.append(f"HTTP 动态验证无法裁决: {dynamic.get('reason', '')}")
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
        # 入口级 Harness 的真实代码是目标特定复现，不是猜测式 HTTP exploit。
        # 函数级 Harness 则只保存在 harness/forensic artifact，绝不提升为主 PoC 代码。
        if (verification.get("dynamic_method") == "target_harness"
                and harness_evidence.get("harness_code")):
            exploit = dict(exploit)
            exploit["exploit_code"] = harness_evidence["harness_code"]
            exploit["code_kind"] = "target_harness_reproduction"
            exploit["generation_status"] = "generated"
            exploit["validation_status"] = "validated"
        exploit_evidence = _redact_sensitive({
            "trigger_location": exploit.get("trigger_location"),
            "exploit_path": exploit.get("exploit_path"),
            "attack_vector": exploit.get("attack_vector"),
            "payloads": exploit.get("payloads"),
            "exploit_code": exploit.get("exploit_code"),
            "code_kind": exploit.get("code_kind"),
            "generation_status": exploit.get("generation_status"),
            "validation_status": exploit.get("validation_status"),
            "failure_code": exploit.get("failure_code"),
            "manual_instructions": exploit.get("manual_instructions"),
            "verification_method": exploit.get("verification_method"),
            "impact": exploit.get("impact"),
        })
        attack_plan = _build_attack_plan_evidence(
            exploit, runtime, verify_result=verify_result, harness=harness_evidence,
        )
        runtime = _redact_sensitive(runtime)
        harness_evidence = _redact_sensitive(harness_evidence)
        project_root = str((sandbox or {}).get("code_root") or "") if isinstance(sandbox, dict) else ""
        sandbox = _redact_sensitive(sandbox)
        logs = _redact_sensitive(logs)

        evidence = {
            # 静态数据流证据
            "source": verify_result.get("source"),
            "sink": verify_result.get("sink"),
            "data_flow": verify_result.get("propagation_path"),
            # 结构化调用路径：source -> 传播 -> sink，逐跳可追溯
            "call_path": call_path,
            # 利用证据（PDF 模块③要求）
            "exploit": exploit_evidence,
            # 静态已确认 finding 的本地授权攻击计划；与已确认 PoC 分离，不能据此声称已利用。
            "attack_plan": attack_plan,
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
            "artifacts": _initial_artifact_states(verification),
            "logs": logs,
        }
        if project_root:
            evidence = _replace_project_root(evidence, project_root)
        return apply_product_evidence_policy(evidence)

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
        dynamic_exploit: dict = {}
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
                    "code_kind": ep.get("code_kind"),
                    "generation_status": ep.get("generation_status"),
                    "validation_status": ep.get("validation_status"),
                    "failure_code": ep.get("failure_code"),
                    "manual_instructions": ep.get("manual_instructions"),
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
                dynamic_exploit = dict(payload.get("exploit") or {})
                logs.append(f"动态 HTTP 验证: {status}")

            elif "harness.verify.result" in mtype:
                hp = payload.get("harness") or payload
                harness = {
                    "verdict": hp.get("verdict"),
                    "dynamically_triggered": hp.get("dynamically_triggered", False),
                    "function_extracted": hp.get("function_extracted", False),
                    "target_function_called": hp.get("target_function_called", False),
                    "verification_level": hp.get("verification_level"),
                    "entrypoint_reachable": hp.get("entrypoint_reachable", False),
                    "reason": hp.get("reason", ""),
                    "harness_code": hp.get("harness_code"),
                    "trigger_detail": hp.get("trigger_detail"),
                    "execution_backend": hp.get("execution_backend"),
                    "attempts": hp.get("attempts"),
                    "execution_log": hp.get("execution_log"),
                }
                logs.append(f"Harness 验证: {hp.get('verdict', '')}")

        # An exploit.generate.result is always a hypothesis.  A formal HTTP replay
        # may be created only from the framework's matching confirmed_record; never
        # reuse code carried by an earlier ACP message.
        exploit = _rebuild_confirmed_acp_http_replay(exploit, dynamic, dynamic_exploit)

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


def _rebuild_confirmed_acp_http_replay(exploit: dict, dynamic: dict,
                                       dynamic_exploit: dict) -> dict:
    """Replace ACP candidate code with the exact, locally guarded confirmed replay.

    The runtime confirmation record is the sole source for HTTP PoC parameters.
    Without both a dynamic confirmation and that record, any code in an ACP
    exploit message remains untrusted candidate content and is left for the
    product evidence policy to redact.
    """
    record = dynamic.get("confirmed_record") if isinstance(dynamic, dict) else None
    if not (
        dynamic.get("reproduction_status") == "dynamic_confirmed"
        and dynamic.get("reproducible")
        and isinstance(record, dict)
        and record.get("url")
    ):
        return exploit

    from backend.agents.exploit_agent import build_confirmed_http_poc

    rebuilt = dict(exploit or {})
    try:
        rebuilt["exploit_code"] = build_confirmed_http_poc(
            record,
            dynamic.get("matched_indicator") or "",
            dynamic_exploit.get("setup_requests") or [],
        )
    except ValueError:
        # Historical ACP messages can attest a runtime result while omitting
        # the exact request fields needed for a safe replay.  Keep that
        # diagnostic evidence, but never turn an incomplete record into a
        # generated or validated PoC.
        rebuilt.update({
            "exploit_code": None,
            "code_kind": "candidate_metadata",
            "generation_status": "validation_pending",
            "validation_status": "validation_pending",
            "failure_code": "incomplete_confirmed_http_record",
            "verification_method": (
                "ACP confirmed_record is incomplete; validated HTTP replay withheld"
            ),
        })
        return rebuilt
    rebuilt["code_kind"] = "validated_http_replay"
    rebuilt["generation_status"] = "generated"
    rebuilt["validation_status"] = "validated"
    rebuilt["verification_method"] = "重放 ACP 动态确认的 confirmed_record，并匹配成功判据"
    return rebuilt


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

    request_params = sample_record.get("params") if isinstance(sample_record.get("params"), dict) else {}
    request_param = sample_record.get("param") or (next(iter(request_params)) if len(request_params) == 1 else None)
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
            "param": request_param,
            "params": request_params,
            "payload": sample_record.get("payload"),
            "transport": sample_record.get("transport"),
        },
        "baseline": dynamic.get("baseline_record") or {},
            "response_status": sample_record.get("status_code") or sample_record.get("status"),
            "response_headers": sample_record.get("response_headers") or {},
        "response_excerpt": (sample_record.get("response_excerpt") or "")[:400],
        "runtime_log_excerpt": (sample_record.get("runtime_log_excerpt") or "")[:1200],
        "elapsed_ms": sample_record.get("elapsed_ms"),
        "records": dynamic.get("records", [])[:10],
        "baseline_records": dynamic.get("baseline_records", [])[:10],
        "setup_records": dynamic.get("setup_records", [])[:10],
        "confirmation_records": dynamic.get("confirmation_records", [])[:6],
        "candidate_endpoints": dynamic.get("candidate_endpoints") or [],
        "manual_endpoint_override": dynamic.get("manual_endpoint_override"),
        "manual_static_override": dynamic.get("manual_static_override"),
            "surfaces": dynamic.get("surfaces", [])[:40],
            "server_binding": dynamic.get("server_binding") or {},
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
    harness_code = harness.get("harness_code")
    harness_hash = harness.get("harness_code_sha256") or (
        hashlib.sha256(str(harness_code).encode("utf-8", "ignore")).hexdigest()
        if harness_code else None
    )
    return {
        "verdict": harness.get("verdict") or "not_executed",
        "dynamically_triggered": harness.get("dynamically_triggered", False),
        "function_mechanism_verified": harness.get("function_mechanism_verified", False),
        "verification_level": harness.get("verification_level"),
        "reason": harness.get("reason", ""),
        "harness_code": harness_code,
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
        "function_location": harness.get("function_location"),
        "function_code_sha256": harness.get("function_code_sha256"),
        "harness_code_sha256": harness_hash,
        "nonce_attestation": harness.get("nonce_attestation"),
        "sandbox_image": harness.get("sandbox_image"),
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


def _build_attack_plan_evidence(exploit: dict, runtime: dict, *,
                                verify_result: dict | None = None,
                                harness: dict | None = None) -> dict | None:
    """Keep a generated local plan distinct from framework-confirmed replay evidence."""
    try:
        from backend.agents.exploit_agent import build_authorized_attack_plan
        finding = {
            "type": exploit.get("vuln_type"),
            "file": str(exploit.get("trigger_location") or "").split(":", 1)[0],
            "line": None,
            "status": "needs_review" if str((verify_result or {}).get("final_verdict") or "").lower() == "needs_review" else None,
            "_verify": verify_result or {},
        }
        plan = build_authorized_attack_plan(finding, exploit)
    except Exception:  # noqa: BLE001 - evidence collection must remain non-fatal
        plan = None
    if not plan:
        return None
    if runtime.get("reproducible") and exploit.get("exploit_code"):
        plan["plan_status"] = "validated_replay"
        plan["label"] = "已验证请求复放"
        plan["code_kind"] = "validated_http_replay"
        plan["generation_status"] = "generated"
        plan["validation_status"] = "validated"
        plan["code_language"] = "python"
        plan["code"] = exploit["exploit_code"]
    elif is_target_harness_confirmed(harness) and exploit.get("exploit_code"):
        plan["plan_status"] = "validated_reproduction"
        plan["label"] = "已验证目标入口 Harness 复现"
        plan["code_kind"] = "target_harness_reproduction"
        plan["generation_status"] = "generated"
        plan["validation_status"] = "validated"
        plan["code_language"] = "python"
        plan["code"] = exploit["exploit_code"]
    return _redact_sensitive(plan)


def _initial_artifact_states(verification: dict) -> dict:
    method = verification.get("dynamic_method")
    level = verification.get("evidence_level")
    primary_required = method in {"http_dynamic", "target_harness"}
    forensic_required = level == "function_unit_reproduced"

    def state(required: bool, *, validation_pending: bool = False) -> dict:
        return {
            "generation_status": "generated" if required else "not_generated",
            "validation_status": (
                "validated" if required else ("validation_pending" if validation_pending else "not_applicable")
            ),
            "persistence_status": "pending" if required else "not_attempted",
            "name": None,
            "sha256": None,
            "failure_code": None,
        }

    return {
        "validated_poc": state(primary_required, validation_pending=not primary_required),
        "function_forensic": state(forensic_required),
    }


def is_persisted_validated_artifact(artifact: object) -> bool:
    """Canonical gate for releasing executable reproduction content."""
    return bool(
        isinstance(artifact, dict)
        and artifact.get("persistence_status") == "persisted"
        and isinstance(artifact.get("sha256"), str)
        and artifact.get("sha256").strip()
    )


def apply_product_evidence_policy(evidence: dict, *, status: str | None = None,
                                  verified: bool | None = None,
                                  file: str | None = None,
                                  line: int | None = None) -> dict:
    """Attach the canonical product decision without conflating diagnostics.

    Runtime failures remain diagnostic evidence. They do not negate an
    independently confirmed static verdict. A finding is exposed as
    actionable/exploitable only when confirmation and a traceable evidence
    chain are both present.
    """
    result = deepcopy(evidence or {})
    verification = dict(result.get("verification") or {})
    final_verdict = str(verification.get("final_verdict") or "").lower()
    static_verdict = str(verification.get("static_verdict") or "").lower()
    normalized_status = str(status or "").lower()
    confirmed = (
        normalized_status == "confirmed"
        if status is not None
        else final_verdict in {"confirmed", "statically_verified", "dynamic_confirmed"}
        or static_verdict in {"confirmed", "statically_verified"}
        or bool(verification.get("dynamically_verified"))
    )
    if verified is False:
        confirmed = False

    blockers = verification.get("confirmed_blockers") or []
    exploit = result.get("exploit") or {}
    ground_truth = result.get("ground_truth") or {}
    source, sink = result.get("source"), result.get("sink")
    call_path = result.get("call_path") or []
    data_flow = result.get("data_flow") or []
    has_location = bool(
        (file and line)
        or exploit.get("trigger_location")
        or (isinstance(source, dict) and source.get("file") and source.get("line"))
        or (isinstance(sink, dict) and sink.get("file") and sink.get("line"))
    )
    has_trace = bool(
        (source and sink)
        or len(call_path) >= 2
        or len(data_flow) >= 2
        or verification.get("dynamically_verified")
        or (ground_truth.get("label") == "true_positive" and ground_truth.get("references"))
    )
    if verification.get("evidence_level") == "function_unit_reproduced":
        confirmed = False
    evidence_complete = bool(confirmed and not blockers and has_location and has_trace)
    artifacts = result.get("artifacts") or {}
    validated_poc = artifacts.get("validated_poc") or {}
    function_forensic = artifacts.get("function_forensic") or {}
    dynamic_method = verification.get("dynamic_method")
    evidence_level = verification.get("evidence_level")
    if dynamic_method in {"http_dynamic", "target_harness"}:
        legacy_primary = result.get("poc_file") or {}
        evidence_complete = bool(
            evidence_complete
            and (
                is_persisted_validated_artifact(validated_poc)
            )
        )
    elif evidence_level == "function_unit_reproduced":
        legacy_forensic = result.get("forensic_poc_file") or {}
        evidence_complete = bool(
            evidence_complete
            and (
                is_persisted_validated_artifact(function_forensic)
            )
        )
    diagnostic = (
        verification.get("runtime_verification_status")
        or (result.get("runtime") or {}).get("reproduction_status")
        or verification.get("harness_verdict")
        or "not_executed"
    )
    verification.update({
        "evidence_complete": evidence_complete,
        "actionable": evidence_complete,
        "exploitable": evidence_complete,
        "diagnostic_verdict": diagnostic,
    })
    result["verification"] = verification
    result["evidence_complete"] = evidence_complete
    result["actionable"] = evidence_complete
    result["exploitable"] = evidence_complete
    result = _enforce_poc_code_policy(result)
    if status is not None and not (normalized_status == "confirmed" and verified is True):
        return _revoke_poc_for_finding_status(result, normalized_status or "unconfirmed")
    return result


_POC_CODE_KEYS = {"code", "exploit_code", "harness_code"}


def _redact_poc_code_tree(value):
    """Remove executable PoC fields at every nesting level in a PoC section."""
    if isinstance(value, dict):
        return {
            key: (None if str(key).lower() in _POC_CODE_KEYS else _redact_poc_code_tree(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_poc_code_tree(item) for item in value]
    return value


def _revoke_poc_for_finding_status(evidence: dict, status: str) -> dict:
    """Remove every formal PoC code path while retaining immutable artifact identity."""
    result = _redact_poc_code_tree(evidence)
    for artifact in (result.get("artifacts") or {}).values():
        if isinstance(artifact, dict) and (
            artifact.get("sha256") or artifact.get("persistence_status") == "persisted"
        ):
            artifact["revoked_by_finding_status"] = status
            artifact["usable"] = False
    for key in ("poc_file", "forensic_poc_file"):
        if isinstance(result.get(key), dict):
            result[key]["revoked_by_finding_status"] = status
            result[key]["usable"] = False
    result.setdefault("verification", {})["poc_revoked_by_finding_status"] = status
    return result


def _enforce_poc_code_policy(evidence: dict) -> dict:
    """Do not expose generated candidate scripts through any evidence consumer.

    A persisted HTTP/target-harness artifact is the sole authorization for an
    end-to-end reproduction script. Function-level Harness source stays in its
    separate forensic evidence and is never promoted to an exploit plan.
    """
    result = dict(evidence or {})
    verification = result.get("verification") or {}
    runtime_validated = bool(verification.get("dynamically_verified")) and (
        verification.get("dynamic_method") in {"http_dynamic", "target_harness"}
    )
    artifacts = result.get("artifacts") or {}
    primary_persisted = is_persisted_validated_artifact(artifacts.get("validated_poc"))
    code_authorized = runtime_validated and primary_persisted
    if not code_authorized:
        # Legacy/partial evidence can nest generated code under arbitrary
        # metadata.  Redact every code field in PoC-bearing sections, not only
        # their common top-level keys, before any report/API consumer sees it.
        for section in ("exploit", "attack_plan", "harness", "poc_result"):
            if section in result:
                result[section] = _redact_poc_code_tree(result[section])
    exploit = dict(result.get("exploit") or {})
    plan = dict(result.get("attack_plan") or {})
    if not code_authorized:
        if exploit:
            exploit["exploit_code"] = None
            exploit["code_kind"] = "candidate_metadata"
            exploit["generation_status"] = "validation_pending"
            exploit["validation_status"] = "validation_pending"
            result["exploit"] = exploit
        if plan:
            plan["code"] = None
            plan["code_kind"] = "candidate_metadata"
            plan["generation_status"] = "validation_pending"
            plan["validation_status"] = "validation_pending"
            result["attack_plan"] = plan
    harness = dict(result.get("harness") or {})
    target_harness_code_authorized = bool(
        code_authorized
        and verification.get("dynamic_method") == "target_harness"
        and is_target_harness_confirmed(harness)
    )
    if harness and not target_harness_code_authorized:
        if harness.get("harness_code"):
            harness["harness_code"] = None
            harness["code_redaction_reason"] = (
                "Harness source is withheld until target-entrypoint confirmation and validated artifact persistence."
            )
        result["harness"] = harness
    return result


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
    runtime_status = runtime.get("reproduction_status")
    runtime_completed_without_hit = (
        runtime_status == "not_reproduced" and not runtime.get("skipped")
    )
    harness_completed_without_hit = harness_verdict == "not_reproduced"
    static_confirmed = static_verdict in {"confirmed", "statically_verified"}

    static_http_not_reproduced = bool(
        static_confirmed and runtime_completed_without_hit and not harness_target
    )
    if static_http_not_reproduced:
        dynamic_verdict = runtime_status
        final_verdict = "statically_verified"
        dynamic_method = "static_confirmation"
        evidence_level = "static_confirmed_http_not_reproduced"
    elif http_reproduced:
        dynamic_verdict = "dynamic_confirmed"
        final_verdict = "dynamic_confirmed"
        dynamic_method = "http_dynamic"
    elif harness_target:
        dynamic_verdict = "harness_confirmed"
        final_verdict = "dynamic_confirmed"
        dynamic_method = "target_harness"
    elif function_reproduced:
        dynamic_verdict = "function_reproduced"
        final_verdict = "needs_review"
        dynamic_method = "function_harness"
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
    if static_http_not_reproduced:
        evidence_level = "static_confirmed_http_not_reproduced"
    elif http_reproduced:
        evidence_level = "http_reproduced"
    elif harness_target:
        evidence_level = "target_harness"
    elif function_reproduced:
        evidence_level = "function_unit_reproduced"
    elif mechanism_only:
        evidence_level = "mechanism_only"
    elif runtime_status == "blocked" or harness_verdict in {"unsafe_harness_blocked", "target_blocked"}:
        evidence_level = "blocked"
    elif (runtime_status in {"inconclusive", "connection_failed", "request_timeout", "setup_failed"}
          or harness_verdict == "sandbox_failed"):
        evidence_level = "inconclusive"
    elif runtime_completed_without_hit or harness_completed_without_hit:
        evidence_level = "not_reproduced"
    else:
        # not_applicable means no Harness execution.  A skipped HTTP verifier
        # plus a non-applicable/unexecuted Harness must not look like a real
        # negative reproduction result.
        evidence_level = "not_executed"

    sandbox = runtime.get("sandbox") if isinstance(runtime.get("sandbox"), dict) else {}
    environment_status = sandbox.get("status") or runtime.get("environment_status")
    execution_blocker = None
    if sandbox and environment_status != "started":
        execution_blocker = sandbox.get("failure_code") or sandbox.get("reason")
    if not execution_blocker and (
        runtime.get("skipped")
        or runtime_status in {"blocked", "inconclusive", "connection_failed", "request_timeout", "setup_failed"}
    ):
        execution_blocker = (
            runtime.get("failure_code")
            or runtime.get("blocker_reason")
            or runtime.get("reason")
        )
    execution_blocker = _sanitize_execution_blocker(execution_blocker)

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
        "entrypoint_confirmed": bool(http_reproduced or harness_target),
        "evidence_level": evidence_level,
        "execution_blocker": execution_blocker,
        "environment_status": environment_status,
        "runtime_verification_status": runtime.get("reproduction_status"),
        "manual_overrides": verify_result.get("manual_overrides") or [],
        "harness_verdict": harness_verdict,
        "harness_dynamically_triggered": bool(harness.get("dynamically_triggered")),
        "function_mechanism_verified": bool(harness.get("function_mechanism_verified")),
        "function_unit_reproduced": function_reproduced,
    }


_ENV_ASSIGNMENT_RE = re.compile(r"(?<![\w])([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\s,;]+)")


def _sanitize_execution_blocker(value):
    """Expose why execution stopped without copying environment values."""
    if value in (None, ""):
        return None
    redacted = str(_redact_sensitive(str(value)))
    return _ENV_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)


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


def _static_verdict_log(verify_result: dict) -> str:
    verdict = str(verify_result.get("static_verdict") or "unverified").lower()
    if verdict in {"confirmed", "statically_verified"}:
        return "VerifyAgent 独立复核通过"
    if verdict == "needs_review":
        return "VerifyAgent 静态复核待人工确认"
    if verdict == "false_positive":
        return "VerifyAgent 判定为误报"
    if verdict == "out_of_scope":
        return "VerifyAgent 判定超出范围"
    return "VerifyAgent 未完成复核"


def _replace_project_root(value, root: str):
    """Replace one sandbox root recursively without touching relative source paths."""
    if isinstance(value, dict):
        return {key: _replace_project_root(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_project_root(item, root) for item in value]
    if isinstance(value, tuple):
        return tuple(_replace_project_root(item, root) for item in value)
    if isinstance(value, str):
        variants = {root, root.replace("\\", "/"), root.replace("/", "\\")}
        text = value
        for candidate in sorted((item for item in variants if item), key=len, reverse=True):
            text = re.sub(re.escape(candidate), "<project_root>", text,
                          flags=re.I if re.match(r"^[A-Za-z]:", candidate) else 0)
        return text
    return value
