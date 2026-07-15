"""DynamicAnalysisAgent —— 动态分析智能体（专职动态验证调度）。

职责边界（与 VerifyAgent 区分）：
  - VerifyAgent  ：判断候选漏洞真伪（静态复核 + 可选动态工具），产出 static/dynamic 裁决。
   - DynamicAnalysisAgent（本类）：对「已确认」漏洞做**专项动态验证调度**——
       先以 Harness/PoC Sandbox 做主验证，再仅对未决且 HTTP-capable 的 finding
       选择 Docker/HTTP 作为可选端到端增强，最后汇总分层证据。

实现说明：真正的执行逻辑复用 verifier/pipeline.py 的 ExploitPipeline（避免重复造轮子），
本类是它的「智能体外壳」：对外是一个可被 Orchestrator 调用、名字明确的 Agent，
额外提供 plan()（启动方式识别 + 端点提取 + 策略映射）供答辩展示动态分析决策过程。
"""
from __future__ import annotations

import logging
from pathlib import Path

from backend.dynamic.launch_detector import detect_launch
from backend.dynamic.endpoint_extractor import extract_endpoints, candidate_endpoints
from backend.dynamic.strategy import resolve_strategy, NOT_APPLICABLE
from backend.skills.harness_tools import is_target_harness_confirmed
from backend.verifier.pipeline import ExploitPipeline

logger = logging.getLogger(__name__)


def _build_runtime_plan(launch: dict, code_root: Path | None,
                        requested_target: dict | None) -> dict:
    """Build the one plan consumed by execution, ACP, reports, and UI.

    User-provided target fields remain authoritative. Automatic detection only fills
    omitted fields and never reads project environment files or approves Dockerfile
    execution by itself.
    """
    detected_launch = {
        key: launch.get(key) for key in (
            "framework", "runtime_kind", "source", "source_evidence", "dockerfile",
            "build_context", "compose", "working_dir", "install_command", "run_command",
            "command", "port", "health_path", "manual_steps", "notes",
        ) if launch.get(key) not in (None, "", [], {})
    }
    inferred_target = {
        "mode": "docker_project",
        "endpoints": candidate_endpoints(code_root) if code_root else [],
        "launch_plan": detected_launch,
    }
    supplied = dict(requested_target or {})
    supplied_launch = dict(supplied.pop("launch_plan", {}) or {})
    # URL/local/image targets are explicit user choices. Docker-project defaults are
    # merged with repository evidence, including the previously missed nested Dockerfile.
    if supplied.get("mode") in {"url", "local", "docker"}:
        target = {**inferred_target, **supplied}
        target["launch_plan"] = {**detected_launch, **supplied_launch}
        status = "provided_target"
    else:
        target = {**inferred_target, **supplied}
        target["launch_plan"] = {**detected_launch, **supplied_launch}
        status = "ready" if (launch.get("dockerfile") or launch.get("compose")
                              or launch.get("run_command")) else "manual_required"
    return {
        "schema_version": "dynamic-runtime-plan/v1",
        "status": status,
        "launch_evidence": {
            "source": launch.get("source"),
            "source_evidence": launch.get("source_evidence"),
            "confidence": launch.get("confidence"),
        },
        "project_container_config_requires_approval": bool(
            target.get("launch_plan", {}).get("dockerfile")
            and not target.get("trust_project_container_config")
        ),
        "dynamic_target": target,
        "verification_policy": {
            "primary": "poc_sandbox_harness",
            "docker_http": "optional_fallback_after_unresolved_harness",
            "enable_docker_fallback": bool(target.get("enable_docker_fallback", True)),
        },
        "harness": {"enabled": True,
                    "supported_languages": ["python", "javascript", "php", "ruby", "go"]},
    }


class DynamicAnalysisAgent:
    name = "dynamic_analysis_agent"

    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id
        self._pipeline = ExploitPipeline(scan_id=scan_id)
        self._last_runtime_plan: dict | None = None

    # ------------------------------------------------------------------ #
    # 决策阶段：识别启动方式 + 提取端点 + 漏洞类型→策略映射（可单独展示）      #
    # ------------------------------------------------------------------ #
    def plan(self, findings: list[dict], code_root: Path | None,
             requested_target: dict | None = None) -> dict:
        """生成可审计的运行时计划；执行端必须消费同一份计划。"""
        launch = detect_launch(code_root)
        endpoints = extract_endpoints(code_root)
        per_finding = []
        for f in findings:
            # 与 ExploitPipeline 候选口径一致：confirmed 全量 + needs_review（动态可验证者）。
            # 只跳过 false_positive 等明确非候选状态，避免 plan 低估 deep 模式的验证范围。
            if f.get("status") not in ("confirmed", "needs_review"):
                continue
            strat = resolve_strategy(f.get("type"))
            per_finding.append({
                "type": f.get("type"),
                "file": f.get("file"),
                "strategy": strat.get("strategy"),
                "primary_lane": strat.get("primary_lane"),
                "docker_fallback": bool(strat.get("docker_fallback")),
                "applicable": strat.get("strategy") != NOT_APPLICABLE,
                "reason": strat.get("reason"),
                "param_hint": strat.get("param_hint", []),
            })
        return {
            "launch": launch,
            "endpoints": endpoints,
            "endpoint_count": endpoints.get("count", 0),
            "strategies": per_finding,
            "dynamic_applicable_count": sum(1 for p in per_finding if p["applicable"]),
            "runtime_plan": _build_runtime_plan(launch, code_root, requested_target),
        }

    # ------------------------------------------------------------------ #
    # 执行阶段：委托 ExploitPipeline 完成动态验证 + 证据链                   #
    # ------------------------------------------------------------------ #
    def run(self, findings: list[dict], *, code_root: Path | None = None,
            enable_exploit: bool = True, enable_dynamic: bool = False,
            enable_harness: bool = True, dynamic_target: dict | None = None,
            max_candidates: int | None = None, progress_callback=None) -> list[dict]:
        """对候选漏洞执行动态验证。返回同一 findings 列表（就地附加证据）。

        - 候选 = 上下文允许的 confirmed + 所有 needs_review（受预算上限约束）。
        - enable_dynamic=True 且未显式给 dynamic_target 时，尝试用启动识别结果自动补全靶场启动方式。
        - enable_harness 默认 True：函数级 Harness 验证无需靶场，默认开启。
        - max_candidates 为 None 时用 settings.max_dynamic_candidates。
        """
        plan = self.plan(findings, code_root, dynamic_target)
        self._last_runtime_plan = plan["runtime_plan"]
        if enable_dynamic:
            dynamic_target = self._last_runtime_plan["dynamic_target"]

        return self._pipeline.run(
            findings, enable_exploit=enable_exploit,
            enable_dynamic=enable_dynamic, dynamic_target=dynamic_target,
            enable_harness=enable_harness, code_root=code_root,
            max_candidates=max_candidates, on_progress=progress_callback,
        )

    # ------------------------------------------------------------------ #
    # ACP 接口：dynamic.verify.request → dynamic.verify.result            #
    # ------------------------------------------------------------------ #
    def run_acp(self, request: "ACPMessage") -> "ACPMessage":  # noqa: F821
        """ACP 接口：对单条已确认漏洞做动态验证，返回 dynamic.verify.result。

        输入 payload：finding + verification + exploit + dynamic_target
                      + enable_dynamic / enable_harness / enable_exploit。
        输出 payload：finding + runtime + harness + sandbox + exploit
                      + verification（含同步后的 dynamic_verdict / final_verdict）。

        关键点：runtime/harness 若产生新动态结论，必须同步回 verification 的
        dynamic_verdict 与 final_verdict，避免出现「dynamic_verdict=not_executed
        但 runtime=dynamic_confirmed」这类自相矛盾。
        """
        from backend.acp.factory import make_reply
        from backend.acp.models import ACPMessageType, ACPState, ACPVerdict
        from backend.acp.adapters import acp_to_legacy_finding

        opts = request.context.options or {}
        dynamic_target = request.payload.get("dynamic_target") or opts.get("dynamic_target")
        enable_dynamic = bool(request.payload.get("enable_dynamic", opts.get("enable_dynamic", False)))
        # Harness/PoC Sandbox is the architecture default.  A caller may still
        # explicitly opt out for a diagnostic run, but omitted ACP fields must
        # never silently turn a Deep verification into Docker-first execution.
        enable_harness = bool(request.payload.get("enable_harness", opts.get("enable_harness", True)))
        enable_exploit = bool(request.payload.get("enable_exploit", opts.get("enable_exploit", True)))
        code_root_str = request.payload.get("code_root") or request.context.code_root
        code_root = Path(code_root_str) if code_root_str else None

        # 批量兼容入口：Orchestrator 传入 legacy findings，DynamicAnalysisAgent
        # 内部继续复用 ExploitPipeline，不把底层工具 ACP 化。
        if isinstance(request.payload.get("findings"), list):
            legacy_findings = [dict(item) for item in request.payload.get("findings") or []]
            max_candidates = request.payload.get("max_dynamic_candidates") or opts.get("max_dynamic_candidates")
            progress_callback = self._progress_recorder(request)
            results = self.run(
                legacy_findings, code_root=code_root, enable_exploit=enable_exploit,
                enable_dynamic=enable_dynamic, enable_harness=enable_harness,
                dynamic_target=dynamic_target,
                max_candidates=int(max_candidates) if max_candidates else None,
                progress_callback=progress_callback,
            )
            summary = _dynamic_summary(results, code_root)
            # 路径①(dynamic_confirmed) + 路径②(harness_confirmed 入口级 / function_reproduced 函数级)
            # 任一非零即视为存在动态确定漏洞。
            dyn_confirmed_total = summary["dynamic_confirmed"] + summary["harness_confirmed"]
            completed_no_hit_total = summary["executed_not_reproduced"]
            verdict_enum = (
                ACPVerdict.DYNAMIC_CONFIRMED if dyn_confirmed_total
                else ACPVerdict.CONFIRMED if completed_no_hit_total
                else ACPVerdict.STATICALLY_VERIFIED
            )
            return make_reply(
                request, sender=self.name,
                message_type=ACPMessageType.DYNAMIC_VERIFY_RESULT,
                intent=("动态验证批处理完成："
                        f"confirmed={dyn_confirmed_total + completed_no_hit_total}"),
                payload={"findings": results, "dynamic_summary": summary,
                         "runtime_plan": self._last_runtime_plan},
                state=ACPState.SUCCESS,
                verdict=verdict_enum,
                confidence=_max_confidence(results),
            )

        acp_finding = request.payload.get("finding") or {}
        verification = dict(request.payload.get("verification") or {})
        exploit_in = request.payload.get("exploit") or {}
        if not code_root_str:
            code_root_str = (acp_finding.get("extra") or {}).get("code_root")
            code_root = Path(code_root_str) if code_root_str else None

        # ACP finding → legacy dict；必须保留 VerifyAgent 的裁决边界。旧实现无条件置为
        # confirmed，会让 false_positive 重新进入利用/动态验证并浪费 API。
        legacy = acp_to_legacy_finding(acp_finding)
        static_verdict = str(
            verification.get("static_verdict") or verification.get("final_verdict") or "needs_review"
        ).lower()
        if static_verdict == "false_positive":
            legacy["status"] = "false_positive"
        elif static_verdict in {"confirmed", "statically_verified", "dynamic_confirmed", "harness_confirmed"}:
            legacy["status"] = "confirmed"
        else:
            legacy["status"] = "needs_review"
        legacy["_verify"] = {
            "source": verification.get("source"),
            "sink": verification.get("sink"),
            "call_path": verification.get("call_path") or [],
            "propagation_path": None,
        }
        if exploit_in:
            legacy["_exploit"] = dict(exploit_in)

        results = self.run(
            [legacy], code_root=code_root, enable_exploit=enable_exploit,
            enable_dynamic=enable_dynamic, enable_harness=enable_harness,
            dynamic_target=dynamic_target,
        )
        res = results[0] if results else legacy

        runtime = res.get("_dynamic") or {}
        harness = res.get("_harness") or {}
        sandbox = res.get("_sandbox") or {}
        exploit_out = res.get("_exploit") or exploit_in or {}

        # 动态裁决严格取自 runtime/harness 的真实执行结果，再同步综合裁决
        dynamic_verdict = _derive_dynamic_verdict(runtime, harness)
        static_verdict = verification.get("static_verdict") or static_verdict
        final_verdict = _derive_final_verdict(static_verdict, dynamic_verdict)
        verification["dynamic_verdict"] = dynamic_verdict
        verification["final_verdict"] = final_verdict

        if dynamic_verdict in DYNAMIC_CONFIRMED_VERDICTS:
            verdict_enum = ACPVerdict.DYNAMIC_CONFIRMED
        elif static_verdict == "false_positive":
            verdict_enum = ACPVerdict.FALSE_POSITIVE
        elif dynamic_verdict == "not_reproduced":
            verdict_enum = ACPVerdict.CONFIRMED
        else:
            verdict_enum = ACPVerdict.STATICALLY_VERIFIED

        return make_reply(
            request, sender=self.name,
            message_type=ACPMessageType.DYNAMIC_VERIFY_RESULT,
            intent=f"动态验证完成：dynamic={dynamic_verdict} final={final_verdict}",
            payload={
                "finding": acp_finding,
                "exploit": exploit_out,
                "runtime": runtime,
                "harness": harness,
                "sandbox": sandbox,
                "verification": verification,
                "findings": [res],
                "dynamic_summary": _dynamic_summary([res], code_root),
                "runtime_plan": self._last_runtime_plan,
            },
            state=ACPState.SUCCESS,
            verdict=verdict_enum,
            confidence=float(res.get("confidence") or verification.get("confidence") or 0.5),
        )

    def _progress_recorder(self, request):
        """把 pipeline 的阶段进度持久化为 ACP，前端可真实显示而非猜测 88%。"""
        from backend.acp.factory import make_message
        from backend.acp.models import ACPMessageType, ACPState
        from backend.acp.trace import ACPTracer

        scan_id = self.scan_id or request.context.scan_id or request.header.task_id

        def record(progress: dict) -> None:
            if not scan_id:
                return
            message = make_message(
                sender=self.name,
                receiver="orchestrator_agent",
                message_type=ACPMessageType.DYNAMIC_PROGRESS,
                intent=f"动态验证进度：{progress.get('phase')}",
                conversation_id=request.header.conversation_id,
                task_id=request.header.task_id or scan_id,
                trace_id=request.header.trace_id,
                in_reply_to=request.header.message_id,
                context=request.context,
                payload={"progress": progress},
                state=ACPState.PENDING if progress.get("phase") != "completed" else ACPState.SUCCESS,
            )
            ACPTracer(scan_id=scan_id).save(message)

        return record


def _derive_dynamic_verdict(runtime: dict, harness: dict) -> str:
    """由 runtime(HTTP) / harness(函数级) 的真实执行结果推导动态裁决——取两路中最强证据。

    关键：harness 是动态验证主力（自包含切片），它的典型强结论是 function_reproduced
    （函数级复现，nonce 证明真实函数被调用）。绝不能因为 HTTP 那一路没起靶场（not_executed）
    就把 harness 已经跑出的结果一并抹成 not_executed——那等于把"已验证"误报成"未执行"。

    证据强度从高到低：
      harness_confirmed(入口/目标级) > dynamic_confirmed(HTTP端点级) >
      function_reproduced(harness函数级) > mechanism_confirmed(模板机理) >
      HTTP 明确结论(not_reproduced/blocked/inconclusive/...) >
      harness 明确结论(not_reproduced/model_gap/synthetic_demo_only/...) > not_executed(两路都没跑)
    只有两路都没有任何真实执行结果时，才返回 not_executed。
    """
    h = harness or {}
    hv = h.get("verdict")
    http_status = (runtime or {}).get("reproduction_status")

    # 1) 最强：入口级/目标级 harness 或 HTTP 端点级确认
    if is_target_harness_confirmed(h):
        return "harness_confirmed"
    if http_status == "dynamic_confirmed":
        return "dynamic_confirmed"
    # 2) harness 函数级复现（slice 主力的典型结论）——绝不能被 HTTP 的 not_executed 覆盖
    if hv == "function_reproduced":
        return "function_reproduced"
    if hv == "mechanism_confirmed":
        return "mechanism_confirmed"
    # 3) HTTP 有真实执行结论（not_reproduced/blocked/inconclusive/连接失败等）
    if http_status and http_status != "not_executed":
        return http_status
    # 4) harness 有真实执行结论（跑了但未触发/被阻/合成）——也不是"未执行"
    if hv in ("not_reproduced", "model_gap", "inconclusive", "synthetic_demo_only",
               "sandbox_failed", "unsafe_harness_blocked"):
        return f"harness_{hv}" if hv in {"not_reproduced", "model_gap"} else hv
    # 5) 两路都没有任何真实执行结果
    return http_status or "not_executed"


# 动态「确定」仅限 HTTP 端点复现或真实入口级 Harness。函数级切片的
# function_reproduced 只证明目标函数单元，并不证明端到端入口可达，必须维持 needs_review。
# 集中定义以避免摘要、ACP 和前端把函数级结果误写成动态确认。
DYNAMIC_CONFIRMED_VERDICTS = ("dynamic_confirmed", "harness_confirmed")


def _derive_final_verdict(static_verdict: str, dynamic_verdict: str) -> str:
    """综合静态 + 动态裁决得出最终裁决。

    取值集合：statically_verified | dynamic_confirmed | harness_confirmed |
              function_reproduced | false_positive | needs_review。
    关键：路径①(dynamic_confirmed) 或 路径②(harness_confirmed / function_reproduced)
    任一通过即为「确定」——保留具体来源以便证据溯源。
    """
    if static_verdict == "false_positive":
        return "false_positive"
    if dynamic_verdict in DYNAMIC_CONFIRMED_VERDICTS:
        return dynamic_verdict
    if dynamic_verdict == "not_reproduced":
        # The runtime fact stays not_reproduced; this is the product-level
        # confirmation required for an actually executed no-hit campaign.
        return "confirmed"
    if dynamic_verdict == "function_reproduced":
        return "needs_review"
    if static_verdict in ("confirmed", "statically_verified"):
        return "statically_verified"
    return "needs_review"


def _dynamic_summary(findings: list[dict], code_root: Path | None = None) -> dict:
    plan = None
    if code_root is not None:
        try:
            plan = DynamicAnalysisAgent().plan(findings, code_root)
        except Exception:  # noqa: BLE001
            plan = None
    def _verdict(f: dict) -> str:
        return _derive_dynamic_verdict(f.get("_dynamic") or {}, f.get("_harness") or {})

    return {
        "total": len(findings),
        "exploited": sum(1 for f in findings if f.get("_exploit")),
        "dynamic_confirmed": sum(
            1 for f in findings
            if (f.get("_dynamic") or {}).get("reproduction_status") == "dynamic_confirmed"
        ),
        "harness_confirmed": sum(
            1 for f in findings
            if is_target_harness_confirmed(f.get("_harness") or {})
        ),
        "executed_not_reproduced": sum(
            1 for f in findings
            if _verdict(f) in {"not_reproduced", "harness_not_reproduced"}
        ),
        "model_gap": sum(
            1 for f in findings
            if _verdict(f) == "harness_model_gap"
        ),
        # 函数级复现（slice 主力典型结论）单列，不再被误并进 not_executed。
        "function_reproduced": sum(1 for f in findings if _verdict(f) == "function_reproduced"),
        # not_executed 只计【HTTP 与 harness 两路都没有任何真实执行结果】的 finding，
        # 而不是仅看 HTTP 那一路——否则 harness 已复现的会被误报成未执行。
        "not_executed": sum(1 for f in findings if _verdict(f) == "not_executed"),
        "plan": plan,
    }


def _max_confidence(findings: list[dict]) -> float | None:
    values = []
    for finding in findings:
        try:
            values.append(float(finding.get("confidence")))
        except (TypeError, ValueError, AttributeError):
            continue
    return max(values) if values else None
