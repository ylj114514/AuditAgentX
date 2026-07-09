"""DynamicAnalysisAgent —— 动态分析智能体（专职动态验证调度）。

职责边界（与 VerifyAgent 区分）：
  - VerifyAgent  ：判断候选漏洞真伪（静态复核 + 可选动态工具），产出 static/dynamic 裁决。
  - DynamicAnalysisAgent（本类）：对「已确认」漏洞做**专项动态验证调度**——
      识别项目启动方式、提取攻击面端点、按漏洞类型选择动态策略（HTTP / Harness），
      再委托 DynamicVerifier(HTTP) 与 HarnessVerifier(函数级) 执行，汇总运行时证据。

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
from backend.verifier.pipeline import ExploitPipeline

logger = logging.getLogger(__name__)


class DynamicAnalysisAgent:
    name = "dynamic_analysis_agent"

    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id
        self._pipeline = ExploitPipeline(scan_id=scan_id)

    # ------------------------------------------------------------------ #
    # 决策阶段：识别启动方式 + 提取端点 + 漏洞类型→策略映射（可单独展示）      #
    # ------------------------------------------------------------------ #
    def plan(self, findings: list[dict], code_root: Path | None) -> dict:
        """生成动态分析计划（不执行），用于前端/报告展示决策过程。"""
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
        }

    # ------------------------------------------------------------------ #
    # 执行阶段：委托 ExploitPipeline 完成动态验证 + 证据链                   #
    # ------------------------------------------------------------------ #
    def run(self, findings: list[dict], *, code_root: Path | None = None,
            enable_exploit: bool = True, enable_dynamic: bool = False,
            enable_harness: bool = True, dynamic_target: dict | None = None,
            max_candidates: int | None = None) -> list[dict]:
        """对候选漏洞执行动态验证。返回同一 findings 列表（就地附加证据）。

        - 候选 = confirmed（全量）+ needs_review 中动态可验证者（受预算上限约束）。
        - enable_dynamic=True 且未显式给 dynamic_target 时，尝试用启动识别结果自动补全靶场启动方式。
        - enable_harness 默认 True：函数级 Harness 验证无需靶场，默认开启。
        - max_candidates 为 None 时用 settings.max_dynamic_candidates。
        """
        # 若要 HTTP 动态但没给靶场，尝试用 launch_detector 自动补全启动方式
        if enable_dynamic and not dynamic_target and code_root is not None:
            dynamic_target = self._auto_target(code_root)

        return self._pipeline.run(
            findings, enable_exploit=enable_exploit,
            enable_dynamic=enable_dynamic, dynamic_target=dynamic_target,
            enable_harness=enable_harness, code_root=code_root,
            max_candidates=max_candidates,
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
        enable_harness = bool(request.payload.get("enable_harness", opts.get("enable_harness", False)))
        enable_exploit = bool(request.payload.get("enable_exploit", opts.get("enable_exploit", True)))
        code_root_str = request.payload.get("code_root") or request.context.code_root
        code_root = Path(code_root_str) if code_root_str else None

        # 批量兼容入口：Orchestrator 传入 legacy findings，DynamicAnalysisAgent
        # 内部继续复用 ExploitPipeline，不把底层工具 ACP 化。
        if isinstance(request.payload.get("findings"), list):
            legacy_findings = [dict(item) for item in request.payload.get("findings") or []]
            max_candidates = request.payload.get("max_dynamic_candidates") or opts.get("max_dynamic_candidates")
            results = self.run(
                legacy_findings, code_root=code_root, enable_exploit=enable_exploit,
                enable_dynamic=enable_dynamic, enable_harness=enable_harness,
                dynamic_target=dynamic_target,
                max_candidates=int(max_candidates) if max_candidates else None,
            )
            summary = _dynamic_summary(results, code_root)
            verdict_enum = (ACPVerdict.DYNAMIC_CONFIRMED
                            if summary["dynamic_confirmed"] or summary["harness_confirmed"]
                            else ACPVerdict.STATICALLY_VERIFIED)
            return make_reply(
                request, sender=self.name,
                message_type=ACPMessageType.DYNAMIC_VERIFY_RESULT,
                intent=("动态验证批处理完成："
                        f"confirmed={summary['dynamic_confirmed'] + summary['harness_confirmed']}"),
                payload={"findings": results, "dynamic_summary": summary},
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

        # ACP finding → legacy dict；动态验证只处理「已确认」漏洞，故置 confirmed
        legacy = acp_to_legacy_finding(acp_finding)
        legacy["status"] = "confirmed"
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
        static_verdict = verification.get("static_verdict") or "confirmed"
        final_verdict = _derive_final_verdict(static_verdict, dynamic_verdict)
        verification["dynamic_verdict"] = dynamic_verdict
        verification["final_verdict"] = final_verdict

        if dynamic_verdict in ("dynamic_confirmed", "harness_confirmed"):
            verdict_enum = ACPVerdict.DYNAMIC_CONFIRMED
        elif static_verdict == "false_positive":
            verdict_enum = ACPVerdict.FALSE_POSITIVE
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
            },
            state=ACPState.SUCCESS,
            verdict=verdict_enum,
            confidence=float(res.get("confidence") or verification.get("confidence") or 0.5),
        )

    def _auto_target(self, code_root: Path) -> dict | None:
        """根据启动识别结果构造 local 模式靶场启动配置（隔离环境使用）。"""
        launch = detect_launch(code_root)
        command = launch.get("command")
        if not command:
            logger.info("未识别到启动命令，跳过自动靶场启动")
            return None
        # command 含 {port} 占位符时交由 LocalAppRunner 分配端口
        cmd_list = command.split() if isinstance(command, str) else command
        target = {
            "mode": "local",
            "command": cmd_list,
            "cwd": str(code_root),
            "endpoints": candidate_endpoints(code_root),
            "_framework": launch.get("framework"),
            "_health_path": launch.get("health_path", "/"),
        }
        logger.info("自动靶场启动配置: framework=%s command=%s",
                    launch.get("framework"), command)
        return target


def _derive_dynamic_verdict(runtime: dict, harness: dict) -> str:
    """由 runtime(HTTP) / harness(函数级) 的真实执行结果推导动态裁决。

    取值集合（与 ACPVerification.dynamic_verdict 语义一致）：
      dynamic_confirmed | not_reproduced | not_executed | not_runtime_verifiable | ...
    严格以真实执行结果为准，禁止在未执行时臆造 confirmed。
    """
    if harness.get("dynamically_triggered"):
        return "harness_confirmed"
    status = runtime.get("reproduction_status")
    if status:
        return status
    return "not_executed"


def _derive_final_verdict(static_verdict: str, dynamic_verdict: str) -> str:
    """综合静态 + 动态裁决得出最终裁决。

    取值集合：statically_verified | dynamic_confirmed | false_positive | needs_review。
    """
    if static_verdict == "false_positive":
        return "false_positive"
    if dynamic_verdict in ("dynamic_confirmed", "harness_confirmed"):
        return dynamic_verdict
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
    return {
        "total": len(findings),
        "exploited": sum(1 for f in findings if f.get("_exploit")),
        "dynamic_confirmed": sum(
            1 for f in findings
            if (f.get("_dynamic") or {}).get("reproduction_status") == "dynamic_confirmed"
        ),
        "harness_confirmed": sum(
            1 for f in findings
            if (f.get("_harness") or {}).get("dynamically_triggered")
        ),
        "not_executed": sum(
            1 for f in findings
            if (f.get("_dynamic") or {}).get("reproduction_status") == "not_executed"
        ),
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
