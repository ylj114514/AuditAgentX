"""SummaryAgent: aggregate audit results into an executive summary.

This agent is intentionally deterministic first: reports must be useful even
when no LLM key is configured. If a real LLM key is available, the model may
polish the wording, but the local summary remains the fallback contract.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.config import settings


class SummaryAgent(BaseAgent):
    name = "summary_agent"
    prompt_file = "summary_agent_prompt.md"

    def run(self, project: dict, scan: dict, findings: list[dict], stats: dict) -> dict:
        context = self._build_context(project, scan, findings, stats)
        fallback = self._fallback(context)
        if not self._llm_enabled():
            self._trace(json.dumps(context, ensure_ascii=False), "", fallback)
            return fallback

        result = self._call(json.dumps(context, ensure_ascii=False, default=str))
        if not isinstance(result, dict) or result.get("_error"):
            return fallback
        return self._normalize(result, fallback)

    def _build_context(self, project: dict, scan: dict, findings: list[dict], stats: dict) -> dict:
        static_findings = list(findings)
        dynamic_findings = [f for f in findings if self._has_runtime_evidence(f)]
        reproduced = [
            f for f in dynamic_findings
            if ((f.get("evidence") or {}).get("runtime") or {}).get("reproducible")
        ]
        dynamic_breakdown = self._dynamic_breakdown(scan, findings)
        confirmed = [f for f in findings if f.get("status") == "confirmed"]
        verified = [f for f in findings if f.get("verified")]
        type_counts = Counter(f.get("type") or "Unknown" for f in findings)
        source_counts = Counter(f.get("source") or "unknown" for f in findings)

        return {
            "project": project,
            "scan": scan,
            "stats": stats,
            "total": len(findings),
            "confirmed": len(confirmed),
            "verified": len(verified),
            "static_total": len(static_findings),
            "dynamic_total": len(dynamic_findings),
            "reproduced": len(reproduced),
            "dynamic_breakdown": dynamic_breakdown,
            "type_counts": dict(type_counts.most_common(8)),
            "source_counts": dict(source_counts.most_common(8)),
            "top_findings": self._top_findings(findings),
            "agent_workflow": [
                {
                    "agent": "RepoParserAgent",
                    "role": "解析仓库结构、语言、框架、入口文件、依赖与代码规模，为后续审计提供项目画像。",
                },
                {
                    "agent": "StaticScanAgent",
                    "role": "调用 Semgrep、Gitleaks、自定义规则等工具进行静态扫描，产出 SQL 注入、命令注入、路径遍历、硬编码密钥等候选风险。",
                },
                {
                    "agent": "AuditAgent",
                    "role": "基于 LLM 对代码上下文做语义审计，补充传统 SAST 工具可能漏掉的业务逻辑与调用链风险。",
                },
                {
                    "agent": "VerifyAgent",
                    "role": "独立复核候选漏洞，调用本地代码上下文读取、启发式分析和 SAST replay 工具过滤误报。",
                },
                {
                    "agent": "ExploitAgent / DynamicVerifier",
                    "role": "为已确认漏洞生成授权 PoC、触发路径和利用代码，并在本地靶场或授权目标上保存动态验证证据。",
                },
                {
                    "agent": "SummaryAgent",
                    "role": "汇总项目概况、静态/动态结果、证据链和修复优先级，生成执行摘要与修改建议。",
                },
            ],
        }

    def _fallback(self, ctx: dict) -> dict:
        project = ctx["project"]
        stats = ctx["stats"]
        total = ctx["total"]
        risk = self._overall_risk(stats)
        languages = "、".join(project.get("languages") or []) or "未识别"
        frameworks = "、".join(project.get("frameworks") or []) or "未识别"
        source = project.get("url") or project.get("local_path") or "未记录"
        top_types = self._format_top_types(ctx["type_counts"])

        executive_summary = (
            f"本次审计对象为 {project.get('name')}，来源为 {source}，项目主要语言为 {languages}，"
            f"框架识别结果为 {frameworks}，共解析 {project.get('file_count', 0)} 个文件、"
            f"{project.get('loc', 0)} 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，"
            f"再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，"
            f"VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC "
            f"并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 {total} 条风险，"
            f"其中 Critical {stats.get('critical', 0)} 条、High {stats.get('high', 0)} 条、"
            f"Medium {stats.get('medium', 0)} 条、Low {stats.get('low', 0)} 条；"
            f"静态分析覆盖 {ctx['static_total']} 条，动态验证覆盖 {ctx['dynamic_total']} 条，"
            f"其中 {ctx['reproduced']} 条已复现。主要风险类型集中在 {top_types}，总体风险评级为 {risk.upper()}。"
        )

        static_summary = (
            f"静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 {ctx['static_total']} 条静态风险。"
            f"主要来源分布为 {self._format_top_types(ctx['source_counts'])}。这些结果先作为候选项进入 VerifyAgent，"
            "避免仅凭规则命中直接下结论。"
        )
        dynamic_summary = self._dynamic_summary_text(ctx)

        workflow_summary = [
            f"{item['agent']}：{item['role']}" for item in ctx["agent_workflow"]
        ]
        key_risks = self._key_risks(ctx)
        remediation_plan = self._remediation_plan(ctx, risk)
        conclusion = (
            f"综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 {risk.upper()} 风险水平。"
            "建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。"
        )
        return {
            "executive_summary": executive_summary,
            "overall_risk": risk,
            "static_summary": static_summary,
            "dynamic_summary": dynamic_summary,
            "dynamic_breakdown": ctx.get("dynamic_breakdown", {}),
            "workflow_summary": workflow_summary,
            "key_risks": key_risks,
            "remediation_plan": remediation_plan,
            "conclusion": conclusion,
        }

    def _normalize(self, result: dict, fallback: dict) -> dict:
        normalized = dict(fallback)
        for key in (
            "executive_summary", "overall_risk", "static_summary", "dynamic_summary",
            "workflow_summary", "key_risks", "remediation_plan", "conclusion",
        ):
            value = result.get(key)
            if value:
                normalized[key] = value
        # dynamic_breakdown 是确定性统计，不允许 LLM 覆盖，避免报告丢失真实执行状态。
        normalized["dynamic_breakdown"] = fallback.get("dynamic_breakdown", {})
        normalized["overall_risk"] = str(normalized["overall_risk"]).lower()
        if normalized["overall_risk"] not in {"critical", "high", "medium", "low"}:
            normalized["overall_risk"] = fallback["overall_risk"]
        return normalized

    @staticmethod
    def _llm_enabled() -> bool:
        if os.getenv("SUMMARY_AGENT_USE_LLM") != "1":
            return False
        key = (settings.llm_api_key or "").strip().lower()
        return bool(key and key not in {"sk-test", "your-api-key-here", "test"})

    @staticmethod
    def _has_runtime_evidence(finding: dict) -> bool:
        evidence = finding.get("evidence") or {}
        return bool(evidence.get("runtime"))

    @staticmethod
    def _dynamic_breakdown(scan: dict, findings: list[dict]) -> dict:
        """提取动态验证真实执行状态，供报告展示 quick/deep 差异与未复现原因。"""
        config = scan.get("config") or {}
        options = config.get("options") or {}
        target = options.get("dynamic_target") or {}
        runtime_status = Counter()
        runtime_reasons = Counter()
        sandbox_status = Counter()
        harness_verdict = Counter()
        harness_source = Counter()
        target_confirmed = 0
        mechanism_confirmed = 0
        dynamically_verified = 0   # 经运行时证据（HTTP 复现或目标函数级 Harness）确认
        http_reproduced = 0        # 仅 HTTP 可复现
        status_counts = Counter()

        for f in findings:
            status_counts[f.get("status") or "unknown"] += 1
            evidence = f.get("evidence") or {}
            verification = evidence.get("verification") or {}
            if verification.get("dynamically_verified"):
                dynamically_verified += 1
            runtime = evidence.get("runtime") or {}
            if runtime.get("reproducible"):
                http_reproduced += 1
            if runtime:
                status = runtime.get("reproduction_status") or (
                    "dynamic_confirmed" if runtime.get("reproducible") else "not_executed"
                )
                runtime_status[status] += 1
                reason = runtime.get("reason") or runtime.get("error")
                if reason:
                    runtime_reasons[str(reason)] += 1
                sb = evidence.get("sandbox") or runtime.get("sandbox") or {}
                if sb:
                    sandbox_status[sb.get("status") or "unknown"] += 1

            harness = evidence.get("harness") or {}
            if harness:
                verdict = harness.get("verdict") or "not_executed"
                harness_verdict[verdict] += 1
                if harness.get("harness_source"):
                    harness_source[harness.get("harness_source")] += 1
                if verdict == "target_confirmed" or harness.get("dynamically_triggered"):
                    target_confirmed += 1
                elif verdict == "mechanism_confirmed":
                    mechanism_confirmed += 1

        return {
            "scan_mode": config.get("scan_mode") or "legacy/custom",
            "enabled_agents": config.get("enabled_agents") or [],
            "enabled_tools": config.get("enabled_tools") or [],
            "enable_exploit": bool(options.get("enable_exploit")),
            "enable_dynamic": bool(options.get("enable_dynamic")),
            "enable_harness": bool(options.get("enable_harness")),
            "dynamic_target_mode": target.get("mode") if isinstance(target, dict) else None,
            "runtime_status_counts": dict(runtime_status.most_common()),
            "runtime_reason_counts": dict(runtime_reasons.most_common(6)),
            "sandbox_status_counts": dict(sandbox_status.most_common()),
            "harness_verdict_counts": dict(harness_verdict.most_common()),
            "harness_source_counts": dict(harness_source.most_common()),
            "harness_target_confirmed": target_confirmed,
            "harness_mechanism_confirmed": mechanism_confirmed,
            "dynamically_verified": dynamically_verified,
            "http_reproduced": http_reproduced,
            "status_counts": dict(status_counts.most_common()),
        }

    @staticmethod
    def _format_counts(counter: dict) -> str:
        if not counter:
            return "无"
        return "、".join(f"{k}={v}" for k, v in counter.items())

    def _dynamic_summary_text(self, ctx: dict) -> str:
        bd = ctx.get("dynamic_breakdown") or {}
        mode = bd.get("scan_mode") or "unknown"
        switches = (
            f"exploit={'开' if bd.get('enable_exploit') else '关'}，"
            f"HTTP动态={'开' if bd.get('enable_dynamic') else '关'}，"
            f"Harness={'开' if bd.get('enable_harness') else '关'}"
        )
        if not ctx["dynamic_total"] and not bd.get("harness_verdict_counts"):
            return (
                f"本次扫描模式为 {mode}，动态开关：{switches}。报告未发现已落库的 runtime/Harness 动态证据；"
                "若需要展示漏洞利用效果，应使用 Deep 模式或显式启用 ExploitAgent、HTTP 动态验证和 Harness。"
            )
        runtime_counts = self._format_counts(bd.get("runtime_status_counts") or {})
        harness_counts = self._format_counts(bd.get("harness_verdict_counts") or {})
        reason_counts = self._format_counts(bd.get("runtime_reason_counts") or {})
        return (
            f"本次扫描模式为 {mode}，动态开关：{switches}。"
            f"动态验证阶段对 {ctx['dynamic_total']} 条漏洞保存了 runtime 证据，其中 {ctx['reproduced']} 条具备 HTTP 可复现结果；"
            f"经运行时证据动态确认（HTTP 复现或目标函数级 Harness）共 {bd.get('dynamically_verified', 0)} 条；"
            f"runtime 状态分布为 {runtime_counts}；Harness 裁决分布为 {harness_counts}。"
            f"其中目标函数级 Harness 确认 {bd.get('harness_target_confirmed', 0)} 条，"
            f"模板机理级确认 {bd.get('harness_mechanism_confirmed', 0)} 条。"
            f"未复现或未执行的主要原因：{reason_counts}。"
            "注意：0 条 HTTP 可复现不等于 Deep 阶段未执行，可能是沙箱启动失败、入口缺失、类型不适合动态验证、payload 未命中，或仅达到 Harness 机理级验证。"
        )

    @staticmethod
    def _overall_risk(stats: dict) -> str:
        if stats.get("critical", 0) > 0:
            return "critical"
        if stats.get("high", 0) > 0:
            return "high"
        if stats.get("medium", 0) > 0:
            return "medium"
        return "low"

    @staticmethod
    def _format_top_types(counter: dict) -> str:
        if not counter:
            return "暂无明显集中类型"
        return "、".join(f"{name}({count})" for name, count in list(counter.items())[:4])

    @staticmethod
    def _top_findings(findings: list[dict]) -> list[dict]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        rows = sorted(
            findings,
            key=lambda f: (order.get(str(f.get("severity", "low")).lower(), 9), -(f.get("confidence") or 0)),
        )
        return [
            {
                "type": f.get("type"),
                "severity": f.get("severity"),
                "file": f.get("file"),
                "line": f.get("start_line") or f.get("line"),
                "verified": f.get("verified"),
                "status": f.get("status"),
            }
            for f in rows[:8]
        ]

    def _key_risks(self, ctx: dict) -> list[str]:
        risks: list[str] = []
        for item in ctx["top_findings"][:5]:
            risks.append(
                f"{item.get('severity', 'unknown').upper()} {item.get('type') or 'Unknown'} "
                f"位于 {item.get('file') or '未知文件'}:{item.get('line') or '-'}，"
                f"状态为 {item.get('status') or 'unknown'}。"
            )
        if not risks:
            risks.append("未发现可展示的漏洞明细，但仍建议保留依赖、密钥和输入校验的基础安全检查。")
        return risks

    def _remediation_plan(self, ctx: dict, risk: str) -> list[dict[str, Any]]:
        plan: list[dict[str, Any]] = []
        if ctx["stats"].get("critical", 0) or ctx["stats"].get("high", 0):
            plan.append({
                "priority": "P0",
                "title": "优先修复 Critical/High 漏洞",
                "detail": "先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。",
            })
        plan.extend([
            {
                "priority": "P1",
                "title": "按漏洞类型批量治理",
                "detail": "对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。",
            },
            {
                "priority": "P1",
                "title": "补充动态验证覆盖",
                "detail": "为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。",
            },
            {
                "priority": "P2",
                "title": "纳入持续审计流程",
                "detail": "将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。",
            },
        ])
        if risk in {"medium", "low"}:
            plan[0]["detail"] += " 当前无 Critical 结论时，也应优先处理已确认且靠近外部输入面的 Medium 风险。"
        return plan
