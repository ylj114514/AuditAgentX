"""OrchestratorAgent —— 总控调度智能体。

串联完整审计链路（md 文档第 4 节系统总体架构）：
  RepoParser -> StaticScan -> Audit -> Verify -> (PoC/Sandbox) -> 裁决 -> 落库
运行在后台任务中，通过更新 scans/findings/evidence 表反映进度。

新增：每阶段生成 ACPMessage 并通过 ACPTracer 保存到
  data/scans/{scan_id}/agent_messages/
供后续证据链重建和答辩展示。
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from backend.core import ids
from backend.models import Project, Scan, Finding, Evidence
from backend.repository.git_client import prepare_workspace
from backend.agents.repo_parser_agent import RepoParserAgent
from backend.agents.static_scan_agent import StaticScanAgent
from backend.agents.audit_agent import AuditAgent
from backend.agents.verify_agent import VerifyAgent
from backend.verifier.poc_runner import PocRunner
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier.pipeline import ExploitPipeline
from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent
from backend.verifier import exploit_validator as judge

# ACP 通信协议
from backend.acp.factory import make_message
from backend.acp.models import ACPContext, ACPMessageType, ACPState, ACPVerdict
from backend.acp.trace import ACPTracer

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    def __init__(self, db: Session, scan: Scan) -> None:
        self.db = db
        self.scan = scan
        self.project: Project = scan.project
        self.config = json.loads(scan.config_json or "{}")
        # ACP 追踪器：每阶段消息落盘到 data/scans/{scan_id}/agent_messages/
        self.tracer = ACPTracer(scan_id=scan.id)
        # 构建 scan 级别的 ACP context（所有阶段共享）
        self._acp_context = ACPContext(
            project_id=self.project.id,
            scan_id=scan.id,
            enabled_tools=self.config.get("enabled_tools", []),
            enabled_agents=self.config.get("enabled_agents", []),
            options=self.config.get("options", {}),
        )

    # ---------- 进度辅助 ----------
    def _stage(self, name: str, progress: int) -> None:
        self.scan.current_stage = name
        self.scan.progress = progress
        self.db.commit()
        logger.info("[%s] 阶段=%s 进度=%d", self.scan.id, name, progress)

    # ---------- ACP 消息记录辅助 ----------
    def _acp_record(
        self,
        sender: str,
        receiver: str,
        message_type: ACPMessageType | str,
        intent: str,
        payload_summary: dict | None = None,
        state: ACPState = ACPState.SUCCESS,
        verdict: ACPVerdict | str | None = None,
        confidence: float | None = None,
        tools: list | None = None,
        artifacts: list | None = None,
        error: str | None = None,
    ) -> None:
        """生成一条 ACPMessage 并追踪保存，不影响主流程。"""
        try:
            msg = make_message(
                sender=sender,
                receiver=receiver,
                message_type=message_type,
                intent=intent,
                task_id=self.scan.id,
                context=self._acp_context,
                payload=payload_summary or {},
                tools=tools or [],
                artifacts=artifacts or [],
                state=state,
                verdict=verdict,
                confidence=confidence,
                error=error,
            )
            self.tracer.save(msg)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ACP trace 保存失败（不影响主流程）: %s", exc)

    # ---------- 主流程 ----------
    def run(self) -> None:
        try:
            self.scan.status = "running"
            self.scan.started_at = datetime.utcnow()
            self.db.commit()

            # ACP 记录：扫描启动
            self._acp_record(
                sender="orchestrator_agent",
                receiver="system",
                message_type=ACPMessageType.SCAN_START,
                intent=f"启动扫描任务 scan_id={self.scan.id}",
                payload_summary={"scan_id": self.scan.id, "project_id": self.project.id},
            )

            code_root = self._prepare()
            metadata = self._parse(code_root)
            raw = self._static_scan(code_root)
            candidates = self._audit(metadata, raw, code_root)
            confirmed = self._verify_and_poc(candidates, code_root)
            self._persist(confirmed)

            self.scan.status = "done"
            self.scan.progress = 100
            self.scan.current_stage = "finished"
            self.scan.finished_at = datetime.utcnow()
            self.db.commit()

            # ACP 记录：扫描完成
            self._acp_record(
                sender="orchestrator_agent",
                receiver="system",
                message_type=ACPMessageType.SCAN_COMPLETE,
                intent="扫描完成",
                payload_summary={
                    "total_findings": len(confirmed),
                    "confirmed": sum(1 for f in confirmed if f.get("status") == "confirmed"),
                },
                state=ACPState.SUCCESS,
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("扫描 %s 失败: %s", self.scan.id, e)
            self.scan.status = "failed"
            self.scan.error = str(e)
            self.scan.finished_at = datetime.utcnow()
            self.db.commit()
            # ACP 记录：扫描失败
            self._acp_record(
                sender="orchestrator_agent",
                receiver="system",
                message_type=ACPMessageType.SCAN_FAILED,
                intent="扫描异常终止",
                payload_summary={"error": str(e)},
                state=ACPState.FAILED,
                error=str(e),
            )

    # ---------- 各阶段 ----------
    def _prepare(self) -> Path:
        self._stage("RepoParserAgent:clone", 5)
        self._acp_record(
            sender="orchestrator_agent",
            receiver="repo_parser_agent",
            message_type=ACPMessageType.PARSE_REQUEST,
            intent="克隆/准备代码仓库工作区",
            payload_summary={"project_id": self.project.id, "source_type": self.project.source_type},
        )
        return prepare_workspace(
            self.project.id, self.project.source_type, self.project.url,
            self.project.local_path, self.project.branch,
        )

    def _parse(self, code_root: Path) -> dict:
        self._stage("RepoParserAgent:parse", 15)
        metadata = RepoParserAgent().run(code_root)
        # 回写项目元信息
        self.project.language_summary = ", ".join(metadata.get("languages", []))
        self.project.metadata_json = json.dumps(
            {k: v for k, v in metadata.items() if k != "_files"}, ensure_ascii=False
        )
        self.project.status = "parsed"
        self.db.commit()
        # ACP 记录：解析结果
        self._acp_record(
            sender="repo_parser_agent",
            receiver="orchestrator_agent",
            message_type=ACPMessageType.PARSE_RESULT,
            intent="代码仓库解析完成",
            payload_summary={
                "languages": metadata.get("languages", []),
                "file_count": metadata.get("file_count", 0),
                "frameworks": metadata.get("frameworks", []),
            },
        )
        return metadata

    def _static_scan(self, code_root: Path) -> list:
        self._stage("StaticScanAgent", 35)
        tools = self.config.get("enabled_tools", ["semgrep", "gitleaks"])
        self._acp_record(
            sender="orchestrator_agent",
            receiver="static_scan_agent",
            message_type=ACPMessageType.STATIC_SCAN_REQUEST,
            intent=f"启动静态扫描，工具: {tools}",
            payload_summary={"enabled_tools": tools},
        )
        raw = StaticScanAgent().run(code_root, tools)
        self._acp_record(
            sender="static_scan_agent",
            receiver="orchestrator_agent",
            message_type=ACPMessageType.STATIC_SCAN_RESULT,
            intent="静态扫描完成",
            payload_summary={"raw_finding_count": len(raw)},
        )
        return raw

    def _audit(self, metadata: dict, raw: list, code_root: Path) -> list[dict]:
        self._stage("AuditAgent", 55)
        agents_enabled = self.config.get("enabled_agents", ["audit", "verify"])
        candidates: list[dict] = []

        # 1) 静态扫描结果转候选
        for rf in raw:
            candidates.append({
                "type": rf.type, "severity": rf.severity, "file": rf.file,
                "start_line": rf.line, "line": rf.line, "code_snippet": rf.code_snippet,
                "confidence": 0.5, "source": rf.source, "verified": False,
                "status": "candidate", "message": rf.message,
            })

        # 2) LLM 语义审计补充（可发现工具漏报）
        if "audit" in agents_enabled:
            self._acp_record(
                sender="orchestrator_agent",
                receiver="audit_agent",
                message_type=ACPMessageType.AUDIT_REQUEST,
                intent="LLM 语义审计，补充工具漏报",
                payload_summary={"raw_count": len(raw), "candidate_count": len(candidates)},
            )
            llm_findings = AuditAgent(scan_id=self.scan.id).run(metadata, raw, code_root)
            for lf in llm_findings:
                candidates.append({
                    "type": lf.get("vulnerability_type"),
                    "severity": lf.get("severity", "medium"),
                    "file": lf.get("file_path"),
                    "start_line": lf.get("start_line"),
                    "line": lf.get("start_line"),
                    "end_line": lf.get("end_line"),
                    "code_snippet": lf.get("vulnerable_code"),
                    "confidence": float(lf.get("confidence", 0.6) or 0.6),
                    "source": "audit_agent", "verified": False, "status": "candidate",
                    "detail": lf,
                })
            self._acp_record(
                sender="audit_agent",
                receiver="orchestrator_agent",
                message_type=ACPMessageType.AUDIT_RESULT,
                intent="LLM 审计完成",
                payload_summary={"llm_finding_count": len(llm_findings), "total_candidates": len(candidates)},
            )

        return judge.deduplicate(candidates)

    def _verify_and_poc(self, candidates: list[dict], code_root: Path | None = None) -> list[dict]:
        self._stage("VerifyAgent", 70)
        agents_enabled = self.config.get("enabled_agents", ["audit", "verify"])
        opts = self.config.get("options", {})
        use_poc = "poc" in agents_enabled and opts.get("enable_poc", False)
        use_sandbox = opts.get("enable_sandbox", False)
        enable_exploit = opts.get("enable_exploit", False) or "exploit" in agents_enabled
        enable_dynamic = opts.get("enable_dynamic", False)
        enable_harness = opts.get("enable_harness", False) or "harness" in agents_enabled
        dynamic_target = opts.get("dynamic_target")

        verify_agent = VerifyAgent(scan_id=self.scan.id)
        poc_runner = PocRunner(scan_id=self.scan.id) if use_poc else None

        # 1) 独立验证（降低误报）
        results: list[dict] = []
        for c in candidates:
            if "verify" in agents_enabled:
                # ACP 记录：验证请求
                self._acp_record(
                    sender="orchestrator_agent",
                    receiver="verify_agent",
                    message_type=ACPMessageType.VERIFY_REQUEST,
                    intent=f"验证候选漏洞: {c.get('type')} @ {c.get('file')}",
                    payload_summary={
                        "type": c.get("type"),
                        "file": c.get("file"),
                        "line": c.get("start_line") or c.get("line"),
                    },
                )
                vr = verify_agent.run(c, code_root=code_root)
                is_valid = vr.get("is_valid", True)
                c["verified"] = bool(is_valid)
                c["status"] = "confirmed" if is_valid else "false_positive"
                c["confidence"] = float(vr.get("confidence", c.get("confidence", 0.5)) or 0.5)
                if vr.get("severity"):
                    c["severity"] = vr["severity"]
                if vr.get("runtime_verification_status"):
                    c["runtime_verification_status"] = vr["runtime_verification_status"]
                c["_verify"] = vr
                # ACP 记录：验证结果
                self._acp_record(
                    sender="verify_agent",
                    receiver="orchestrator_agent",
                    message_type=ACPMessageType.VERIFY_RESULT,
                    intent="验证完成",
                    payload_summary={
                        "is_valid": is_valid,
                        "status": c["status"],
                        "confidence": c["confidence"],
                    },
                    verdict=ACPVerdict.STATICALLY_VERIFIED if is_valid else ACPVerdict.FALSE_POSITIVE,
                    confidence=c["confidence"],
                )
            else:
                c["status"] = "confirmed"

            # PoC 沙箱脚本（可选）
            if poc_runner and c["status"] == "confirmed":
                self._stage("PocAgent", 80)
                c["_poc"] = poc_runner.run(c, use_sandbox=use_sandbox)

            results.append(c)

        results = judge.filter_false_positives(results)
        results = judge.rank(results)

        # 2) 漏洞自动利用 + 动态验证（PDF 模块③；含 DeepAudit 式 Fuzzing Harness）
        if enable_exploit or enable_dynamic or enable_harness:
            self._stage("ExploitAgent/DynamicVerify", 88)
            self._acp_record(
                sender="orchestrator_agent",
                receiver="exploit_agent",
                message_type=ACPMessageType.EXPLOIT_GENERATE_REQUEST,
                intent="启动漏洞利用+动态验证流水线",
                payload_summary={
                    "enable_exploit": enable_exploit,
                    "enable_dynamic": enable_dynamic,
                    "enable_harness": enable_harness,
                    "confirmed_count": sum(1 for r in results if r.get("status") == "confirmed"),
                },
            )
            # 由 DynamicAnalysisAgent 统一调度动态验证（内部委托 ExploitPipeline）
            dyn_agent = DynamicAnalysisAgent(scan_id=self.scan.id)
            plan = dyn_agent.plan(results, code_root)
            self._acp_record(
                sender="dynamic_analysis_agent",
                receiver="orchestrator_agent",
                message_type=ACPMessageType.DYNAMIC_VERIFY_REQUEST,
                intent="动态分析计划：启动方式识别 + 端点提取 + 策略映射",
                payload_summary={
                    "framework": plan.get("launch", {}).get("framework"),
                    "endpoint_count": plan.get("endpoint_count", 0),
                    "dynamic_applicable_count": plan.get("dynamic_applicable_count", 0),
                },
            )
            dyn_agent.run(
                results, code_root=code_root, enable_exploit=enable_exploit,
                enable_dynamic=enable_dynamic, enable_harness=enable_harness,
                dynamic_target=dynamic_target,
            )
            self._acp_record(
                sender="dynamic_analysis_agent",
                receiver="orchestrator_agent",
                message_type=ACPMessageType.DYNAMIC_VERIFY_RESULT,
                intent="漏洞利用+动态验证流水线完成",
                payload_summary={
                    "exploited": sum(1 for r in results if r.get("_exploit")),
                    "dynamic_verified": sum(1 for r in results if r.get("dynamically_verified")),
                },
                verdict=ACPVerdict.EXPLOIT_GENERATED,
            )
        else:
            # 未启用利用模块时，用 PoC 证据兜底证据链
            for c in results:
                if c.get("_poc") and not c.get("_evidence"):
                    c["_evidence"] = EvidenceCollector.build(
                        c.get("_verify", {}), poc_result=c["_poc"])

        return results

    def _persist(self, findings: list[dict]) -> None:
        self._stage("Persisting", 95)
        for f in findings:
            fid = ids.finding_id()
            self.db.add(Finding(
                id=fid, scan_id=self.scan.id,
                type=f.get("type"), severity=f.get("severity", "low"),
                file_path=f.get("file"),
                start_line=f.get("start_line") or f.get("line"),
                end_line=f.get("end_line"),
                code_snippet=f.get("code_snippet"),
                source=f.get("source"), confidence=f.get("confidence", 0.0),
                verified=f.get("verified", False), status=f.get("status", "candidate"),
                fix_suggestion=(f.get("detail") or {}).get("fix_suggestion"),
                detail_json=json.dumps(
                    {k: v for k, v in f.items() if k.startswith("_") or k in ("detail",)},
                    ensure_ascii=False, default=str,
                ),
            ))
            ev = f.get("_evidence")
            if ev:
                self.db.add(Evidence(
                    id=ids.evidence_id(), finding_id=fid,
                    source=json.dumps(ev.get("source"), ensure_ascii=False, default=str),
                    sink=json.dumps(ev.get("sink"), ensure_ascii=False, default=str),
                    data_flow=json.dumps(ev.get("data_flow"), ensure_ascii=False, default=str),
                    poc_result=json.dumps({
                        "exploit": ev.get("exploit"),
                        "runtime": ev.get("runtime"),
                        "call_path": ev.get("call_path"),
                        "harness": ev.get("harness"),
                        "sandbox": ev.get("sandbox"),
                        "poc_result": ev.get("poc_result"),
                        "tool_calls": ev.get("tool_calls"),
                        "static_evidence_chain": ev.get("static_evidence_chain"),
                        "verification": ev.get("verification"),
                    }, ensure_ascii=False, default=str),
                    logs=json.dumps(ev.get("logs"), ensure_ascii=False, default=str),
                ))
        self.db.commit()
