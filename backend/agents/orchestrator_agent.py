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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from backend.config import settings
from backend.core import ids
from backend.models import Project, Scan, Finding, Evidence
from backend.repository.git_client import prepare_workspace, workspace_commit
from backend.agents.repo_parser_agent import RepoParserAgent
from backend.agents.static_scan_agent import StaticScanAgent
from backend.agents.audit_agent import AuditAgent
from backend.agents.verify_agent import VerifyAgent
from backend.verifier.pipeline import ExploitPipeline
from backend.verifier.evidence_collector import EvidenceCollector
from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent
from backend.verifier import exploit_validator as judge
from backend.verifier.context_classifier import apply_context_to_finding, classify_finding_context

# ACP 通信协议
from backend.acp.factory import make_message
from backend.acp.models import (
    ACPContext, ACPMessage, ACPMessageType, ACPState, ACPVerdict,
)
from backend.acp.dispatcher import ACPDispatcher
from backend.acp.adapters import (
    legacy_finding_to_acp, acp_to_legacy_finding,
)
from backend.acp.trace import ACPTracer
from backend.scanners.base import RawFinding
from backend.runtime.scan_execution import (
    SandboxCommandCancelled, is_cancelled, scan_mutation_lock,
)

logger = logging.getLogger(__name__)


class ScanCancelled(RuntimeError):
    """Raised when a running scan receives a user cancellation request."""


_RAW_FINDING_FIELDS = {
    "type", "file", "line", "severity", "source",
    "code_snippet", "message", "rule_id", "extra",
}


def _collect_static_coverage_gaps(scanner_status: list[dict] | None) -> list[dict[str, str]]:
    """Collect explicit Semgrep coverage gaps without turning them into findings."""
    gaps: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for status in scanner_status or []:
        tool = str(status.get("tool") or "")
        if tool != "semgrep":
            continue
        groups = [status.get("workspace") or {}] + list(status.get("batches") or [])
        for group in groups:
            for item in group.get("coverage_missing_files") or []:
                file = str(item.get("file") or "").replace("\\", "/")
                reason = str(item.get("reason") or "unknown")
                key = (file, reason, tool)
                if file and key not in seen:
                    seen.add(key)
                    gaps.append({"file": file, "reason": reason, "tool": tool})
    return gaps


def _apply_static_coverage_priority(raw: list[RawFinding], gaps: list[dict[str, str]]) -> None:
    """Prioritize independent Custom evidence in files Semgrep could not cover."""
    reasons = {str(item.get("file") or ""): str(item.get("reason") or "unknown") for item in gaps}
    for finding in raw:
        if str(finding.source or "").lower() not in {"custom", "custom-taint"}:
            continue
        reason = reasons.get(str(finding.file or "").replace("\\", "/"))
        if not reason:
            continue
        finding.extra = dict(finding.extra or {})
        finding.extra["static_coverage_gap"] = reason
        finding.extra["audit_priority"] = "high"


def _raw_finding_from_dict(d: dict) -> RawFinding:
    """从 static_scan.result 的 _raw dict 重建 RawFinding（供 legacy 下游沿用）。"""
    return RawFinding(**{k: v for k, v in d.items() if k in _RAW_FINDING_FIELDS})


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
    def _cancel_requested(self) -> bool:
        if is_cancelled(self.scan.id):
            return True
        try:
            self.db.refresh(self.scan)
        except Exception:
            pass
        return getattr(self.scan, "status", "") in {"cancelling", "cancelled"}

    def _raise_if_cancelled(self) -> None:
        if self._cancel_requested():
            raise ScanCancelled("用户已取消扫描")

    def _raise_if_cancelled_locked(self) -> None:
        """Refresh and check cancellation while the per-scan DB lock is held."""
        try:
            self.db.refresh(self.scan)
        except Exception:
            pass
        if is_cancelled(self.scan.id) or getattr(self.scan, "status", "") in {"cancelling", "cancelled"}:
            self.db.rollback()
            raise ScanCancelled("用户已取消扫描")

    def _mark_cancelled(self, reason: str) -> None:
        """Converge terminal cancellation without allowing a later done write."""
        with scan_mutation_lock(self.scan.id):
            try:
                self.db.refresh(self.scan)
            except Exception:
                pass
            if getattr(self.scan, "status", "") == "cancelled":
                return
            self.scan.status = "cancelled"
            self.scan.error = reason
            self.scan.finished_at = datetime.utcnow()
            self.db.commit()

    def _finish_success(self, scanner_failures: list[dict]) -> None:
        """Write done/partial only after a final cancellation guard."""
        try:
            with scan_mutation_lock(self.scan.id):
                self._raise_if_cancelled_locked()
                self.scan.status = "partial_completed" if scanner_failures else "done"
                self.scan.progress = 100
                self.scan.current_stage = "finished_with_tool_failures" if scanner_failures else "finished"
                if scanner_failures:
                    summary = "; ".join(
                        f"{item.get('tool')}: {item.get('error') or ('partial results' if item.get('partial_results') else 'failed')}"
                        for item in scanner_failures
                    )
                    self.scan.error = f"部分扫描器未完整执行: {summary}"[:4000]
                self.scan.finished_at = datetime.utcnow()
                self._raise_if_cancelled_locked()
                self.db.commit()
                # request_cancel latches before acquiring the DB mutation lock.
                # Recheck after commit return to converge a last-instant latch.
                self._raise_if_cancelled_locked()
        except ScanCancelled as exc:
            self._mark_cancelled(str(exc))
            raise

    def _stage(self, name: str, progress: int) -> None:
        with scan_mutation_lock(self.scan.id):
            self._raise_if_cancelled_locked()
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

    # ---------- ACP 消息驱动调度 ----------
    def _make_request(
        self,
        *,
        receiver: str,
        message_type: ACPMessageType | str,
        intent: str,
        payload: dict,
        context: ACPContext | None = None,
    ) -> ACPMessage:
        """构造一条以 orchestrator_agent 为发送方的 ACP 请求消息（默认共享 scan 级 context）。"""
        return make_message(
            sender="orchestrator_agent",
            receiver=receiver,
            message_type=message_type,
            intent=intent,
            task_id=self.scan.id,
            context=context or self._acp_context,
            payload=payload,
        )

    def _dispatch_acp(self, request: ACPMessage) -> ACPMessage:
        """把请求消息真正分发给目标 Agent，落盘完整 request/reply，返回回复消息。

        这是「ACP 作为内部调度协议」的核心：Agent 间通信一律走这里，
        而非直接调用各 Agent 的 run()。request 与 reply 都是完整 ACPMessage，
        被 tracer 完整保存（非仅 payload_summary）。
        """
        self.tracer.save(request)
        reply = ACPDispatcher(scan_id=self.scan.id).dispatch(request)
        self.tracer.save(reply)
        if reply.status.state == ACPState.FAILED:
            raise RuntimeError(reply.error or reply.status.detail or
                               f"ACP dispatch failed: {request.header.message_type}")
        return reply

    # ---------- 主流程 ----------
    def run(self) -> None:
        try:
            with scan_mutation_lock(self.scan.id):
                self._raise_if_cancelled_locked()
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
            try:
                from backend.rag.ground_truth import calibrate_findings
                commit = workspace_commit(code_root)
                calibration = calibrate_findings(confirmed, self.project.url or "", commit or "")
                if calibration["matched"]:
                    self.config["ground_truth_calibration"] = calibration
                    self.config["ground_truth_commit"] = commit
                    self.scan.config_json = json.dumps(self.config, ensure_ascii=False, default=str)
            except Exception:  # noqa: BLE001
                logger.exception("[%s] 固定 commit ground truth 校准失败（已忽略）", self.scan.id)
            self._raise_if_cancelled()
            self._persist(confirmed)

            # RAG 自进化：共享 canonical evidence gate 只允许入口已确认的
            # HTTP / target-harness 动态 TP 进入知识库；静态、函数级、机理和
            # blocked 结果一律不学。失败不影响扫描。
            try:
                from backend.rag.feedback_learner import ingest_dynamic_confirmation
                ingested = sum(1 for finding in confirmed if ingest_dynamic_confirmation(finding))
                if ingested:
                    logger.info("[%s] RAG 自进化录入动态确认 %d 条", self.scan.id, ingested)
            except Exception:  # noqa: BLE001
                logger.exception("[%s] RAG 自进化录入失败（已忽略）", self.scan.id)
            self._raise_if_cancelled()

            scanner_failures = [
                item for item in (self.config.get("scanner_status") or [])
                if item.get("tool") in set(self.config.get("enabled_tools") or [])
                and (not item.get("success") or item.get("partial_results"))
            ]

            # ACP completion is durable before the final DB transition.  If the
            # process dies in that narrow window, status reads can conservatively
            # reconcile only from this explicit terminal trace.
            self._acp_record(
                sender="orchestrator_agent",
                receiver="system",
                message_type=ACPMessageType.SCAN_COMPLETE,
                intent="扫描完成",
                payload_summary={
                    "total_findings": len(confirmed),
                    "confirmed": sum(1 for f in confirmed if f.get("status") == "confirmed"),
                },
                state=ACPState.SKIPPED if scanner_failures else ACPState.SUCCESS,
                error=self.scan.error if scanner_failures else None,
            )
            self._finish_success(scanner_failures)
        except ScanCancelled as e:
            logger.info("扫描 %s 已取消: %s", self.scan.id, e)
            self._mark_cancelled(str(e))
            self._acp_record(
                sender="orchestrator_agent",
                receiver="system",
                message_type=ACPMessageType.SCAN_FAILED,
                intent="扫描已由用户取消",
                payload_summary={"reason": str(e)},
                state=ACPState.SKIPPED,
                error=str(e),
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("扫描 %s 失败: %s", self.scan.id, e)
            if self._cancel_requested():
                self._mark_cancelled("用户已取消扫描")
                return
            with scan_mutation_lock(self.scan.id):
                self._raise_if_cancelled_locked()
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
        # clone/准备工作区属基础设施步骤（非 Agent 通信）；真正的 parse.request 在 _parse 中经 _dispatch_acp 发出
        self._stage("RepoParserAgent:clone", 5)
        return prepare_workspace(
            self.project.id, self.project.source_type, self.project.url,
            self.project.local_path, self.project.branch,
        )

    def _parse(self, code_root: Path) -> dict:
        self._stage("RepoParserAgent:parse", 15)
        # ACP 消息驱动：orchestrator --parse.request--> RepoParserAgent.run_acp
        req = self._make_request(
            receiver="repo_parser_agent",
            message_type=ACPMessageType.PARSE_REQUEST,
            intent="解析代码仓库元信息",
            payload={
                "code_root": str(code_root),
                "max_files": (self.config.get("options") or {}).get("max_files"),
            },
        )
        reply = self._dispatch_acp(req)
        metadata = dict(reply.payload.get("metadata") or {})
        # 还原文件清单（run_acp 单列在 _files），供需要的下游复用
        if reply.payload.get("_files"):
            metadata["_files"] = reply.payload["_files"]
        # 回写项目元信息
        self.project.language_summary = ", ".join(metadata.get("languages", []))
        self.project.metadata_json = json.dumps(
            {k: v for k, v in metadata.items() if k != "_files"}, ensure_ascii=False
        )
        self.project.status = "parsed"
        self.db.commit()
        return metadata

    def _static_scan(self, code_root: Path) -> list:
        self._stage("StaticScanAgent", 35)
        tools = self.config.get("enabled_tools", ["semgrep", "bandit", "gitleaks", "trivy"])
        # ACP 消息驱动：orchestrator --static_scan.request--> StaticScanAgent.run_acp
        req = self._make_request(
            receiver="static_scan_agent",
            message_type=ACPMessageType.STATIC_SCAN_REQUEST,
            intent=f"启动静态扫描，工具: {tools}",
            payload={
                "code_root": str(code_root), "enabled_tools": tools,
                "max_files": (self.config.get("options") or {}).get("max_files") or 20000,
                "severity_threshold": (self.config.get("options") or {}).get("severity_threshold") or "low",
                "include_test_findings": bool(
                    (self.config.get("options") or {}).get("include_test_findings", False)
                ),
            },
        )
        reply = self._dispatch_acp(req)
        self.config["scanner_status"] = reply.payload.get("scanner_status") or []
        self.config["static_coverage_gaps"] = _collect_static_coverage_gaps(
            self.config["scanner_status"]
        )
        self.config["raw_finding_count"] = len(
            reply.payload.get("raw_findings") or reply.payload.get("_raw") or []
        )
        self.scan.config_json = json.dumps(self.config, ensure_ascii=False, default=str)
        self.db.commit()
        # run_acp 在 payload.raw_findings 中保留原始 RawFinding dict；_raw 仅作旧别名
        raw_dicts = reply.payload.get("raw_findings") or reply.payload.get("_raw") or []
        raw = [_raw_finding_from_dict(d) for d in raw_dicts]
        _apply_static_coverage_priority(raw, self.config["static_coverage_gaps"])
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
                "confidence": float((rf.extra or {}).get("confidence", 0.5) or 0.5),
                "source": rf.source, "verified": False,
                "status": "candidate", "message": rf.message,
                "rule_id": rf.rule_id, "extra": rf.extra,
            })

        # 2) LLM 语义审计补充（可发现工具漏报）——ACP 消息驱动
        if "audit" in agents_enabled:
            req = self._make_request(
                receiver="audit_agent",
                message_type=ACPMessageType.AUDIT_REQUEST,
                intent="LLM 语义审计，补充工具漏报",
                payload={
                    "metadata": {k: v for k, v in metadata.items() if k != "_files"},
                    "raw_findings": [rf.to_dict() for rf in raw],
                    "static_coverage_gaps": self.config.get("static_coverage_gaps") or [],
                    "code_root": str(code_root),
                },
            )
            reply = self._dispatch_acp(req)
            # 优先使用 legacy_findings 保持 AuditAgent.run() 原始输出兼容；缺省再从 ACPFinding 转回 legacy。
            legacy_findings = reply.payload.get("legacy_findings")
            if legacy_findings is None:
                legacy_findings = [acp_to_legacy_finding(acp_f)
                                   for acp_f in (reply.payload.get("findings") or [])]
            for idx, legacy in enumerate(legacy_findings):
                acp_f = (reply.payload.get("findings") or [{}])[idx] if idx < len(reply.payload.get("findings") or []) else {}
                candidates.append({
                    "type": legacy.get("vulnerability_type") or legacy.get("type"),
                    "severity": legacy.get("severity", "medium"),
                    "file": legacy.get("file_path") or legacy.get("file"),
                    "start_line": legacy.get("start_line") or legacy.get("line"),
                    "line": legacy.get("start_line") or legacy.get("line"),
                    "end_line": legacy.get("end_line"),
                    "code_snippet": legacy.get("vulnerable_code") or legacy.get("code_snippet"),
                    "confidence": float(legacy.get("confidence", 0.6) or 0.6),
                    "source": "audit_agent", "verified": False, "status": "candidate",
                    "detail": legacy if legacy else (acp_f.get("extra") or acp_f),
                })

        return judge.deduplicate(candidates)

    def _verify_worker_count(self, opts: dict, total: int) -> int:
        raw = opts.get("max_verify_workers") or getattr(settings, "verify_workers", 4)
        try:
            workers = int(raw)
        except (TypeError, ValueError):
            workers = 4
        return max(1, min(workers, max(total, 1)))

    def _verify_candidate_limit(self, opts: dict, total: int) -> int:
        raw = opts.get("max_verify_candidates")
        if raw is None:
            raw = getattr(settings, "max_verify_candidates", 50)
        try:
            limit = int(raw)
        except (TypeError, ValueError):
            limit = 50
        if limit <= 0:
            return total
        return max(1, min(limit, total))

    def _verify_and_poc(self, candidates: list[dict], code_root: Path | None = None) -> list[dict]:
        self._stage("VerifyAgent", 70)
        agents_enabled = self.config.get("enabled_agents", ["audit", "verify"])
        opts = self.config.get("options", {})
        enable_exploit = opts.get("enable_exploit", False) or "exploit" in agents_enabled
        enable_dynamic = opts.get("enable_dynamic", False)
        enable_harness = opts.get("enable_harness", False) or "harness" in agents_enabled
        dynamic_target = opts.get("dynamic_target")

        # 在昂贵的 VerifyAgent/LLM 之前，对所有候选执行廉价且确定性的项目范围分流。
        # 以前先截 Top-N，导致测试/样例代码和低置信度单规则告警在截断后被统一写成
        # needs_review；这正是大型真实项目人工复核数失控的根因。
        preclassified: list[dict] = []
        verify_candidates: list[dict] = []
        include_test_findings = bool(opts.get("include_test_findings", False))
        for original in candidates:
            c = dict(original)
            context = classify_finding_context(c)
            apply_context_to_finding(c, context)
            excluded_by_scope = context.get("risk_modifier") == "out_of_scope"
            if ((context.get("context") == "test_fixture" and not include_test_findings)
                    or excluded_by_scope):
                c["verified"] = False
                c["status"] = "out_of_scope"
                c["false_positive_reason"] = context.get("reason") or (
                    "默认生产代码扫描不包含 sample/test/demo/docs/fixture；"
                    "如需审计测试资产请设置 include_test_findings=true。"
                )
                c["_verify"] = {
                    "static_verdict": "out_of_scope",
                    "final_verdict": "out_of_scope",
                    "confidence": c.get("confidence", 0.5),
                    "false_positive_reason": c["false_positive_reason"],
                    "excluded_by_scope": True,
                }
                preclassified.append(c)
            elif self._is_low_confidence_advisory(c):
                c["verified"] = False
                c["status"] = "informational"
                c["_verify"] = {
                    "static_verdict": "informational",
                    "final_verdict": "informational",
                    "confidence": c.get("confidence", 0.5),
                    "detail": (
                        "单一静态规则的低置信度线索；缺少交叉工具或数据流证据，"
                        "保留用于搜索，不进入漏洞人工复核队列。"
                    ),
                    "low_confidence_advisory": True,
                }
                preclassified.append(c)
            else:
                verify_candidates.append(c)

        candidates = judge.rank(verify_candidates)
        verify_limit = self._verify_candidate_limit(opts, len(candidates))
        skipped_candidates: list[dict] = []
        if "verify" in agents_enabled and verify_limit < len(candidates):
            skipped_candidates = [
                self._mark_verify_skipped(c, verify_limit, len(candidates))
                for c in candidates[verify_limit:]
            ]
            candidates = candidates[:verify_limit]
            logger.info(
                "[%s] VerifyAgent 候选裁剪: total=%d selected=%d skipped=%d",
                self.scan.id, verify_limit + len(skipped_candidates),
                verify_limit, len(skipped_candidates),
            )

        # 验证阶段专用 context：只做静态验证，动态验证放到后续专门阶段执行
        verify_ctx = ACPContext(
            project_id=self.project.id, scan_id=self.scan.id,
            code_root=str(code_root) if code_root else None,
            enabled_tools=self._acp_context.enabled_tools,
            enabled_agents=self._acp_context.enabled_agents,
            options={},
        )

        def _mark_verify_failed(c: dict, exc: Exception) -> dict:
            conf = float(c.get("confidence", 0.5) or 0.5)
            c["verified"] = False
            c["status"] = "needs_review"
            c["confidence"] = conf
            c["_verify"] = {
                "static_verdict": "needs_review",
                "dynamic_verdict": "not_executed",
                "final_verdict": "needs_review",
                "confidence": conf,
                "false_positive_reason": f"VerifyAgent dispatch failed: {exc}",
                "detail": "VerifyAgent 静态复核异常，保留为待人工复核，避免整次扫描失败。",
            }
            return c

        def _verify_one(idx: int, candidate: dict) -> tuple[int, dict]:
            c = dict(candidate)
            if "verify" in agents_enabled:
                try:
                    acp_finding = legacy_finding_to_acp(c)
                    # code_root 通过 finding.extra 冗余传递，兼容 verify_agent 两条读取路径
                    acp_finding.setdefault("extra", {})
                    if code_root is not None:
                        acp_finding["extra"]["code_root"] = str(code_root)
                    req = self._make_request(
                        receiver="verify_agent",
                        message_type=ACPMessageType.VERIFY_REQUEST,
                        intent=f"验证候选漏洞: {c.get('type')} @ {c.get('file')}",
                        payload={
                            "finding": acp_finding,
                            "code_root": str(code_root) if code_root else None,
                            "verify_index": idx,
                            "worker_id": threading.current_thread().name,
                        },
                        context=verify_ctx,
                    )
                    reply = self._dispatch_acp(req)
                    vinfo = reply.payload.get("verification") or {}
                    sv = str(vinfo.get("static_verdict") or "").lower()
                    # needs_review（LLM 确认但本地启发式有异议）不能当成 confirmed，保留为待人工复核
                    if sv == "false_positive":
                        c["verified"] = False
                        c["status"] = "false_positive"
                    elif sv == "needs_review" or vinfo.get("confirmed_blockers"):
                        c["verified"] = False
                        c["status"] = "needs_review"
                    elif sv == "confirmed":
                        c["verified"] = True
                        c["status"] = "confirmed"
                    else:
                        c["verified"] = False
                        c["status"] = "needs_review"
                        vinfo.setdefault(
                            "confirmed_blockers",
                            [f"VerifyAgent returned unknown static_verdict={sv or '<missing>'}"],
                        )
                    conf = reply.status.confidence
                    c["confidence"] = float(conf if conf is not None else c.get("confidence", 0.5) or 0.5)
                    if vinfo.get("dynamic_verdict"):
                        c["runtime_verification_status"] = vinfo["dynamic_verdict"]
                    for key in ("context", "risk_modifier", "downgrade_reason",
                                "dynamic_applicable", "confirmed_blockers"):
                        if key in vinfo:
                            c[key] = vinfo[key]
                    # 保留 verification（含 source/sink/call_path/裁决）供利用与证据链复用
                    c["_verify"] = {**vinfo, "knowledge": reply.payload.get("knowledge") or {}}
                    apply_context_to_finding(c)
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "VerifyAgent 静态复核失败，已降级为 needs_review: %s @ %s",
                        c.get("type"), c.get("file"),
                    )
                    c = _mark_verify_failed(c, exc)
            else:
                # quick 模式（未启用 verify）：已检出但未经任何验证，语义为 unverified。
                # 不能标 confirmed——那会让「未验证」冒充「已确认」，也让 quick 与 deep 失去区分。
                c["verified"] = False
                c["status"] = "unverified"
            return idx, c

        # 1) 独立验证（降低误报）——ACP 消息驱动：orchestrator --verify.request--> VerifyAgent.run_acp
        results_by_index: list[dict | None] = [None] * len(candidates)
        verify_workers = self._verify_worker_count(opts, len(candidates))
        if len(candidates) > 1 and "verify" in agents_enabled and verify_workers > 1:
            logger.info(
                "[%s] VerifyAgent 静态复核并发启动: candidates=%d workers=%d",
                self.scan.id, len(candidates), verify_workers,
            )
            with ThreadPoolExecutor(max_workers=verify_workers, thread_name_prefix="verify") as pool:
                futures = {
                    pool.submit(_verify_one, idx, c): idx
                    for idx, c in enumerate(candidates)
                }
                for future in as_completed(futures):
                    if self._cancel_requested():
                        for pending in futures:
                            pending.cancel()
                        raise ScanCancelled("用户已取消扫描")
                    idx, verified = future.result()
                    results_by_index[idx] = verified
        else:
            for idx, c in enumerate(candidates):
                _, verified = _verify_one(idx, c)
                results_by_index[idx] = verified

        results: list[dict] = [c for c in results_by_index if c is not None]
        results.extend(skipped_candidates)
        results.extend(preclassified)

        results = judge.rank(results)
        # Every statically confirmed finding gets a deterministic, localhost-only
        # attack plan even when it is outside this run's dynamic budget. The plan
        # is explicitly pending runtime validation and never substitutes for PoC.
        from backend.agents.exploit_agent import build_authorized_attack_plan
        for finding in results:
            if finding.get("status") != "confirmed":
                continue
            existing = finding.get("_exploit") or {}
            plan = build_authorized_attack_plan(finding, existing)
            if plan:
                finding.setdefault("_exploit", dict(existing))
                finding["_exploit"].setdefault("exploit_code", plan["code"])
                finding["_exploit"].setdefault("payloads", plan["payloads"])
                finding["_exploit"].setdefault("success_indicators", plan["success_indicators"])
                finding["_exploit"].setdefault("trigger_location", plan["trigger_location"])
                finding["_exploit"]["attack_plan_status"] = plan["plan_status"]
        # 2) 漏洞自动利用 + 动态验证（PDF 模块③；含 DeepAudit 式 Fuzzing Harness）
        if enable_exploit or enable_dynamic or enable_harness:
            self._stage("ExploitAgent/DynamicVerify", 88)
            dynamic_ctx = ACPContext(
                project_id=self.project.id, scan_id=self.scan.id,
                code_root=str(code_root) if code_root else None,
                enabled_tools=self._acp_context.enabled_tools,
                enabled_agents=self._acp_context.enabled_agents,
                options={
                    "enable_exploit": enable_exploit,
                    "enable_dynamic": enable_dynamic,
                    "enable_harness": enable_harness,
                    "dynamic_target": dynamic_target,
                    "max_dynamic_candidates": opts.get("max_dynamic_candidates"),
                },
            )
            req = self._make_request(
                receiver="dynamic_analysis_agent",
                message_type=ACPMessageType.DYNAMIC_VERIFY_REQUEST,
                intent="漏洞利用+动态验证流水线",
                payload={
                    "findings": results,
                    "code_root": str(code_root) if code_root else None,
                    "enable_exploit": enable_exploit,
                    "enable_dynamic": enable_dynamic,
                    "enable_harness": enable_harness,
                    "dynamic_target": dynamic_target,
                    "max_dynamic_candidates": opts.get("max_dynamic_candidates"),
                },
                context=dynamic_ctx,
            )
            # 关键降级保障：动态验证阶段（Docker 沙箱 / HTTP 发包 / Harness）任何异常
            # 都必须在此就地捕获并优雅降级——绝不能让动态失败向上抛到 run() 顶层 except，
            # 那会把整次扫描标记 failed 并跳过 _persist()，导致已通过静态审计的漏洞一条都存不下来
            # （用户反馈「docker 一出错就一点漏洞都检测不出来」的根因）。
            # 沙箱级失败（sandbox_start_failed 等）本就由 DockerProjectRunner 内部优雅处理并如实标注；
            # 此处兜底的是 dispatch/pipeline 级的意外异常，降级后保留静态结果并如实标注 dynamic_error。
            try:
                reply = self._dispatch_acp(req)
                results = reply.payload.get("findings") or results
                runtime_plan = reply.payload.get("runtime_plan")
                if isinstance(runtime_plan, dict):
                    self.config["dynamic_runtime_plan"] = runtime_plan
            except ScanCancelled:
                # Cancellation is control flow, not a degradable dynamic failure.
                # DockerProjectRunner has left its context and completed cleanup
                # before this reaches the scan-level cancellation handler.
                raise
            except SandboxCommandCancelled as cancel_exc:
                raise ScanCancelled("用户已取消扫描") from cancel_exc
            except Exception as dyn_exc:  # noqa: BLE001
                if self._cancel_requested():
                    raise ScanCancelled("用户已取消扫描") from dyn_exc
                logger.exception(
                    "[%s] 动态验证阶段异常，已优雅降级：保留静态复核结果正常入库，动态证据缺省",
                    self.scan.id,
                )
                self._acp_record(
                    sender="orchestrator_agent",
                    receiver="dynamic_analysis_agent",
                    message_type=ACPMessageType.DYNAMIC_VERIFY_RESULT,
                    intent="动态验证阶段异常，优雅降级为静态结果",
                    payload_summary={"error": str(dyn_exc), "degraded_to_static": True},
                    state=ACPState.FAILED,
                    error=str(dyn_exc),
                )
                for c in results:
                    # 如实标注：动态阶段未能执行/异常；不伪造任何 http 证据
                    c.setdefault("runtime_verification_status", "dynamic_error")
                    c["_dynamic_error"] = str(dyn_exc)[:300]

        self.config["result_counts"] = {
            status: sum(1 for item in results if item.get("status") == status)
            for status in (
                "confirmed", "needs_review", "false_positive", "out_of_scope",
                "informational", "unverified",
            )
        }
        self.scan.config_json = json.dumps(self.config, ensure_ascii=False, default=str)
        if hasattr(self, "db"):
            self.db.commit()
        return results

    @staticmethod
    def _is_low_confidence_advisory(candidate: dict) -> bool:
        """Keep noisy low-confidence rules visible without calling them reviewable vulnerabilities."""
        rule_id = str(candidate.get("rule_id") or (candidate.get("extra") or {}).get("rule_id") or "").upper()
        finding_type = str(candidate.get("type") or "").lower()
        message = str(candidate.get("message") or "").lower()
        if rule_id in {"DS-0026"} or "healthcheck" in finding_type or "healthcheck" in message:
            return True
        try:
            confidence = float(candidate.get("confidence", 0.5) or 0.5)
        except (TypeError, ValueError):
            confidence = 0.5
        if confidence >= 0.5:
            return False
        if str(candidate.get("severity") or "low").lower() in {"high", "critical"}:
            return False
        sources = candidate.get("corroborating_sources") or (candidate.get("extra") or {}).get("corroborating_sources") or []
        if len({str(source).lower() for source in sources if source}) > 1:
            return False
        extra = candidate.get("extra") or {}
        if extra.get("taint_flow") or candidate.get("taint_flow"):
            return False
        return str(candidate.get("source") or "").lower() in {"semgrep", "custom-taint"}

    @staticmethod
    def _mark_verify_skipped(candidate: dict, limit: int, total: int) -> dict:
        c = dict(candidate)
        conf = float(c.get("confidence", 0.5) or 0.5)
        c["verified"] = False
        c["status"] = "unverified"
        c["confidence"] = conf
        c["_verify"] = {
            "static_verdict": "unverified",
            "dynamic_verdict": "not_executed",
            "final_verdict": "unverified",
            "confidence": conf,
            "false_positive_reason": (
                f"超过本次 VerifyAgent 自动复核上限，仅自动复核 Top {limit}/{total} 个候选。"
            ),
            "detail": "为控制 Standard/Deep 模式耗时，该候选未自动复核；标记为 unverified，而非待人工验证。",
            "skipped_by_budget": True,
        }
        return c

    def _persist(self, findings: list[dict]) -> None:
        # Persisting is an internal database operation, not a user-visible scan
        # phase. Keep the last meaningful analysis stage while results are saved;
        # success/cancellation will replace it with a terminal state afterwards.
        from backend.verifier.evidence_collector import build_static_evidence_chain

        # Evidence construction can parse/source-normalize data; keep it outside
        # the lifecycle lock so no scan holds a DB mutation lock during work that
        # is not itself a database mutation.
        for f in findings:
            self._raise_if_cancelled()
            if not f.get("_evidence"):
                try:
                    f["_evidence"] = build_static_evidence_chain(f)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("静态证据链构建失败（忽略）: %s", exc)
        with scan_mutation_lock(self.scan.id):
            self._persist_db_mutations(findings)

    def _persist_db_mutations(self, findings: list[dict]) -> None:
        try:
            for f in findings:
                self._raise_if_cancelled_locked()
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
                # Runtime raw objects can contain request bodies, cookies, container
                # logs and harness output. Only persist the canonical redacted
                # Evidence separately; detail_json keeps a narrow diagnostic allowlist.
                detail_json=json.dumps(
                    {k: v for k, v in f.items() if k in (
                        "_exploit", "_verify", "_poc_file", "_function_forensic_poc_file", "_evidence",
                        "detail", "context", "risk_modifier", "downgrade_reason",
                        "false_positive_reason", "dynamic_applicable", "confirmed_blockers",
                        "rule_id", "message", "extra", "corroborating_sources",
                        "corroborating_evidence", "duplicate_count",
                    )},
                    ensure_ascii=False, default=str,
                ),
                ))
                self._raise_if_cancelled_locked()
                ev = f.get("_evidence")
                if not ev and f.get("_verify"):
                    ev = EvidenceCollector.build(f.get("_verify") or {})
                if ev:
                    self.db.add(Evidence(
                    id=ids.evidence_id(), finding_id=fid,
                    source=json.dumps(ev.get("source"), ensure_ascii=False, default=str),
                    sink=json.dumps(ev.get("sink"), ensure_ascii=False, default=str),
                    data_flow=json.dumps(ev.get("data_flow"), ensure_ascii=False, default=str),
                    poc_result=json.dumps({
                        "exploit": ev.get("exploit"),
                        "attack_plan": ev.get("attack_plan"),
                        "runtime": ev.get("runtime"),
                        "call_path": ev.get("call_path"),
                        "harness": ev.get("harness"),
                        "sandbox": ev.get("sandbox"),
                        "poc_result": ev.get("poc_result"),
                        "tool_calls": ev.get("tool_calls"),
                        "static_evidence_chain": ev.get("static_evidence_chain"),
                        "knowledge": ev.get("knowledge"),
                        "verification": ev.get("verification"),
                        "artifacts": ev.get("artifacts"),
                        "poc_file": ev.get("poc_file"),
                        "reproduction_metadata": ev.get("reproduction_metadata"),
                        "forensic_poc_file": ev.get("forensic_poc_file"),
                        "function_reproduction_metadata": ev.get("function_reproduction_metadata"),
                    }, ensure_ascii=False, default=str),
                    logs=json.dumps(ev.get("logs"), ensure_ascii=False, default=str),
                    ))
                self._raise_if_cancelled_locked()
            self._raise_if_cancelled_locked()
            self.db.commit()
            self._raise_if_cancelled_locked()
        except ScanCancelled:
            self.db.rollback()
            raise
