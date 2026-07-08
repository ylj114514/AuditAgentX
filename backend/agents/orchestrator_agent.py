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
from backend.acp.models import (
    ACPContext, ACPMessage, ACPMessageType, ACPState, ACPVerdict,
)
from backend.acp.dispatcher import ACPDispatcher
from backend.acp.adapters import (
    legacy_finding_to_acp, acp_to_legacy_finding,
)
from backend.acp.trace import ACPTracer
from backend.scanners.base import RawFinding

logger = logging.getLogger(__name__)

_RAW_FINDING_FIELDS = {
    "type", "file", "line", "severity", "source",
    "code_snippet", "message", "rule_id", "extra",
}


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
            payload={"code_root": str(code_root)},
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
        tools = self.config.get("enabled_tools", ["semgrep", "gitleaks"])
        # ACP 消息驱动：orchestrator --static_scan.request--> StaticScanAgent.run_acp
        req = self._make_request(
            receiver="static_scan_agent",
            message_type=ACPMessageType.STATIC_SCAN_REQUEST,
            intent=f"启动静态扫描，工具: {tools}",
            payload={"code_root": str(code_root), "enabled_tools": tools},
        )
        reply = self._dispatch_acp(req)
        # run_acp 在 payload.raw_findings 中保留原始 RawFinding dict；_raw 仅作旧别名
        raw_dicts = reply.payload.get("raw_findings") or reply.payload.get("_raw") or []
        return [_raw_finding_from_dict(d) for d in raw_dicts]

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

        # 2) LLM 语义审计补充（可发现工具漏报）——ACP 消息驱动
        if "audit" in agents_enabled:
            req = self._make_request(
                receiver="audit_agent",
                message_type=ACPMessageType.AUDIT_REQUEST,
                intent="LLM 语义审计，补充工具漏报",
                payload={
                    "metadata": {k: v for k, v in metadata.items() if k != "_files"},
                    "raw_findings": [rf.to_dict() for rf in raw],
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

        poc_runner = PocRunner(scan_id=self.scan.id) if use_poc else None

        # 验证阶段专用 context：只做静态验证，动态验证放到后续专门阶段执行
        verify_ctx = ACPContext(
            project_id=self.project.id, scan_id=self.scan.id,
            code_root=str(code_root) if code_root else None,
            enabled_tools=self._acp_context.enabled_tools,
            enabled_agents=self._acp_context.enabled_agents,
            options={},
        )

        # 1) 独立验证（降低误报）——ACP 消息驱动：orchestrator --verify.request--> VerifyAgent.run_acp
        results: list[dict] = []
        for c in candidates:
            if "verify" in agents_enabled:
                acp_finding = legacy_finding_to_acp(c)
                # code_root 通过 finding.extra 冗余传递，兼容 verify_agent 两条读取路径
                acp_finding.setdefault("extra", {})
                if code_root is not None:
                    acp_finding["extra"]["code_root"] = str(code_root)
                req = self._make_request(
                    receiver="verify_agent",
                    message_type=ACPMessageType.VERIFY_REQUEST,
                    intent=f"验证候选漏洞: {c.get('type')} @ {c.get('file')}",
                    payload={"finding": acp_finding, "code_root": str(code_root) if code_root else None},
                    context=verify_ctx,
                )
                reply = self._dispatch_acp(req)
                vinfo = reply.payload.get("verification") or {}
                is_valid = vinfo.get("static_verdict") != "false_positive"
                c["verified"] = bool(is_valid)
                c["status"] = "confirmed" if is_valid else "false_positive"
                conf = reply.status.confidence
                c["confidence"] = float(conf if conf is not None else c.get("confidence", 0.5) or 0.5)
                if vinfo.get("dynamic_verdict"):
                    c["runtime_verification_status"] = vinfo["dynamic_verdict"]
                # 保留 verification（含 source/sink/call_path/裁决）供利用与证据链复用
                c["_verify"] = {**vinfo, "knowledge": reply.payload.get("knowledge") or {}}
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
                },
                context=dynamic_ctx,
            )
            reply = self._dispatch_acp(req)
            results = reply.payload.get("findings") or results
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
                        "knowledge": ev.get("knowledge"),
                        "verification": ev.get("verification"),
                    }, ensure_ascii=False, default=str),
                    logs=json.dumps(ev.get("logs"), ensure_ascii=False, default=str),
                ))
        self.db.commit()
