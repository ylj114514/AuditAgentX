"""OrchestratorAgent —— 总控调度智能体。

串联完整审计链路（md 文档第 4 节系统总体架构）：
  RepoParser -> StaticScan -> Audit -> Verify -> (PoC/Sandbox) -> 裁决 -> 落库
运行在后台任务中，通过更新 scans/findings/evidence 表反映进度。
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
from backend.verifier import exploit_validator as judge

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    def __init__(self, db: Session, scan: Scan) -> None:
        self.db = db
        self.scan = scan
        self.project: Project = scan.project
        self.config = json.loads(scan.config_json or "{}")

    # ---------- 进度辅助 ----------
    def _stage(self, name: str, progress: int) -> None:
        self.scan.current_stage = name
        self.scan.progress = progress
        self.db.commit()
        logger.info("[%s] 阶段=%s 进度=%d", self.scan.id, name, progress)

    # ---------- 主流程 ----------
    def run(self) -> None:
        try:
            self.scan.status = "running"
            self.scan.started_at = datetime.utcnow()
            self.db.commit()

            code_root = self._prepare()
            metadata = self._parse(code_root)
            raw = self._static_scan(code_root)
            candidates = self._audit(metadata, raw, code_root)
            confirmed = self._verify_and_poc(candidates)
            self._persist(confirmed)

            self.scan.status = "done"
            self.scan.progress = 100
            self.scan.current_stage = "finished"
            self.scan.finished_at = datetime.utcnow()
            self.db.commit()
        except Exception as e:  # noqa: BLE001
            logger.exception("扫描 %s 失败: %s", self.scan.id, e)
            self.scan.status = "failed"
            self.scan.error = str(e)
            self.scan.finished_at = datetime.utcnow()
            self.db.commit()

    # ---------- 各阶段 ----------
    def _prepare(self) -> Path:
        self._stage("RepoParserAgent:clone", 5)
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
        return metadata

    def _static_scan(self, code_root: Path) -> list:
        self._stage("StaticScanAgent", 35)
        tools = self.config.get("enabled_tools", ["semgrep", "gitleaks"])
        return StaticScanAgent().run(code_root, tools)

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

        return judge.deduplicate(candidates)

    def _verify_and_poc(self, candidates: list[dict]) -> list[dict]:
        self._stage("VerifyAgent", 70)
        agents_enabled = self.config.get("enabled_agents", ["audit", "verify"])
        opts = self.config.get("options", {})
        use_poc = "poc" in agents_enabled and opts.get("enable_poc", False)
        use_sandbox = opts.get("enable_sandbox", False)
        enable_exploit = opts.get("enable_exploit", False) or "exploit" in agents_enabled
        enable_dynamic = opts.get("enable_dynamic", False)
        dynamic_target = opts.get("dynamic_target")

        verify_agent = VerifyAgent(scan_id=self.scan.id)
        poc_runner = PocRunner(scan_id=self.scan.id) if use_poc else None

        # 1) 独立验证（降低误报）
        results: list[dict] = []
        for c in candidates:
            if "verify" in agents_enabled:
                vr = verify_agent.run(c)
                is_valid = vr.get("is_valid", True)
                c["verified"] = bool(is_valid)
                c["status"] = "confirmed" if is_valid else "false_positive"
                c["confidence"] = float(vr.get("confidence", c.get("confidence", 0.5)) or 0.5)
                if vr.get("severity"):
                    c["severity"] = vr["severity"]
                c["_verify"] = vr
            else:
                c["status"] = "confirmed"

            # PoC 沙箱脚本（可选）
            if poc_runner and c["status"] == "confirmed":
                self._stage("PocAgent", 80)
                c["_poc"] = poc_runner.run(c, use_sandbox=use_sandbox)

            results.append(c)

        results = judge.filter_false_positives(results)
        results = judge.rank(results)

        # 2) 漏洞自动利用 + 动态验证（PDF 模块③）
        if enable_exploit or enable_dynamic:
            self._stage("ExploitAgent/DynamicVerify", 88)
            ExploitPipeline(scan_id=self.scan.id).run(
                results, enable_exploit=enable_exploit,
                enable_dynamic=enable_dynamic, dynamic_target=dynamic_target,
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
                    poc_result=json.dumps(ev.get("poc_result"), ensure_ascii=False, default=str),
                    logs=json.dumps(ev.get("logs"), ensure_ascii=False, default=str),
                ))
        self.db.commit()
