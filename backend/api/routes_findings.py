"""漏洞详情 / 验证 / 证据链接口（md 7.7 / 7.8 / 7.9）。"""
from __future__ import annotations

import json
import logging
import ntpath
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.core import ids
from backend.models import Finding, Evidence, Project, Scan
from backend.schemas import FindingDetail, VerifyRequest, VerifyResponse
from backend.agents.exploit_agent import ExploitAgent
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.evidence_collector import EvidenceCollector, apply_product_evidence_policy
from backend.verifier.pipeline import (
    ExploitPipeline, _auth_bootstrap_inventory, _proven_surfaces_for_finding,
    _static_counterevidence_reason,
)
from backend.dynamic.endpoint_extractor import extract_endpoints
from backend.verifier import exploit_templates as tpl
from backend.verifier import app_runner
from backend.verifier.context_classifier import classify_finding_context
from backend.dynamic.target_guard import validate_dynamic_base_url
from backend.dynamic.source_route_binding import is_server_bound_surface
from backend.config import settings
from contextlib import nullcontext

router = APIRouter(prefix="/api/findings", tags=["findings"])
logger = logging.getLogger(__name__)

@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, db: Session = Depends(get_db)) -> FindingDetail:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    detail = json.loads(f.detail_json or "{}")
    inner = detail.get("detail", {}) or {}
    ev = _latest_evidence(db, finding_id)
    evidence = _decode_evidence(ev) if ev else None
    verification = {"verified": f.verified, "confidence": f.confidence,
                    "status": f.status}
    if evidence and evidence.get("runtime"):
        runtime = evidence["runtime"]
        verification.update({
            "reproducible": runtime.get("reproducible", False),
            "matched_indicator": runtime.get("matched_indicator"),
            "dynamic_reason": runtime.get("reason"),
        })
    return FindingDetail(
        finding_id=f.id, type=f.type, severity=f.severity, file=f.file_path,
        start_line=f.start_line, end_line=f.end_line, vulnerable_code=f.code_snippet,
        source=inner.get("source"), sink=inner.get("sink"),
        data_flow=inner.get("data_flow", []),
        verification=verification,
        fix_suggestion=f.fix_suggestion,
    )


@router.post("/{finding_id}/label")
def label_finding(finding_id: str, label: str = Body(..., embed=True),
                  db: Session = Depends(get_db)) -> dict:
    """人工标注真漏洞/误报（黄金 ground truth）——录入 RAG 知识库供后续复核自进化。

    ``false_positive``、``out_of_scope`` 和 ``informational`` 都会撤销
    已持久化 PoC 的展示资格；仅前两种反馈给 RAG 学习器。
    """
    status_by_label = {
        "true_positive": "confirmed",
        "false_positive": "false_positive",
        "out_of_scope": "out_of_scope",
        "informational": "informational",
    }
    if label not in status_by_label:
        raise HTTPException(400, "label 必须是 true_positive、false_positive、out_of_scope 或 informational")
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    detail = json.loads(f.detail_json or "{}")
    inner = detail.get("detail", {}) or {}
    ev = _latest_evidence(db, finding_id)
    evidence = _decode_evidence(ev) if ev else {}
    finding = {
        "type": f.type, "file": f.file_path, "status": f.status,
        "cwe_id": (evidence.get("knowledge") or {}).get("cwe_id"),
        "context": detail.get("context"),
        "false_positive_reason": detail.get("false_positive_reason") or detail.get("downgrade_reason"),
        "source_symbol": inner.get("source"),
        "evidence": evidence or {"source": inner.get("source"), "sink": inner.get("sink")},
    }
    from backend.rag.feedback_learner import ingest_feedback
    learned = ingest_feedback(finding, label, "human") if label in {"true_positive", "false_positive"} else False
    f.status = status_by_label[label]
    if label != "true_positive":
        f.verified = False
    db.commit()
    return {"finding_id": finding_id, "label": label, "label_source": "human", "learned": learned}


@router.post("/{finding_id}/verify", response_model=VerifyResponse)
def verify_finding(finding_id: str, payload: VerifyRequest,
                   db: Session = Depends(get_db)) -> VerifyResponse:
    """按需对单条漏洞执行「漏洞利用 + 动态验证」（md 7.8）。

    - mode=url   ：对 payload.base_url 指向的已运行靶场发包
    - mode=local ：用 payload.dynamic_target 在本机子进程启动靶场（隔离环境）
    - mode=docker：用 payload.dynamic_target 在 Docker 中启动靶场
    """
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")

    existing_evidence = _latest_evidence(db, finding_id)
    verify_context = _verify_context_from_existing(f, existing_evidence)

    finding_dict = {
        "finding_id": f.id, "type": f.type, "file": f.file_path,
        "start_line": f.start_line, "line": f.start_line,
        "severity": f.severity, "status": f.status, "verified": f.verified,
        "confidence": f.confidence,
        "code_snippet": f.code_snippet, "_verify": verify_context,
    }
    context = classify_finding_context(finding_dict)

    # 1) 生成利用方案
    exploit = ExploitAgent(scan_id=f.scan_id).run(finding_dict)
    template = tpl.match_template(f.type)
    if template:
        exploit.setdefault("_injection_points", template.injection_points)

    # 2) Parse target and dynamically verify. Explicit static counterevidence
    # is a shared eligibility gate, not merely batch-pipeline guidance.
    verifier = DynamicVerifier(timeout=payload.timeout)
    dyn = None
    counterevidence = _static_counterevidence_reason(finding_dict)
    if counterevidence and not payload.allow_static_counterevidence_override:
        dyn = _manual_policy_skip(counterevidence)
    else:
        if counterevidence:
            reason = str(payload.static_counterevidence_override_reason or "").strip()
            if not reason:
                raise HTTPException(400, "static counterevidence override requires an audit reason")
            verify_context.setdefault("manual_overrides", []).append({
                "kind": "static_counterevidence", "reason": reason,
                "counterevidence": counterevidence,
            })
        try:
            with _resolve_verify_target(payload) as (base_url, endpoints):
                if base_url and exploit.get("payloads"):
                    requested_endpoints = (payload.endpoints if payload.endpoints is not None
                                           else endpoints)
                    # Persisted evidence, ACP/MCP messages, and request JSON are
                    # all untrusted descriptions. Only a fresh server-side source
                    # extraction can mint a source→route capability for this run.
                    target_inventory, auth_endpoints = _server_extracted_verification_inventories(db, f)
                    bound_endpoints = _bound_requested_endpoints(requested_endpoints, target_inventory)
                    if bound_endpoints:
                        dr = verifier.verify(
                            base_url, exploit, bound_endpoints,
                            auth_endpoints=auth_endpoints,
                        )
                        dyn = dr.__dict__
                        if counterevidence:
                            dyn["manual_static_override"] = {
                                "reason": payload.static_counterevidence_override_reason,
                            }
                    else:
                        dyn = {
                            "skipped": True, "reproducible": False, "verified": False,
                            "reproduction_status": "endpoint_unresolved", "records": [],
                            "reason": "未解析到 source→route/endpoint 绑定；未发送 HTTP 探测请求",
                        }
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            dyn = {"skipped": True, "reason": f"动态验证失败: {e}", "reproducible": False}

    # 3) Reuse the batch assembly lifecycle: confirmed HTTP evidence always
    # rebuilds its exact replay and persists the same artifact/hash metadata.
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = f.scan_id
    pipeline._code_root = None
    pipeline._assemble(finding_dict, exploit, dyn, None, None)
    evidence = finding_dict["_evidence"]
    eid = ids.evidence_id()
    db.add(Evidence(
        id=eid, finding_id=finding_id,
        source=json.dumps(evidence.get("source"), ensure_ascii=False, default=str),
        sink=json.dumps(evidence.get("sink"), ensure_ascii=False, default=str),
        data_flow=json.dumps(evidence.get("data_flow"), ensure_ascii=False, default=str),
        poc_result=json.dumps({
            "exploit": evidence.get("exploit"),
            "attack_plan": evidence.get("attack_plan"),
            "runtime": evidence.get("runtime"),
            "call_path": evidence.get("call_path"),
            "harness": evidence.get("harness"),
            "poc_result": evidence.get("poc_result"),
            "tool_calls": evidence.get("tool_calls"),
            "static_evidence_chain": evidence.get("static_evidence_chain"),
            "knowledge": evidence.get("knowledge"),
            "verification": evidence.get("verification"),
            "artifacts": evidence.get("artifacts"),
            "poc_file": evidence.get("poc_file"),
            "reproduction_metadata": evidence.get("reproduction_metadata"),
            "forensic_poc_file": evidence.get("forensic_poc_file"),
            "function_reproduction_metadata": evidence.get("function_reproduction_metadata"),
        }, ensure_ascii=False, default=str),
        logs=json.dumps(evidence.get("logs"), ensure_ascii=False, default=str),
    ))
    reproducible = bool((finding_dict.get("_dynamic") or {}).get("reproducible"))
    f.verified = bool(finding_dict.get("verified"))
    f.status = finding_dict.get("status") or f.status
    f.confidence = finding_dict.get("confidence") or f.confidence
    db.commit()

    # Learn only after the finding and its canonical, redacted evidence are
    # durable.  The shared gate rejects static/function/mechanism/blocked
    # outcomes, so a failed learning write never changes the verification API.
    try:
        from backend.rag.feedback_learner import ingest_dynamic_confirmation
        ingest_dynamic_confirmation({
            "type": f.type,
            "file": f.file_path,
            "status": f.status,
            "evidence": {
                "source": evidence.get("source"),
                "sink": evidence.get("sink"),
                "knowledge": evidence.get("knowledge"),
                "verification": evidence.get("verification"),
            },
        })
    except Exception:  # noqa: BLE001
        logger.exception("手动动态确认后的 RAG 录入失败（已忽略）: %s", finding_id)

    return VerifyResponse(
        finding_id=finding_id,
        verified=bool(f.verified),
        reproducible=reproducible,
        matched_indicator=(dyn or {}).get("matched_indicator"),
        evidence_id=eid,
        message=("动态验证成功，漏洞可复现" if reproducible
                 else (dyn or {}).get("reason") or "已生成利用方案；动态未复现或未提供靶场"),
    )


def _resolve_verify_target(payload: VerifyRequest):
    """根据 VerifyRequest 解析动态验证目标（上下文管理器）。"""
    if payload.mode == "url" and payload.base_url:
        try:
            base_url = validate_dynamic_base_url(payload.base_url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return nullcontext((base_url, payload.endpoints))
    dt = payload.dynamic_target or {}
    if payload.mode == "local" and dt.get("command"):
        if not settings.enable_local_dynamic_runner:
            raise HTTPException(400, "local dynamic runner is disabled; use docker/url localhost target")
        return _wrap(app_runner.LocalAppRunner(dt["command"], dt.get("cwd", "."),
                                               env=dt.get("env")), payload.endpoints)
    if payload.mode == "docker" and dt.get("image"):
        return _wrap(app_runner.DockerAppRunner(
            dt["image"], internal_port=dt.get("internal_port", 80),
            build_context=dt.get("build_context")), payload.endpoints)
    return nullcontext((None, payload.endpoints))


from contextlib import contextmanager


@contextmanager
def _wrap(runner_cm, endpoints):
    with runner_cm as base_url:
        yield (base_url, endpoints)


@router.get("/{finding_id}/evidence")
def get_evidence(finding_id: str, db: Session = Depends(get_db)) -> dict:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    ev = _latest_evidence(db, finding_id)
    if not ev:
        return {"finding_id": finding_id, "evidence": None,
                "message": "该漏洞暂无 PoC/证据链（未启用 PoC 或未验证）"}
    return {
        "finding_id": finding_id,
        "evidence": _decode_evidence(
            ev, status=f.status, verified=f.verified, file=f.file_path, line=f.start_line,
        ),
    }


def _latest_evidence(db: Session, finding_id: str) -> Evidence | None:
    return (db.query(Evidence)
            .filter(Evidence.finding_id == finding_id)
            .order_by(Evidence.created_at.desc())
            .first())


def _verify_context_from_existing(f: Finding, ev: Evidence | None) -> dict:
    """Recover VerifyAgent context before appending manual dynamic evidence."""
    detail = _loads(f.detail_json)
    verify = (detail or {}).get("_verify") if isinstance(detail, dict) else None
    context = dict(verify or {}) if isinstance(verify, dict) else {}

    if not ev:
        return context

    decoded = _decode_evidence(ev, status=f.status, verified=f.verified,
                               file=f.file_path, line=f.start_line)
    _fill_missing(context, "source", decoded.get("source"))
    _fill_missing(context, "sink", decoded.get("sink"))
    _fill_missing(context, "propagation_path", decoded.get("data_flow"))
    _fill_missing(context, "call_path", decoded.get("call_path"))
    _fill_missing(context, "tool_calls", decoded.get("tool_calls"))
    _fill_missing(context, "evidence_chain", decoded.get("static_evidence_chain"))
    _fill_missing(context, "knowledge", decoded.get("knowledge"))

    verification = decoded.get("verification") or {}
    if isinstance(verification, dict):
        for key in (
            "mcp_server", "skill", "static_verdict", "dynamic_verdict",
            "final_verdict", "false_positive_reason",
        ):
            _fill_missing(context, key, verification.get(key))

    return context


def _fill_missing(target: dict, key: str, value):
    if target.get(key) in (None, "", [], {}) and value not in (None, "", [], {}):
        target[key] = value


def _loads(value: str | None):
    return json.loads(value or "null")


def _decode_evidence(ev: Evidence, *, status: str | None = None, verified: bool | None = None,
                     file: str | None = None, line: int | None = None) -> dict:
    poc = _loads(ev.poc_result)
    if isinstance(poc, dict) and ("exploit" in poc or "runtime" in poc):
        exploit = poc.get("exploit")
        attack_plan = poc.get("attack_plan")
        runtime = poc.get("runtime")
        call_path = poc.get("call_path")
        harness = poc.get("harness")
        poc_result = poc.get("poc_result")
        tool_calls = poc.get("tool_calls")
        static_evidence_chain = poc.get("static_evidence_chain")
        knowledge = poc.get("knowledge")
        verification = poc.get("verification")
        sandbox = poc.get("sandbox")
        artifacts = poc.get("artifacts")
        poc_file = _safe_artifact_metadata(poc.get("poc_file"))
        reproduction_metadata = poc.get("reproduction_metadata")
        forensic_poc_file = _safe_artifact_metadata(poc.get("forensic_poc_file"))
        function_reproduction_metadata = poc.get("function_reproduction_metadata")
    else:
        exploit = None
        attack_plan = None
        runtime = None
        call_path = None
        harness = None
        poc_result = poc
        tool_calls = None
        static_evidence_chain = None
        knowledge = None
        verification = None
        sandbox = None
        artifacts = None
        poc_file = None
        reproduction_metadata = None
        forensic_poc_file = None
        function_reproduction_metadata = None
    # 沙箱信息也可能嵌在 runtime 里
    if sandbox is None and isinstance(runtime, dict):
        sandbox = runtime.get("sandbox")
    decoded = {
        "source": _loads(ev.source),
        "sink": _loads(ev.sink),
        "data_flow": _loads(ev.data_flow),
        "call_path": call_path,
        "exploit": exploit,
        "attack_plan": attack_plan,
        "runtime": runtime,
        "harness": harness,
        "sandbox": sandbox,
        "poc_result": poc_result,
        "tool_calls": tool_calls or [],
        "static_evidence_chain": static_evidence_chain or {},
        "knowledge": knowledge or {},
        "verification": verification or {},
        "artifacts": artifacts or {},
        "poc_file": poc_file,
        "reproduction_metadata": reproduction_metadata,
        "forensic_poc_file": forensic_poc_file,
        "function_reproduction_metadata": function_reproduction_metadata,
        "logs": _loads(ev.logs),
    }
    return apply_product_evidence_policy(
        _sanitize_evidence_host_paths(decoded), status=status, verified=verified, file=file, line=line,
    )


def _bound_requested_endpoints(requested: list | None,
                               server_extracted_surfaces: list[dict] | None) -> list[dict]:
    """Intersect client path suggestions with fresh server-minted capabilities.

    A persisted ``endpoint_bindings``/``call_path`` value (including nested
    ``source_route_binding`` metadata) is intentionally absent from this API.
    JSON can never reconstruct ``_ServerBoundSurface`` after a request boundary.
    """
    bindings = {
        str(surface.get("path")): surface
        for surface in server_extracted_surfaces or []
        if is_server_bound_surface(surface) and _is_project_relative_path(str(surface.get("path") or ""))
    }
    return [bindings[path] for path in _requested_endpoint_paths(requested) if path in bindings]


def _requested_endpoint_paths(requested: list | None) -> list[str]:
    """Client data is a path suggestion only; discard all binding and parameter claims."""
    paths: list[str] = []
    for raw in requested or []:
        path = str(raw.get("path") if isinstance(raw, dict) else raw)
        if _is_project_relative_path(path) and path not in paths:
            paths.append(path)
    return paths


def _is_project_relative_path(path: str) -> bool:
    return path.startswith("/") and not path.startswith("//") and "://" not in path


def _server_extracted_bound_endpoints(db: Session, finding: Finding) -> list[dict]:
    """Mint the batch pipeline's source→route→parameter capabilities for this run."""
    return _server_extracted_verification_inventories(db, finding)[0]


def _server_extracted_verification_inventories(db: Session, finding: Finding) -> tuple[list[dict], list[dict]]:
    """Return finding scope and auth bootstrap inventory from one fresh extraction."""
    scan = db.get(Scan, finding.scan_id)
    project = db.get(Project, scan.project_id) if scan else None
    code_root = Path(str(project.local_path)) if project and project.local_path else None
    if not code_root or not code_root.is_dir():
        return [], []
    extracted = extract_endpoints(code_root).get("endpoints") or []
    target_inventory = _proven_surfaces_for_finding({
        "file": finding.file_path,
        "start_line": finding.start_line,
        "line": finding.start_line,
        "type": finding.type,
    }, extracted, code_root)
    return target_inventory, _auth_bootstrap_inventory(extracted)


def _manual_policy_skip(counterevidence: str) -> dict:
    return {
        "skipped": True, "reproducible": False, "verified": False,
        "reproduction_status": "policy_skipped", "records": [],
        "reason": counterevidence, "manual_static_override": None,
    }


def _safe_artifact_metadata(value):
    """Expose immutable artifact identity while never returning a host path."""
    if not isinstance(value, dict):
        return None
    result = {key: item for key, item in value.items() if key != "path"}
    path = value.get("path")
    if path and not result.get("name"):
        result["name"] = ntpath.basename(str(path).replace("/", "\\"))
    return result


def _sanitize_evidence_host_paths(evidence: dict) -> dict:
    """Defense in depth for legacy evidence persisted before root redaction."""
    roots: set[str] = set()

    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "code_root" and isinstance(item, str) and item:
                    roots.add(item)
                collect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect(item)

    collect(evidence)

    def sanitize(value):
        if isinstance(value, dict):
            return {key: ("<project_root>" if key == "code_root" and item else sanitize(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if isinstance(value, tuple):
            return tuple(sanitize(item) for item in value)
        if isinstance(value, str):
            text = value
            for root in sorted(roots, key=len, reverse=True):
                variants = {root, root.replace("\\", "/"), root.replace("/", "\\")}
                for candidate in sorted(variants, key=len, reverse=True):
                    if candidate:
                        text = re.sub(
                            re.escape(candidate), "<project_root>", text,
                            flags=re.I if re.match(r"^[A-Za-z]:", candidate) else 0,
                        )
            return text
        return value

    return sanitize(evidence)
