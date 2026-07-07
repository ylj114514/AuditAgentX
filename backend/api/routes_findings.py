"""漏洞详情 / 验证 / 证据链接口（md 7.7 / 7.8 / 7.9）。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.core import ids
from backend.models import Finding, Evidence
from backend.schemas import FindingDetail, VerifyRequest, VerifyResponse
from backend.agents.exploit_agent import ExploitAgent
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier import exploit_templates as tpl
from backend.verifier import app_runner
from contextlib import nullcontext

router = APIRouter(prefix="/api/findings", tags=["findings"])


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

    finding_dict = {
        "type": f.type, "file": f.file_path,
        "start_line": f.start_line, "line": f.start_line,
        "code_snippet": f.code_snippet, "_verify": {},
    }

    # 1) 生成利用方案
    exploit = ExploitAgent(scan_id=f.scan_id).run(finding_dict)
    template = tpl.match_template(f.type)
    if template:
        exploit.setdefault("_injection_points", template.injection_points)

    # 2) 解析目标并动态验证
    verifier = DynamicVerifier(timeout=payload.timeout)
    dyn = None
    try:
        with _resolve_verify_target(payload) as (base_url, endpoints):
            if base_url and exploit.get("payloads"):
                dr = verifier.verify(base_url, exploit, payload.endpoints or endpoints)
                dyn = dr.__dict__
    except Exception as e:  # noqa: BLE001
        dyn = {"skipped": True, "reason": f"动态验证失败: {e}", "reproducible": False}

    # 3) 落库证据链 + 回写状态
    evidence = EvidenceCollector.build(finding_dict.get("_verify", {}),
                                       exploit=exploit, dynamic=dyn)
    eid = ids.evidence_id()
    db.add(Evidence(
        id=eid, finding_id=finding_id,
        source=json.dumps(evidence.get("source"), ensure_ascii=False, default=str),
        sink=json.dumps(evidence.get("sink"), ensure_ascii=False, default=str),
        data_flow=json.dumps(evidence.get("data_flow"), ensure_ascii=False, default=str),
        poc_result=json.dumps({
            "exploit": evidence.get("exploit"),
            "runtime": evidence.get("runtime"),
            "call_path": evidence.get("call_path"),
            "harness": evidence.get("harness"),
            "poc_result": evidence.get("poc_result"),
            "tool_calls": evidence.get("tool_calls"),
            "static_evidence_chain": evidence.get("static_evidence_chain"),
            "verification": evidence.get("verification"),
        }, ensure_ascii=False, default=str),
        logs=json.dumps(evidence.get("logs"), ensure_ascii=False, default=str),
    ))
    reproducible = bool(dyn and dyn.get("reproducible"))
    if reproducible:
        f.verified = True
        f.status = "confirmed"
        f.confidence = max(f.confidence or 0.0, 0.98)
    db.commit()

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
        return nullcontext((payload.base_url, payload.endpoints))
    dt = payload.dynamic_target or {}
    if payload.mode == "local" and dt.get("command"):
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
    return {"finding_id": finding_id, "evidence": _decode_evidence(ev)}


def _latest_evidence(db: Session, finding_id: str) -> Evidence | None:
    return (db.query(Evidence)
            .filter(Evidence.finding_id == finding_id)
            .order_by(Evidence.created_at.desc())
            .first())


def _loads(value: str | None):
    return json.loads(value or "null")


def _decode_evidence(ev: Evidence) -> dict:
    poc = _loads(ev.poc_result)
    if isinstance(poc, dict) and ("exploit" in poc or "runtime" in poc):
        exploit = poc.get("exploit")
        runtime = poc.get("runtime")
        call_path = poc.get("call_path")
        harness = poc.get("harness")
        poc_result = poc.get("poc_result")
        tool_calls = poc.get("tool_calls")
        static_evidence_chain = poc.get("static_evidence_chain")
        verification = poc.get("verification")
        sandbox = poc.get("sandbox")
    else:
        exploit = None
        runtime = None
        call_path = None
        harness = None
        poc_result = poc
        tool_calls = None
        static_evidence_chain = None
        verification = None
        sandbox = None
    # 沙箱信息也可能嵌在 runtime 里
    if sandbox is None and isinstance(runtime, dict):
        sandbox = runtime.get("sandbox")
    return {
        "source": _loads(ev.source),
        "sink": _loads(ev.sink),
        "data_flow": _loads(ev.data_flow),
        "call_path": call_path,
        "exploit": exploit,
        "runtime": runtime,
        "harness": harness,
        "sandbox": sandbox,
        "poc_result": poc_result,
        "tool_calls": tool_calls or [],
        "static_evidence_chain": static_evidence_chain or {},
        "verification": verification or {},
        "logs": _loads(ev.logs),
    }
