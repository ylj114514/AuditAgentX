"""PoC 文件生成 + 不可变复现元数据测试（作业补项 1 与 3）。

核心诚信保证：只有**框架侧真实动态确认**后才生成 PoC；元数据是可核验的不可变事实。
"""
import hashlib
from pathlib import Path

import pytest

from backend.verifier.poc_writer import (
    build_reproduction_metadata,
    generate_function_forensic_poc,
    generate_poc_file,
)

_CONFIRMED_EV = {
    "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
    "runtime": {
        "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "AAX_PWNED",
        "response_excerpt": "... AAX_PWNED ...",
        "response_status": 200,
        "response_headers": {"content-type": "text/plain"},
        "baseline": {"status_code": 200, "response_excerpt": "normal"},
        "server_binding": {"kind": "nearest_source_route", "route_file": "vulnapp.py", "route_line": 9},
        "request": {"url": "http://127.0.0.1:8000/lookup?domain=x", "method": "GET",
                    "param": "domain", "params": {"domain": "127.0.0.1 & echo AAX_PWNED"},
                    "payload": "127.0.0.1 & echo AAX_PWNED"},
    },
    "exploit": {"payloads": ["127.0.0.1 & echo AAX_PWNED"], "_injection_points": ["domain"],
                "http_method": "GET"},
}
_FINDING = {"finding_id": "f_demo1", "type": "Command Injection",
            "file": "vulnapp.py", "start_line": 9, "status": "confirmed", "verified": True}


def test_poc_only_generated_after_real_dynamic_confirmation(tmp_path):
    """未真实动态确认 -> 不生成 PoC（不为机理级/自报成功造 PoC）。"""
    not_confirmed = {"verification": {"dynamically_verified": False}}
    assert generate_poc_file(_FINDING, not_confirmed, tmp_path) is None
    # 机理级也不算
    mech = {"verification": {"dynamically_verified": False, "dynamic_method": "mechanism"}}
    assert generate_poc_file(_FINDING, mech, tmp_path) is None


def test_poc_file_contains_required_reproduction_fields(tmp_path):
    """确认后生成的 PoC 必须含：路径/URL、方法、参数位置、payload、成功判据、运行命令、脱敏环境。"""
    r = generate_poc_file(_FINDING, _CONFIRMED_EV, tmp_path)
    assert r is not None
    body = Path(r["path"]).read_text(encoding="utf-8")
    for token in ("Command Injection", "vulnapp.py:9", "/lookup", "GET",
                   "domain", "echo AAX_PWNED", "AAX_PWNED", "运行命令", "基线响应",
                   "响应头", "服务端绑定", "persistence_status",
                   "target_guard", "trust_env", "脱敏"):
        assert token in body, f"PoC 缺少必要内容: {token}"


def test_reproduction_metadata_is_immutable_and_hashed(tmp_path):
    """复现元数据必须含不可变可核验字段：PoC hash、请求/响应 hash、生成时间、镜像/commit。"""
    r = generate_poc_file(_FINDING, _CONFIRMED_EV, tmp_path)
    meta = r["reproduction_metadata"]
    for k in ("generated_at", "poc_sha256", "request_hash", "response_hash",
              "dynamic_method", "sandbox_image", "source_commit"):
        assert k in meta
    # hash 是稳定的 sha256（同输入同 hash）
    meta2 = build_reproduction_metadata(_FINDING, _CONFIRMED_EV)
    assert meta2["request_hash"] == meta["request_hash"]
    assert len(meta["request_hash"]) == 64
    # PoC 文件本身的 sha256 与返回一致
    assert len(r["sha256"]) == 64


def test_reproduction_metadata_uses_actual_http_sandbox_image(tmp_path):
    evidence = {**_CONFIRMED_EV, "sandbox": {"status": "started", "mode": "docker",
                                                    "image": "target-app:verified"}}
    r = generate_poc_file(_FINDING, evidence, tmp_path)
    assert r["reproduction_metadata"]["sandbox_image"] == "target-app:verified"


def test_reproduction_metadata_records_default_harness_image_when_unconfigured():
    """harness 在 Docker 跑过、但未配置固定镜像时，元数据须如实记默认基础镜像，不得漏成 None。"""
    ev = {
        "verification": {"dynamically_verified": True, "dynamic_method": "target_harness"},
        "runtime": {},
        "harness": {"execution_backend": "docker", "verification_level": "entrypoint_reproduced"},
    }
    from backend.config import settings
    old = settings.harness_sandbox_image
    settings.harness_sandbox_image = ""  # 未配置固定镜像
    try:
        meta = build_reproduction_metadata(_FINDING, ev)
        assert meta["sandbox_image"] == "python:3.11-slim", "docker 跑过就必有真实镜像，不能是 None"
    finally:
        settings.harness_sandbox_image = old


def test_reproduction_metadata_no_image_when_not_docker():
    """非 Docker 后端（如纯本地模板）不应虚构镜像。"""
    ev = {"verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
          "runtime": {}, "harness": {"execution_backend": "local"}}
    meta = build_reproduction_metadata(_FINDING, ev)
    assert meta["sandbox_image"] is None


def test_poc_redacts_sensitive_values(tmp_path):
    """PoC/元数据必须脱敏敏感字段。"""
    ev = {
        "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
        "runtime": {"reproduction_status": "dynamic_confirmed", "matched_indicator": "token=abc123secret",
                    "baseline": {"status_code": 200, "response_excerpt": "normal"},
                    "response_status": 200, "response_headers": {"content-type": "text/plain"},
                    "server_binding": {"kind": "test_source_route"},
                    "request": {"url": "http://127.0.0.1:8000/x?password=hunter2", "method": "GET",
                                "param": "q", "params": {"q": "authorization=Bearer sk-xxx"},
                                "payload": "authorization=Bearer sk-xxx"}},
        "exploit": {},
    }
    r = generate_poc_file(_FINDING, ev, tmp_path)
    body = Path(r["path"]).read_text(encoding="utf-8")
    assert "hunter2" not in body
    assert "sk-xxx" not in body
    assert "REDACTED" in body


def test_authenticated_poc_includes_session_aware_exploit_code(tmp_path):
    evidence = {
        **_CONFIRMED_EV,
        "runtime": {
            **_CONFIRMED_EV["runtime"],
            "setup_records": [{"url": "http://127.0.0.1:8000/login", "status_code": 200}],
        },
        "exploit": {
            **_CONFIRMED_EV["exploit"],
            "exploit_code": (
                "import os\n"
                "password = os.environ.get('AAX_SETUP_PASSWORD', 'CHANGE_ME')\n"
                "# login then replay confirmed request"
            ),
        },
    }
    result = generate_poc_file(_FINDING, evidence, tmp_path)
    body = Path(result["path"]).read_text(encoding="utf-8")
    assert "精确利用代码" in body
    assert "AAX_SETUP_PASSWORD" in body
    assert "AAX_TARGET_URL" in body
    assert "python exploit.py" in body


def _function_evidence():
    return {
        "verification": {"dynamically_verified": False, "evidence_level": "function_unit_reproduced"},
        "harness": {
            "verdict": "function_reproduced", "harness_source": "scaffold",
            "harness_kind": "selfcontained_slice", "execution_backend": "docker",
            "verification_level": "target_specific", "target_function_called": True,
            "harness_code": "# framework scaffold\nprint('safe')",
            "function_code_sha256": "b" * 64,
            "sink_name": "system", "captured_argument": "ping 127.0.0.1; id",
            "payload": "127.0.0.1; id", "sandbox_image": "auditagentx-harness:fixed",
            "nonce_attestation": {"scheme": "sha256", "digest": "a" * 64,
                                  "marker_observed": True},
            "function_location": {"file": "vulnapp.py", "start_line": 7, "end_line": 9,
                                  "function_name": "run_ping"},
        },
    }


def test_function_reproduced_generates_separate_forensic_poc(tmp_path):
    result = generate_function_forensic_poc(_FINDING, _function_evidence(), tmp_path)

    assert result is not None
    assert result["path"].endswith("f_demo1.function-forensic.md")
    body = Path(result["path"]).read_text(encoding="utf-8")
    assert "函数级复现(非端到端)" in body
    assert "selfcontained_slice" in body
    assert "run_ping" in body
    assert "auditagentx-harness:fixed" in body
    assert "a" * 64 in body
    assert "print('safe')" not in body
    assert "仅保存 Harness 源码哈希" in body
    metadata = result["reproduction_metadata"]
    assert metadata["artifact_kind"] == "function_forensic_reproduction"
    assert metadata["function_location"]["start_line"] == 7
    assert metadata["nonce_attestation"]["marker_observed"] is True


def test_function_forensic_poc_requires_framework_nonce_and_docker(tmp_path):
    missing_nonce = _function_evidence()
    missing_nonce["harness"].pop("nonce_attestation")
    assert generate_function_forensic_poc(_FINDING, missing_nonce, tmp_path) is None

    local = _function_evidence()
    local["harness"]["execution_backend"] = "local"
    assert generate_function_forensic_poc(_FINDING, local, tmp_path) is None


def test_pipeline_stores_function_forensic_artifact_separately(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from backend.verifier.pipeline import ExploitPipeline

    monkeypatch.setattr("backend.verifier.pipeline.settings", SimpleNamespace(data_path=tmp_path))
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "scan-function"
    pipeline._code_root = None
    finding = {**_FINDING, "status": "needs_review", "verified": False, "confidence": 0.7,
               "_verify": {"source": "host", "sink": "os.system"}}
    harness = _function_evidence()["harness"]

    pipeline._assemble(finding, {}, None, harness, None)

    assert "forensic_poc_file" in finding["_evidence"]
    assert finding["_evidence"]["forensic_poc_file"]["label"] == "函数级复现(非端到端)"
    assert "poc_file" not in finding["_evidence"]
    assert finding.get("function_unit_reproduced") is True
    assert finding.get("dynamically_verified") is False
    assert finding.get("status") == "needs_review"
    verification = finding["_evidence"]["verification"]
    assert verification["dynamic_method"] == "function_harness"
    assert verification["evidence_level"] == "function_unit_reproduced"
    assert verification["entrypoint_confirmed"] is False
    assert finding["_evidence"]["artifacts"]["validated_poc"]["generation_status"] == "not_generated"
    forensic = finding["_evidence"]["artifacts"]["function_forensic"]
    assert forensic["generation_status"] == "generated"
    assert forensic["validation_status"] == "validated"
    assert forensic["persistence_status"] == "persisted"
    assert forensic["name"] == "f_demo1.function-forensic.md"
    assert len(forensic["sha256"]) == 64
    assert finding["_evidence"]["evidence_complete"] is False
    assert finding["_evidence"]["actionable"] is False
    assert finding["_evidence"]["exploitable"] is False


def test_target_harness_uses_real_harness_as_target_specific_reproduction(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from backend.verifier.pipeline import ExploitPipeline

    monkeypatch.setattr("backend.verifier.pipeline.settings", SimpleNamespace(data_path=tmp_path))
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "scan-target"
    pipeline._code_root = None
    finding = {**_FINDING, "status": "needs_review", "verified": False, "confidence": 0.7,
               "_verify": {"source": "request.args[host]", "sink": "os.system"}}
    harness = {
        "verdict": "target_confirmed", "dynamically_triggered": True,
        "function_extracted": True, "target_function_called": True,
        "verification_level": "entrypoint_reproduced", "entrypoint_reachable": True,
        "harness_code": "# real target test-client harness\nclient.get('/ping?host=x')",
        "execution_backend": "docker", "trigger_detail": "sink reached",
    }

    pipeline._assemble(finding, {}, None, harness, None)

    exploit = finding["_evidence"]["exploit"]
    plan = finding["_evidence"]["attack_plan"]
    assert exploit["code_kind"] == "target_harness_reproduction"
    assert exploit["exploit_code"] == harness["harness_code"]
    assert plan["code_kind"] == "target_harness_reproduction"
    assert plan["plan_status"] == "validated_reproduction"
    assert finding["_evidence"]["artifacts"]["validated_poc"]["persistence_status"] == "persisted"


def test_primary_poc_persistence_failure_is_structured_and_not_actionable(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from backend.verifier.pipeline import ExploitPipeline

    monkeypatch.setattr("backend.verifier.pipeline.settings", SimpleNamespace(data_path=tmp_path))
    monkeypatch.setattr(
        "backend.verifier.poc_writer.generate_poc_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError(r"C:\\private\\pocs\\denied")),
    )
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "scan-failed-poc"
    pipeline._code_root = None
    finding = {**_FINDING, "status": "needs_review", "verified": False, "confidence": 0.7,
               "_verify": {"source": "host", "sink": "os.system"}}
    dynamic = {
        "reproducible": True, "verified": True, "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "AAX_PWNED", "confirmed_record": {
            "url": "http://127.0.0.1:8000/ping", "method": "GET", "param": "host",
            "params": {"host": "; id"}, "payload": "; id", "transport": "query",
        },
    }

    pipeline._assemble(finding, {"payloads": ["; id"]}, dynamic, None, None)

    artifact = finding["_evidence"]["artifacts"]["validated_poc"]
    assert artifact["persistence_status"] == "persistence_failed"
    assert artifact["failure_code"] == "artifact_persistence_failed"
    assert "C:\\private" not in artifact["error_summary"]
    assert finding["_evidence"]["evidence_complete"] is False
    assert finding["_evidence"]["actionable"] is False
    assert finding["_evidence"]["exploit"]["exploit_code"] is None
    assert finding["_evidence"]["attack_plan"]["code"] is None


def test_pipeline_canonicalizes_confirmed_record_with_required_sibling_params(monkeypatch, tmp_path):
    """A real DynamicVerifier record may include required siblings but still has one injected value."""
    from types import SimpleNamespace
    from backend.verifier.pipeline import ExploitPipeline

    monkeypatch.setattr("backend.verifier.pipeline.settings", SimpleNamespace(data_path=tmp_path))
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "confirmed-siblings"
    pipeline._code_root = None
    payload = "' OR '1'='1"
    finding = {**_FINDING, "finding_id": "f-siblings", "status": "needs_review",
               "verified": False, "confidence": 0.7,
               "_verify": {"source": "request.body.query", "sink": "db.execute"}}
    dynamic = {
        "verified": True, "reproducible": True, "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "SQL syntax", "server_binding": {
            "kind": "source_route_sink", "route_file": "app.py", "route_line": 9,
        },
        "baseline_record": {"status_code": 200, "response_excerpt": "normal", "role": "baseline"},
        # ProbeRecord intentionally exposes full request values, not its internal ``param`` field.
        "confirmed_record": {
            "url": "http://127.0.0.1:18080/search", "method": "POST", "transport": "json",
            "params": {"query": payload, "page": 1}, "payload": payload,
            "status_code": 500, "response_headers": {"content-type": "text/plain"},
        },
    }

    pipeline._assemble(finding, {"payloads": [payload], "exploit_code": "candidate code"}, dynamic, None, None)

    evidence = finding["_evidence"]
    assert evidence["runtime"]["request"] == {
        "url": "http://127.0.0.1:18080/search", "method": "POST", "param": "query",
        "params": {"query": payload, "page": 1}, "payload": payload, "transport": "json",
    }
    assert evidence["runtime"]["baseline"] == dynamic["baseline_record"]
    assert evidence["runtime"]["response_status"] == 500
    assert evidence["runtime"]["response_headers"] == {"content-type": "text/plain"}
    assert evidence["runtime"]["matched_indicator"] == "SQL syntax"
    assert evidence["runtime"]["server_binding"] == dynamic["server_binding"]
    artifact = evidence["artifacts"]["validated_poc"]
    assert artifact["persistence_status"] == "persisted"
    assert len(artifact["sha256"]) == 64
    # Candidate code is restored only after the immutable artifact is on disk.
    assert evidence["exploit"]["exploit_code"]
    assert evidence["attack_plan"]["code"] == evidence["exploit"]["exploit_code"]
    assert "'page': 1" in evidence["exploit"]["exploit_code"]
    assert "request_data =" in evidence["exploit"]["exploit_code"]
    persisted = tmp_path / "scans" / "confirmed-siblings" / "pocs" / "f-siblings.md"
    assert persisted.is_file()
    assert hashlib.sha256(persisted.read_bytes()).hexdigest() == artifact["sha256"]


def test_ambiguous_confirmed_record_never_persists_or_releases_code(monkeypatch, tmp_path):
    """A claimed confirmation cannot choose an injection parameter by guesswork."""
    from types import SimpleNamespace
    from backend.verifier.pipeline import ExploitPipeline

    monkeypatch.setattr("backend.verifier.pipeline.settings", SimpleNamespace(data_path=tmp_path))
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "ambiguous-record"
    pipeline._code_root = None
    payload = "AAX_LOCAL_CMD_MARKER"
    finding = {**_FINDING, "finding_id": "f-ambiguous", "status": "needs_review",
               "verified": False, "confidence": 0.7,
               "_verify": {"source": "request.form", "sink": "os.system"}}
    dynamic = {
        "verified": True, "reproducible": True, "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "AAX_LOCAL_CMD_MARKER", "server_binding": {"kind": "source_route_sink"},
        "baseline_record": {"status_code": 200, "response_excerpt": "normal"},
        "confirmed_record": {
            "url": "http://127.0.0.1:18080/run", "method": "POST", "transport": "form",
            "params": {"host": payload, "command": payload}, "payload": payload,
            "status_code": 200, "response_headers": {"content-type": "text/plain"},
        },
    }

    pipeline._assemble(finding, {"payloads": [payload], "exploit_code": "candidate code"}, dynamic, None, None)

    artifact = finding["_evidence"]["artifacts"]["validated_poc"]
    assert artifact["persistence_status"] == "persistence_failed"
    assert artifact["failure_code"] == "required_artifact_not_generated"
    assert finding["_evidence"]["exploit"]["exploit_code"] is None
    assert finding["_evidence"]["attack_plan"]["code"] is None


def test_pipeline_never_builds_http_poc_before_confirmed_record_is_canonical(monkeypatch, tmp_path):
    """Incomplete dynamic claims may remain diagnostic, but cannot produce replay code."""
    from types import SimpleNamespace
    from backend.verifier import pipeline as pipeline_module
    from backend.verifier.pipeline import ExploitPipeline

    monkeypatch.setattr("backend.verifier.pipeline.settings", SimpleNamespace(data_path=tmp_path))
    built = []
    monkeypatch.setattr(
        pipeline_module, "build_confirmed_http_poc",
        lambda *_args, **_kwargs: (built.append(True) or "must not be created"),
    )
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "uncanonical-confirmation"
    pipeline._code_root = None
    finding = {**_FINDING, "finding_id": "f-uncanonical", "status": "needs_review",
               "verified": False, "confidence": 0.7,
               "_verify": {"source": "request.args.id", "sink": "cursor.execute"}}
    dynamic = {
        "verified": True, "reproducible": True, "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "SQL syntax", "server_binding": {"kind": "source_route_sink"},
        # Missing baseline_record makes the record non-canonical.
        "confirmed_record": {
            "url": "http://127.0.0.1:18080/search", "method": "POST", "transport": "json",
            "params": {"query": "'"}, "payload": "'", "status_code": 500,
            "response_headers": {"content-type": "text/plain"},
        },
    }

    pipeline._assemble(finding, {"payloads": ["'"]}, dynamic, None, None)

    assert built == []
    assert finding["_evidence"]["exploit"]["exploit_code"] is None


def test_function_level_harness_code_is_never_exposed_as_evidence_code():
    """函数切片/机理/合成 Harness 可保留哈希与摘要，但不能导出源代码。"""
    from backend.verifier.evidence_collector import EvidenceCollector

    evidence = EvidenceCollector.build(
        {"static_verdict": "needs_review", "final_verdict": "needs_review"},
        harness={
            "verdict": "function_reproduced", "harness_source": "scaffold",
            "harness_code": "print('function-only secret code')",
            "harness_code_sha256": "c" * 64,
            "reason": "function-only reproduction",
        },
    )

    assert evidence["harness"]["harness_code"] is None
    assert evidence["harness"]["harness_code_sha256"] == "c" * 64
    assert "function-only secret code" not in str(evidence)


@pytest.mark.parametrize("static_verdict", ["confirmed", "statically_verified"])
@pytest.mark.parametrize("harness", [
    {"verdict": "not_applicable"},
    {"verdict": "mechanism_confirmed", "function_mechanism_verified": True},
])
def test_static_confirmed_open_redirect_stays_confirmed_when_executed_http_does_not_reproduce(
        static_verdict, harness):
    """静态确认不能被已执行但无指示器的 HTTP 探测降级或伪装成 HTTP PoC。"""
    from backend.verifier.pipeline import ExploitPipeline

    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "static-http-no-hit"
    pipeline._code_root = None
    finding = {
        "finding_id": "f-open-redirect", "type": "Open Redirect", "file": "routes.py",
        "start_line": 12, "status": "confirmed", "verified": True, "confidence": 0.91,
        "_verify": {"static_verdict": static_verdict, "final_verdict": static_verdict},
    }
    dynamic = {
        "reproduction_status": "not_reproduced", "reproducible": False, "verified": False,
        "skipped": False, "reason": "redirect indicator was not observed",
        "records": [{
            "role": "attack", "url": "http://127.0.0.1:8080/redirect", "method": "GET",
            "status_code": 200, "payload": "https://example.invalid",
        }],
    }

    pipeline._assemble(finding, {"payloads": ["https://example.invalid"]}, dynamic, harness, None)

    verification = finding["_evidence"]["verification"]
    assert finding["status"] == "confirmed"
    assert finding["verified"] is True
    assert finding["runtime_verification_status"] == "not_reproduced"
    assert finding.get("dynamically_verified") is False
    assert verification["static_verdict"] == static_verdict
    assert verification["final_verdict"] == "statically_verified"
    assert verification["dynamic_verdict"] == "not_reproduced"
    assert verification["dynamic_method"] in (None, "static_confirmation")
    assert verification["evidence_level"] == "static_confirmed_http_not_reproduced"
    assert "poc_file" not in finding["_evidence"]
    assert finding["_evidence"]["artifacts"]["validated_poc"]["generation_status"] == "not_generated"
