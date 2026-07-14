"""确定性 BOLA/IDOR 工作流规划与端到端裁决测试。"""
from __future__ import annotations

import json

from backend.dynamic.authorization_planner import (
    plan_authorization_workflow,
    plan_disposable_initializer,
)
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord
from backend.verifier.pipeline import (
    ExploitPipeline,
    _is_disposable_sandbox,
    _should_run_dynamic_verify,
    _surfaces_for_finding,
)
from backend.dynamic.source_route_binding import bind_server_surface


def _vampi_surfaces():
    return [
        {"path": "/createdb", "methods": ["GET"], "params": [],
         "tags": ["db-init"], "file": "api_views/main.py", "line": 8,
         "operation_id": "api_views.main.populate_db", "source": "static_openapi"},
        {"path": "/users/v1/register", "methods": ["POST"],
         "params": [{"name": name, "location": "json"}
                    for name in ("username", "password", "email")],
         "file": "api_views/users.py", "line": 28},
        {"path": "/users/v1/login", "methods": ["POST"],
         "params": [{"name": name, "location": "json"}
                    for name in ("username", "password")],
         "file": "api_views/users.py", "line": 65},
        {"path": "/books/v1", "methods": ["POST"],
         "params": [{"name": "book_title", "location": "json"},
                    {"name": "secret", "location": "json"}],
         "file": "api_views/books.py", "line": 19},
        {"path": "/books/v1/{book}", "raw_path": "/books/v1/{book}",
         "methods": ["GET"], "params": [{"name": "book", "location": "path"}],
         "response_fields": ["book_title", "owner", "secret"],
         "file": "api_views/books.py", "line": 49},
    ]


def _finding():
    return {
        "finding_id": "f-bola-auto", "type": "Broken Object Level Authorization",
        "severity": "high", "file": "api_views/books.py", "start_line": 56,
        "status": "needs_review",
    }


def test_planner_builds_unambiguous_disposable_openapi_workflow():
    workflow = plan_authorization_workflow(
        _finding(), _vampi_surfaces(), disposable=True, seed="scan-test")

    assert workflow["planner"] == "openapi_bola_v1"
    assert [step["role"] for step in workflow["steps"]] == [
        "initialize", "setup", "setup", "setup", "setup",
        "owner_create", "owner_control", "authorization_attack",
    ]
    assert workflow["oracle"]["owner_identity"] != workflow["oracle"]["attacker_identity"]
    assert workflow["oracle"]["secret_value"].startswith("AAX_BOLA_SENTINEL_")
    assert workflow["steps"][-1]["path"].startswith("/books/v1/aax-private-")
    assert set(workflow["source_surfaces"]) == {"register", "login", "create", "read"}


def test_planner_refuses_state_mutation_on_non_disposable_target():
    assert plan_authorization_workflow(
        _finding(), _vampi_surfaces(), disposable=False, seed="scan-test") is None


def test_disposable_initializer_requires_one_recognized_route():
    assert plan_disposable_initializer(_vampi_surfaces()) == {
        "name": "initialize_disposable_target",
        "path": "/createdb",
        "method": "GET",
        "transport": "query",
        "values": {},
        "role": "initialize",
    }
    assert plan_disposable_initializer([
        {"path": "/run-anything", "methods": ["GET"], "params": [],
         "source": "static_openapi", "file": "api_views/main.py", "line": 8},
    ]) is None


def test_disposable_initializer_rejects_unextracted_or_unsafe_routes():
    assert plan_disposable_initializer([
        {"path": "/createdb", "methods": ["GET"], "params": [],
         "file": "api_views/main.py", "line": 8, "source": "heuristic"},
    ]) is None
    assert plan_disposable_initializer([
        {"path": "/createdb", "methods": ["POST"], "params": [],
         "file": "api_views/main.py", "line": 8, "source": "static_openapi"},
    ]) is None
    assert plan_disposable_initializer([
        {"path": "/createdb", "methods": ["GET"],
         "params": [{"name": "reset", "location": "query"}],
         "file": "api_views/main.py", "line": 8, "source": "static_openapi"},
    ]) is None


class _VampiLikeInitializerProbe:
    def __init__(self):
        self.calls = []

    def send_values(self, base_url, path, values, *, method="POST", transport="json",
                    role="setup", headers=None, payload=""):
        self.calls.append((role, path, method, dict(values)))
        return ProbeRecord(
            url=base_url + path, method=method, params=dict(values), payload=payload,
            transport=transport, role=role, status=200, status_code=200,
            response_excerpt='{"status":"database initialized"}',
        )

    def send(self, base_url, path, param, payload, method="GET", transport="query",
             role="attack", headers=None, sibling_values=None):
        self.calls.append((role, path, method, {param: payload}))
        body = "SQLite error: near quote" if role == "attack" else "normal"
        return ProbeRecord(
            url=base_url + path, method=method, params={param: payload}, payload=payload,
            transport=transport, role=role, status=200, status_code=200,
            response_excerpt=body,
        )


def _bound_vampi_sink():
    return bind_server_surface({
        "path": "/users/v1", "methods": ["GET"],
        "params": [{"name": "id", "location": "query"}],
        "file": "api_views/users.py", "line": 90, "source": "static_route",
    }, {"kind": "test"})


def _bound_vampi_username_sink():
    return bind_server_surface({
        "path": "/users/v1/{username}", "raw_path": "/users/v1/{username}",
        "methods": ["GET"],
        "params": [{"name": "username", "location": "path"}],
        "file": "api_views/users.py", "line": 90, "source": "static_route",
    }, {"kind": "source_route_sink", "source_parameter": "username"})


def _sqli_exploit():
    return {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": [r"SQLite error"], "_injection_points": ["id"],
    }


class _VampiSqliProbe:
    def __init__(self):
        self.calls = []

    def send_values(self, base_url, path, values, *, method="POST", transport="json",
                    role="setup", headers=None, payload=""):
        self.calls.append((role, path, method, dict(values)))
        return ProbeRecord(
            url=base_url + path, method=method, params=dict(values), payload=payload,
            transport=transport, role=role, status=200, status_code=200,
            response_excerpt='{"status":"database initialized"}',
        )

    def send(self, base_url, path, param, payload, method="GET", transport="query",
             role="attack", headers=None, sibling_values=None):
        self.calls.append((role, path, method, {param: payload}))
        status = 404 if payload == "AUDITAGENTX_CONTROL" else 200
        body = '{"message":"user record","username":"admin"}' if status == 200 else "not found"
        return ProbeRecord(
            url=base_url + "/users/v1/" + payload, method=method,
            params={param: payload}, payload=payload, transport=transport,
            role=role, status=status, status_code=status, response_excerpt=body,
        )


def _vampi_username_sqli_exploit():
    return {
        "vuln_type": "SQL Injection", "payloads": ["1' OR '1'='1"],
        "success_indicators": [r"user record"], "_injection_points": ["username"],
    }


def test_pipeline_initializes_vampi_openapi_db_in_owned_docker_before_http_verify():
    pipeline = ExploitPipeline(scan_id="scan-test")
    probe = _VampiLikeInitializerProbe()
    pipeline.dynamic = DynamicVerifier(max_probes=4)
    pipeline.dynamic.probe = probe
    finding = {"type": "SQL Injection", "severity": "high", "file": "api_views/users.py", "line": 96}
    exploit = _sqli_exploit()

    result = pipeline._http_verify(
        finding, exploit, "http://127.0.0.1:18080", [_bound_vampi_sink()],
        {"mode": "docker_project", "status": "started"}, None, False,
        full_endpoint_inventory=_vampi_surfaces(),
    )

    assert probe.calls[0] == ("setup", "/createdb", "GET", {})
    assert len(result["setup_records"]) == 1
    assert result["setup_records"][0]["url"] == "http://127.0.0.1:18080/createdb"
    assert result["setup_records"][0]["status_code"] == 200
    assert result["setup_records"][0]["role"] == "setup"
    assert exploit["setup_requests"][0]["path"] == "/createdb"


def test_successful_disposable_initializer_preserves_vampi_sqli_confirmation():
    pipeline = ExploitPipeline(scan_id="scan-test")
    probe = _VampiSqliProbe()
    pipeline.dynamic = DynamicVerifier(max_probes=4)
    pipeline.dynamic.probe = probe
    finding = {"type": "SQL Injection", "severity": "high", "file": "api_views/users.py", "line": 96}

    result = pipeline._http_verify(
        finding, _vampi_username_sqli_exploit(), "http://127.0.0.1:18080",
        [_bound_vampi_username_sink()], {"mode": "docker_project", "status": "started"},
        None, False, full_endpoint_inventory=_vampi_surfaces(),
    )

    assert result["baseline_record"]["status_code"] == 404
    assert result["confirmed_record"]["status_code"] == 200
    assert "user record" in result["confirmed_record"]["response_excerpt"]
    assert result["reproduction_status"] == "dynamic_confirmed"
    assert result["reproducible"] is True


def test_non_reset_setup_still_downgrades_dynamic_confirmation():
    pipeline = ExploitPipeline(scan_id="scan-test")
    probe = _VampiSqliProbe()
    pipeline.dynamic = DynamicVerifier(max_probes=4)
    pipeline.dynamic.probe = probe
    finding = {"type": "SQL Injection", "severity": "high", "file": "api_views/users.py", "line": 96}
    exploit = _vampi_username_sqli_exploit()
    exploit["setup_requests"] = [{
        "path": "/session", "method": "POST", "transport": "json", "values": {},
    }]

    result = pipeline._http_verify(
        finding, exploit, "http://127.0.0.1:18080", [_bound_vampi_username_sink()],
        {"mode": "docker_project", "status": "started"}, None, False,
        full_endpoint_inventory=_vampi_surfaces(),
    )

    assert probe.calls[:2] == [
        ("setup", "/createdb", "GET", {}),
        ("setup", "/session", "POST", {}),
    ]
    assert result["reproduction_status"] == "inconclusive"
    assert result["reason"] == "state_contamination_possible"
    assert result["reproducible"] is False


def test_pipeline_never_adds_initializer_for_non_disposable_or_external_target():
    finding = {"type": "SQL Injection", "severity": "high", "file": "api_views/users.py", "line": 96}
    for base_url, sandbox in (
        ("http://127.0.0.1:18080", {"mode": "url", "status": "started"}),
        ("http://example.test", None),
    ):
        pipeline = ExploitPipeline(scan_id="scan-test")
        probe = _VampiLikeInitializerProbe()
        pipeline.dynamic = DynamicVerifier(max_probes=4)
        pipeline.dynamic.probe = probe
        exploit = _sqli_exploit()

        result = pipeline._http_verify(
            finding, exploit, base_url, [_bound_vampi_sink()], sandbox, None, False,
            full_endpoint_inventory=_vampi_surfaces(),
        )

        assert "setup_requests" not in exploit
        assert result.get("setup_records", []) == []
        assert not any(call[1] == "/createdb" for call in probe.calls)


def test_pipeline_uses_planner_without_calling_llm_for_bola():
    pipeline = ExploitPipeline(scan_id="scan-test")
    pipeline.exploit_agent.run = lambda finding: (_ for _ in ()).throw(
        AssertionError("BOLA planner must not call LLM"))

    exploit = pipeline._gen_exploit(
        _finding(), True, endpoints=_vampi_surfaces(), disposable_target=True)

    assert exploit["authorization_workflow"]["planner"] == "openapi_bola_v1"
    # BOLA 工作流在 HTTP framework confirmation 前只是元数据/载荷假设，
    # 绝不能生成或持久化可执行状态机脚本。
    assert exploit["exploit_code"] is None
    assert exploit["generation_status"] == "validation_pending"
    assert exploit["payloads"] == []
    from backend.verifier.pipeline import _surfaces_for_finding
    should_run, status, reason = _should_run_dynamic_verify(
        _finding(), exploit, "http://127.0.0.1:5002",
        _surfaces_for_finding(_finding(), _vampi_surfaces()))
    assert (should_run, status, reason) == (True, "", "")


def test_bola_planner_does_not_call_workflow_poc_builder_before_confirmation(monkeypatch):
    """未确认 BOLA 即使可规划，也不能调用可执行 PoC 构造器。"""
    pipeline = ExploitPipeline(scan_id="scan-test")
    monkeypatch.setattr(
        "backend.verifier.pipeline.build_authorization_workflow_poc",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not build candidate code")),
    )

    exploit = pipeline._gen_exploit(
        _finding(), False, endpoints=_vampi_surfaces(), disposable_target=True)

    assert exploit["authorization_workflow"]["planner"] == "openapi_bola_v1"
    assert exploit["exploit_code"] is None


def test_pipeline_rejects_legacy_string_endpoints_without_sending_http():
    """旧动态配置 list[str] 不能绕过 source→route binding。"""
    pipeline = ExploitPipeline(scan_id="scan-test")
    calls = []

    class _Dynamic:
        def verify(self, *_args, **_kwargs):
            calls.append(True)
            raise AssertionError("unbound string endpoints must not probe")

    pipeline.dynamic = _Dynamic()
    finding = {"type": "SQL Injection", "severity": "high", "file": "app.py", "line": 20}
    result = pipeline._http_verify(
        finding, {"payloads": ["'"], "_injection_points": ["id"]},
        "http://127.0.0.1:18080", ["/legacy-search"], None, None, False,
    )

    assert calls == []
    assert result["reproduction_status"] == "endpoint_unresolved"
    assert result["records"] == []


def test_pipeline_does_not_add_initializer_without_a_server_bound_route():
    pipeline = ExploitPipeline(scan_id="scan-test")
    pipeline.exploit_agent.run = lambda finding: {
        "payloads": ["'"], "vuln_type": finding["type"],
    }
    finding = {"type": "SQL Injection", "severity": "high", "file": "models/user_model.py"}

    disposable = pipeline._gen_exploit(
        finding, True, endpoints=_vampi_surfaces(), disposable_target=True)
    persistent = pipeline._gen_exploit(
        finding, True, endpoints=_vampi_surfaces(), disposable_target=False)

    assert "setup_requests" not in disposable
    assert "setup_requests" not in persistent


def test_compose_project_runtime_remains_disposable_after_mode_specialization():
    assert _is_disposable_sandbox({"mode": "docker_compose", "status": "started"})
    assert not _is_disposable_sandbox({"mode": "docker_compose", "status": "health_check_failed"})
    assert not _is_disposable_sandbox({"mode": "url", "status": "started"})


class _StatefulBolaProbe:
    def __init__(self):
        self.users = {}
        self.resource = None

    def send_values(self, base_url, path, values, *, method="POST", transport="json",
                    role="setup", headers=None, payload=""):
        status, body = 200, {"status": "ok"}
        if path == "/createdb":
            self.users.clear()
            self.resource = None
        elif path.endswith("/register"):
            self.users[values["username"]] = values["password"]
        elif path.endswith("/login"):
            if self.users.get(values["username"]) != values["password"]:
                status, body = 401, {"status": "fail"}
            else:
                body = {"auth_token": "token-" + values["username"]}
        elif path == "/books/v1" and method == "POST":
            actor = (headers or {}).get("Authorization", "").removeprefix("Bearer token-")
            self.resource = {"book_title": values["book_title"],
                             "secret": values["secret"], "owner": actor}
        elif path.startswith("/books/v1/"):
            body = dict(self.resource or {})
            if not body:
                status = 404
        return ProbeRecord(
            url=base_url + path, method=method, params=dict(values), payload=payload,
            transport=transport, role=role, status=status, status_code=status,
            response_excerpt=json.dumps(body, sort_keys=True),
        )


def test_planned_workflow_is_confirmed_only_by_framework_observed_invariant():
    workflow = plan_authorization_workflow(
        _finding(), _vampi_surfaces(), disposable=True, seed="scan-test")
    verifier = DynamicVerifier(max_probes=12)
    verifier.probe = _StatefulBolaProbe()

    bound = _surfaces_for_finding(_finding(), _vampi_surfaces())
    # The fake probe avoids socket I/O, but the verifier still enforces the
    # production loopback-only boundary before executing any workflow step.
    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "BOLA", "authorization_workflow": workflow,
    }, endpoints=bound)

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.oracle == "cross_identity_owner_secret_replay"
    assert {surface["path"] for surface in result.surfaces} >= {
        "/users/v1/register", "/users/v1/login", "/books/v1", "/books/v1/{book}",
    }
    assert all(
        record["params"].get("password") == "<redacted>"
        for record in result.setup_records if "password" in record["params"]
    )
    public_json = json.dumps({
        "setup": result.setup_records,
        "records": result.records,
        "confirmation": result.confirmation_records,
    })
    assert "token-aax_" not in public_json
    assert workflow["oracle"]["secret_value"] not in public_json
    assert "<redacted>" in public_json
