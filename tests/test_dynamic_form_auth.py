"""Offline form-auth bootstrap coverage for the HTTP dynamic verifier."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest

from backend.dynamic.source_route_binding import bind_server_surface
from backend.agents.exploit_agent import build_confirmed_http_poc
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.pipeline import ExploitPipeline, _auth_bootstrap_inventory, _recorded_poc_setup_steps
from backend.verifier.poc_writer import generate_poc_file


def _surface(path, methods, params):
    return bind_server_surface(
        {"path": path, "methods": methods, "params": params},
        {"kind": "test_source_route"},
    )


def _inventory():
    return [
        _surface("/learn", ["GET"], [{"name": "url", "location": "query"}]),
        _surface("/register", ["GET", "POST"], [
            {"name": "username", "location": "form"},
            {"name": "email", "location": "form"},
            {"name": "password", "location": "form"},
            {"name": "password_confirm", "location": "form"},
        ]),
        _surface("/login", ["GET", "POST"], [
            {"name": "username", "location": "form"},
            {"name": "password", "location": "form"},
        ]),
    ]


def _split_auth_inventory():
    inventory = _inventory()[1:]
    split = []
    for surface in inventory:
        for method in surface["methods"]:
            split.append(_surface(surface["path"], [method], surface["params"]))
    return split


def _nodegoat_auth_inventory():
    surfaces = [
        _surface("/signup", ["GET", "POST"], []),
        _surface("/login", ["GET", "POST"], []),
    ]
    split = []
    for surface in surfaces:
        for method in surface["methods"]:
            split.append(_surface(surface["path"], [method], surface["params"]))
    return split


@contextmanager
def _form_auth_target(*, oracle=True, protected=True, form_variant="valid", open_redirect=False,
                      empty_nodegoat_csrf=False):
    state = {"registered": False, "posts": 0, "register_csrf": "register-live-csrf",
             "login_csrf": "login-live-csrf", "registered_identity": {}}
    signup_path = "/signup" if form_variant == "nodegoat" else "/register"

    if form_variant == "external_action":
        register_form = (
            '<form method="post" action="http://example.invalid/register">'
            '<input name="username"><input name="password" type="password"></form>'
        )
    elif form_variant == "unknown_field":
        register_form = (
            '<form method="post" action="/register">'
            '<input name="username"><input name="company"><input name="password" type="password"></form>'
        )
    elif form_variant == "csrf_missing":
        register_form = (
            '<form method="post" action="/register">'
            '<input type="hidden" name="_csrf">'
            '<input name="username"><input name="password" type="password"></form>'
        )
    elif form_variant == "csrf_visible":
        register_form = (
            '<form method="post" action="/register">'
            '<input name="_csrf" value="must-not-be-accepted">'
            '<input name="username"><input name="password" type="password"></form>'
        )
    elif form_variant == "nodegoat":
        # NodeGoat-style signup: the form and its live token are intentionally
        # beyond the regular 800-character evidence excerpt.
        register_form = (
            "x" * 900
            + '<form method="post" action="/signup">'
            + f'<input type="hidden" name="_csrf" value="{("" if empty_nodegoat_csrf else state["register_csrf"])}">'
            + '<input name="userName"><input name="firstName"><input name="lastName">'
            + '<input name="password" type="password"><input name="verify" type="password">'
            + '<input name="email" type="email"></form>'
        )
    else:
        register_form = (
            '<form method="post" action="/register">'
            '<input name="username"><input name="email" type="email">'
            '<input name="password" type="password">'
            '<input name="password_confirm" type="password"></form>'
        )
    login_form = (
        ('y' * 900 if form_variant == "nodegoat" else "")
        + '<form method="post" action="/login">'
        + (f'<input type="hidden" name="_csrf" value="{("" if empty_nodegoat_csrf else state["login_csrf"])}">'
           if form_variant == "nodegoat" else "")
        + ('<input name="userName">' if form_variant == "nodegoat" else '<input name="username">')
        + '<input name="password" type="password"></form>'
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _write(self, status, body="", headers=None):
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/learn":
                if protected and "session=aax" not in self.headers.get("Cookie", ""):
                    self._write(302, headers={"Location": "/login"})
                    return
                value = parse_qs(parsed.query).get("url", [""])[0]
                if open_redirect:
                    self._write(302, headers={"Location": value})
                    return
                self._write(200, "SQL syntax test marker" if oracle and "'" in value else "learn")
                return
            if parsed.path == signup_path:
                self._write(200, register_form)
                return
            if parsed.path == "/login":
                self._write(200, login_form)
                return
            self._write(404, "missing")

        def do_POST(self):  # noqa: N802
            state["posts"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            values = parse_qs(self.rfile.read(length).decode("utf-8"))
            if self.path == signup_path:
                if form_variant == "nodegoat":
                    state["registered"] = bool(
                        (not values.get("_csrf") if empty_nodegoat_csrf
                         else values.get("_csrf") == [state["register_csrf"]])
                        and values.get("userName") and values.get("firstName") and values.get("lastName")
                        and values.get("email") and values.get("password") == values.get("verify")
                    )
                    if state["registered"]:
                        state["registered_identity"] = {
                            key: values[key][0]
                            for key in ("userName", "email", "password")
                        }
                else:
                    state["registered"] = bool(values.get("username") and values.get("password"))
                self._write(204)
                return
            if (self.path == "/login" and state["registered"]
                    and (form_variant != "nodegoat" or (
                        (not values.get("_csrf") if empty_nodegoat_csrf
                         else values.get("_csrf") == [state["login_csrf"]])
                        and values.get("userName") == [state["registered_identity"].get("userName")]
                        and values.get("password") == [state["registered_identity"].get("password")]
                    ))):
                self._write(302, headers={"Location": "/learn", "Set-Cookie": "session=aax; HttpOnly"})
                return
            self._write(401, "authentication failed")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _exploit():
    return {
        "vuln_type": "SQL Injection",
        "payloads": ["1' OR '1'='1"],
        "success_indicators": ["SQL syntax test marker"],
        "_injection_points": ["url"],
    }


def _open_redirect_exploit(base_url):
    return {
        "vuln_type": "Open Redirect",
        "open_redirect_plan": {
            "path": "/learn", "method": "GET", "param": "url", "transport": "query",
            "payload": base_url + "/__auditagentx_redirect/nodegoat-canary",
        },
    }


def test_form_auth_redirect_bootstrap_replays_bound_baseline_and_attack():
    with _form_auth_target() as (base_url, _state):
        result = DynamicVerifier().verify(
            base_url, _exploit(), endpoints=[_inventory()[0]], auth_endpoints=_split_auth_inventory())

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.oracle == "new_database_error_indicator"
    assert result.disposable_auth_bootstrap is True
    assert result.confirmed_record["url"].endswith("/learn?url=1%27+OR+%271%27%3D%271")
    assert {record["auth_bootstrap"]["stage"] for record in result.setup_records} >= {
        "form_fetch", "form_submit",
    }
    assert all("password" not in str(record["params"]).lower() or "<redacted>" in str(record["params"])
               for record in result.setup_records)
    steps = _recorded_poc_setup_steps(result.__dict__)
    assert [(step["method"], step["path"]) for step in steps] == [
        ("GET", "/register"), ("POST", "/register"), ("GET", "/login"), ("POST", "/login"),
    ]
    assert steps[1]["values"]["password"] == "CHANGE_ME"


def test_pipeline_mints_only_source_inventory_auth_capabilities():
    extracted = [
        {"path": "/register", "methods": ["GET"], "params": [], "file": "routes.py", "line": 1},
        {"path": "/register", "methods": ["POST"], "params": [], "file": "routes.py", "line": 2},
        {"path": "/login", "methods": ["GET"], "params": [], "file": "routes.py", "line": 3},
        {"path": "/login", "methods": ["POST"], "params": [], "file": "routes.py", "line": 4},
        {"path": "/learn", "methods": ["GET"], "params": [], "file": "routes.py", "line": 5},
    ]

    inventory = _auth_bootstrap_inventory(extracted)

    assert [(item["path"], item["methods"]) for item in inventory] == [
        ("/register", ["GET"]), ("/register", ["POST"]), ("/login", ["GET"]), ("/login", ["POST"]),
    ]
    assert all(item["source_route_binding"]["kind"] == "auth_bootstrap_inventory" for item in inventory)


def test_owned_docker_sandbox_keeps_disposable_auth_confirmation_for_poc_assembly():
    with _form_auth_target() as (base_url, _state):
        pipeline = object.__new__(ExploitPipeline)
        pipeline.dynamic = DynamicVerifier()
        result = pipeline._http_verify(
            {"type": "SQL Injection", "severity": "medium"}, _exploit(), base_url,
            [_inventory()[0]], {"status": "started", "mode": "docker"}, None, False,
            auth_endpoints=_split_auth_inventory(),
        )

    assert result["reproduction_status"] == "dynamic_confirmed"
    assert result["reproducible"] is True
    assert result["disposable_auth_bootstrap"] is True


def test_nodegoat_style_csrf_signup_authenticates_open_redirect_and_replays_exact_canary(tmp_path, monkeypatch):
    with _form_auth_target(form_variant="nodegoat", open_redirect=True) as (base_url, state):
        result = DynamicVerifier().verify(
            base_url, _open_redirect_exploit(base_url), endpoints=[_inventory()[0]],
            auth_endpoints=_nodegoat_auth_inventory(),
        )
        assert result.reproduction_status == "dynamic_confirmed"
        assert result.oracle == "exact_redirect_location"
        assert result.confirmed_record["redirect_location"] == base_url + "/__auditagentx_redirect/nodegoat-canary"
        assert result.disposable_auth_bootstrap is True
        assert state["posts"] == 2
        assert state["register_csrf"] not in str(result.setup_records)
        assert state["login_csrf"] not in str(result.setup_records)
        verifier_identity = dict(state["registered_identity"])
        setup_steps = _recorded_poc_setup_steps(result.__dict__)
        assert setup_steps == [
            {"path": "/signup", "method": "GET", "transport": "query", "values": {}},
            {"path": "/signup", "method": "POST", "transport": "form", "values": {
                "userName": "aax_replay_user", "firstName": "Audit", "lastName": "Agent",
                "password": "CHANGE_ME", "verify": "CHANGE_ME", "email": "aax_replay@example.invalid",
            }, "dynamic_csrf_field": "_csrf"},
            {"path": "/login", "method": "GET", "transport": "query", "values": {}},
            {"path": "/login", "method": "POST", "transport": "form", "values": {
                "userName": "aax_replay_user", "password": "CHANGE_ME",
            }, "dynamic_csrf_field": "_csrf"},
        ]
        code = build_confirmed_http_poc(result.confirmed_record, result.matched_indicator, setup_steps)
        assert "_aax_hidden_csrf" in code
        assert state["register_csrf"] not in code
        assert state["login_csrf"] not in code
        compile(code, "confirmed_open_redirect_csrf_poc.py", "exec")

        monkeypatch.setenv("AAX_SETUP_PASSWORD", "override-only-for-test")
        exec(compile(code, "confirmed_open_redirect_csrf_poc.py", "exec"), {})

        evidence = {
            "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
            "runtime": {
                "reproduction_status": result.reproduction_status,
                "matched_indicator": result.matched_indicator,
                "response_excerpt": result.confirmed_record["response_excerpt"],
                "response_status": result.confirmed_record["status_code"],
                "response_headers": result.confirmed_record["response_headers"],
                "baseline": result.baseline_record,
                "server_binding": result.server_binding,
                "setup_records": result.setup_records,
                "request": {
                    "url": result.confirmed_record["url"], "method": result.confirmed_record["method"],
                    "param": "url", "params": result.confirmed_record["params"],
                    "payload": result.confirmed_record["payload"], "transport": result.confirmed_record["transport"],
                },
            },
            "exploit": {"exploit_code": code},
        }
        artifact = generate_poc_file(
            {"finding_id": "nodegoat-open-redirect", "type": "Open Redirect", "file": "learn.js",
             "start_line": 1, "status": "confirmed", "verified": True},
            evidence, tmp_path,
        )
        body = (tmp_path / "nodegoat-open-redirect.md").read_text(encoding="utf-8")

    assert artifact is not None
    assert state["posts"] == 4
    for raw_value in (
        state["register_csrf"], state["login_csrf"],
        verifier_identity["userName"], verifier_identity["email"], verifier_identity["password"],
    ):
        assert raw_value not in body


def test_nodegoat_empty_conventional_csrf_is_omitted_then_requires_real_auth_success():
    """An empty _csrf field is not a token; omission remains safe because auth must succeed."""
    with _form_auth_target(form_variant="nodegoat", open_redirect=True,
                           empty_nodegoat_csrf=True) as (base_url, state):
        result = DynamicVerifier().verify(
            base_url, _open_redirect_exploit(base_url), endpoints=[_inventory()[0]],
            auth_endpoints=_nodegoat_auth_inventory(),
        )

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.disposable_auth_bootstrap is True
    assert state["posts"] == 2
    submits = [item for item in result.setup_records
               if item["auth_bootstrap"]["stage"] == "form_submit"]
    assert all(item["auth_bootstrap"]["dynamic_csrf_field"] == "" for item in submits)


def test_no_auth_response_falls_back_to_existing_no_oracle_verdict():
    with _form_auth_target(oracle=False, protected=False) as (base_url, state):
        result = DynamicVerifier().verify(base_url, _exploit(), endpoints=[_inventory()[0]])

    assert result.reproduction_status == "not_reproduced"
    assert result.setup_records == []
    assert state["posts"] == 0


@pytest.mark.parametrize("form_variant", ["external_action", "unknown_field", "csrf_missing", "csrf_visible"])
def test_cross_origin_or_unknown_auth_forms_fail_closed(form_variant):
    with _form_auth_target(form_variant=form_variant) as (base_url, state):
        result = DynamicVerifier().verify(base_url, _exploit(), endpoints=_inventory())

    assert result.reproduction_status == "authentication_required"
    assert result.reproducible is False
    assert result.confirmed_record is None
    assert state["posts"] == 0


def test_successful_auth_without_existing_oracle_never_creates_confirmed_poc_record():
    with _form_auth_target(oracle=False) as (base_url, _state):
        result = DynamicVerifier().verify(base_url, _exploit(), endpoints=_inventory())

    assert result.reproduction_status == "not_reproduced"
    assert result.reproducible is False
    assert result.confirmed_record is None
