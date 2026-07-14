"""源码/运行时攻击面与真实 HTTP 证据链回归测试。"""
from __future__ import annotations

import json

import pytest

from backend.dynamic.endpoint_extractor import candidate_attack_surfaces, extract_endpoints
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord, _replace_path_parameter
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier.pipeline import ExploitPipeline, _proven_surfaces_for_finding
from backend.dynamic.source_route_binding import bind_server_surface, is_server_bound_surface


def _bound_surface(surface: dict) -> dict:
    return bind_server_surface(surface, {"kind": "test"})


def test_static_attack_surface_keeps_route_method_and_parameter_location(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        """from flask import Flask, request
app = Flask(__name__)
@app.route('/search', methods=['POST'])
def search():
    return request.get_json().get('query')
@app.route('/download')
def download():
    return request.args.get('file')
""",
        encoding="utf-8",
    )

    endpoints = extract_endpoints(tmp_path)["endpoints"]
    search = next(item for item in endpoints if item["path"] == "/search")
    download = next(item for item in endpoints if item["path"] == "/download")
    assert search["methods"] == ["POST"]
    assert search["line"] == 3
    assert {"name": "query", "location": "json"} in search["params"]
    assert {"name": "file", "location": "query"} in download["params"]
    assert any(item["source"] == "static_route" for item in candidate_attack_surfaces(tmp_path))


def test_static_attack_surface_resolves_request_json_alias(tmp_path):
    (tmp_path / "app.py").write_text(
        """from flask import Flask, request
app = Flask(__name__)
@app.route('/search', methods=['POST'])
def search():
    content = request.json
    search_term = content['search']
    return search_term
""",
        encoding="utf-8",
    )
    endpoint = extract_endpoints(tmp_path)["endpoints"][0]
    assert endpoint["path"] == "/search"
    assert {"name": "search", "location": "json"} in endpoint["params"]


def test_flask_blueprint_route_binds_handler_input_through_imported_model_sink(tmp_path):
    """Blueprint prefixes and a proven local import chain authorize one route only."""
    (tmp_path / "api_views").mkdir()
    (tmp_path / "models").mkdir()
    (tmp_path / "app.py").write_text(
        """from flask import Flask
from api_views.main import api
app = Flask(__name__)
app.register_blueprint(api, url_prefix='/api')
""",
        encoding="utf-8",
    )
    (tmp_path / "api_views" / "main.py").write_text(
        """from flask import Blueprint, request
from models.user_model import find_user
api = Blueprint('api', __name__, url_prefix='/v1')

@api.get('/users')
def users():
    username = request.args.get('username')
    return find_user(username)

@api.get('/health')
def health():
    return 'ok'
""",
        encoding="utf-8",
    )
    (tmp_path / "models" / "user_model.py").write_text(
        """def find_user(username):
    return db.execute(f\"SELECT * FROM users WHERE username = '{username}'\")
""",
        encoding="utf-8",
    )

    endpoints = extract_endpoints(tmp_path)["endpoints"]
    endpoint = next(item for item in endpoints if item["path"] == "/api/users")
    bound = _proven_surfaces_for_finding(
        {"file": "models/user_model.py", "start_line": 2}, endpoints, tmp_path,
    )

    assert endpoint["framework"] == "flask"
    assert endpoint["methods"] == ["GET"]
    assert {"name": "username", "location": "query"} in endpoint["params"]
    assert len(bound) == 1
    assert bound[0]["path"] == "/api/users"
    assert bound[0]["source_route_binding"]["proof_kind"] == "intermodule_parameter_flow"


def test_openapi_route_binds_path_parameter_through_imported_static_model_method(tmp_path):
    """OpenAPI handlers may dispatch to imported model static methods (VAmPI pattern)."""
    (tmp_path / "api_views").mkdir()
    (tmp_path / "models").mkdir()
    (tmp_path / "api_views" / "users.py").write_text(
        """from models.user_model import User

def get_by_username(username):
    return User.get_user(username)
""",
        encoding="utf-8",
    )
    (tmp_path / "models" / "user_model.py").write_text(
        """class User:
    @staticmethod
    def get_user(username):
        return db.execute(f\"SELECT * FROM users WHERE username = '{username}'\")
""",
        encoding="utf-8",
    )
    (tmp_path / "openapi.yml").write_text(
        """openapi: 3.0.1
paths:
  /users/v1/{username}:
    get:
      operationId: api_views.users.get_by_username
      parameters:
        - name: username
          in: path
          required: true
          schema: {type: string}
""",
        encoding="utf-8",
    )

    endpoints = extract_endpoints(tmp_path)["endpoints"]
    bound = _proven_surfaces_for_finding(
        {"file": "models/user_model.py", "start_line": 4}, endpoints, tmp_path,
    )

    assert len(bound) == 1
    assert bound[0]["path"] == "/users/v1/1"
    assert bound[0]["methods"] == ["GET"]
    assert {"name": "username", "location": "path", "required": True,
            "type": "string", "enum": [], "default": None} in bound[0]["params"]
    assert bound[0]["source_route_binding"]["proof_kind"] == "intermodule_parameter_flow"


def test_proven_openapi_handler_parameter_overrides_unbound_template_hint(tmp_path):
    """A server-proven handler parameter must remain executable through the HTTP gate."""
    (tmp_path / "api_views").mkdir()
    (tmp_path / "models").mkdir()
    (tmp_path / "api_views" / "users.py").write_text(
        "from models.user_model import User\n\ndef get_by_username(username):\n    return User.get_user(username)\n",
        encoding="utf-8",
    )
    (tmp_path / "models" / "user_model.py").write_text(
        "class User:\n    @staticmethod\n    def get_user(username):\n        return db.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n",
        encoding="utf-8",
    )
    (tmp_path / "openapi.yml").write_text(
        """openapi: 3.0.1
paths:
  /users/v1/{username}:
    get:
      operationId: api_views.users.get_by_username
      parameters:
        - name: username
          in: path
          required: true
          schema: {type: string}
""",
        encoding="utf-8",
    )

    calls = []

    class VulnerablePathProbe:
        def send(self, base_url, path, param, payload, method="GET", transport="query", role="attack", **_kwargs):
            calls.append((path, param, transport, role))
            body = "SQLite error" if role == "attack" else "normal"
            return ProbeRecord(
                url=base_url + path, method=method, params={param: payload}, payload=payload,
                transport=transport, role=role, status=500, status_code=500,
                response_excerpt=body,
            )

    endpoints = _proven_surfaces_for_finding(
        {"file": "models/user_model.py", "start_line": 4},
        extract_endpoints(tmp_path)["endpoints"], tmp_path,
    )
    pipeline = object.__new__(ExploitPipeline)
    pipeline.dynamic = DynamicVerifier(max_probes=4)
    pipeline.dynamic.probe = VulnerablePathProbe()
    result = pipeline._http_verify(
        {"type": "SQL Injection", "severity": "high", "file": "models/user_model.py", "start_line": 4},
        {
            "vuln_type": "SQL Injection", "payloads": ["'"],
            "success_indicators": ["SQLite error"],
            # Generic template metadata is not proof for this source route.
            "_injection_points": ["id"],
        },
        "http://127.0.0.1:18080", endpoints, None, None, True,
    )

    assert result["reproduction_status"] == "dynamic_confirmed"
    assert calls == [
        ("/users/v1/{username}", "username", "path", "baseline"),
        ("/users/v1/{username}", "username", "path", "attack"),
    ]


def test_static_attack_surface_resolves_express_router_mount_and_route_parameters(tmp_path):
    routes = tmp_path / "routes"
    routes.mkdir()
    (tmp_path / "app.js").write_text(
        """const users = require('./routes/users');
app.use('/api/v1', users);
""",
        encoding="utf-8",
    )
    (routes / "users.js").write_text(
        """const router = express.Router();
router.get('/users/:user_id', (req, res) => {
  return res.json(req.query.filter);
});
router.post('/users/:user_id', (req, res) => {
  return res.json(req.body.display_name);
});
module.exports = router;
""",
        encoding="utf-8",
    )

    endpoints = extract_endpoints(tmp_path)["endpoints"]
    get_endpoint = next(item for item in endpoints if item["methods"] == ["GET"])
    post_endpoint = next(item for item in endpoints if item["methods"] == ["POST"])

    assert get_endpoint["raw_path"] == "/api/v1/users/:user_id"
    assert get_endpoint["path"] == "/api/v1/users/1"
    assert {"name": "user_id", "location": "path", "required": True, "type": "string"} in get_endpoint["params"]
    assert {"name": "filter", "location": "query"} in get_endpoint["params"]
    assert {"name": "display_name", "location": "json"} not in get_endpoint["params"]
    assert {"name": "display_name", "location": "json"} in post_endpoint["params"]
    assert {"name": "filter", "location": "query"} not in post_endpoint["params"]


def test_static_attack_surface_resolves_fastapi_prefix_and_declared_parameters(tmp_path):
    (tmp_path / "api.py").write_text(
        """from fastapi import APIRouter, Body, Path, Query
router = APIRouter(prefix='/api/v1')

@router.post('/items/{item_id}')
async def create_item(
    item_id: int = Path(...),
    search: str = Query(...),
    note: str = Body(...),
):
    return {"item_id": item_id, "search": search, "note": note}
""",
        encoding="utf-8",
    )

    endpoint = extract_endpoints(tmp_path)["endpoints"][0]

    assert endpoint["raw_path"] == "/api/v1/items/{item_id}"
    assert endpoint["path"] == "/api/v1/items/1"
    assert endpoint["methods"] == ["POST"]
    assert {(item["name"], item["location"]) for item in endpoint["params"]} == {
        ("item_id", "path"), ("search", "query"), ("note", "json"),
    }


def test_static_attack_surface_resolves_spring_class_mapping_and_request_parameters(tmp_path):
    (tmp_path / "UsersController.java").write_text(
        """@RestController
@RequestMapping("/api/users")
class UsersController {
  @PostMapping("/{userId}")
  String update(@PathVariable String userId, @RequestParam("view") String view,
                @RequestBody String displayName) { return displayName; }
}
""",
        encoding="utf-8",
    )

    endpoint = extract_endpoints(tmp_path)["endpoints"][0]

    assert endpoint["raw_path"] == "/api/users/{userId}"
    assert endpoint["methods"] == ["POST"]
    assert {(item["name"], item["location"]) for item in endpoint["params"]} == {
        ("userId", "path"), ("view", "query"), ("displayName", "json"),
    }


def test_static_attack_surface_does_not_borrow_parameter_from_another_source_file(tmp_path):
    (tmp_path / "routes.py").write_text(
        """from flask import Flask
app = Flask(__name__)
@app.route('/health')
def health():
    return 'ok'
""",
        encoding="utf-8",
    )
    (tmp_path / "unrelated.py").write_text(
        """from flask import request
def unrelated_helper():
    return request.args.get('forged_id')
""",
        encoding="utf-8",
    )

    endpoint = extract_endpoints(tmp_path)["endpoints"][0]

    assert endpoint["path"] == "/health"
    assert endpoint["params"] == []


def test_static_route_keeps_raw_path_template_and_separates_methods(tmp_path):
    (tmp_path / "app.py").write_text(
        """from flask import request
@app.get('/users/<int:user_id>')
def get_user():
    return request.args.get('view')
@app.post('/users/<int:user_id>')
def update_user():
    return request.get_json().get('display_name')
""",
        encoding="utf-8",
    )
    endpoints = extract_endpoints(tmp_path)["endpoints"]
    get_endpoint = next(item for item in endpoints if item["methods"] == ["GET"])
    post_endpoint = next(item for item in endpoints if item["methods"] == ["POST"])

    assert get_endpoint["raw_path"] == "/users/<int:user_id>"
    assert get_endpoint["path"] == "/users/1"
    assert {"name": "view", "location": "query"} in get_endpoint["params"]
    assert {"name": "display_name", "location": "json"} in post_endpoint["params"]
    assert {"name": "view", "location": "query"} not in post_endpoint["params"]


def test_openapi_first_project_maps_operations_to_source(tmp_path):
    (tmp_path / "api_views").mkdir()
    (tmp_path / "api_views" / "users.py").write_text(
        "def update_password(username):\n    return username\n", encoding="utf-8")
    (tmp_path / "openapi.yml").write_text(
        """openapi: 3.0.1
paths:
  /users/v1/{username}/password:
    put:
      tags: [users]
      summary: Update password
      operationId: api_views.users.update_password
      parameters:
        - name: username
          in: path
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                password:
                  type: string
      responses:
        '200':
          description: updated
          content:
            application/json:
              schema:
                type: object
                properties:
                  owner: {type: string}
                  secret: {type: string}
""",
        encoding="utf-8",
    )
    endpoints = extract_endpoints(tmp_path)["endpoints"]
    endpoint = next(item for item in endpoints if item["methods"] == ["PUT"])
    assert endpoint["source"] == "static_openapi"
    assert endpoint["raw_path"] == "/users/v1/{username}/password"
    assert endpoint["file"] == "api_views/users.py"
    assert endpoint["line"] == 1
    # params 现携带 default/enum/type 等最小有效请求模板字段，按 (name, location) 子集校验。
    _param_keys = {(p["name"], p["location"]) for p in endpoint["params"]}
    assert ("username", "path") in _param_keys
    assert ("password", "json") in _param_keys
    assert endpoint["tags"] == ["users"]
    assert endpoint["summary"] == "Update password"
    assert endpoint["response_fields"] == ["owner", "secret"]


def test_connexion_controller_operation_id_maps_to_qualified_source_handler(tmp_path):
    """Connexion's controller extension qualifies an otherwise local operationId."""
    (tmp_path / "api_views").mkdir()
    (tmp_path / "api_views" / "users.py").write_text(
        "def get_by_username(username):\n    return username\n", encoding="utf-8",
    )
    (tmp_path / "openapi.yml").write_text(
        """openapi: 3.0.1
paths:
  /users/v1/{username}:
    get:
      x-openapi-router-controller: api_views.users
      operationId: get_by_username
      parameters:
        - name: username
          in: path
          required: true
          schema: {type: string}
""",
        encoding="utf-8",
    )

    endpoint = extract_endpoints(tmp_path)["endpoints"][0]

    assert endpoint["raw_path"] == "/users/v1/{username}"
    assert endpoint["methods"] == ["GET"]
    assert endpoint["operation_id"] == "api_views.users.get_by_username"
    assert endpoint["file"] == "api_views/users.py"
    assert endpoint["line"] == 1
    assert {"name": "username", "location": "path", "required": True,
            "type": "string", "enum": [], "default": None} in endpoint["params"]


def test_path_parameter_replacement_is_encoded_and_scoped():
    assert _replace_path_parameter(
        "/users/v1/{username}/password", "username", "alice/../admin") == (
        "/users/v1/alice%2F..%2Fadmin/password")


def test_json_surface_uses_json_transport_and_stores_paired_baseline():
    calls = []

    class JsonTargetProbe:
        def send(self, base_url, path, param, payload, method="GET", transport="query", role="attack"):
            calls.append((path, method, param, payload, transport, role))
            body = "normal response"
            if role != "baseline" and transport == "json" and "'" in payload:
                body = "SQLite error: near quote"
            return ProbeRecord(
                url=base_url + path, method=method, params={param: payload}, payload=payload,
                transport=transport, role=role, status=200, status_code=200,
                response_excerpt=body, elapsed_ms=20,
            )

    verifier = DynamicVerifier(max_probes=8)
    verifier.probe = JsonTargetProbe()
    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "SQL Injection",
        "payloads": ["1' OR '1'='1"],
        "success_indicators": [r"SQLite error"],
        "_injection_points": ["query"],
        "http_method": "POST",
        }, endpoints=[_bound_surface({
            "path": "/search", "methods": ["POST"],
            "params": [{"name": "query", "location": "json"}], "source": "static_route",
        })])

    assert result.reproducible is True
    assert result.verification_level == "endpoint_reproduced"
    assert result.oracle == "new_database_error_indicator"
    assert result.baseline_record is not None
    assert any(call[-2:] == ("json", "baseline") for call in calls)
    assert any(call[-2:] == ("json", "attack") for call in calls)


def test_authenticated_setup_captures_header_for_baseline_and_attack():
    calls = []

    class AuthenticatedProbe:
        def send_values(self, base_url, path, values, *, method="POST", transport="json",
                        role="setup", headers=None, payload=""):
            calls.append((role, path, dict(headers or {})))
            return ProbeRecord(
                url=base_url + path, method=method, params=values, payload="",
                transport=transport, role=role, status=200, status_code=200,
                response_headers={"authorization": "signed-test-token"},
            )

        def send(self, base_url, path, param, payload, method="GET", transport="query",
                 role="attack", headers=None):
            calls.append((role, path, dict(headers or {})))
            authorized = (headers or {}).get("Authorization") == "signed-test-token"
            body = "normal"
            if authorized and role == "attack" and "'" in payload:
                body = "sqlite3.OperationalError near quote"
            return ProbeRecord(
                url=base_url + path, method=method, params={param: payload}, payload=payload,
                transport=transport, role=role, status=200 if authorized else 403,
                status_code=200 if authorized else 403, response_excerpt=body,
            )

    verifier = DynamicVerifier(max_probes=4)
    verifier.probe = AuthenticatedProbe()
    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": [r"sqlite3\.OperationalError"],
        "_injection_points": ["search"], "http_method": "POST",
        "setup_requests": [{
            "path": "/login", "method": "POST", "transport": "json",
            "values": {"username": "admin", "password": "admin123"},
            "capture_response_headers": {"authorization": "Authorization"},
        }],
        }, endpoints=[_bound_surface({"path": "/search", "methods": ["POST"],
                        "params": [{"name": "search", "location": "json"}],
                        })])

    assert result.reproducible is True
    assert len(result.setup_records) == 1
    assert all(call[2].get("Authorization") == "signed-test-token"
               for call in calls if call[0] in {"baseline", "attack"})
    evidence = EvidenceCollector.build({}, dynamic=result.__dict__)
    setup = evidence["runtime"]["setup_records"][0]
    assert setup["response_headers"]["authorization"] == "<redacted>"


def test_openapi_like_json_surface_does_not_fallback_to_generic_query_params():
    class NoHitProbe:
        def send(self, base_url, path, param, payload, method="GET", transport="query", role="attack"):
            return ProbeRecord(url=base_url + path, method=method, params={param: payload}, payload=payload,
                               transport=transport, role=role, status=200, status_code=200,
                               response_excerpt="normal", elapsed_ms=10)

    verifier = DynamicVerifier(max_probes=4)
    verifier.probe = NoHitProbe()
    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQL syntax"], "_injection_points": ["id", "q"],
    }, endpoints=[_bound_surface({"path": "/api/search", "methods": ["POST"],
                                  "params": [{"name": "filter", "location": "json"}]})])
    assert all(record["params"].keys() == {"filter"} for record in result.records)


def test_persisted_binding_claim_and_unknown_parameter_perform_zero_requests():
    calls = []

    class CountingProbe:
        def send(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("unproven request must not be sent")

    verifier = DynamicVerifier(max_probes=4)
    verifier.probe = CountingProbe()
    forged = json.loads(json.dumps({
        "path": "/search", "methods": ["GET"],
        "params": [{"name": "id", "location": "query"}],
        "source_route_binding": {"kind": "persisted"},
    }))

    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQL syntax"], "_injection_points": ["id"],
    }, endpoints=[forged])

    assert result.reproduction_status == "endpoint_unresolved"
    assert calls == []

    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQL syntax"], "_injection_points": ["unknown"],
    }, endpoints=[_bound_surface({
        "path": "/search", "methods": ["GET"],
        "params": [{"name": "id", "location": "query"}],
    })])

    assert result.reproduction_status == "endpoint_unresolved"
    assert calls == []


def test_server_binding_rejects_mutation_and_external_route_forms():
    bound = bind_server_surface({
        "path": "/search", "methods": ["GET"],
        "params": [{"name": "id", "location": "query"}],
    }, {"kind": "test"})
    bound["params"][0]["name"] = "forged"

    assert is_server_bound_surface(bound) is False
    assert is_server_bound_surface(bind_server_surface(
        {"path": "//evil.example/search", "methods": ["GET"], "params": []}, {"kind": "test"},
    )) is False
    assert is_server_bound_surface(bind_server_surface(
        {"path": "https://evil.example/search", "methods": ["GET"], "params": []}, {"kind": "test"},
    )) is False

    calls = []

    class CountingProbe:
        def send(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("external route form must not be requested")

    verifier = DynamicVerifier(max_probes=2)
    verifier.probe = CountingProbe()
    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQL syntax"], "_injection_points": ["id"],
    }, endpoints=[bind_server_surface(
        {"path": "//evil.example/search", "methods": ["GET"],
         "params": [{"name": "id", "location": "query"}]}, {"kind": "test"},
    )])

    assert result.reproduction_status == "endpoint_unresolved"
    assert calls == []


def test_required_same_transport_siblings_are_preserved_without_cross_transport_pollution():
    calls = []

    class TemplateProbe:
        def send(self, base_url, path, param, payload, method="GET", transport="query",
                 role="attack", sibling_values=None, **kwargs):
            calls.append((param, transport, role, dict(sibling_values or {})))
            return ProbeRecord(
                url=base_url + path, method=method,
                params={**(sibling_values or {}), param: payload}, payload=payload,
                transport=transport, role=role, status=200, status_code=200,
                response_excerpt="normal",
            )

    verifier = DynamicVerifier(max_probes=4)
    verifier.probe = TemplateProbe()
    verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQLite error"], "_injection_points": ["search"],
        "http_method": "POST",
        }, endpoints=[_bound_surface({
            "path": "/search/{tenant_id}", "raw_path": "/search/{tenant_id}", "methods": ["POST"],
            "params": [
            {"name": "search", "location": "json", "required": True},
            {"name": "page", "location": "json", "required": True, "type": "integer"},
            {"name": "verbose", "location": "query", "required": True},
            {"name": "optional_note", "location": "json", "required": False},
            {"name": "tenant_id", "location": "path", "required": True, "type": "integer"},
        ],
        })])

    json_calls = [siblings for param, transport, _role, siblings in calls
                  if transport == "json" and param == "search"]
    assert json_calls
    assert all(siblings == {"page": 1} for siblings in json_calls)


def test_evidence_keeps_baseline_oracle_and_transport_for_real_confirmation():
    evidence = EvidenceCollector.build({}, dynamic={
        "reproduction_status": "dynamic_confirmed", "reproducible": True,
        "verification_level": "endpoint_reproduced", "oracle": "new_database_error_indicator",
        "baseline_record": {"url": "http://127.0.0.1:1/user?id=1", "status_code": 200},
        "confirmed_record": {
            "url": "http://127.0.0.1:1/user?id=%27", "method": "GET", "params": {"id": "'"},
            "payload": "'", "transport": "query", "status_code": 500,
            "runtime_log_excerpt": "sqlite3.OperationalError",
        },
    })
    runtime = evidence["runtime"]
    assert runtime["verification_level"] == "endpoint_reproduced"
    assert runtime["oracle"] == "new_database_error_indicator"
    assert runtime["request"]["transport"] == "query"
    assert runtime["baseline"]["status_code"] == 200


def test_evidence_preserves_blocked_instead_of_relabeling_not_reproduced():
    evidence = EvidenceCollector.build({
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "call_path": [
            {"stage": "source", "detail": "request.args['id']"},
            {"stage": "sink", "detail": "cursor.execute"},
        ],
        "static_verdict": "confirmed",
        "final_verdict": "confirmed",
    }, exploit={"trigger_location": "app.py:21"}, dynamic={
        "reproduction_status": "blocked", "blocker_reason": "authentication_failed",
        "reason": "authentication_failed", "reproducible": False, "records": [],
    })
    assert evidence["runtime"]["reproduction_status"] == "blocked"
    assert evidence["verification"]["evidence_level"] == "blocked"
    assert evidence["evidence_complete"] is True
    assert evidence["actionable"] is True
    assert evidence["exploitable"] is True
    assert any("阻断" in line for line in evidence["logs"])


@pytest.mark.parametrize(
    ("dynamic", "harness", "expected_level"),
    [
        (
            {"reproduction_status": "not_executed", "skipped": True, "reason": "runtime skipped"},
            {"verdict": "not_applicable", "reason": "no target function"},
            "not_executed",
        ),
        (
            {"reproduction_status": "not_executed", "skipped": True},
            {"verdict": "not_executed"},
            "not_executed",
        ),
        (
            {"reproduction_status": "not_reproduced", "skipped": False},
            {"verdict": "not_applicable"},
            "http_executed_not_reproduced",
        ),
        (
            {"reproduction_status": "setup_failed", "skipped": False},
            {"verdict": "not_applicable"},
            "inconclusive",
        ),
        (
            {"reproduction_status": "connection_failed", "skipped": False},
            {"verdict": "not_reproduced"},
            "inconclusive",
        ),
    ],
)
def test_evidence_level_requires_a_completed_non_hit(dynamic, harness, expected_level):
    evidence = EvidenceCollector.build({}, dynamic=dynamic, harness=harness)

    assert evidence["verification"]["evidence_level"] == expected_level


def test_verification_exposes_redacted_environment_blocker():
    sandbox = {
        "status": "sandbox_start_failed",
        "failure_code": "missing_env_file",
        "reason": "DATABASE_PASSWORD=do-not-expose",
    }
    evidence = EvidenceCollector.build(
        {},
        dynamic={
            "reproduction_status": "not_executed",
            "skipped": True,
            "reason": "未配置 base_url",
        },
        harness={"verdict": "not_applicable"},
        sandbox=sandbox,
    )

    verification = evidence["verification"]
    assert verification["evidence_level"] == "not_executed"
    assert verification["execution_blocker"] == "missing_env_file"
    assert verification["environment_status"] == "sandbox_start_failed"
    assert "do-not-expose" not in str(verification)


def test_pipeline_no_base_url_uses_sandbox_failure_reason_and_code():
    sandbox = {
        "status": "sandbox_start_failed",
        "failure_code": "missing_env_file",
        "reason": "Compose 必需环境文件缺失: .env",
    }

    dynamic = object.__new__(ExploitPipeline)._http_verify(
        {"type": "SQL Injection", "severity": "high"},
        {"payloads": ["'"], "_injection_points": ["id"]},
        None,
        [{"path": "/users", "params": [{"name": "id", "location": "query"}]}],
        sandbox,
        sandbox["status"],
        False,
    )

    assert dynamic["reproduction_status"] == "sandbox_start_failed"
    assert "Compose 必需环境文件缺失" in dynamic["reason"]
    assert "未配置本地授权靶场 base_url" not in dynamic["reason"]
    assert dynamic["sandbox"]["failure_code"] == "missing_env_file"


def test_evidence_completeness_requires_location_and_accepted_verification():
    evidence = EvidenceCollector.build({
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "call_path": [
            {"stage": "source", "detail": "request.args['id']"},
            {"stage": "sink", "detail": "cursor.execute"},
        ],
        "static_verdict": "confirmed",
        "final_verdict": "confirmed",
    })

    assert evidence["evidence_complete"] is False
    assert evidence["actionable"] is False
    assert evidence["exploitable"] is False


def _bola_workflow():
    return {
        "steps": [
            {"path": "/createdb", "method": "GET", "role": "initialize"},
            {"path": "/users/v1/login", "method": "POST", "transport": "json",
             "values": {"username": "owner", "password": "owner-pass"},
             "capture_json": {"auth_token": "owner_token"}},
            {"path": "/users/v1/login", "method": "POST", "transport": "json",
             "values": {"username": "attacker", "password": "attacker-pass"},
             "capture_json": {"auth_token": "attacker_token"}},
            {"path": "/books/v1", "method": "POST", "transport": "json",
             "headers": {"Authorization": "Bearer ${owner_token}"},
             "values": {"book_title": "aax-owned", "secret": "AAX_BOLA_SENTINEL"},
             "role": "owner_create"},
            {"path": "/books/v1/aax-owned", "method": "GET",
             "headers": {"Authorization": "Bearer ${owner_token}"},
             "role": "owner_control"},
            {"path": "/books/v1/aax-owned", "method": "GET",
             "headers": {"Authorization": "Bearer ${attacker_token}"},
             "role": "authorization_attack"},
        ],
        "oracle": {
            "owner_identity": "owner", "attacker_identity": "attacker",
            "owner_json_field": "owner", "secret_json_field": "secret",
            "secret_value": "AAX_BOLA_SENTINEL",
        },
    }


def _bound_workflow_surfaces(workflow: dict) -> list[dict]:
    """Server-minted test fixture for each declarative BOLA workflow route."""
    seen = set()
    surfaces = []
    for step in workflow["steps"]:
        key = (step["path"], step.get("method", "GET"))
        if key not in seen:
            seen.add(key)
            surfaces.append(_bound_surface({"path": key[0], "methods": [key[1]], "params": []}))
    return surfaces


class _BolaProbe:
    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self.calls = []

    def send_values(self, base_url, path, values, *, method="POST", transport="json",
                    role="setup", headers=None, payload=""):
        self.calls.append((role, path, dict(values), dict(headers or {})))
        status = 200
        body = {"status": "ok"}
        response_headers = {}
        if path == "/users/v1/login":
            body = {"auth_token": "token-" + values["username"]}
            response_headers = {"Authorization": body["auth_token"]}
        elif role in {"owner_control", "authorization_attack", "confirmation"}:
            actor = (headers or {}).get("Authorization", "").removeprefix("Bearer token-")
            if actor != "owner" and not self.vulnerable:
                status, body = 404, {"message": "not found"}
            else:
                body = {"book_title": "aax-owned", "owner": "owner",
                        "secret": "AAX_BOLA_SENTINEL"}
        return ProbeRecord(
            url=base_url + path, method=method, params=values, payload=payload,
            transport=transport, role=role, status=status, status_code=status,
            response_excerpt=json.dumps(body, sort_keys=True), response_headers=response_headers,
        )


def test_bola_workflow_requires_owner_control_and_stable_cross_identity_replay():
    verifier = DynamicVerifier(max_probes=12)
    probe = _BolaProbe(vulnerable=True)
    verifier.probe = probe
    workflow = _bola_workflow()
    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "Broken Object Level Authorization",
        "authorization_workflow": workflow,
    }, endpoints=_bound_workflow_surfaces(workflow))

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.oracle == "cross_identity_owner_secret_replay"
    assert result.baseline_record["role"] == "owner_control"
    assert result.confirmed_record["role"] == "authorization_attack"
    assert result.confirmation_records[0]["role"] == "confirmation"
    assert sum(call[0] == "authorization_attack" for call in probe.calls) == 1
    assert sum(call[0] == "confirmation" for call in probe.calls) == 1
    # 动态对象本身也必须脱敏，不能等报告阶段才处理凭据。
    login_records = [item for item in result.setup_records if item["url"].endswith("/login")]
    assert all(item["params"]["password"] == "<redacted>" for item in login_records)
    assert all(item["response_headers"].get("Authorization") == "<redacted>"
               for item in login_records)


def test_bola_workflow_does_not_confirm_when_cross_identity_read_is_denied():
    verifier = DynamicVerifier(max_probes=12)
    verifier.probe = _BolaProbe(vulnerable=False)
    workflow = _bola_workflow()
    result = verifier.verify("http://127.0.0.1:18080", {
        "vuln_type": "IDOR",
        "authorization_workflow": workflow,
    }, endpoints=_bound_workflow_surfaces(workflow))

    assert result.verified is False
    assert result.reproduction_status == "not_reproduced"
    assert "returned 404" in result.reason
