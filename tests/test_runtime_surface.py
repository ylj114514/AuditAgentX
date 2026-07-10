"""源码/运行时攻击面与真实 HTTP 证据链回归测试。"""
from __future__ import annotations

from backend.dynamic.endpoint_extractor import candidate_attack_surfaces, extract_endpoints
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord
from backend.verifier.evidence_collector import EvidenceCollector


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
    assert {"name": "query", "location": "json"} in search["params"]
    assert {"name": "file", "location": "query"} in download["params"]
    assert any(item["source"] == "static_route" for item in candidate_attack_surfaces(tmp_path))


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
    result = verifier.verify("http://target.local", {
        "vuln_type": "SQL Injection",
        "payloads": ["1' OR '1'='1"],
        "success_indicators": [r"SQLite error"],
        "_injection_points": ["query"],
        "http_method": "POST",
    }, endpoints=[{
        "path": "/search", "methods": ["POST"],
        "params": [{"name": "query", "location": "json"}], "source": "static_route",
    }])

    assert result.reproducible is True
    assert result.verification_level == "endpoint_reproduced"
    assert result.oracle == "new_database_error_indicator"
    assert result.baseline_record is not None
    assert any(call[-2:] == ("json", "baseline") for call in calls)
    assert any(call[-2:] == ("json", "attack") for call in calls)


def test_openapi_like_json_surface_does_not_fallback_to_generic_query_params():
    class NoHitProbe:
        def send(self, base_url, path, param, payload, method="GET", transport="query", role="attack"):
            return ProbeRecord(url=base_url + path, method=method, params={param: payload}, payload=payload,
                               transport=transport, role=role, status=200, status_code=200,
                               response_excerpt="normal", elapsed_ms=10)

    verifier = DynamicVerifier(max_probes=4)
    verifier.probe = NoHitProbe()
    result = verifier.verify("http://target.local", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQL syntax"], "_injection_points": ["id", "q"],
    }, endpoints=[{"path": "/api/search", "methods": ["POST"],
                    "params": [{"name": "filter", "location": "json"}]}])
    assert all(record["params"].keys() == {"filter"} for record in result.records)


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
