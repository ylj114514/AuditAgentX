"""动态验证器逻辑测试。

用注入式假探针模拟目标响应，确定性验证「载荷迭代 → 特征匹配 → 取证判定」，
不依赖真实 socket（部分 Windows 安全软件会拦截本地监听端口）。
真实靶场联调见 examples/vulnerable_projects/safe_sqli_target/server.py 与 docs。
"""
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord, _log_delta, _public_record
from backend.verifier import exploit_templates as tpl


class FakeProbe:
    """模拟一个 error-based SQL 注入靶场：注入单引号即回显 SQL 报错。"""

    def __init__(self):
        self.calls = []

    def send(self, base_url, path, param, payload, method="GET"):
        self.calls.append((path, param, payload))
        rec = ProbeRecord(url=base_url + path, method=method,
                          params={param: payload}, payload=payload, status=200)
        if "'" in payload:
            rec.response_excerpt = ("You have an error in your SQL syntax near '"
                                    + payload + "' admin@example.com")
        else:
            rec.response_excerpt = "<html>user list</html>"
        return rec


class NotFoundProbe:
    def send(self, base_url, path, param, payload, method="GET"):
        return ProbeRecord(
            url=base_url + path,
            method=method,
            params={param: payload},
            payload=payload,
            status=404,
            status_code=404,
            response_excerpt="not found",
            reason="endpoint_not_found",
        )


class ErrorProbe:
    def __init__(self, reason):
        self.reason = reason
        self.calls = 0

    def send(self, base_url, path, param, payload, method="GET"):
        self.calls += 1
        return ProbeRecord(
            url=base_url + path,
            method=method,
            params={param: payload},
            payload=payload,
            error=self.reason,
            reason=self.reason,
        )


class NoHitProbe:
    def send(self, base_url, path, param, payload, method="GET"):
        return ProbeRecord(
            url=base_url + path,
            method=method,
            params={param: payload},
            payload=payload,
            status=200,
            status_code=200,
            response_excerpt="normal response",
        )


class BlockedProbe:
    """模拟鉴权/授权拦截：所有请求在进入业务逻辑前返回固定阻断状态码。"""

    def __init__(self, status):
        self.status = status

    def send(self, base_url, path, param, payload, method="GET", **kwargs):
        return ProbeRecord(
            url=base_url + path, method=method, params={param: payload}, payload=payload,
            status=self.status, status_code=self.status, response_excerpt="blocked", role="attack",
        )


def _make_verifier_with_fake():
    v = DynamicVerifier(timeout=5)
    v.probe = FakeProbe()
    return v


def test_blocked_status_is_not_reported_as_not_reproduced():
    """核心信任边界：401/403 等在进入业务逻辑前被拦截，必须判 blocked，
    绝不能写成 not_reproduced（那等于把环境失败谎报成“漏洞不存在”）。"""
    exploit = {"payloads": ["1' OR '1'='1"], "success_indicators": ["SQL syntax"],
               "_injection_points": ["id"]}
    for status, expected_reason in [(401, "authentication_failed"),
                                    (403, "authorization_blocked"),
                                    (415, "unsupported_media_type"),
                                    (422, "request_invalid")]:
        v = DynamicVerifier()
        v.probe = BlockedProbe(status)
        result = v.verify("http://target.local", exploit, endpoints=["/user"])
        assert result.reproduction_status == "blocked", f"{status} 应 blocked，实得 {result.reproduction_status}"
        assert result.blocker_reason == expected_reason
        assert result.application_reached is False
        assert result.verified is False


def test_server_error_counts_as_business_logic_reached():
    """500 说明 handler 已执行（error-based 注入的关键信号）：算 application_reached，
    未命中特征时才是真正的 not_reproduced，而非 blocked。"""
    exploit = {"payloads": ["x"], "success_indicators": ["SQL syntax"], "_injection_points": ["id"]}
    v = DynamicVerifier()
    v.probe = BlockedProbe(500)
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    assert result.application_reached is True
    assert result.reproduction_status == "not_reproduced"


def test_blocked_response_with_indicator_cannot_confirm_vulnerability():
    """网关/认证页中的 SQL 文案不是目标数据流证据。"""
    class MisleadingBlockedProbe:
        def send(self, base_url, path, param, payload, method="GET", **kwargs):
            return ProbeRecord(
                url=base_url + path, method=method, params={param: payload}, payload=payload,
                status=403, status_code=403, response_excerpt="SQL syntax denied by gateway",
                reason="authorization_blocked",
            )

    verifier = DynamicVerifier()
    verifier.probe = MisleadingBlockedProbe()
    result = verifier.verify("http://target.local", {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQL syntax"], "_injection_points": ["id"],
    }, endpoints=["/admin/search"])

    assert result.reproduction_status == "blocked"
    assert result.reproducible is False
    assert result.application_reached is False


def test_dynamic_verifier_confirms_sqli():
    template = tpl.match_template("SQL Injection")
    exploit = {
        "payloads": template.payloads,
        "success_indicators": template.success_indicators,
        "_injection_points": ["id"],
    }
    v = _make_verifier_with_fake()
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    assert result.verified is True
    assert result.reproducible is True
    assert result.confirmed_record is not None
    assert "'" in result.confirmed_record["payload"]
    assert result.matched_indicator
    # 证据链应记录命中日志
    assert any("命中" in log for log in result.logs)
    assert result.confirmed_record["status_code"] == 200


def test_confirmed_vuln_marks_application_reached():
    """复现成立即证明请求已到达并触发业务逻辑：application_reached 必为 True，
    证据链不得自相矛盾（confirmed 却声称没进业务逻辑）。"""
    template = tpl.match_template("SQL Injection")
    exploit = {"payloads": template.payloads, "success_indicators": template.success_indicators,
               "_injection_points": ["id"]}
    result = _make_verifier_with_fake().verify("http://target.local", exploit, endpoints=["/user"])
    assert result.reproducible is True
    assert result.application_reached is True


def test_dynamic_verifier_skips_static_finding():
    exploit = {"payloads": [], "success_indicators": [], "_injection_points": ["id"]}
    v = _make_verifier_with_fake()
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    assert result.skipped is True


def test_dynamic_verifier_no_target():
    exploit = {"payloads": ["1' OR '1'='1"], "success_indicators": ["sql"]}
    result = DynamicVerifier().verify("", exploit)
    assert result.skipped is True
    assert "base_url" in result.reason


def test_dynamic_verifier_endpoint_not_found():
    exploit = {"payloads": ["1' OR '1'='1"], "success_indicators": ["SQL syntax"]}
    v = DynamicVerifier()
    v.probe = NotFoundProbe()
    result = v.verify("http://target.local", exploit, endpoints=["/missing"])
    assert result.verified is False
    assert result.reason == "endpoint_not_found"
    assert result.records[0]["status_code"] == 404


def test_dynamic_verifier_connection_failed():
    exploit = {"payloads": ["1' OR '1'='1"], "success_indicators": ["SQL syntax"]}
    v = DynamicVerifier()
    v.probe = ErrorProbe("connection_failed")
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    assert result.reason == "connection_failed"
    assert result.error == "connection_failed"


def test_dynamic_verifier_request_timeout():
    exploit = {"payloads": ["1' OR '1'='1"], "success_indicators": ["SQL syntax"]}
    v = DynamicVerifier()
    v.probe = ErrorProbe("request_timeout")
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    assert result.reason == "request_timeout"


def test_public_http_record_redacts_url_payload_redirect_and_runtime_log():
    record = ProbeRecord(
        url="http://127.0.0.1/search?token=live-token&safe=1",
        method="GET", params={"token": "live-token"}, payload="live-token",
        redirect_location="/login?access_token=redirect-secret",
        runtime_log_excerpt="Authorization: Bearer runtime-secret password=hunter2",
        response_headers={"set-cookie": "session=real-session", "x-request-id": "safe"},
    )
    public = _public_record(record)
    text = str(public)
    for secret in ("live-token", "redirect-secret", "runtime-secret", "hunter2", "real-session"):
        assert secret not in text
    assert public["url"].endswith("token=%3Credacted%3E&safe=1")
    assert public["payload"] == "<redacted>"


def test_dynamic_verifier_generic_request_error_is_not_endpoint_not_found():
    exploit = {"payloads": ["payload"], "success_indicators": ["SQL syntax"]}
    v = DynamicVerifier()
    v.probe = ErrorProbe("request_error")
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    # 传输层错误、拿不到任何响应：既不是 endpoint_not_found，也绝不能当 not_reproduced
    # （请求没进入业务逻辑，无从证明漏洞不存在）——诚实判 inconclusive。
    assert result.reason == "request_error"
    assert result.reproduction_status == "inconclusive"


def test_unattributable_rotated_logs_are_not_used_as_attack_delta():
    assert _log_delta("old-prefix", "rotated tail with SQL syntax error") == ""


def test_dynamic_verifier_stops_repeated_unreachable_target_probes():
    """失效靶场只保留少量失败证据，不能把 120 次请求都耗在同一连接错误上。"""
    exploit = {
        "payloads": ["one", "two", "three"],
        "success_indicators": ["SQL syntax"],
        "_injection_points": ["id", "q"],
    }
    v = DynamicVerifier(max_probes=120)
    probe = ErrorProbe("connection_failed")
    v.probe = probe

    result = v.verify("http://target.local", exploit, endpoints=["/user", "/search"])

    # 每个攻击请求都有对应基线；提前停止后总调用数不应继续向 120 次预算扩张。
    assert probe.calls == 4
    assert len(result.records) == 2
    assert result.reason == "connection_failed"
    assert any("提前停止" in log for log in result.logs)


def test_dynamic_verifier_payload_not_matched():
    exploit = {"payloads": ["1' OR '1'='1"], "success_indicators": ["SQL syntax"]}
    v = DynamicVerifier()
    v.probe = NoHitProbe()
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    assert result.reason == "payload_not_matched"
    assert result.verification_level == "endpoint_not_reproduced"
    assert result.verified is False


def test_dynamic_verifier_confirms_stable_paired_boolean_sqli():
    class BooleanProbe:
        def send(self, base_url, path, param, payload, method="GET",
                 transport="query", role="attack", headers=None):
            if "'1'='1" in payload:
                body = "row:" + ("customer-data," * 20)
            else:
                body = "[]"
            return ProbeRecord(
                url=base_url + path, method=method, params={param: payload}, payload=payload,
                transport=transport, role=role, status=200, status_code=200,
                response_excerpt=body,
            )

    verifier = DynamicVerifier(max_probes=4)
    verifier.probe = BooleanProbe()
    result = verifier.verify("http://target.local", {
        "vuln_type": "SQL Injection", "payloads": ["1' OR '1'='1"],
        "success_indicators": [], "_injection_points": ["search"],
    }, endpoints=["/search"])

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.oracle == "paired_boolean_differential"
    assert result.matched_indicator.startswith("boolean-differential")
    assert {record["role"] for record in result.records} >= {
        "attack", "boolean_false", "confirmation",
    }
    assert [record["role"] for record in result.confirmation_records] == [
        "boolean_false", "confirmation",
    ]


def test_dynamic_verifier_uses_post_method_from_exploit():
    calls = []

    class MethodProbe:
        def send(self, base_url, path, param, payload, method="GET"):
            calls.append(method)
            return ProbeRecord(
                url=base_url + path,
                method=method,
                params={param: payload},
                payload=payload,
                status=200,
                status_code=200,
                response_excerpt="normal response",
            )

    v = DynamicVerifier()
    v.probe = MethodProbe()
    v.verify("http://target.local", {
        "payloads": ["admin=true"],
        "success_indicators": ["never"],
        "_injection_points": ["role"],
        "http_method": "POST",
    }, endpoints=["/login"])

    assert calls
    assert set(calls) == {"POST"}
