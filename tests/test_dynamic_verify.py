"""动态验证器逻辑测试。

用注入式假探针模拟目标响应，确定性验证「载荷迭代 → 特征匹配 → 取证判定」，
不依赖真实 socket（部分 Windows 安全软件会拦截本地监听端口）。
真实靶场联调见 examples/vulnerable_projects/safe_sqli_target/server.py 与 docs。
"""
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord, _log_delta
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


def _make_verifier_with_fake():
    v = DynamicVerifier(timeout=5)
    v.probe = FakeProbe()
    return v


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


def test_dynamic_verifier_generic_request_error_is_not_endpoint_not_found():
    exploit = {"payloads": ["payload"], "success_indicators": ["SQL syntax"]}
    v = DynamicVerifier()
    v.probe = ErrorProbe("request_error")
    result = v.verify("http://target.local", exploit, endpoints=["/user"])
    assert result.reason == "payload_not_matched"
    assert result.reproduction_status == "not_reproduced"


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
    assert result.verified is False


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
