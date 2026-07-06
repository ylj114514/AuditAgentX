"""动态验证器逻辑测试。

用注入式假探针模拟目标响应，确定性验证「载荷迭代 → 特征匹配 → 取证判定」，
不依赖真实 socket（部分 Windows 安全软件会拦截本地监听端口）。
真实靶场联调见 examples/vulnerable_projects/safe_sqli_target/server.py 与 docs。
"""
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord
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
