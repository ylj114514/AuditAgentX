"""静态确定性复核覆盖测试（Q1 静态补强）。

目标：把「清晰的 source→sink+无净化」以及「存在即漏洞的确定性缺陷」直接判为
statically confirmed，而不是一律塞给人工复核（此前只有 4 类有复核，其余全 needs_review）。
断言均基于确定性判据，不依赖 LLM。
"""
from backend.agents.verification_tools import _run_heuristic_verifier


def _verdict(vtype: str, snippet: str):
    return _run_heuristic_verifier(
        {"type": vtype, "code_snippet": snippet, "file": "app.py", "line": 1},
        {"snippet": snippet, "lines": []},
    ).get("is_valid")


def test_deterministic_weak_crypto_and_random_are_confirmed():
    """弱加密/弱随机是确定性缺陷（无需污点源）-> 直接确认，不塞人工。"""
    assert _verdict("Weak Cryptography", "password_hash = hashlib.md5(password).hexdigest()") is True
    assert _verdict("Weak Cryptography", "c = Cipher.getInstance('DES/ECB/PKCS5Padding')") is True
    assert _verdict("Weak Randomness", "token = random.randint(1000, 9999)") is True
    assert _verdict("Weak Randomness", "x = Math.random()") is not True
    # 用安全随机则不确认
    assert _verdict("Weak Randomness", "token = secrets.token_hex(16)") is not True


def test_injection_types_beyond_sql_command_are_now_verifiable():
    """XSS/SSTI/反序列化/SSRF/代码注入等：清晰 source→sink+无净化 -> 确认。"""
    assert _verdict("XSS", 'return "<div>" + request.args.get("n") + "</div>"') is True
    assert _verdict("SSTI", 'return render_template_string(request.args.get("t"))') is True
    assert _verdict("Insecure Deserialization", "obj = pickle.loads(request.data)") is True
    assert _verdict("SSRF", 'r = requests.get(request.args.get("url"))') is True
    assert _verdict("Code Injection", 'eval(request.args.get("expr"))') is True


def test_sanitized_or_sourceless_injection_stays_uncertain_not_false_confirm():
    """已净化 / 无可控源 -> 不得误判为确认（保持诚实，交人工或判 FP）。"""
    # 已净化的 XSS（且有 source）-> 不确认
    assert _verdict("XSS", 'return escape("<div>" + request.args.get("n"))') is not True
    # 反序列化但无用户输入源 -> 不确认（可能是内部可信数据）
    assert _verdict("Insecure Deserialization", "obj = pickle.loads(open('cache.bin','rb').read())") is not True
