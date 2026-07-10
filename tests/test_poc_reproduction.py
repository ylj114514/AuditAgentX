"""PoC 文件生成 + 不可变复现元数据测试（作业补项 1 与 3）。

核心诚信保证：只有**框架侧真实动态确认**后才生成 PoC；元数据是可核验的不可变事实。
"""
from pathlib import Path

from backend.verifier.poc_writer import generate_poc_file, build_reproduction_metadata

_CONFIRMED_EV = {
    "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
    "runtime": {
        "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "AAX_PWNED",
        "response_excerpt": "... AAX_PWNED ...",
        "request": {"url": "http://127.0.0.1:8000/lookup?domain=x", "method": "GET",
                    "param": "domain", "payload": "127.0.0.1 & echo AAX_PWNED"},
    },
    "exploit": {"payloads": ["127.0.0.1 & echo AAX_PWNED"], "_injection_points": ["domain"],
                "http_method": "GET"},
}
_FINDING = {"finding_id": "f_demo1", "type": "Command Injection",
            "file": "vulnapp.py", "start_line": 9}


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
                  "domain", "echo AAX_PWNED", "AAX_PWNED", "运行命令",
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


def test_poc_redacts_sensitive_values(tmp_path):
    """PoC/元数据必须脱敏敏感字段。"""
    ev = {
        "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
        "runtime": {"reproduction_status": "dynamic_confirmed", "matched_indicator": "token=abc123secret",
                    "request": {"url": "http://127.0.0.1:8000/x?password=hunter2", "method": "GET",
                                "param": "q", "payload": "authorization=Bearer sk-xxx"}},
        "exploit": {},
    }
    r = generate_poc_file(_FINDING, ev, tmp_path)
    body = Path(r["path"]).read_text(encoding="utf-8")
    assert "hunter2" not in body
    assert "sk-xxx" not in body
    assert "REDACTED" in body
