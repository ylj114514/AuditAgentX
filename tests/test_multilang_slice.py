"""多语言自包含切片 Harness（PHP / JavaScript）单元测试。

- 结构性断言（不依赖运行时）：始终执行。
- 运行时断言：本地有 node 才跑 JS；docker 可用才跑 PHP。缺失则 skip，保证 CI 稳定。
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from backend.skills.harness_tools import (
    build_selfcontained_slice_harness_js,
    build_selfcontained_slice_harness_php,
    build_selfcontained_slice_harness_multilang,
    NONCE_PLACEHOLDER,
    TARGET_INVOKED_MARKER,
)


def _js_func(name, code):
    return {"language": "javascript", "function_name": name, "found": True, "function_code": code}


def _php_func(name, code):
    return {"language": "php", "function_name": name, "found": True, "function_code": code}


# --------------------------- 结构性断言 ---------------------------

def test_php_builder_returns_none_for_method():
    """class 方法（需真实对象）不构建过程式切片。"""
    f = _php_func("q", "function q($x){ return mysqli_query($c, $x); }")
    f["class_name"] = "UserDao"
    assert build_selfcontained_slice_harness_php(f, "sqli") is None


def test_php_builder_returns_none_without_interceptable_sink():
    f = _php_func("noop", "function noop($x){ return strtoupper($x); }")
    assert build_selfcontained_slice_harness_php(f, "sqli") is None


def test_php_builder_emits_nonce_and_function():
    code = "function do_ping($t){ return shell_exec('ping '.$t); }"
    h = build_selfcontained_slice_harness_php(_php_func("do_ping", code), "command injection")
    assert h is not None
    assert NONCE_PLACEHOLDER in h            # run_harness 会注入随机 nonce
    assert "namespace AAX;" in h             # 命名空间遮蔽
    assert "function shell_exec" in h        # sink 被遮蔽
    assert "do_ping" in h                    # 内联真实函数


def test_js_builder_emits_nonce_and_function():
    code = "function ping(req){ require('child_process').exec('ping ' + req.query.host); }"
    h = build_selfcontained_slice_harness_js(_js_func("ping", code), "command injection")
    assert h is not None
    assert NONCE_PLACEHOLDER in h
    assert "ping" in h
    assert "_SINKS" in h


def test_multilang_dispatch_by_language():
    php = build_selfcontained_slice_harness_multilang(
        _php_func("do_ping", "function do_ping($t){ return shell_exec('ping '.$t); }"), "command injection")
    assert php and php[1] == "php"
    js = build_selfcontained_slice_harness_multilang(
        _js_func("ping", "function ping(req){ require('child_process').exec('x'+req.query.h); }"), "command injection")
    assert js and js[1] == "javascript"
    # 编译型语言不适用切片
    java = build_selfcontained_slice_harness_multilang(
        {"language": "java", "function_name": "f", "found": True, "function_code": "void f(){}"}, "sqli")
    assert java is None


# --------------------------- 运行时断言（JS，本地 node）---------------------------

def _run_js(func):
    import secrets
    h = build_selfcontained_slice_harness_js(func, "x")
    nonce = secrets.token_hex(16)
    code = h.replace(NONCE_PLACEHOLDER, nonce)
    p = subprocess.run(["node", "-e", code], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=25)
    out = (p.stdout or "") + (p.stderr or "")
    return {
        "nonce": (TARGET_INVOKED_MARKER + nonce) in out,
        "triggered": "AUDITAGENTX_VULN_TRIGGERED" in out,
    }


@pytest.mark.skipif(not shutil.which("node"), reason="node 未安装")
def test_js_command_injection_triggers():
    r = _run_js(_js_func("ping", """function ping(req, res) {
  const cp = require('child_process');
  cp.exec('ping -c 1 ' + req.query.host, function(e,o){ res.send(o); });
}"""))
    assert r["nonce"] and r["triggered"]


@pytest.mark.skipif(not shutil.which("node"), reason="node 未安装")
def test_js_parameterized_query_not_triggered():
    """参数化查询（值放绑定参数数组）是安全的，不应误报。"""
    r = _run_js(_js_func("safeUser", """function safeUser(req, res) {
  const conn = require('mysql').createConnection({});
  conn.query('SELECT * FROM users WHERE id = ?', [req.query.id], function(e,r){ res.json(r); });
}"""))
    assert r["nonce"] and not r["triggered"]
