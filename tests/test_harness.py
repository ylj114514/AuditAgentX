"""Fuzzing Harness 动态验证测试（DeepAudit 式，离线不依赖 LLM）。"""
import shutil

import pytest
from pathlib import Path

from backend.skills.harness_tools import (
    run_harness, build_template_harness, extract_function,
    normalize_language, TRIGGER_MARKER,
)
from backend.verifier.harness_verifier import HarnessVerifier
from backend.mcp.audit_mcp_server import AuditMCPServer

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_run_harness_detects_trigger():
    harness = (
        'executed=[]\n'
        'import os\n'
        'os.system=lambda c:(executed.append(c),0)[1]\n'
        'os.system("ping ; id")\n'
        'if any(";" in c for c in executed):\n'
        f'    print("{TRIGGER_MARKER}","cmdi")\n'
    )
    r = run_harness(harness, source="template")  # 可信模板，允许本地执行
    assert r["executed"] is True
    assert r["triggered"] is True


def test_template_harness_triggers_each_type():
    """模板 Harness 触发时 verdict 应为 mechanism_confirmed（机理级），不是 target_confirmed。"""
    for vt in ["Command Injection", "SQL Injection", "Path Traversal", "Insecure Deserialization"]:
        harness = build_template_harness(vt)
        r = run_harness(harness, source="template")
        assert r["triggered"] is True, f"{vt} 模板 harness 未触发"
        assert r["verdict"] == "mechanism_confirmed", f"{vt} 应为 mechanism_confirmed"
        assert r["verification_level"] == "template_mechanism"


def test_expanded_template_harness_types_trigger():
    """扩类后的模板 Harness：代码注入 / SSTI / XPath / LDAP 都应能触发（机理级）。"""
    for vt in ["Code Injection", "SSTI", "Server-Side Template Injection",
               "XPath Injection", "LDAP Injection"]:
        harness = build_template_harness(vt)
        r = run_harness(harness, source="template")
        assert r["triggered"] is True, f"{vt} 模板 harness 未触发"
        assert r["verdict"] == "mechanism_confirmed"


def test_expanded_types_not_generic_fallback():
    """新类型应命中专用模板，而非弱的通用 sink 检测兜底。"""
    # 通用兜底里不会出现这些专用 mock 关键字
    assert "fake_eval" in build_template_harness("Code Injection")
    assert "fake_render" in build_template_harness("SSTI")
    assert "fake_xpath" in build_template_harness("XPath Injection")
    assert "fake_search" in build_template_harness("LDAP Injection")


def test_normalize_language():
    assert normalize_language("py") == "python"
    assert normalize_language(".php") == "python"  # 带点后缀不匹配 -> 默认 python
    assert normalize_language("php") == "php"
    assert normalize_language("js") == "javascript"
    assert normalize_language("ts") == "javascript"
    assert normalize_language(None) == "python"
    assert normalize_language("rust") == "python"  # 未知回退


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
def test_run_harness_javascript_triggers():
    """多语言执行：JavaScript Harness 能被 node 真实运行并识别触发标记。"""
    js = (
        "const executed = [];\n"
        "function target(inp){ executed.push('ping ' + inp); }  // mock sink\n"
        "['127.0.0.1','; id','| whoami'].forEach(p => target(p));\n"
        "if (executed.some(c => c.includes(';') || c.includes('|'))) {\n"
        "  console.log('AUDITAGENTX_VULN_TRIGGERED', 'cmdi(js)');\n"
        "} else { console.log('AUDITAGENTX_NO_TRIGGER'); }\n"
    )
    r = run_harness(js, language="javascript", source="template")
    assert r["language"] == "javascript"
    assert r["backend"] == "local"
    assert r["triggered"] is True


def test_run_harness_missing_interpreter_is_honest(monkeypatch):
    """解释器未安装时如实返回 interpreter_unavailable，不造假触发。"""
    monkeypatch.setattr("backend.skills.harness_tools.shutil.which", lambda name: None)
    r = run_harness("<?php echo 'x'; ?>", language="php", source="template")
    assert r["triggered"] is False
    assert r["executed"] is False
    assert "interpreter_unavailable" in r["reason"]


def test_llm_harness_requires_docker_no_local_exec(monkeypatch):
    """LLM 生成的 Harness 在 Docker 不可用且 require_docker=True 时不本地执行 -> sandbox_failed。"""
    # 强制 Docker 不可用（无论本机是否装了 Docker）
    def _no_docker(*a, **k):
        raise RuntimeError("docker unavailable (mocked)")
    monkeypatch.setattr("backend.verifier.app_runner.get_docker_client", _no_docker)
    r = run_harness('print("AUDITAGENTX_VULN_TRIGGERED")', source="llm", require_docker=True)
    assert r["verdict"] == "sandbox_failed"
    assert r["backend"] == "none"
    assert r["triggered"] is False


def test_unsafe_llm_harness_blocked():
    """LLM Harness 含真实 os.system / requests / subprocess 时应被 unsafe_harness_blocked。"""
    for bad in [
        "import os\nos.system('rm -rf /')",              # 未 mock 的真实 os.system
        "import requests\nrequests.get('http://x')",     # 真实网络
        "import socket\nsocket.socket()",                # 真实 socket
    ]:
        r = run_harness(bad, source="llm", require_docker=False)
        assert r["verdict"] == "unsafe_harness_blocked", bad
        assert r["safety"]["allowed"] is False


def test_unrecognized_template_harness_is_blocked():
    r = AuditMCPServer().call_tool("run_fuzzing_harness", {
        "harness_code": 'print("AUDITAGENTX_VULN_TRIGGERED")',
        "source": "template",
    })["structuredContent"]
    assert r["verdict"] == "unsafe_harness_blocked"
    assert r["safety"]["allowed"] is False


def test_llm_self_report_cannot_be_target_confirmed():
    """LLM 自报 target_function_called 不是后端证明，最多只能算机理级证据。"""
    code = (
        "calls=[]\n"
        "def os_system(c): calls.append(c)  # mock sink\n"
        "def target(x): os_system('ping '+x)  # 真实目标函数\n"
        "target('; id')\n"
        "import json\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({"
        "'triggered':True,'target_function_called':True,'sink_called':True,"
        "'sink_name':'os.system','captured_argument':calls[-1],'payload':'; id'}))\n"
    )
    r = run_harness(code, source="llm", require_docker=False)
    assert r["verdict"] == "mechanism_confirmed"
    assert r["verification_level"] == "unattested_generated"
    # 关键：框架不采信脚本自报的 target_function_called；非 scaffold 来源无框架 nonce 证明 -> False
    assert r["target_function_called"] is False
    assert r["sink_name"] == "os.system"


def test_untrusted_scaffold_source_is_downgraded():
    code = (
        "import json\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({"
        "'triggered':True,'target_function_called':True,'sink_called':True}))\n"
    )
    r = run_harness(code, source="scaffold", require_docker=False)
    assert r["verdict"] == "mechanism_confirmed"
    assert r["verification_level"] == "unattested_generated"


def test_authenticated_scaffold_cannot_fake_invocation_without_nonce(monkeypatch):
    """核心防线：即便持有效 scaffold 令牌，脚本自报 target_function_called 也无法伪造真实调用。

    只有框架每次运行注入、脚本无从得知的随机 nonce 被真实打印出来，才算目标函数被调用。
    这里的脚本不含框架 nonce，故断言在【框架独立观测事实】上：target_function_called=False，
    verification_level 不是 target_specific，至多 mechanism_confirmed。
    """
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability
    # scaffold 现在必须 Docker；用受控本地执行器模拟沙箱，避免依赖 CI 有 Docker
    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda code, timeout, language, code_root=None: harness_tools._run_local(code, timeout, language, "template"))
    fake = (
        "import json\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({"
        "'triggered':True,'target_function_called':True,'sink_called':True,"
        "'sink_name':'os.system','payload':'; id'}))\n"
        "print('AUDITAGENTX_VULN_TRIGGERED fake')\n"
    )
    r = run_harness(fake, source="scaffold", scaffold_token=scaffold_capability())
    assert r["target_function_called"] is False        # 框架 nonce 未出现，不认定真实调用
    assert r["verification_level"] != "target_specific"
    assert r["verdict"] == "mechanism_confirmed"


def test_extract_function_ast_metadata():
    """Python AST 提取应返回 function_name / module_path / imports。"""
    f = extract_function(DEMO, "app.py", 21)
    assert f["found"] is True
    assert f["function_name"] == "get_user"
    assert f["module_path"] == "app"
    assert isinstance(f["imports"], list) and len(f["imports"]) >= 1
    assert f["language"] == "python"


def test_extract_function_from_demo():
    f = extract_function(DEMO, "app.py", 21)
    assert f["found"] is True
    assert "def " in f["function_code"]


def test_extract_javascript_function_requires_real_enclosing_boundary(tmp_path):
    """JS 无函数边界时不能把附近代码伪装成可执行的目标函数。"""
    (tmp_path / "handler.js").write_text(
        "const outside = 1;\n"
        "function handle(input) {\n"
        "  return exec('echo ' + input);\n"
        "}\n"
        "const after = 2;\n",
        encoding="utf-8",
    )
    inside = extract_function(tmp_path, "handler.js", 3)
    outside = extract_function(tmp_path, "handler.js", 5)

    assert inside["found"] is True
    assert inside["function_name"] == "handle"
    assert inside["extraction_method"] == "regex_brace_limited"
    assert outside["found"] is False
    assert outside["reason"] == "no_enclosing_recognized_function_at_line"


def test_mcp_harness_tools_end_to_end():
    srv = AuditMCPServer()
    names = {t["name"] for t in srv.list_tools()}
    assert {"extract_target_function", "generate_fuzzing_harness", "run_fuzzing_harness",
            "run_harness_code"} <= names
    h = srv.call_tool("generate_fuzzing_harness", {"vuln_type": "Command Injection"})["structuredContent"]
    r = srv.call_tool("run_fuzzing_harness",
                      {"harness_code": h["harness_code"], "source": "template"})["structuredContent"]
    assert r["triggered"] is True
    assert r["verdict"] == "mechanism_confirmed"


def test_generic_harness_code_tool_is_structured_and_template_guarded():
    """新通用工具复用同一安全边界，不能靠改工具名绕过模板信任校验。"""
    result = AuditMCPServer().call_tool("run_harness_code", {
        "code": 'print("AUDITAGENTX_VULN_TRIGGERED")',
        "source": "template",
    })["structuredContent"]
    assert result["verdict"] == "unsafe_harness_blocked"


def test_harness_verifier_template_fallback(monkeypatch):
    # 强制 LLM 返回空 -> 走模板兜底：只证明漏洞机理，判 mechanism_confirmed（不是真实可利用）
    monkeypatch.setattr(HarnessVerifier, "_call", lambda self, content: {})
    hv = HarnessVerifier()
    finding = {"type": "Command Injection", "file": "app.py", "line": 38,
               "start_line": 38, "status": "confirmed", "code_snippet": "os.system(...)"}
    result = hv.run(finding, DEMO, max_retries=1)
    assert result["verdict"] == "mechanism_confirmed"
    assert result["harness_source"] == "template"
    # 模板机理 != 完全动态确认
    assert result["dynamically_triggered"] is False
    assert result["function_mechanism_verified"] is True
    assert result["confidence"] <= 0.75


def test_harness_scaffold_is_function_unit_reproduced(monkeypatch, tmp_path):
    """真实函数被强制调用只能证明函数单元复现，不能冒充入口级动态确认。"""
    from backend.config import settings
    (tmp_path / "svc.py").write_text(
        "def run_query(x, cur):\n"
        "    return cur.execute('SELECT * FROM u WHERE id=' + x)\n", encoding="utf-8")
    # LLM 返回空 -> 走脚手架层；测试用受控执行器模拟 Docker，不允许真实回退宿主机。
    monkeypatch.setattr(HarnessVerifier, "_call", lambda self, c: {})
    from backend.skills import harness_tools
    monkeypatch.setattr(harness_tools, "_run_in_docker", lambda code, timeout, language, code_root=None: harness_tools._run_local(
        code, timeout, language, "template"))
    finding = {"type": "SQL Injection", "file": "svc.py", "line": 2, "start_line": 2,
               "status": "confirmed", "code_snippet": "cur.execute(...)"}
    r = HarnessVerifier().run(finding, tmp_path, max_retries=0)
    assert r["harness_source"] == "scaffold"
    assert r["verdict"] == "function_reproduced"
    assert r["verification_level"] == "target_specific"
    assert r["target_function_called"] is True
    assert r["entrypoint_reachable"] is False
    assert r["dynamically_triggered"] is False
    assert r["function_mechanism_verified"] is True
    assert r["confidence"] <= 0.85


def test_scaffold_none_when_no_param_to_sink():
    """无法用 AST 定位「参数→sink」时，脚手架返回 None（交由类型模板兜底）。"""
    from backend.skills.harness_tools import build_target_scaffold_harness
    # 函数体内读局部 source（无参数流向 sink）-> 脚手架不构造
    func = {"function_name": "ping", "language": "python", "function_code":
            "def ping():\n    import os\n    host = request.args.get('h')\n    os.system('ping '+host)\n"}
    assert build_target_scaffold_harness(func, "Command Injection") is None


def test_harness_verifier_not_applicable_for_static_type():
    """硬编码密钥等静态类漏洞不适合函数级 Harness -> not_applicable，不执行。"""
    hv = HarnessVerifier()
    finding = {"type": "Hardcoded Secret", "file": "app.py", "line": 16,
               "start_line": 16, "status": "confirmed", "code_snippet": "API_KEY='sk-...'"}
    result = hv.run(finding, DEMO, max_retries=1)
    assert result["verdict"] == "not_applicable"
    assert result["dynamically_triggered"] is False


def _docker_ok() -> bool:
    try:
        from backend.verifier.app_runner import get_docker_client
        return bool(get_docker_client().ping())
    except Exception:  # noqa: BLE001
        return False


def test_import_scaffold_builds_and_imports_before_patching():
    """import 真实模块脚手架（DeepAudit 式）：模块级命令注入函数应生成脚手架，
    且必须【先 import 再打桩 sink】——Python import 机制依赖真实 exec，
    先打桩 builtins.exec 会导致模块体不执行、函数导不出来。"""
    from backend.skills.harness_tools import build_import_scaffold_harness, NONCE_PLACEHOLDER
    func = {"found": True, "language": "python", "class_name": None,
            "module_path": "vulnmod", "function_name": "run_ping",
            "function_code": "def run_ping(host):\n    return os.system('ping ' + host)\n"}
    code = build_import_scaffold_harness(func, "Command Injection")
    assert code is not None
    assert "from vulnmod import run_ping" in code
    assert NONCE_PLACEHOLDER in code                 # 框架 nonce 插桩（脚本无法伪造）
    assert "__subclasses__" not in code              # 不含会被安全校验硬拦的 token
    # 关键顺序：import 必须早于 sink 打桩
    assert code.index("from vulnmod import") < code.index("os.system = _record")


def test_import_scaffold_none_for_method_and_object_sink():
    """类方法（需实例化）与对象方法 sink（如 cursor.execute）无法全局打桩 -> None 回退内联。"""
    from backend.skills.harness_tools import build_import_scaffold_harness
    method = {"found": True, "language": "python", "class_name": "Svc",
              "module_path": "svc", "function_name": "run",
              "function_code": "def run(self, x):\n    return os.system('ping ' + x)\n"}
    assert build_import_scaffold_harness(method, "Command Injection") is None
    obj_sink = {"found": True, "language": "python", "class_name": None,
                "module_path": "db", "function_name": "q",
                "function_code": "def q(x, cur):\n    return cur.execute('SELECT ' + x)\n"}
    assert build_import_scaffold_harness(obj_sink, "SQL Injection") is None


def test_route_testclient_harness_none_for_non_route_function():
    """非路由函数（不读 request）不生成 test-client harness -> None 回退。"""
    from backend.skills.harness_tools import build_route_testclient_harness
    func = {"found": True, "language": "python", "class_name": None,
            "module_path": "util", "function_name": "run_cmd",
            "function_code": "def run_cmd(host):\n    return os.system('ping ' + host)\n"}
    assert build_route_testclient_harness(func, "Command Injection") is None


@pytest.mark.skipif(not _docker_ok(), reason="Docker 引擎不可用，跳过真实沙箱集成测试")
def test_route_testclient_harness_reaches_entrypoint_confirmed(tmp_path):
    """DeepAudit 式端到端：框架 test-client 进程内调真实 Flask 路由 handler，
    真命令注入 sink 被真实用户输入触发，nonce 证明真实路由被调用 ->
    entrypoint_reproduced（可达性成立）-> finding 级 target_confirmed。

    需固定沙箱镜像 auditagentx-harness-python（含 flask）。缺镜像时优雅跳过。"""
    from backend.skills.harness_tools import is_target_harness_confirmed
    from backend.config import settings
    if not settings.harness_sandbox_image:
        pytest.skip("未配置 harness_sandbox_image（固定沙箱镜像），跳过 test-client 集成")
    (tmp_path / "vulnapp.py").write_text(
        "from flask import Flask, request\n"
        "import subprocess\n"
        "app = Flask(__name__)\n"
        "@app.route('/lookup')\n"
        "def lookup():\n"
        "    domain = request.args.get('domain', 'x')\n"
        "    return subprocess.run('nslookup ' + domain, shell=True, capture_output=True, text=True).stdout\n",
        encoding="utf-8")
    finding = {"type": "Command Injection", "file": "vulnapp.py", "line": 7, "start_line": 7,
               "status": "confirmed", "code_snippet": "subprocess.run('nslookup ' + domain, shell=True)"}
    r = HarnessVerifier(scan_id="t").run(finding, tmp_path, max_retries=0)
    assert r["harness_source"] == "scaffold"
    assert r["target_function_called"] is True       # 框架 nonce 证明真实路由被调用
    assert r["entrypoint_reachable"] is True          # 经真实路由 dispatch 可达
    assert r["verification_level"] == "entrypoint_reproduced"
    assert r["verdict"] == "target_confirmed"
    assert is_target_harness_confirmed(r) is True     # 唯一 canonical 判据认可


@pytest.mark.skipif(not _docker_ok(), reason="Docker 引擎不可用，跳过真实沙箱集成测试")
def test_import_scaffold_runs_real_module_end_to_end(tmp_path):
    """DeepAudit 式端到端：挂载真实源码、import 真实模块跑真实代码（含模块级依赖
    HELPER_PREFIX——内联 scaffold 会因缺它失败），框架 nonce 证明真实函数被真正调用。"""
    (tmp_path / "vulnmod.py").write_text(
        "import os\nHELPER_PREFIX = 'ping -c 1 '\n"
        "def run_ping(host):\n    return os.system(HELPER_PREFIX + host)\n", encoding="utf-8")
    finding = {"type": "Command Injection", "file": "vulnmod.py", "line": 4, "start_line": 4,
               "status": "confirmed", "code_snippet": "os.system(HELPER_PREFIX + host)"}
    r = HarnessVerifier(scan_id="t").run(finding, tmp_path, max_retries=0)
    assert r["harness_source"] == "scaffold"
    assert r["verification_level"] == "target_specific"
    assert r["target_function_called"] is True       # 框架 nonce 证明真实函数被真正调用
    assert r["verdict"] == "function_reproduced"
