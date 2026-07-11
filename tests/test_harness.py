"""Fuzzing Harness 动态验证测试（DeepAudit 式，离线不依赖 LLM）。"""
import shutil

import pytest
from pathlib import Path

from backend.skills.harness_tools import (
    run_harness, build_template_harness, extract_function,
    normalize_language, TRIGGER_MARKER, build_django_classview_harness,
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
    # 目标函数不可抽取且 LLM 返回空 -> 走模板兜底：只证明漏洞机理，不能是真实可利用。
    # 固定 Harness 镜像存在时，可抽取目标会优先走确定性 scaffold，因此这里显式模拟
    # “无可抽取函数”这一回退边界。
    monkeypatch.setattr(HarnessVerifier, "_call", lambda self, content: {})
    monkeypatch.setattr(HarnessVerifier, "_mcp_extract", lambda self, finding, code_root: {
        "found": False, "language": "python", "reason": "test_no_extract",
    })
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


def test_route_failure_automatically_falls_back_to_selfcontained_slice(monkeypatch, tmp_path):
    """route/import 未证明调用时不能停在 not_reproduced：下一 attempt 必须改跑
    不导入 app 的切片。该测试故意让首次切片不可用，以覆盖历史 route-first 场景。"""
    from backend.verifier import harness_verifier as verifier_module

    (tmp_path / "app.py").write_text(
        "def probe():\n"
        "    return os.system('ping ' + request.args.get('host'))\n",
        encoding="utf-8",
    )
    real_slice = verifier_module.build_selfcontained_slice_harness
    slice_attempts = []

    def delayed_slice(func, vuln_type):
        slice_attempts.append(func["function_name"])
        return None if len(slice_attempts) == 1 else real_slice(func, vuln_type)

    monkeypatch.setattr(verifier_module, "build_selfcontained_slice_harness", delayed_slice)
    monkeypatch.setattr(verifier_module, "build_route_testclient_harness", lambda func, vt: "route-placeholder")

    executed_kinds = []
    def fake_mcp_run(self, code, language, source, code_root=None, harness_kind=None):
        executed_kinds.append(harness_kind)
        if harness_kind == "testclient_route":
            return {"verdict": "not_reproduced", "triggered": False,
                    "target_function_called": False, "import_error": "ModuleNotFoundError: flask",
                    "verification_level": "none", "backend": "docker"}
        assert harness_kind == "selfcontained_slice"
        return {"verdict": "target_confirmed", "triggered": True,
                "target_function_called": True, "verification_level": "target_specific",
                "backend": "docker", "sink_name": "os.system", "captured_argument": "AAXSLICE"}

    monkeypatch.setattr(HarnessVerifier, "_mcp_run", fake_mcp_run)
    result = HarnessVerifier().run(
        {"type": "Command Injection", "file": "app.py", "start_line": 2, "line": 2},
        tmp_path, max_retries=1,
    )
    assert executed_kinds == ["testclient_route", "selfcontained_slice"]
    assert len(result["attempts"]) == 2
    assert result["attempts"][0]["verdict"] == "not_reproduced"
    assert result["verdict"] == "function_reproduced"


def test_selfcontained_slice_covers_direct_injection_without_deps():
    """自包含切片主力：inline 真实函数体 + mock 一切外部依赖 + 桩危险 sink，
    直接型注入（命令/SSTI/代码）无需 import/装依赖/起服务即可复现。本地安全执行（sink 全 mock）。"""
    import io, contextlib, secrets as _s
    from backend.skills.harness_tools import build_selfcontained_slice_harness

    def _triggers(code, fn, vt):
        h = build_selfcontained_slice_harness(
            {"language": "python", "function_name": fn, "function_code": code}, vt)
        assert h is not None, f"{vt} 应生成切片 harness"
        hh = h.replace("__AUDITAGENTX_NONCE__", _s.token_hex(8))
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exec(hh, {})
        except SystemExit:
            pass
        return "AUDITAGENTX_VULN_TRIGGERED" in buf.getvalue()

    assert _triggers('def v():\n return render_template_string("Hi "+request.args.get("n"))\n', "v", "SSTI")
    assert _triggers('def p():\n h=request.args.get("host")\n return subprocess.run("ping "+h, shell=True)\n', "p", "Command Injection")
    assert _triggers('def c():\n return eval(request.args.get("e"))\n', "c", "Code Injection")
    # 无危险 sink -> 不生成切片（交别的路径）
    assert build_selfcontained_slice_harness(
        {"language": "python", "function_name": "f", "function_code": "def f():\n return 1+1\n"},
        "Unknown") is None


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


def test_django_classview_scaffold_keeps_real_validator_and_is_function_level():
    """Django 类视图路径穿越不能退回 LLM 网络脚本；必须保留真实 validator。"""
    func = {
        "found": True, "language": "python", "class_name": "DownloadReportView",
        "function_name": "get",
        "function_code": (
            "    def get(self, request, format=None):\n"
            "        name = request.query_params.get('filename')\n"
            "        if not validate_filename(name): return Response({}, status=400)\n"
            "        path = os.path.abspath(os.path.join(settings.BASE_DIR, 'reports', unquote(name)))\n"
            "        if os.path.exists(path) and os.path.isfile(path): return FileResponse(open(path, 'rb'))\n"
        ),
        "helper_functions": [{
            "name": "validate_filename",
            "code": "def validate_filename(value):\n    return bool(re.fullmatch(r'(?:[A-Za-z0-9]|%[0-9A-Fa-f]{2})*', value))\n",
        }],
    }
    code = build_django_classview_harness(func, "Path Traversal")
    assert code is not None
    assert "def validate_filename" in code
    assert "request.query_params.get" in code
    assert "AUDITAGENTX_TARGET_INVOKED=" in code


@pytest.mark.skipif(not _docker_ok(), reason="Docker 引擎不可用，跳过真实沙箱集成测试")
def test_selfcontained_slice_reproduces_real_exception_gated_ssti():
    """真实 Vulnerable-Flask-App：SQL 执行异常回显进入 except 中的
    render_template_string。DB 替身仅在 marker 到 execute 时抛异常；最终确认仍
    必须是 marker 到达真实函数里的模板 sink，且 nonce 由框架侧独立观察。"""
    from backend.config import settings
    from backend.skills.harness_tools import (
        build_selfcontained_slice_harness, scaffold_capability,
    )

    if settings.harness_sandbox_image != "auditagentx-harness-python:latest":
        pytest.skip("本回归必须使用固定 auditagentx-harness-python:latest 镜像")
    project_root = Path(__file__).resolve().parent.parent / "data" / "projects" / "proj_9708a316"
    func = extract_function(project_root, "app/app.py", 281)
    assert func["found"] is True
    assert func["function_name"] == "search_customer"
    harness = build_selfcontained_slice_harness(func, "SSTI")
    assert harness is not None

    execution = run_harness(
        harness, source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(project_root), harness_kind="selfcontained_slice",
    )
    assert execution["backend"] == "docker"
    assert execution["target_function_called"] is True  # 随机 nonce，不接受脚本自报
    assert execution["triggered"] is True
    assert execution["sink_name"] == "render_template_string"
    assert execution["verification_level"] == "target_specific"
    assert execution["verdict"] == "target_confirmed"  # 执行级：真实函数切片已复现

    # finding 级不能越权宣称真实 HTTP 入口：切片只能升级到 function_reproduced。
    result = HarnessVerifier().run(
        {"type": "SSTI", "file": "app/app.py", "start_line": 281, "line": 281},
        project_root, max_retries=0,
    )
    assert result["harness_kind"] == "selfcontained_slice"
    assert result["target_function_called"] is True
    assert result["verdict"] == "function_reproduced"
    assert result["dynamically_triggered"] is False


@pytest.mark.skipif(not _docker_ok(), reason="Docker 引擎不可用，跳过真实沙箱集成测试")
def test_selfcontained_slice_reproduces_object_method_sqli(tmp_path):
    """对象方法 SQLi 不依赖真实 DB：真实函数切片中的 db.session.execute 收到
    框架 marker 后由受控替身记录。异常本身不是证据，execute 参数中的 marker 才是。"""
    from backend.config import settings
    from backend.skills.harness_tools import (
        build_selfcontained_slice_harness, scaffold_capability,
    )

    if settings.harness_sandbox_image != "auditagentx-harness-python:latest":
        pytest.skip("本回归必须使用固定 auditagentx-harness-python:latest 镜像")
    (tmp_path / "db_api.py").write_text(
        "def search_orders():\n"
        "    term = request.args.get('term')\n"
        "    statement = \"SELECT * FROM orders WHERE owner='\" + term + \"'\"\n"
        "    return db.session.execute(statement)\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "db_api.py", 4)
    harness = build_selfcontained_slice_harness(func, "SQL Injection")
    assert harness is not None
    assert "'sqli'" in harness
    assert "_DANGER_METHODS" in harness
    execution = run_harness(
        harness, source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="selfcontained_slice",
    )
    assert execution["backend"] == "docker"
    assert execution["target_function_called"] is True
    assert execution["triggered"] is True
    assert execution["sink_called"] is True
    assert execution["sink_name"] == "execute"
    assert execution["verdict"] == "target_confirmed"


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
    # 直接测 route 构建器的入口级能力（不经 _generate 优先级——主力已改为自包含切片）。
    from backend.skills.harness_tools import (
        extract_function, build_route_testclient_harness, run_harness, scaffold_capability)
    func = extract_function(str(tmp_path), "vulnapp.py", 7)
    h = build_route_testclient_harness(func, "Command Injection")
    assert h is not None
    r = run_harness(h, source="scaffold", scaffold_token=scaffold_capability(),
                    code_root=str(tmp_path), harness_kind="testclient_route")
    assert r["target_function_called"] is True        # 框架 nonce 证明真实路由被调用
    assert r["entrypoint_reachable"] is True           # 经真实路由 dispatch 可达
    assert r["verification_level"] == "entrypoint_reproduced"
    assert r["verdict"] == "target_confirmed"


@pytest.mark.skipif(not _docker_ok(), reason="Docker 引擎不可用，跳过真实沙箱集成测试")
def test_import_scaffold_runs_real_module_end_to_end(tmp_path):
    """DeepAudit 式端到端：挂载真实源码、import 真实模块跑真实代码（含模块级依赖
    HELPER_PREFIX——内联 scaffold 会因缺它失败），框架 nonce 证明真实函数被真正调用。"""
    (tmp_path / "vulnmod.py").write_text(
        "import os\nHELPER_PREFIX = 'ping -c 1 '\n"
        "def run_ping(host):\n    return os.system(HELPER_PREFIX + host)\n", encoding="utf-8")
    # 直接测 import 构建器（能解析模块级 HELPER_PREFIX，内联/切片会因缺它失败）。
    from backend.skills.harness_tools import (
        extract_function, build_import_scaffold_harness, run_harness, scaffold_capability)
    func = extract_function(str(tmp_path), "vulnmod.py", 4)
    h = build_import_scaffold_harness(func, "Command Injection")
    assert h is not None
    r = run_harness(h, source="scaffold", scaffold_token=scaffold_capability(),
                    code_root=str(tmp_path), harness_kind="import_module")
    assert r["target_function_called"] is True        # 框架 nonce 证明真实函数被真正调用
    assert r["verification_level"] == "target_specific"
    assert r["verdict"] == "target_confirmed"          # 执行级（函数被触发）
