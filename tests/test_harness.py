"""Fuzzing Harness 动态验证测试（DeepAudit 式，离线不依赖 LLM）。"""
import shutil

import pytest
from pathlib import Path

from backend.skills.harness_tools import (
    run_harness, build_template_harness, extract_function,
    normalize_language, TRIGGER_MARKER, build_django_classview_harness,
    build_js_express_open_redirect_entrypoint_harness,
)
from backend.verifier.harness_verifier import HarnessVerifier
from backend.mcp.audit_mcp_server import AuditMCPServer
from backend.dynamic.strategy import is_harness_applicable, resolve_strategy
from tests.adversarial_helpers import synthetic_self_report_harness

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


def test_react_dom_finding_gets_a_trusted_poc_sandbox_source_assertion():
    """React/TSX sink findings must not be thrown away before PoC analysis.

    The assertion is intentionally evidence-level only: it proves that the
    reported real source contains the DOM sink, not that a browser executed a
    payload or that an HTTP endpoint is reachable.
    """
    verifier = object.__new__(HarnessVerifier)
    finding = {
        "type": "react-dangerouslySetInnerHTML",
        "file": "src/Editor.tsx",
        "line": 13,
        "code_snippet": "return <div dangerouslySetInnerHTML={{ __html: content }} />",
    }
    generated = verifier._generate(finding, {"found": False}, "javascript", previous=None)

    assert generated["_source"] == "scaffold"
    assert generated["_kind"] == "source_assertion"
    result = run_harness(generated["harness_code"], source="template")
    assert result["triggered"] is True
    assert result["sink_name"] == "dangerouslySetInnerHTML"
    assert "dangerouslySetInnerHTML" in result["trigger_detail"]


def test_go_harness_uses_restricted_docker_runtime(monkeypatch):
    """Go scaffold 只能在禁网、只读的 golang 容器内编译运行。"""
    from backend.skills.harness_tools import _run_in_docker

    captured = {}

    class FakeContainer:
        removed = False
        wait_timeout = None

        def wait(self, timeout):
            self.wait_timeout = timeout
            return {"StatusCode": 0}

        def logs(self, **_kwargs):
            return b""

        def remove(self, force):
            self.removed = force

    class FakeContainers:
        container = None

        def run(self, **kwargs):
            captured.update(kwargs)
            self.container = FakeContainer()
            return self.container

    class FakeClient:
        def __init__(self):
            self.containers = FakeContainers()

    client = FakeClient()
    monkeypatch.setattr("backend.verifier.app_runner.get_docker_client", lambda: client)
    result = _run_in_docker("package main\nfunc main(){}\n", 3, "go")

    assert result["executed"] is True
    assert captured["image"].startswith("golang:")
    assert captured["network_disabled"] is True
    assert captured["read_only"] is True
    assert captured["tmpfs"] == {"/tmp": "size=32m"}
    assert captured["cap_drop"] == ["ALL"]
    assert captured["security_opt"] == ["no-new-privileges"]
    assert captured["pids_limit"] == 64
    assert captured["mem_limit"] == "512m"
    assert captured["nano_cpus"] == 1_000_000_000
    assert captured["user"] != "0:0"
    assert "environment" not in captured
    assert "volumes" not in captured
    assert "go run /tmp/main.go" in captured["command"][-1]
    assert client.containers.container.wait_timeout == 3
    assert client.containers.container.removed is True


def test_source_mounted_harness_keeps_readonly_container_and_explicit_environment(monkeypatch, tmp_path):
    """真实源码脚手架也只能只读挂载，不能带入宿主环境或 Docker socket。"""
    from backend.config import settings
    from backend.skills.harness_tools import _run_in_docker

    captured = {}

    class FakeContainer:
        def wait(self, timeout):
            return {"StatusCode": 0}

        def logs(self, **_kwargs):
            return b""

        def remove(self, force):
            pass

    class FakeContainers:
        def run(self, **kwargs):
            captured.update(kwargs)
            return FakeContainer()

    class FakeClient:
        containers = FakeContainers()

    monkeypatch.setattr(settings, "harness_install_target_deps", False)
    monkeypatch.setenv("AAX_HOST_ONLY_SECRET", "must-not-reach-container")
    monkeypatch.setattr("backend.verifier.app_runner.get_docker_client", lambda: FakeClient())

    result = _run_in_docker("print('safe')", 3, "python", code_root=str(tmp_path),
                            harness_kind="import_module")

    assert result["executed"] is True
    assert captured["network_disabled"] is True
    assert captured["read_only"] is True
    assert captured["volumes"] == {str(tmp_path.resolve()): {"bind": "/target", "mode": "ro"}}
    assert captured["environment"] == {"PYTHONPATH": "/target", "PYTHONDONTWRITEBYTECODE": "1"}
    assert "AAX_HOST_ONLY_SECRET" not in captured["environment"]
    assert all("docker.sock" not in host_path for host_path in captured["volumes"])


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


def test_run_harness_timeout_is_inconclusive_not_not_reproduced():
    """超时 != 未复现：容器/子进程超时且未见触发，应判 inconclusive，绝不误报 not_reproduced。

    真实短超时触发本地子进程 TimeoutExpired，验证 _run_local 打了 timed_out 标记、
    _finalize 据此判 inconclusive（未复现是已跑完且 sink 没被打到；超时是没跑完，不知道）。
    """
    slow = "import time\nprint('BEFORE', flush=True)\ntime.sleep(10)\n"
    r = run_harness(slow, language="python", source="template", timeout=2)
    assert r["executed"] is True
    assert r["triggered"] is False
    assert r["verdict"] == "inconclusive", f"超时应 inconclusive，实得 {r['verdict']}"
    assert "timeout" in (r["reason"] or "")


def test_finalize_docker_timeout_without_trigger_is_inconclusive():
    """_finalize：Docker 执行超时(timed_out) 且未触发 -> inconclusive（不是 not_reproduced）。"""
    from backend.skills.harness_tools import _finalize
    exec_out = {"executed": True, "stdout": "partial output no marker",
                "stderr": "", "backend": "docker", "reason": "timeout", "timed_out": True}
    res = _finalize(exec_out, "scaffold", "python", "docker", nonce="n" * 32)
    assert res["verdict"] == "inconclusive"
    assert res["triggered"] is False


def test_finalize_docker_image_unavailable_is_inconclusive():
    """_finalize：镜像缺失(executed=False) -> inconclusive 并保留 image_unavailable 原因，
    不冒充引擎离线的 sandbox_failed。"""
    from backend.skills.harness_tools import _finalize
    exec_out = {"executed": False, "backend": "docker",
                "reason": "image_unavailable: foo:latest"}
    res = _finalize(exec_out, "scaffold", "python", "docker", nonce="n" * 32)
    assert res["verdict"] == "inconclusive"
    assert "image_unavailable" in (res["reason"] or "")


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


@pytest.mark.parametrize("language, content_marker", [
    ("python", "# __subclasses__"),
    ("python", "# open('/etc/passwd')"),
    ("python", "# os.system("),
    ("python", "# eval("),
    ("python", "# requests.get("),
    ("python", "# shutil.rmtree("),
    ("javascript", "// child_process"),
    ("javascript", "// require('http')"),
    ("javascript", "// fs.unlinkSync("),
])
def test_deep_docker_harness_allows_content_policy_hits_without_host_fallback(
        monkeypatch, language, content_marker):
    """Deep 的明确授权只让命中内容 denylist 的代码进入受控 Docker。

    标记均在注释中；mock runner 只证明 Docker 路径被选中，测试绝不执行危险代码。
    """
    from backend.skills import harness_tools

    observed = {}

    def docker_only(code, timeout, actual_language, code_root=None, harness_kind=None):
        observed.update({"code": code, "language": actual_language, "timeout": timeout,
                         "code_root": code_root, "harness_kind": harness_kind})
        return {"executed": True, "backend": "docker",
                "stdout": "AUDITAGENTX_VULN_TRIGGERED mock-docker", "stderr": ""}

    monkeypatch.setattr(harness_tools, "_run_in_docker", docker_only)
    monkeypatch.setattr(
        harness_tools, "_run_local",
        lambda *_args, **_kwargs: pytest.fail("unsafe Deep harness must not fall back to the host"),
    )

    verifier = object.__new__(HarnessVerifier)
    verifier.mcp = AuditMCPServer()
    verifier._tool_calls = []
    result = verifier._mcp_run(
        content_marker + "\nprint('safe test marker')\n",
        language=language,
        source="llm",
        require_docker=True,
        allow_unsafe_harness_in_docker=True,
    )

    assert observed["language"] == language
    assert result["backend"] == "docker"
    assert result["executed"] is True
    assert result["safety"]["allowed"] is True
    assert "denylist disabled" in " ".join(result["safety"]["checks"])


def test_deep_unsafe_harness_returns_sandbox_failed_when_docker_is_unavailable(monkeypatch):
    """Deep 授权不是宿主机回退授权：Docker 不可用时必须失败闭合。"""
    from backend.skills import harness_tools

    monkeypatch.setattr(harness_tools, "_run_in_docker", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        harness_tools, "_run_local",
        lambda *_args, **_kwargs: pytest.fail("Docker failure must not execute unsafe content locally"),
    )

    verifier = object.__new__(HarnessVerifier)
    verifier.mcp = AuditMCPServer()
    verifier._tool_calls = []
    result = verifier._mcp_run(
        "# os.system(\nprint('safe test marker')\n",
        source="llm",
        require_docker=True,
        allow_unsafe_harness_in_docker=True,
    )

    assert result["verdict"] == "sandbox_failed"
    assert result["backend"] == "none"
    assert result["triggered"] is False


def test_unsafe_content_remains_blocked_outside_docker(monkeypatch):
    """非 Docker/host 路径无权使用 Deep 的内容策略例外。"""
    from backend.skills import harness_tools

    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda *_args, **_kwargs: pytest.fail("non-Docker unsafe content must be rejected before execution"),
    )
    monkeypatch.setattr(
        harness_tools, "_run_local",
        lambda *_args, **_kwargs: pytest.fail("non-Docker unsafe content must not run locally"),
    )

    result = run_harness(
        "# eval(\nprint('safe test marker')\n",
        source="llm",
        require_docker=False,
    )

    assert result["verdict"] == "unsafe_harness_blocked"
    assert result["safety"]["allowed"] is False


def test_deep_docker_has_no_generated_code_denylist(monkeypatch):
    """Deep Docker 移除所有字符串 denylist；容器限制仍由 Docker runner 强制。"""
    from backend.skills import harness_tools

    observed = {}
    def docker_only(code, *_args, **_kwargs):
        observed["code"] = code
        return {"executed": True, "backend": "docker", "stdout": "", "stderr": ""}
    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        docker_only,
    )

    verifier = object.__new__(HarnessVerifier)
    verifier.mcp = AuditMCPServer()
    verifier._tool_calls = []
    result = verifier._mcp_run(
        "# requests.get(\nprint('safe test marker')\n",
        source="llm",
        require_docker=True,
        allow_unsafe_harness_in_docker=True,
    )

    assert observed["code"].startswith("# requests.get")
    assert result["backend"] == "docker"
    assert result["safety"]["allowed"] is True


def test_direct_mcp_cannot_enable_the_deep_content_policy_override(monkeypatch):
    """公开 MCP 输入即使伪造内部字段，也必须在 Docker 前被内容策略阻止。"""
    from backend.skills import harness_tools

    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda *_args, **_kwargs: pytest.fail("direct MCP request must not reach Docker"),
    )

    result = AuditMCPServer().call_tool("run_harness_code", {
        "code": "# os.system(\nprint('safe test marker')\n",
        "source": "llm",
        "require_docker": True,
        "allow_unsafe_harness_in_docker": True,
    })["structuredContent"]

    assert result["verdict"] == "unsafe_harness_blocked"
    assert result["safety"]["allowed"] is False


def test_deep_docker_run_failure_is_sandbox_failed_without_host_fallback(monkeypatch):
    """Deep Docker 的镜像/启动失败也必须失败闭合，不能降级为 inconclusive 或宿主机执行。"""
    from backend.skills import harness_tools

    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda *_args, **_kwargs: {
            "executed": False,
            "backend": "docker",
            "reason": "docker_run_error: mocked",
        },
    )
    monkeypatch.setattr(
        harness_tools, "_run_local",
        lambda *_args, **_kwargs: pytest.fail("Deep Docker run failure must not execute on the host"),
    )

    verifier = object.__new__(HarnessVerifier)
    verifier.mcp = AuditMCPServer()
    verifier._tool_calls = []
    result = verifier._mcp_run(
        "# os.system(\nprint('safe test marker')\n",
        source="llm",
        require_docker=True,
        allow_unsafe_harness_in_docker=True,
    )

    assert result["verdict"] == "sandbox_failed"
    assert result["backend"] == "docker"
    assert result["triggered"] is False


def test_js_commonjs_import_scaffold_calls_real_handler_with_framework_evidence(monkeypatch, tmp_path):
    """可导入的 CommonJS handler 必须 require 真实模块，而不是 synthetic slice。"""
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability

    (tmp_path / "handler.js").write_text(
        "const cp = require('child_process');\n"
        "function lookup(req, res) {\n"
        "  cp.exec('echo ' + req.query.host);\n"
        "  return res.status(200).send('ok');\n"
        "}\nmodule.exports = { lookup };\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "handler.js", 3)
    code = harness_tools.build_js_commonjs_import_harness(func, "Command Injection")
    assert code is not None

    def controlled_docker(rendered, timeout, language, code_root=None, harness_kind=None):
        assert code_root == str(tmp_path)
        assert harness_kind == "javascript_commonjs_import"
        local = rendered.replace("/target", tmp_path.as_posix())
        return harness_tools._run_local(local, timeout, language, "template")

    monkeypatch.setattr(harness_tools, "_run_in_docker", controlled_docker)
    result = run_harness(
        code, language="javascript", source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="javascript_commonjs_import",
    )
    assert result["target_function_called"] is True
    assert result["triggered"] is True
    assert result["sink_name"] == "exec"
    assert result["entrypoint_reachable"] is False
    finding_result = HarnessVerifier()._finalize_verdict(
        result["verdict"], result, [], func, "scaffold", "javascript",
    )
    assert finding_result["verdict"] == "function_reproduced"


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
def test_js_commonjs_route_scaffold_confirms_real_express_entrypoint_offline(monkeypatch, tmp_path):
    """A static Express route can produce entrypoint evidence without network or node_modules.

    The fixture is project-like CommonJS source.  The trusted scaffold intercepts
    Express registration, dispatches the *registered* project route with a
    deterministic request, and records the mocked child-process sink.  It must
    not be confused with the older direct-export handler import path.
    """
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability

    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const cp = require('child_process');\n"
        "const app = express();\n"
        "function lookup(req, res) {\n"
        "  cp.exec('echo ' + req.query.host);\n"
        "  return res.status(200).send('ok');\n"
        "}\n"
        "app.get('/lookup', lookup);\n"
        "module.exports = app;\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "app.js", 5)
    assert func["found"] is True
    assert func["route_hints"] == [{"method": "get", "path": "/lookup"}]
    code = harness_tools.build_js_commonjs_entrypoint_harness(func, "Command Injection")
    assert code is not None
    generated = object.__new__(HarnessVerifier)._generate(
        {"type": "Command Injection"}, func, "javascript", previous=None, code_root=tmp_path,
    )
    assert generated["_kind"] == "javascript_commonjs_route"

    def controlled_docker(rendered, timeout, language, code_root=None, harness_kind=None):
        assert code_root == str(tmp_path)
        assert harness_kind == "javascript_commonjs_route"
        return harness_tools._run_local(rendered.replace("/target", tmp_path.as_posix()), timeout, language, "template")

    monkeypatch.setattr(harness_tools, "_run_in_docker", controlled_docker)
    execution = run_harness(
        code, language="javascript", source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="javascript_commonjs_route",
    )
    assert execution["target_function_called"] is True
    assert execution["entrypoint_reachable"] is True
    assert execution["verification_level"] == "entrypoint_reproduced"
    assert execution["triggered"] is True
    assert execution["payload"] in execution["captured_argument"]
    assert execution["verdict"] == "target_confirmed", execution["stdout"] + execution["stderr"]

    result = HarnessVerifier()._finalize_verdict(
        execution["verdict"], execution, [], func, "scaffold", "javascript",
    )
    assert result["verdict"] == "target_confirmed"


def test_js_commonjs_route_scaffold_rejects_dynamic_or_unlinked_routes(tmp_path):
    """Only an extracted function linked to a literal project route is eligible.

    A dynamic path and a route that names another handler have no deterministic
    project-entrypoint evidence, so builders must fail closed rather than call a
    function directly and label it a route test.
    """
    from backend.skills.harness_tools import build_js_commonjs_entrypoint_harness

    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "function lookup(req, res) { return require('child_process').exec(req.query.host); }\n"
        "app.get(process.env.PATH, lookup);\n"
        "app.get('/other', function other(req, res) { return res.end(); });\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "app.js", 2)
    assert func["found"] is True
    assert func["route_hints"] == []
    assert build_js_commonjs_entrypoint_harness(func, "Command Injection") is None


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
def test_source_bound_open_redirect_runs_registered_express_chain_offline(monkeypatch, tmp_path):
    """A NodeGoat-style /learn route is verified as an offline route-handler Harness.

    The fixture intentionally needs a session-bearing request and its real auth
    middleware before the registered redirect handler can run.  The result is
    an entrypoint attestation, not an HTTP session replay.
    """
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability

    (tmp_path / "routes.js").write_text(
        "const SessionHandler = require('./session');\n"
        "const index = (app, db) => {\n"
        "  const sessionHandler = new SessionHandler(db);\n"
        "  const isLoggedIn = sessionHandler.isLoggedInMiddleware;\n"
        "  app.get('/learn', isLoggedIn, (req, res) => {\n"
        "  return res.redirect(req.query.url);\n"
        "  });\n"
        "};\n"
        "module.exports = index;\n",
        encoding="utf-8",
    )
    (tmp_path / "session.js").write_text(
        "module.exports = class SessionHandler {\n"
        "  constructor(db) {}\n"
        "  get isLoggedInMiddleware() {\n"
        "    return function(req, res, next) {\n"
        "      if (req.session && req.session.userId) return next();\n"
        "      return res.status(401).end();\n"
        "    };\n"
        "  }\n"
        "};\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "routes.js", 6)
    assert func["function_name"] == "index"
    assert func["route_hints"] == [{"method": "get", "path": "/learn"}]
    code = build_js_express_open_redirect_entrypoint_harness(func, "Open Redirect")
    assert code is not None

    def controlled_docker(rendered, timeout, language, code_root=None, harness_kind=None):
        assert code_root == str(tmp_path)
        assert harness_kind == "javascript_express_open_redirect_route"
        return harness_tools._run_local(
            rendered.replace("/target", tmp_path.as_posix()), timeout, language, "template",
        )

    monkeypatch.setattr(harness_tools, "_run_in_docker", controlled_docker)
    execution = run_harness(
        code, language="javascript", source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="javascript_express_open_redirect_route",
    )

    assert execution["verdict"] == "target_confirmed", execution["stdout"] + execution["stderr"]
    assert execution["verification_level"] == "entrypoint_reproduced"
    assert execution["entrypoint_reachable"] is True
    attestation = execution["route_entrypoint_attestation"]
    assert attestation["module_executed"] is True
    assert attestation["route"] == {"method": "get", "path": "/learn"}
    assert attestation["middleware_chain"]["count"] == 1
    assert attestation["middleware_chain"]["completed"] is True
    assert attestation["handler_called"] is True
    assert attestation["sink"]["name"] == "res.redirect"
    assert attestation["sink"]["canary_observed"] is True

    finding = HarnessVerifier()._finalize_verdict(
        execution["verdict"], execution, [], func, "scaffold", "javascript",
    )
    assert finding["verdict"] == "target_confirmed"
    assert "project route-handler entrypoint Harness" in finding["reason"]
    assert "not an HTTP session replay" in finding["reason"]

    verifier_result = HarnessVerifier().run(
        {"type": "Open Redirect", "file": "routes.js", "line": 6, "start_line": 6},
        tmp_path, max_retries=0,
    )
    assert verifier_result["verdict"] == "target_confirmed"
    assert verifier_result["harness_kind"] == "javascript_express_open_redirect_route"
    assert verifier_result["route_entrypoint_attestation"]["middleware_chain"]["completed"] is True


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
def test_open_redirect_missing_local_auth_dependency_fails_closed(monkeypatch, tmp_path):
    """A missing local auth module must not be replaced with a next()-calling proxy."""
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability

    (tmp_path / "routes.js").write_text(
        "const SessionHandler = require('./session');\n"
        "const index = (app, db) => {\n"
        "  const auth = new SessionHandler(db).isLoggedInMiddleware;\n"
        "  app.get('/learn', auth, (req, res) => res.redirect(req.query.url));\n"
        "};\n"
        "module.exports = index;\n",
        encoding="utf-8",
    )
    func = {
        "language": "javascript", "file": "routes.js",
        "function_code": "function index(req, res) { return res.redirect(req.query.url); }",
        "route_hints": [{"method": "get", "path": "/learn"}],
    }
    code = build_js_express_open_redirect_entrypoint_harness(func, "Open Redirect")
    assert code is not None
    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda rendered, timeout, language, code_root=None, harness_kind=None: harness_tools._run_local(
            rendered.replace("/target", tmp_path.as_posix()), timeout, language, "template",
        ),
    )

    execution = run_harness(
        code, language="javascript", source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="javascript_express_open_redirect_route",
    )

    assert execution["verdict"] != "target_confirmed"
    assert execution["entrypoint_reachable"] is False
    assert "local_dependency_unresolved" in execution["reason"]


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
def test_open_redirect_harmless_nonlocal_stub_remains_supported(monkeypatch, tmp_path):
    """Unrelated nonlocal dependencies remain safe record-only stubs."""
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability

    (tmp_path / "routes.js").write_text(
        "const harmless = require('harmless-nonlocal-package');\n"
        "const index = (app) => {\n"
        "  app.get('/learn', (req, res, next) => next(), (req, res) => res.redirect(req.query.url));\n"
        "};\n"
        "module.exports = index;\n",
        encoding="utf-8",
    )
    func = {
        "language": "javascript", "file": "routes.js",
        "function_code": "function index(req, res) { return res.redirect(req.query.url); }",
        "route_hints": [{"method": "get", "path": "/learn"}],
    }
    code = build_js_express_open_redirect_entrypoint_harness(func, "Open Redirect")
    assert code is not None
    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda rendered, timeout, language, code_root=None, harness_kind=None: harness_tools._run_local(
            rendered.replace("/target", tmp_path.as_posix()), timeout, language, "template",
        ),
    )

    execution = run_harness(
        code, language="javascript", source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="javascript_express_open_redirect_route",
    )

    assert execution["verdict"] == "target_confirmed", execution["stdout"] + execution["stderr"]


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
@pytest.mark.parametrize("registered, expected", [
    ("// source mentions res.redirect(req.query.url), but never registers /learn\n", "route_unbound"),
    ("router.get('/learn', learn);\n", "middleware_chain_missing"),
])
def test_source_bound_open_redirect_never_confirms_without_runtime_route_chain(
        monkeypatch, tmp_path, registered, expected):
    """Textual redirect evidence alone, an unbound route, and a missing chain fail closed."""
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability

    (tmp_path / "routes.js").write_text(
        "const express = require('express');\n"
        "const router = express.Router();\n"
        "function learn(req, res) { return res.redirect(req.query.url); }\n"
        + registered
        + "module.exports = router;\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "routes.js", 3)
    # The unbound fixture deliberately cannot construct the source-bound harness.
    code = build_js_express_open_redirect_entrypoint_harness(func, "Open Redirect")
    if expected == "route_unbound":
        assert code is None
        return

    assert code is not None
    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda rendered, timeout, language, code_root=None, harness_kind=None: harness_tools._run_local(
            rendered.replace("/target", tmp_path.as_posix()), timeout, language, "template",
        ),
    )
    execution = run_harness(
        code, language="javascript", source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="javascript_express_open_redirect_route",
    )
    assert execution["verdict"] != "target_confirmed"
    assert execution["entrypoint_reachable"] is False
    assert execution["route_entrypoint_attestation"]["middleware_chain"]["count"] == 0
    assert "middleware_chain_missing" in execution["reason"]


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
def test_source_bound_open_redirect_never_confirms_when_registration_module_does_not_execute(
        monkeypatch, tmp_path):
    """A static route hint is insufficient when the actual registration module aborts."""
    from backend.skills import harness_tools
    from backend.skills.harness_tools import scaffold_capability

    (tmp_path / "routes.js").write_text(
        "const express = require('express');\n"
        "const router = express.Router();\n"
        "function auth(req, res, next) { next(); }\n"
        "function learn(req, res) { return res.redirect(req.query.url); }\n"
        "throw new Error('registration aborted');\n"
        "router.get('/learn', auth, learn);\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "routes.js", 4)
    code = build_js_express_open_redirect_entrypoint_harness(func, "Open Redirect")
    assert code is not None
    monkeypatch.setattr(
        harness_tools, "_run_in_docker",
        lambda rendered, timeout, language, code_root=None, harness_kind=None: harness_tools._run_local(
            rendered.replace("/target", tmp_path.as_posix()), timeout, language, "template",
        ),
    )
    execution = run_harness(
        code, language="javascript", source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="javascript_express_open_redirect_route",
    )

    assert execution["verdict"] != "target_confirmed"
    assert execution["route_entrypoint_attestation"]["module_executed"] is False
    assert "module_not_executed" in execution["reason"]


def test_open_redirect_harness_is_supplemental_and_requires_source_bound_entrypoint():
    """Normal Open Redirect routing stays HTTP-only; only a proven route gets this Harness."""
    plan = resolve_strategy("Open Redirect")
    assert plan["strategy"] == "http"
    assert plan["harness_supplement"] == "source_bound_express_route_entrypoint"
    assert is_harness_applicable("Open Redirect") is False
    assert is_harness_applicable("Open Redirect", source_bound=True) is True


def test_open_redirect_source_text_without_registered_route_is_not_harness_applicable(monkeypatch, tmp_path):
    """A redirect-looking function cannot enter Harness without a bound Express registration."""
    (tmp_path / "handler.js").write_text(
        "function learn(req, res) { return res.redirect(req.query.url); }\n"
        "module.exports = { learn };\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        HarnessVerifier, "_mcp_run",
        lambda *_args, **_kwargs: pytest.fail("unbound Open Redirect must not run a generic Harness"),
    )

    result = HarnessVerifier().run(
        {"type": "Open Redirect", "file": "handler.js", "line": 1, "start_line": 1},
        tmp_path, max_retries=0,
    )

    assert result["verdict"] == "not_applicable"
    assert "supplemental only" in result["reason"]
    assert "no HTTP session replay" in result["reason"]


def test_deep_pipeline_explicitly_passes_docker_only_content_policy_authorization(monkeypatch, tmp_path):
    """Deep pipeline must opt in explicitly; direct HarnessVerifier calls retain the safe default."""
    from backend.verifier.harness_verifier import HarnessVerifier
    from backend.verifier.pipeline import ExploitPipeline

    observed = {}

    def fake_run(self, finding, code_root, **kwargs):
        observed.update({"finding": finding, "code_root": code_root, **kwargs})
        return {"verdict": "sandbox_failed", "dynamically_triggered": False}

    monkeypatch.setattr(HarnessVerifier, "run", fake_run)
    finding = {"type": "Command Injection", "file": "app.py", "line": 1}
    ExploitPipeline()._run_harness(
        finding, tmp_path, allow_unsafe_harness_in_docker=True,
    )

    assert observed["allow_unsafe_harness_in_docker"] is True


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
    # LLM 自写玩具函数：只能是 synthetic_demo_only（比 mechanism 更弱），绝不 target_confirmed。
    assert r["verdict"] == "synthetic_demo_only"
    assert r["verification_level"] == "unattested_generated"
    # 关键：框架不采信脚本自报的 target_function_called；非 scaffold 来源无框架 nonce 证明 -> False
    assert r["target_function_called"] is False
    assert r["sink_name"] == "os.system"


def test_untrusted_scaffold_source_is_downgraded():
    r = run_harness(synthetic_self_report_harness(), source="scaffold", require_docker=False)
    # 无有效令牌的 scaffold 被降级为 llm 处理 -> synthetic_demo_only（自报字段一律不采信）。
    assert r["verdict"] == "synthetic_demo_only"
    assert r["verification_level"] == "unattested_generated"


def test_llm_cannot_forge_scaffold_metadata_to_gain_capability(monkeypatch):
    """模型返回的内部 source/kind 字段不是可信能力凭据。

    回归：旧实现用 setdefault 保留 LLM 自报的 ``_source=scaffold``，进而给它
    scaffold capability、源码挂载和 route 级证据资格。
    """
    observed = {}
    monkeypatch.setattr(HarnessVerifier, "_mcp_extract", lambda self, finding, code_root: {
        "found": False, "language": "python", "reason": "no_target",
    })
    monkeypatch.setattr(HarnessVerifier, "_call", lambda self, content: {
        "harness_code": "print('generated')",
        "_source": "scaffold",
        "_kind": "testclient_route",
        "_language": "javascript",
    })

    def fake_run(self, code, language, source, code_root=None, harness_kind=None):
        observed.update({"language": language, "source": source,
                         "code_root": code_root, "kind": harness_kind})
        return {"verdict": "synthetic_demo_only", "triggered": True,
                "target_function_called": False, "verification_level": "unattested_generated"}

    monkeypatch.setattr(HarnessVerifier, "_mcp_run", fake_run)
    result = HarnessVerifier().run({"type": "Command Injection", "file": "x.py", "line": 1},
                                   Path.cwd(), max_retries=0)

    assert observed == {"language": "python", "source": "llm", "code_root": None, "kind": None}
    assert result["verdict"] == "synthetic_demo_only"


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
        lambda code, timeout, language, code_root=None, harness_kind=None:
        harness_tools._run_local(code, timeout, language, "template"))
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


def test_selfcontained_slice_never_mounts_or_installs_target_dependencies(monkeypatch, tmp_path):
    """切片的真实函数体已 inline；即便传入 code_root，也必须不挂载项目、不走
    requirements 安装路径。该边界防止“函数级验证”偷偷退化为整项目运行。"""
    from backend.skills import harness_tools
    from backend.skills.harness_tools import NONCE_PLACEHOLDER, scaffold_capability

    observed = {}

    def controlled_docker(code, timeout, language, code_root=None, harness_kind=None):
        observed.update({"code_root": code_root, "harness_kind": harness_kind})
        return harness_tools._run_local(code, timeout, language, "template")

    monkeypatch.setattr(harness_tools, "_run_in_docker", controlled_docker)
    code = (
        "import json\n"
        f"print('AUDITAGENTX_TARGET_INVOKED={NONCE_PLACEHOLDER}')\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({'triggered': True, 'sink_called': True}))\n"
    )
    result = run_harness(
        code, source="scaffold", scaffold_token=scaffold_capability(), code_root=str(tmp_path),
        harness_kind="selfcontained_slice",
    )
    assert observed == {"code_root": None, "harness_kind": "selfcontained_slice"}
    assert result["target_function_called"] is True


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
    monkeypatch.setattr(harness_tools, "_run_in_docker", lambda code, timeout, language, code_root=None, harness_kind=None: harness_tools._run_local(
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


def test_selfcontained_slice_is_primary_route_is_fallback(monkeypatch, tmp_path):
    """主次已调换：自包含切片是动态验证【主力】——切片可用时直接用它，绝不先走整项目
    route/import（那些需真实导入应用、脆弱）；仅当切片不可用时才兜底到 route。"""
    from backend.verifier import harness_verifier as verifier_module

    (tmp_path / "app.py").write_text(
        "def probe():\n"
        "    return os.system('ping ' + request.args.get('host'))\n",
        encoding="utf-8",
    )
    executed_kinds = []

    def fake_mcp_run(self, code, language, source, code_root=None, harness_kind=None):
        executed_kinds.append(harness_kind)
        if harness_kind == "selfcontained_slice":
            return {"verdict": "target_confirmed", "triggered": True,
                    "target_function_called": True, "verification_level": "target_specific",
                    "backend": "docker", "sink_name": "os.system", "captured_argument": "AAXSLICE"}
        return {"verdict": "not_reproduced", "triggered": False, "target_function_called": False,
                "verification_level": "none", "backend": "docker"}

    monkeypatch.setattr(HarnessVerifier, "_mcp_run", fake_mcp_run)

    # 1) 切片可用 -> 主力：直接跑切片，根本不构建 route
    route_calls = []
    monkeypatch.setattr(verifier_module, "build_route_testclient_harness",
                        lambda func, vt: (route_calls.append(1), "route-placeholder")[1])
    finding = {"type": "Command Injection", "file": "app.py", "start_line": 2, "line": 2}
    HarnessVerifier().run(finding, tmp_path, max_retries=1)
    assert executed_kinds == ["selfcontained_slice"]
    assert route_calls == []   # 切片可用时绝不触碰 route

    # 2) 切片不可用（返回 None）-> 兜底到 route（可选增强）
    executed_kinds.clear()
    monkeypatch.setattr(verifier_module, "build_selfcontained_slice_harness", lambda func, vt: None)
    HarnessVerifier().run(finding, tmp_path, max_retries=0)
    assert executed_kinds == ["testclient_route"]


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


@pytest.mark.skipif(not _docker_ok(), reason="Docker 引擎不可用，跳过本地沙箱集成测试")
def test_selfcontained_slice_reproduces_exception_gated_ssti(tmp_path):
    """本地合成 fixture：SQL 执行异常回显进入 except 中的模板 sink。
    DB 替身仅在 marker 到 execute 时抛异常；最终确认仍必须是 marker 到达
    render_template_string，且 nonce 由框架侧独立观察。"""
    from backend.config import settings
    from backend.skills.harness_tools import (
        build_selfcontained_slice_harness, scaffold_capability,
    )

    if settings.harness_sandbox_image != "auditagentx-harness-python:latest":
        pytest.skip("本回归必须使用固定 auditagentx-harness-python:latest 镜像")
    (tmp_path / "exception_gate.py").write_text(
        "def search_customer():\n"
        "    search_term = request.json['search']\n"
        "    try:\n"
        "        statement = \"SELECT * FROM customer WHERE name='\" + search_term + \"'\"\n"
        "        return db.engine.execute(statement)\n"
        "    except Exception as error:\n"
        "        template = '<h3>' + str(error) + '</h3>'\n"
        "        return render_template_string(template)\n",
        encoding="utf-8",
    )
    func = extract_function(tmp_path, "exception_gate.py", 8)
    assert func["found"] is True
    assert func["function_name"] == "search_customer"
    harness = build_selfcontained_slice_harness(func, "SSTI")
    assert harness is not None

    execution = run_harness(
        harness, source="scaffold", scaffold_token=scaffold_capability(),
        code_root=str(tmp_path), harness_kind="selfcontained_slice",
    )
    assert execution["backend"] == "docker"
    assert execution["target_function_called"] is True  # 随机 nonce，不接受脚本自报
    assert execution["triggered"] is True
    assert execution["sink_name"] == "render_template_string"
    assert execution["verification_level"] == "target_specific"
    assert execution["verdict"] == "target_confirmed"  # 执行级：真实函数切片已复现

    # finding 级不能越权宣称真实 HTTP 入口：切片只能升级到 function_reproduced。
    result = HarnessVerifier().run(
        {"type": "SSTI", "file": "exception_gate.py", "start_line": 8, "line": 8},
        tmp_path, max_retries=0,
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


def test_posix_source_mount_uses_readable_unprivileged_host_identity(monkeypatch):
    """Linux 的 pytest 临时目录通常为 0700，固定 nobody 无法遍历源码挂载。"""
    from backend.skills import harness_tools

    monkeypatch.setattr(harness_tools.os, "name", "posix")
    monkeypatch.setattr(harness_tools.os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(harness_tools.os, "getgid", lambda: 1002, raising=False)

    assert harness_tools._docker_runtime_user(source_mounted=True) == "1001:1002"
    assert harness_tools._docker_runtime_user(source_mounted=False) == "65534:65534"


def test_source_mount_never_selects_root_identity(monkeypatch):
    """即使宿主进程为 root，也不能放宽 Harness 容器的最小权限。"""
    from backend.skills import harness_tools

    monkeypatch.setattr(harness_tools.os, "name", "posix")
    monkeypatch.setattr(harness_tools.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(harness_tools.os, "getgid", lambda: 0, raising=False)

    assert harness_tools._docker_runtime_user(source_mounted=True) == "65534:65534"


def test_nonce_attestation_is_framework_derived_and_does_not_expose_nonce():
    from backend.skills import harness_tools

    nonce = "framework-only-nonce"
    result = harness_tools._finalize(
        {"executed": True,
         "stdout": harness_tools.TARGET_INVOKED_MARKER + nonce,
         "stderr": ""},
        "scaffold", "python", "docker", nonce, "selfcontained_slice",
    )

    attestation = result["nonce_attestation"]
    assert attestation["scheme"] == "sha256"
    assert attestation["marker_observed"] is True
    assert len(attestation["digest"]) == 64
    assert nonce not in str(attestation)
