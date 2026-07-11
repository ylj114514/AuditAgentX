"""对抗式静态扫描回归：阻止窗口词匹配、未来 source 和结果泄密造成自我欺骗。"""
import subprocess
import sys
import time
from pathlib import Path

from backend.repository.language_detector import detect_languages, scan_files
from backend.repository.file_tree_builder import build_tree
from backend.scanners.base import BaseScanner, RawFinding, plausible_secret_assignment
from backend.agents.verification_tools import run_heuristic_static_verifier
from backend.scanners.bandit_runner import _bandit_type
from backend.scanners.custom_rules import CustomRuleScanner
from backend.scanners.java_taint import analyze_java
from backend.scanners.interproc_taint import analyze_python_interproc
from backend.scanners.registry import consolidate_findings
from backend.scanners.gitleaks_runner import _parse_gitleaks_report
from backend.scanners.trivy_runner import _parse_trivy_report
from backend.scanners.semgrep_runner import (
    _framework_rule_mismatch, _detect_project_frameworks, normalize_result_path,
    _project_has_suffix,
)
from backend.dynamic.strategy import is_dynamic_applicable, resolve_strategy
from backend.verifier.exploit_validator import deduplicate
from backend.verifier.context_classifier import classify_finding_context


def _types(lines: list[str], name: str = "case.py") -> set[str]:
    return {f.type for f in CustomRuleScanner()._scan_file(name, lines)}


def test_source_must_precede_and_reach_the_actual_sink_argument():
    assert "SQL Injection" not in _types([
        'cur.execute("SELECT " + local)',
        'uid = request.args.get("id")',  # sink 之后的 source 不能倒流
    ])
    assert "SQL Injection" not in _types([
        'uid = request.args.get("id")',
        'cur.execute("SELECT " + trusted)',  # 无关变量不能充当证据
    ])
    assert "SQL Injection" not in _types([
        'uid = request.args.get("id")',
        'cur.execute("SELECT * FROM u WHERE id=?", (uid,))',  # bind 参数不是 query
    ])


def test_verifier_does_not_invent_flow_from_unrelated_window_terms():
    code = """uid = request.args.get('id')
query = 'SELECT ' + trusted_constant
cursor.execute(query)
"""
    result = run_heuristic_static_verifier(
        {"type": "SQL Injection", "file": "app.py", "line": 3, "code_snippet": code},
        {"found": True, "file": "app.py", "line": 3, "snippet": code, "lines": []},
    )
    assert result.get("is_valid") is not True
    assert not result.get("deterministic_flow")


def test_public_curve_identifier_is_not_a_secret():
    plausible, name, value = plausible_secret_assignment('token = "prime256v1"')
    assert (plausible, name, value) == (False, "token", "prime256v1")
    result = run_heuristic_static_verifier(
        {"type": "Hardcoded Secret", "file": "ssl.c", "line": 1,
         "code_snippet": 'token = "prime256v1"'},
        {"found": True, "file": "ssl.c", "line": 1,
         "snippet": 'token = "prime256v1"', "lines": []},
    )
    assert result.get("is_valid") is False


def test_active_framework_secret_and_default_password_are_credentials():
    assert plausible_secret_assignment(
        "app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'"
    )[0] is True
    assert plausible_secret_assignment("user.password = 'admin123'")[0] is True


def test_sink_only_preclassification_does_not_poison_later_path_flow():
    finding = {"type": "Path Traversal", "file": "src/app.py",
               "code_snippet": "with open(path) as fh:"}
    assert classify_finding_context(finding)["allow_confirmed"] is True


def test_cmake_operator_directory_is_not_a_remote_path_traversal():
    finding = {"type": "Path Traversal", "file": "contrib/cmake/parse.py",
               "code_snippet": "with open(out_path) as fh:"}
    snippet = "out_path = os.path.join(sys.argv[2], 'version.cmake')\nwith open(out_path) as fh:"
    result = classify_finding_context(finding, snippet)
    assert result["context"] == "trusted_build_cli"
    assert result["risk_modifier"] == "false_positive"


def test_php_doc_comments_do_not_create_weak_hash_findings():
    findings = CustomRuleScanner()._scan_file("application/common.php", [
        "/**", " * legacy md5(password) compatibility", " */", "return password_hash($raw);",
    ])
    assert "Weak Hash" not in {item.type for item in findings}


def test_protocol_prescribed_signature_hash_is_not_password_hash_vulnerability():
    code = "$signStr = implode('&', $pairs) . '&key=' . $app_secret; return md5($signStr);"
    result = run_heuristic_static_verifier(
        {"type": "Weak Hash", "file": "application/common/extend/pay/Jeepay.php",
         "line": 2, "code_snippet": code},
        {"found": True, "file": "application/common/extend/pay/Jeepay.php",
         "line": 2, "snippet": code,
         "lines": [{"line": 2, "code": "return md5($signStr);"}]},
    )
    assert result.get("is_valid") is False


def test_bundled_framework_and_sdk_sources_are_sca_scope():
    for path in ("thinkphp/library/think/cache/Sqlite.php", "extend/qiniu/src/Qiniu/Auth.php"):
        result = classify_finding_context({"type": "Weak Hash", "file": path})
        assert result["context"] == "third_party_source"
        assert result["risk_modifier"] == "out_of_scope"


def test_bundled_jquery_is_not_a_project_weak_randomness_candidate():
    result = classify_finding_context({
        "type": "Weak Randomness", "file": "template/default/asset/js/jquery.js",
    })
    assert result["context"] == "bundled_frontend_library"
    assert result["risk_modifier"] == "out_of_scope"


def test_dynamic_template_token_is_not_a_hardcoded_secret():
    code = 'var TD_TOKEN = "{$Request.token}";'
    result = run_heuristic_static_verifier(
        {"type": "Hardcoded Secret", "file": "view.html", "line": 1, "code_snippet": code},
        {"found": True, "file": "view.html", "line": 1,
         "snippet": code, "lines": [{"line": 1, "code": code}]},
    )
    assert result.get("is_valid") is False


def test_csrf_form_body_parameter_name_is_not_a_hardcoded_secret():
    code = "body: 'id=' + id + '&_csrf_token=' + encodeURIComponent(window.AI_CSRF_TOKEN || '')"
    result = run_heuristic_static_verifier(
        {"type": "Hardcoded Secret", "file": "index.html", "line": 1, "code_snippet": code},
        {"found": True, "file": "index.html", "line": 1,
         "snippet": code, "lines": [{"line": 1, "code": code}]},
    )
    assert result.get("is_valid") is False


def test_server_software_metadata_is_not_attacker_controlled_xss():
    finding = {"type": "XSS", "file": "application/admin/view/welcome.html",
               "code_snippet": "<?php echo $_SERVER['SERVER_SOFTWARE'] ?>"}
    result = classify_finding_context(finding, finding["code_snippet"])
    assert result["context"] == "trusted_server_metadata"
    assert result["risk_modifier"] == "false_positive"


def test_sanitizer_is_flow_specific_and_direct_taint_does_not_need_concat():
    findings = CustomRuleScanner()._scan_file("case.py", [
        'uid = request.args.get("id")',
        'other = escape(other)',  # 无关净化器不能洗白 uid
        'cur.execute("SELECT " + uid)',
        'cmd = request.args.get("cmd")',
        'os.system(cmd)',
    ])
    types = {f.type for f in findings}
    assert {"SQL Injection", "Command Injection"} <= types
    assert all(f.extra["source_line"] in {1, 4} for f in findings)


def test_trusted_deserialization_and_non_security_hash_are_suppressed():
    assert "Insecure Deserialization" not in _types([
        "data = load_internal_cache()", "pickle.loads(data)",
    ])
    weak = CustomRuleScanner()._scan_file("checksum.go", ["fileChecksum := md5.New()"])
    assert all(f.extra["confidence"] < 0.5 for f in weak if f.type == "Weak Hash")


def test_new_dynamic_candidate_categories_have_verification_hints():
    findings = CustomRuleScanner()._scan_file("web.py", [
        'expr = request.args.get("expr")', 'eval(expr)',
        'next_url = request.args.get("next")', 'redirect(next_url)',
    ])
    by_type = {f.type: f for f in findings}
    assert {"Code Injection", "Open Redirect"} <= set(by_type)
    assert by_type["Code Injection"].extra["dynamic_verification"] == "harness"
    assert by_type["Open Redirect"].extra["dynamic_verification"] == "http_redirect"


def test_java_analysis_is_ordered_and_reassignment_breaks_taint():
    future_source = """
class T { void f(HttpServletRequest request) {
  String q = "SELECT 1";
  conn.createStatement().executeQuery(q);
  String id = request.getParameter("id");
} }
"""
    reassigned = """
class T { void f(HttpServletRequest request) {
  String id = request.getParameter("id");
  id = "safe";
  String q = "SELECT " + id;
  conn.createStatement().executeQuery(q);
} }
"""
    assert not analyze_java("Future.java", future_source)
    assert not analyze_java("Reassigned.java", reassigned)


def test_python_interproc_respects_sanitizers_and_call_order():
    callee = "\ndef run_query(x, cur):\n    return cur.execute('SELECT ' + x)\n"
    sanitized = (
        "def handler(request, cur):\n"
        "    uid = int(request.args.get('id'))\n"
        "    return run_query(uid, cur)\n" + callee
    )
    future_source = (
        "def handler(request, cur):\n"
        "    run_query(uid, cur)\n"
        "    uid = request.args.get('id')\n" + callee
    )
    assert not analyze_python_interproc("safe.py", sanitized)
    assert not analyze_python_interproc("future.py", future_source)


def test_mainstream_language_detection_includes_extensionless_files(tmp_path: Path):
    for name in ["main.kt", "app.swift", "lib.dart", "main.rs", "tool.ps1", "Dockerfile", "Jenkinsfile"]:
        (tmp_path / name).write_text("// code\n", encoding="utf-8")
    languages, _ = detect_languages(scan_files(tmp_path))
    assert {"Kotlin", "Swift", "Dart", "Rust", "PowerShell", "Dockerfile", "Groovy"} <= set(languages)
    tree = build_tree(tmp_path, scan_files(tmp_path))
    assert next(item for item in tree if item["path"] == "Dockerfile")["language"] == "Dockerfile"


def test_trivy_parser_keeps_cves_distinct_and_never_retains_secret(tmp_path: Path):
    manifest = tmp_path / "package-lock.json"
    manifest.write_text("{}", encoding="utf-8")
    secret_file = tmp_path / "app.py"
    secret_file.write_text('TOKEN="super-secret-value"\n', encoding="utf-8")
    report = {"Results": [
        {"Target": str(manifest), "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "a", "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-2", "PkgName": "a", "Severity": "CRITICAL"},
        ]},
        {"Target": str(secret_file), "Secrets": [
            {"RuleID": "token", "Title": "token", "Severity": "HIGH",
             "StartLine": 1, "Match": "super-secret-value", "Secret": "super-secret-value"},
        ]},
    ]}
    findings = _parse_trivy_report(tmp_path, report)
    assert {f.rule_id for f in findings if f.type == "Dependency Vulnerability"} == {"CVE-1", "CVE-2"}
    assert "super-secret-value" not in repr([f.to_dict() for f in findings])


def test_gitleaks_success_report_returns_findings_and_redacts_secret(tmp_path: Path):
    source = tmp_path / "config.php"
    source.write_text('$token = "real-secret-value";\n', encoding="utf-8")
    findings = _parse_gitleaks_report(tmp_path, [{
        "File": str(source), "StartLine": 1, "EndLine": 1,
        "Secret": "real-secret-value", "RuleID": "generic-api-key",
    }])
    assert len(findings) == 1
    assert findings[0].source == "gitleaks"
    assert "real-secret-value" not in findings[0].code_snippet


def test_tool_path_relative_to_process_cwd_is_normalized_to_project(tmp_path: Path, monkeypatch):
    project = tmp_path / "data" / "projects" / "demo"
    source = project / "src" / "config.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert normalize_result_path(project, "data/projects/demo/src/config.php") == "src/config.php"


def test_language_specific_semgrep_pack_is_only_enabled_for_present_language(tmp_path: Path):
    (tmp_path / "app.php").write_text("<?php", encoding="utf-8")
    assert not _project_has_suffix(tmp_path, ".java")
    (tmp_path / "Main.java").write_text("class Main {}", encoding="utf-8")
    assert _project_has_suffix(tmp_path, ".java")


def test_scanner_timeout_kills_descendant_pipe_holders():
    child = "import time; time.sleep(60)"
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(60)"
    )
    started = time.monotonic()
    try:
        BaseScanner._exec([sys.executable, "-c", parent], timeout=1)
        raise AssertionError("scanner command should have timed out")
    except subprocess.TimeoutExpired:
        pass
    assert time.monotonic() - started < 8


def test_cross_tool_duplicates_are_consolidated_with_evidence():
    items = [
        RawFinding("SQL Injection", "app.py", 10, "high", "semgrep", rule_id="sg",
                   extra={"confidence": 0.85}),
        RawFinding("sql-injection", "app.py", 10, "high", "custom-taint", rule_id="custom",
                   extra={"confidence": 0.82}),
    ]
    merged = consolidate_findings(items)
    assert len(merged) == 1
    assert set(merged[0].extra["corroborating_sources"]) == {"semgrep", "custom-taint"}
    assert merged[0].extra["confidence"] == 0.9


def test_bandit_rule_ids_are_normalized_before_cross_tool_deduplication():
    assert _bandit_type("B608", "hardcoded_sql_expressions") == "SQL Injection"
    assert _bandit_type("B602", "subprocess_popen_with_shell_equals_true") == "Command Injection"
    assert _bandit_type("B301", "blacklist") == "Insecure Deserialization"


def test_new_static_and_dynamic_categories_route_to_the_right_verifier():
    assert resolve_strategy("Regex Injection")["strategy"] == "harness"
    assert resolve_strategy("JWT Signature Verification Disabled")["strategy"] == "http"
    assert not is_dynamic_applicable("Dependency Vulnerability")
    assert not is_dynamic_applicable("TLS Certificate Validation Disabled")


def test_semgrep_django_rule_is_rejected_for_spring_templates(tmp_path: Path):
    (tmp_path / "pom.xml").write_text(
        '<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot</artifactId></dependency>',
        encoding="utf-8",
    )
    template = tmp_path / "src" / "form.html"
    template.parent.mkdir(parents=True)
    template.write_text("<form method='post'></form>", encoding="utf-8")
    _detect_project_frameworks.cache_clear()
    assert _framework_rule_mismatch(
        tmp_path, str(template), "html.django.security.django-no-csrf-token",
    )


def test_django_and_symfony_rules_are_rejected_for_thinkphp(tmp_path: Path):
    (tmp_path / "composer.json").write_text(
        '{"description":"CMS based on ThinkPHP 5","require":{"php":">=7.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "application").mkdir()
    (tmp_path / "thinkphp").mkdir()
    template = tmp_path / "application" / "form.html"
    template.write_text("<form method='post'></form>", encoding="utf-8")
    _detect_project_frameworks.cache_clear()
    assert _framework_rule_mismatch(
        tmp_path, str(template), "html.django.security.django-no-csrf-token",
    )
    assert _framework_rule_mismatch(
        tmp_path, str(template), "php.symfony.security.symfony-non-literal-redirect",
    )


def test_weak_hash_and_random_without_security_context_are_suppressed():
    findings = CustomRuleScanner()._scan_file("app.php", [
        "$etag = md5($content);",
        "$color = mt_rand(0, 255);",
    ])
    assert not {f.type for f in findings} & {"Weak Hash", "Weak Randomness"}


def test_weak_hash_in_authentication_context_is_kept():
    findings = CustomRuleScanner()._scan_file("auth.php", [
        "$passwordHash = md5($password);",
    ])
    assert "Weak Hash" in {f.type for f in findings}


def test_low_confidence_single_rule_is_information_not_manual_review():
    from backend.agents.orchestrator_agent import OrchestratorAgent

    assert OrchestratorAgent._is_low_confidence_advisory({
        "type": "unlink-use", "severity": "medium", "confidence": 0.45,
        "source": "semgrep", "extra": {},
    })
    assert not OrchestratorAgent._is_low_confidence_advisory({
        "type": "md5-loose-equality", "severity": "high", "confidence": 0.45,
        "source": "semgrep", "extra": {},
    })


def test_generic_llm_finding_merges_into_specific_rule_at_same_location():
    findings = deduplicate([
        {"type": "spring-actuator-fully-enabled", "file": "application.properties",
         "line": 21, "confidence": 0.5, "source": "semgrep"},
        {"type": "敏感信息泄露", "file": "application.properties",
         "line": 21, "confidence": 0.75, "source": "audit_agent"},
    ])
    assert len(findings) == 1
    assert findings[0]["type"] == "spring-actuator-fully-enabled"
    assert findings[0]["confidence"] == 0.75


def test_llm_type_variants_merge_into_concrete_tool_rules():
    pairs = [
        ("spring-actuator-fully-enabled", "Information Disclosure - Spring Actuator Exposed"),
        ("github-actions-mutable-action-tag", "Supply Chain Risk - Mutable Action Tag"),
        ("allow-privilege-escalation-no-securitycontext", "Privilege Escalation - Missing SecurityContext"),
    ]
    for concrete, llm_type in pairs:
        findings = deduplicate([
            {"type": concrete, "file": "same.yml", "line": 7,
             "confidence": 0.55, "source": "semgrep"},
            {"type": llm_type, "file": "same.yml", "line": 7,
             "confidence": 0.75, "source": "audit_agent"},
        ])
        assert len(findings) == 1
        assert findings[0]["type"] == concrete
        assert findings[0]["confidence"] == 0.75
