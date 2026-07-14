from backend.rag.retriever import SecurityKnowledgeRetriever
from backend.rag.models import SecurityKnowledgeItem
from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.skills.loader import load_skill
from backend.verifier.evidence_collector import EvidenceCollector


def test_retriever_maps_sql_injection_to_cwe_and_playbook():
    candidate = {
        "type": "SQL Injection",
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "code_snippet": "cursor.execute('select * from users where id=' + uid)",
    }

    result = SecurityKnowledgeRetriever().retrieve(candidate=candidate, limit=2)

    assert result["top_result"]["cwe_id"] == "CWE-89"
    assert "A03:2021 Injection" in result["summary"]["owasp"]
    assert result["summary"]["verification_checks"]


def test_retriever_keeps_canonical_cwe_above_learned_feedback():
    """Feedback augments canonical knowledge instead of replacing its CWE."""
    canonical = SecurityKnowledgeItem(
        id="CWE-89", source_type="cwe_core", title="SQL Injection",
        cwe_id="CWE-89", vuln_types=["SQL Injection"],
    )
    feedback = SecurityKnowledgeItem(
        id="learned-sqli", source_type="learned_feedback", title="SQL Injection",
        vuln_types=["SQL Injection"], sources=["app.py"],
        verification_checks=["Verify the dynamically confirmed pattern."],
    )

    result = SecurityKnowledgeRetriever(items=[canonical, feedback]).retrieve(
        candidate={"type": "SQL Injection", "file": "app.py"}
    )

    assert result["top_result"]["id"] == "CWE-89"
    assert result["top_result"]["cwe_id"] == "CWE-89"
    assert result["top_result"]["learned_feedback_applied"] is True


def test_retriever_filters_verification_playbooks():
    candidate = {"type": "Command Injection", "sink": "subprocess.run", "source": "req.body"}

    result = SecurityKnowledgeRetriever().retrieve_playbook(candidate)

    assert result["top_result"]["id"] == "PLAYBOOK-COMMAND-INJECTION"
    assert result["top_result"]["source_type"] == "verification_playbook"
    assert result["summary"]["dynamic_strategy"] == "harness_or_sandbox_http"


def test_retriever_filters_remediation_guides():
    candidate = {"type": "SQL Injection", "sink": "db.query"}

    result = SecurityKnowledgeRetriever().retrieve_remediation(candidate)

    assert result["top_result"]["id"] == "FIX-SQLI"
    assert any("parameterized" in item.lower() for item in result["summary"]["remediation"])


def test_mcp_verification_skill_includes_knowledge_tools():
    candidate = {
        "type": "SQL Injection",
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "code_snippet": "cursor.execute('select * from users where id=' + uid)",
    }

    context = AuditMCPClient().run_verification_skill(candidate, None, load_skill("vulnerability-verification"))

    tool_names = [tool["name"] for tool in context["tools_used"]]
    assert "retrieve_security_knowledge" in tool_names
    assert "retrieve_verification_playbook" in tool_names
    assert "retrieve_remediation_advice" in tool_names
    assert context["knowledge_result"]["top_result"]["cwe_id"] == "CWE-89"
    assert context["playbook_result"]["top_result"]["id"] == "PLAYBOOK-SQLI"


def test_expanded_playbook_and_remediation_coverage():
    """补厚后的知识库：高频漏洞类型都能同时命中 playbook 与 remediation（按 CWE 对齐）。"""
    retriever = SecurityKnowledgeRetriever()
    # (candidate type, 期望 CWE, 期望 playbook id, 期望 remediation id)
    cases = [
        ("Path Traversal", "CWE-22", "PLAYBOOK-PATH-TRAVERSAL", "FIX-PATH-TRAVERSAL"),
        ("XSS", "CWE-79", "PLAYBOOK-XSS", "FIX-XSS"),
        ("SSRF", "CWE-918", "PLAYBOOK-SSRF", "FIX-SSRF"),
        ("Insecure Deserialization", "CWE-502", "PLAYBOOK-DESERIALIZATION", "FIX-DESERIALIZATION"),
        ("Server-Side Template Injection", "CWE-1336", "PLAYBOOK-SSTI", "FIX-SSTI"),
        ("XXE", "CWE-611", "PLAYBOOK-XXE", "FIX-XXE"),
        ("IDOR", "CWE-639", "PLAYBOOK-IDOR", "FIX-IDOR"),
        ("Hardcoded Secret", "CWE-798", "PLAYBOOK-HARDCODED-SECRET", "FIX-HARDCODED-SECRET"),
        ("Code Injection", "CWE-94", "PLAYBOOK-CODE-INJECTION", "FIX-CODE-INJECTION"),
        ("NoSQL Injection", "CWE-943", "PLAYBOOK-NOSQL-LDAP-XPATH", "FIX-NOSQL-LDAP-XPATH"),
        ("Arbitrary File Upload", "CWE-434", "PLAYBOOK-FILE-UPLOAD", "FIX-FILE-UPLOAD"),
        ("Open Redirect", "CWE-601", "PLAYBOOK-REDIRECT-HEADER", "FIX-REDIRECT-HEADER"),
        ("Weak Cryptography", "CWE-327", "PLAYBOOK-WEAK-CRYPTO", "FIX-WEAK-CRYPTO"),
        ("Insecure Configuration", "CWE-16", "PLAYBOOK-SECURITY-MISCONFIG", "FIX-SECURITY-MISCONFIG"),
        ("Outdated Dependency", "CWE-1104", "PLAYBOOK-OUTDATED-DEPENDENCY", "FIX-OUTDATED-DEPENDENCY"),
    ]
    for vuln_type, cwe, playbook_id, fix_id in cases:
        candidate = {"type": vuln_type}
        assert retriever.retrieve(candidate=candidate)["top_result"]["cwe_id"] == cwe, vuln_type
        pb = retriever.retrieve_playbook(candidate)["top_result"]
        assert pb["id"] == playbook_id, vuln_type
        assert pb["source_type"] == "verification_playbook"
        fix = retriever.retrieve_remediation(candidate)["top_result"]
        assert fix["id"] == fix_id, vuln_type
        assert fix["remediation"], vuln_type


def test_chinese_alias_matches_playbook():
    """中文别名也能命中对应知识（检索鲁棒性）。"""
    retriever = SecurityKnowledgeRetriever()
    assert retriever.retrieve_playbook({"type": "反序列化"})["top_result"]["id"] == "PLAYBOOK-DESERIALIZATION"
    assert retriever.retrieve_remediation({"type": "目录穿越"})["top_result"]["id"] == "FIX-PATH-TRAVERSAL"


def test_typed_playbook_retrieval_does_not_cross_match_generic_terms():
    """类型化检索不能只因共享 injection/file 等泛词而返回错误 playbook。"""
    retriever = SecurityKnowledgeRetriever()
    assert retriever.retrieve_playbook({"type": "Code Injection"})["top_result"]["id"] == "PLAYBOOK-CODE-INJECTION"
    assert retriever.retrieve_playbook({"type": "File Upload"})["top_result"]["id"] == "PLAYBOOK-FILE-UPLOAD"
    assert retriever.retrieve_remediation({"type": "Open Redirect"})["top_result"]["id"] == "FIX-REDIRECT-HEADER"


def test_evidence_collector_preserves_knowledge_evidence():
    verify_result = {
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "knowledge": {
            "cwe_id": "CWE-89",
            "owasp": ["A03:2021 Injection"],
            "verification_checks": ["Confirm source reaches SQL sink."],
            "false_positive_signals": ["Prepared statement is present."],
            "remediation": ["Use parameterized queries."],
            "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        },
    }

    evidence = EvidenceCollector.build(verify_result)

    assert evidence["knowledge"]["cwe_id"] == "CWE-89"
    assert "A03:2021 Injection" in evidence["knowledge"]["owasp"]
    assert any("安全知识增强" in log for log in evidence["logs"])


def test_evidence_collector_emits_not_executed_defaults_and_all_tool_calls():
    verify_result = {
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "tool_calls": [
            {"name": "verify_source_sink", "success": True},
            {"name": "retrieve_security_knowledge", "success": True},
            {"name": "retrieve_remediation_advice", "success": True},
        ],
        "knowledge": {"cwe_id": "CWE-89", "owasp": "A03:2021 Injection"},
        "mcp_server": "audit-mcp",
        "skill": {"name": "vulnerability_verification", "version": "2.0"},
        "static_verdict": "confirmed",
        "dynamic_verdict": "not_executed",
    }

    evidence = EvidenceCollector.build(verify_result)

    assert evidence["runtime"]["reproduction_status"] == "not_executed"
    assert evidence["runtime"]["reason"]
    assert evidence["harness"]["verdict"] == "not_executed"
    assert evidence["harness"]["dynamically_triggered"] is False
    assert [call["name"] for call in evidence["tool_calls"]] == [
        "verify_source_sink",
        "retrieve_security_knowledge",
        "retrieve_remediation_advice",
    ]
    assert evidence["knowledge"]["verification_checks"] == []
    assert evidence["knowledge"]["false_positive_signals"] == []
    assert evidence["knowledge"]["remediation"] == []
    assert evidence["knowledge"]["references"] == []
    assert evidence["verification"]["dynamic_verdict"] == "not_executed"
    assert evidence["verification"]["final_verdict"] == "statically_verified"
