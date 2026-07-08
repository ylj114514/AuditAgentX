"""RAG 接入 AuditAgent / ReportAgent + 知识库全覆盖测试（离线，不触发 LLM）。"""
from backend.agents.audit_agent import AuditAgent
from backend.agents.report_agent import ReportAgent
from backend.scanners.base import RawFinding
from backend.rag.retriever import SecurityKnowledgeRetriever, load_default_items
from backend.dynamic.strategy import STRATEGY_RULES


def test_knowledge_base_covers_all_strategy_types():
    """知识库应覆盖 strategy.py 支持的所有漏洞类型（0 未命中）。"""
    load_default_items.cache_clear()
    r = SecurityKnowledgeRetriever()
    missing = []
    for key in STRATEGY_RULES:
        out = r.retrieve(candidate={"type": key})
        if not out.get("top_result"):
            missing.append(key)
    assert missing == [], f"知识库未覆盖: {missing}"


def test_audit_agent_retrieves_knowledge():
    raws = [
        RawFinding(type="Insecure Deserialization", file="a.py", line=1, severity="high",
                   source="custom", code_snippet="pickle.loads(x)"),
        RawFinding(type="XXE", file="b.py", line=2, severity="high", source="custom"),
    ]
    knowledge = AuditAgent._retrieve_knowledge(raws)
    cwes = {k["cwe_id"] for k in knowledge}
    assert "CWE-502" in cwes
    assert "CWE-611" in cwes
    assert all("verification_checks" in k for k in knowledge)


def test_audit_agent_dedups_and_caps():
    raws = [RawFinding(type="SQL Injection", file=f"{i}.py", line=i, severity="high",
                       source="custom") for i in range(20)]
    knowledge = AuditAgent._retrieve_knowledge(raws)
    assert len(knowledge) == 1  # 同类型去重


def test_report_agent_retrieves_remediation():
    rem = ReportAgent._retrieve_remediation({
        "top_vulnerability_types": [{"type": "SQL Injection"}, {"type": "Hardcoded Secret"}]})
    by_type = {r["for_type"]: r for r in rem}
    assert "SQL Injection" in by_type
    assert by_type["SQL Injection"]["cwe_id"] == "CWE-89"
    assert by_type["SQL Injection"]["remediation"]


def test_new_vuln_types_have_rich_knowledge():
    """抽查新增条目含完整的验证要点与修复建议。"""
    r = SecurityKnowledgeRetriever()
    for vt, cwe in [("SSTI", "CWE-1336"), ("IDOR", "CWE-639"), ("Open Redirect", "CWE-601")]:
        top = r.retrieve(candidate={"type": vt})["top_result"]
        assert top["cwe_id"] == cwe
        assert top["verification_checks"] and top["remediation"]
