"""RAG 自进化闭环测试（Q2）。

核心诚信保证：只有**可信标签**（人工 / 动态确认 / 明确误报）才录入知识库；
Agent 自报 / needs_review 一律拒录，避免"循环自欺"把知识库喂脏。
学到的知识必须能被检索并合并进后续复核。
"""
import pytest

import backend.rag.retriever as R
from backend.rag import feedback_learner as FL


@pytest.fixture
def learned_dir(tmp_path, monkeypatch):
    """把 RAG 反馈目录重定向到临时目录，避免污染真实 data/。"""
    monkeypatch.setattr(R, "feedback_dir", lambda: tmp_path)
    R.load_default_items.cache_clear()
    yield tmp_path
    R.load_default_items.cache_clear()


def test_unreliable_labels_are_rejected(learned_dir):
    """防自我感动：Agent 自报 / needs_review / 未验证的判断一律不录入。"""
    f = {"type": "Command Injection", "evidence": {"source": "request.args", "sink": "os.system"}}
    assert FL.ingest_feedback(f, "true_positive", "agent_self_report") is False
    assert FL.ingest_feedback(f, "true_positive", "needs_review") is False
    assert FL.ingest_feedback(f, "true_positive", "llm_only") is False
    assert not (learned_dir / "learned_feedback.json").exists()


def test_reliable_true_positive_is_learned_and_retrievable(learned_dir):
    """可信动态确认的 TP 录入知识库，并能在后续检索中被合并进复核。"""
    f = {"type": "Command Injection", "evidence": {"source": "request.args.get(cmd)", "sink": "os.system"}}
    assert FL.ingest_feedback(f, "true_positive", "dynamic_confirmed") is True
    assert (learned_dir / "learned_feedback.json").exists()

    R.load_default_items.cache_clear()
    res = R.SecurityKnowledgeRetriever().retrieve(candidate={"type": "Command Injection"})
    top = res["top_result"]
    assert top.get("learned_feedback_applied") is True
    assert any("确认的真实漏洞" in c for c in top.get("verification_checks", []))


def test_reliable_false_positive_signal_is_merged_into_verification(learned_dir):
    """可信误报作为 false_positive_signal 录入，后续复核能拿到 -> 越用越少误报。"""
    fp = {"type": "SQL Injection", "status": "false_positive",
          "false_positive_reason": "使用了参数化查询", "context": "test_fixture",
          "evidence": {"sink": "cursor.execute"}}
    assert FL.ingest_feedback(fp, "false_positive", "verify_false_positive") is True

    R.load_default_items.cache_clear()
    res = R.SecurityKnowledgeRetriever().retrieve(candidate={"type": "SQL Injection"})
    signals = res["top_result"].get("false_positive_signals", [])
    assert any("参数化查询" in s for s in signals)


def test_learn_from_scan_only_ingests_reliable_results(learned_dir):
    """扫描自进化：只从动态确认(TP)/明确误报(FP)学，needs_review/unverified 不学。"""
    findings = [
        {"type": "XSS", "dynamically_verified": True, "evidence": {"sink": "innerHTML"}},
        {"type": "SSRF", "status": "needs_review"},          # 不该学
        {"type": "IDOR", "status": "unverified"},             # 不该学
        {"type": "Path Traversal", "status": "false_positive",
         "false_positive_reason": "secure_filename 已净化"},
    ]
    counts = FL.learn_from_scan(findings)
    assert counts["true_positive_ingested"] == 1
    assert counts["false_positive_ingested"] == 1
