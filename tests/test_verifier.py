"""结果裁决（去重/排序/误报过滤）测试。"""
from backend.verifier import exploit_validator as judge


def test_deduplicate():
    findings = [
        {"type": "SQL Injection", "file": "a.py", "start_line": 10, "confidence": 0.5},
        {"type": "SQL Injection", "file": "a.py", "start_line": 10, "confidence": 0.9},
    ]
    assert len(judge.deduplicate(findings)) == 1
    assert judge.deduplicate(findings)[0]["confidence"] == 0.9


def test_filter_false_positives():
    findings = [
        {"type": "X", "status": "confirmed"},
        {"type": "Y", "status": "false_positive"},
    ]
    assert len(judge.filter_false_positives(findings)) == 1


def test_rank_by_severity():
    findings = [
        {"severity": "low", "confidence": 0.9},
        {"severity": "critical", "confidence": 0.1},
    ]
    assert judge.rank(findings)[0]["severity"] == "critical"
