"""静态扫描（自定义规则）测试 —— 无需外部工具与 LLM。"""
from pathlib import Path

from backend.scanners.custom_rules import CustomRuleScanner

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_custom_scanner_finds_known_vulns():
    findings = CustomRuleScanner().run(DEMO)
    types = {f.type for f in findings}
    assert "SQL Injection" in types
    assert "Command Injection" in types
    assert "Hardcoded Secret" in types
    assert len(findings) >= 4
