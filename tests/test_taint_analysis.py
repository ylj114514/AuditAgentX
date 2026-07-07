"""污点分析扫描器测试（升级自单行正则，验证降误报能力）。"""
from pathlib import Path

from backend.scanners.custom_rules import CustomRuleScanner
from backend.scanners import taint_rules as tr

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_source_sink_sanitizer_detection():
    assert tr.has_source("uid = request.args.get('id')")
    assert tr.has_source("$id = $_GET['id']")
    assert not tr.has_source("uid = 1")
    assert tr.has_sanitizer("uid = int(request.args.get('id'))")
    assert tr.has_injection_marker("cur.execute('select * from u where id=' + uid)")
    assert not tr.has_injection_marker("cur.execute('select * from users')")   # 静态字面量


def test_static_sql_not_flagged():
    """静态字面量 SQL（无拼接）不应被报为注入。"""
    scanner = CustomRuleScanner()
    findings = scanner._scan_file("t.py", [
        "cur.execute('create table users (id int)')",     # 静态，不该报
        "cur.execute('delete from users')",                # 静态，不该报
    ])
    sqli = [f for f in findings if f.type == "SQL Injection"]
    assert len(sqli) == 0


def test_tainted_sql_flagged_with_source():
    """用户输入拼接进 SQL 应被报，且追踪到 source 行。"""
    scanner = CustomRuleScanner()
    findings = scanner._scan_file("t.py", [
        "uid = request.args.get('id')",                    # source (line 1)
        "cur.execute('select * from u where id=' + uid)",  # tainted sink (line 2)
    ])
    sqli = [f for f in findings if f.type == "SQL Injection"]
    assert len(sqli) == 1
    assert sqli[0].extra["source_line"] == 1
    assert sqli[0].extra["confidence"] >= 0.7
    assert sqli[0].extra["analysis"] == "taint"


def test_sink_without_source_downgraded():
    """有拼接但窗口内无用户可控 source -> 降级低置信，不算高危。"""
    scanner = CustomRuleScanner()
    findings = scanner._scan_file("t.py", [
        "x = 'admin'",
        "cur.execute('select * from u where id=' + x)",    # 拼接但 x 非 source
    ])
    sqli = [f for f in findings if f.type == "SQL Injection"]
    assert len(sqli) == 1
    assert sqli[0].severity == "low"
    assert sqli[0].extra["confidence"] < 0.5


def test_placeholder_secret_skipped():
    scanner = CustomRuleScanner()
    findings = scanner._scan_file("c.py", [
        "API_KEY = 'your-api-key-here'",                   # 占位，不该报
        "DB_PASSWORD = 'realpass123456'",                  # 真实，该报
    ])
    secrets = [f for f in findings if f.type == "Hardcoded Secret"]
    assert len(secrets) == 1
    assert "realpass" in secrets[0].code_snippet


def test_demo_target_reduces_false_positives():
    """demo 靶场：升级后应只报真漏洞（静态 SQL 不误报）。"""
    findings = CustomRuleScanner().run(DEMO)
    types = [f.type for f in findings]
    assert "SQL Injection" in types
    assert "Command Injection" in types
    # SQL 注入只应命中 1 条真漏洞（拼接那行），而非全部 execute
    sqli = [f for f in findings if f.type == "SQL Injection"]
    assert len(sqli) == 1
