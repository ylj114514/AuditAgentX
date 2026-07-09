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


def test_php_dot_concat_is_injection_marker():
    """PHP 的 . 字符串拼接应被识别为注入构造痕迹；纯方法调用点号不应误判。"""
    assert tr.has_injection_marker('shell_exec("ping " . $_GET["h"])')
    assert tr.has_injection_marker('$q = "x" . $id')
    assert not tr.has_injection_marker("obj.method(arg)")
    assert not tr.has_injection_marker("cur.execute('select * from users')")


def test_multilang_injection_detection():
    """检测不是 Python-only：PHP / Java / JS 的注入（含跨行污点）都应被检出。"""
    scanner = CustomRuleScanner()

    # PHP：查询先拼进变量、再传给 sink（跨行污点）
    php = scanner._scan_file("a.php", [
        "$id = $_GET['id'];",
        '$q = "SELECT * FROM u WHERE id=" . $id;',
        "mysqli_query($conn, $q);",
    ])
    assert any(f.type == "SQL Injection" for f in php), "PHP 跨行 SQLi 漏检"

    # PHP 命令注入（同行 . 拼接）
    php_cmd = scanner._scan_file("b.php", ['shell_exec("ping " . $_GET["host"]);'])
    assert any(f.type == "Command Injection" for f in php_cmd), "PHP 命令注入漏检"

    # Java：带类型声明的跨行赋值 + getParameter 不被误判为净化
    java = scanner._scan_file("C.java", [
        'String id = req.getParameter("id");',
        'String q = "SELECT * FROM u WHERE id=" + id;',
        "stmt.executeQuery(q);",
    ])
    java_sqli = [f for f in java if f.type == "SQL Injection"]
    assert java_sqli, "Java 跨行 SQLi 漏检"
    assert java_sqli[0].extra["confidence"] >= 0.7, "getParameter 不应被误判为净化而降级"

    # JS：req.query 同行拼接
    js = scanner._scan_file("s.js", [
        'db.query("SELECT * FROM u WHERE id=" + req.query.id);',
    ])
    assert any(f.type == "SQL Injection" for f in js), "JS SQLi 漏检"


def test_go_ruby_injection_detection():
    """补全 Go / Ruby 的 sink 规则：注入类漏洞应被检出（含 Go := 跨行污点）。"""
    scanner = CustomRuleScanner()

    # Go：:= 短声明跨行 + database/sql
    go = scanner._scan_file("h.go", [
        'id := r.URL.Query().Get("id")',
        'q := "SELECT * FROM users WHERE id=" + id',
        "db.Query(q)",
    ])
    assert any(f.type == "SQL Injection" for f in go), "Go 跨行 SQLi 漏检"

    # Go：os/exec 命令注入（同行）
    go_cmd = scanner._scan_file("c.go", [
        'host := r.FormValue("host")',
        'exec.Command("sh", "-c", "ping " + host)',
    ])
    assert any(f.type == "Command Injection" for f in go_cmd), "Go 命令注入漏检"

    # Ruby：ActiveRecord 插值 SQLi + 反序列化
    rb = scanner._scan_file("a.rb", [
        "id = params[:id]",
        'User.where("id = #{id}")',
    ])
    assert any(f.type == "SQL Injection" for f in rb), "Ruby 插值 SQLi 漏检"
    rb2 = scanner._scan_file("b.rb", ["obj = Marshal.load(params[:blob])"])
    assert any(f.type == "Insecure Deserialization" for f in rb2), "Ruby 反序列化漏检"


def test_xss_rule_not_flagging_stdout_print_in_c_cli():
    """收紧 XSS：C 的 printf / Java println / Python print 等标准输出不应被报成 XSS；
    PHP echo 输出用户输入仍应检出。"""
    scanner = CustomRuleScanner()
    # C：printf 输出 argv（标准输出，不是 XSS）
    c = scanner._scan_file("m.c", [
        "int main(int argc, char** argv) {",
        '    printf("hello %s", argv[1]);',
        "}",
    ])
    assert not any(f.type == "XSS" for f in c), "C printf 不应报 XSS"
    # Python：print 用户输入（stdout，不是 XSS）
    py = scanner._scan_file("t.py", ['print("hi " + request.args.get("q"))'])
    assert not any(f.type == "XSS" for f in py), "Python print 不应报 XSS"
    # PHP：echo 输出用户输入（真 XSS）
    php = scanner._scan_file("x.php", ['echo "<div>" . $_GET["name"];'])
    assert any(f.type == "XSS" for f in php), "PHP echo XSS 应检出"


def test_interproc_cross_function_taint():
    """AST 级跨函数污点：用户输入经函数传参到另一函数内的 sink，应被检出；参数化/无输入不误报。"""
    from backend.scanners.interproc_taint import analyze_python_interproc

    vuln = ("def handler(request, cur):\n"
            "    uid = request.args.get('id')\n"
            "    return run_query(uid, cur)\n\n"
            "def run_query(x, cur):\n"
            "    return cur.execute('SELECT * FROM u WHERE id=' + x)\n")
    r = analyze_python_interproc("t.py", vuln)
    assert any(f.type == "SQL Injection" for f in r), "跨函数 SQLi 漏检"
    assert r[0].extra["analysis"] == "interproc-taint"
    assert r[0].extra["caller"] == "handler" and r[0].extra["callee"] == "run_query"

    # 参数化：不应报
    safe = vuln.replace("'SELECT * FROM u WHERE id=' + x", "'SELECT * FROM u WHERE id=?', (x,)")
    assert analyze_python_interproc("t.py", safe) == []

    # 无用户输入（常量入参）：不应报
    const = ("def handler(cur):\n    return run_query('42', cur)\n\n"
             "def run_query(x, cur):\n    return cur.execute('SELECT * FROM u WHERE id=' + x)\n")
    assert analyze_python_interproc("t.py", const) == []


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
