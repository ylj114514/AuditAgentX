# -*- coding: utf-8 -*-
"""AuditAgentX 检测精度基准（self-contained precision/recall benchmark）。

目的：把"原型"变"可信"——用带 ground-truth 标签的漏洞/安全样本，量化检测栈的
precision / recall / F1，而不是只靠"看起来能扫出来"。

设计：
- 每个 case 内嵌代码 + 标签 {vuln_type, is_vulnerable}；
  vulnerable 样本应被检出（TP），safe 样本不应被检出为同类漏洞（否则 FP）。
- 覆盖多语言（Python/PHP/JS）× 多类型（SQLi/命令注入/路径遍历/XSS/反序列化/硬编码密钥）。
- 默认评估内置 custom 污点扫描器（离线、确定性）；semgrep 可用时额外评估并单列。
- 文件级检测口径：某文件被报出「匹配类型」的 finding 即视为「检出该类」。

用法：
    python scripts/run_benchmark.py            # 打印报告
    from scripts.run_benchmark import run_benchmark; m = run_benchmark()
"""
from __future__ import annotations

import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanners.custom_rules import CustomRuleScanner  # noqa: E402
from backend.scanners.semgrep_runner import SemgrepScanner  # noqa: E402


# 类型归一：把扫描器输出的 type 归到基准类别
def _norm_type(t: str) -> str:
    t = (t or "").lower()
    if "sql" in t:
        return "sqli"
    if "command" in t or "os command" in t or "rce" in t:
        return "cmdi"
    if "xpath" in t or "ldap" in t:
        return "injection_other"
    if "path" in t or "traversal" in t or "lfi" in t or "rfi" in t:
        return "path"
    if "ssti" in t or "template" in t:
        return "ssti"
    if "xss" in t or "cross-site" in t:
        return "xss"
    if "deserial" in t or "pickle" in t:
        return "deserialize"
    if "weak hash" in t or "hash" in t:
        return "weakhash"
    if "weak crypto" in t or "cryptograph" in t or "cipher" in t:
        return "weakcrypto"
    if "weak random" in t or "random" in t:
        return "weakrand"
    if "cookie" in t:
        return "cookie"
    if "secret" in t or "credential" in t or "hardcoded" in t or "key" in t:
        return "secret"
    if "ssrf" in t:
        return "ssrf"
    return t


# ---------------------------------------------------------------------------
# 带标签的基准样本（ground truth）
# ---------------------------------------------------------------------------
CASES: list[dict] = [
    # ---- SQL 注入 ----
    {"name": "sqli_vuln.py", "type": "sqli", "vuln": True, "code":
        "def get_user(request, cur):\n"
        "    uid = request.args.get('id')\n"
        "    q = \"SELECT * FROM users WHERE id=\" + uid\n"
        "    return cur.execute(q)\n"},
    {"name": "sqli_safe.py", "type": "sqli", "vuln": False, "code":
        "def get_user(request, cur):\n"
        "    uid = request.args.get('id')\n"
        "    return cur.execute(\"SELECT * FROM users WHERE id=?\", (uid,))\n"},
    {"name": "sqli_vuln.php", "type": "sqli", "vuln": True, "code":
        "<?php\n$id = $_GET['id'];\n$q = \"SELECT * FROM u WHERE id=\" . $id;\nmysqli_query($conn, $q);\n"},

    # ---- 命令注入 ----
    {"name": "cmdi_vuln.py", "type": "cmdi", "vuln": True, "code":
        "import os\n"
        "def ping(request):\n"
        "    host = request.args.get('host')\n"
        "    os.system(\"ping -c 1 \" + host)\n"},
    {"name": "cmdi_safe.py", "type": "cmdi", "vuln": False, "code":
        "import subprocess\n"
        "def ping(request):\n"
        "    host = request.args.get('host')\n"
        "    subprocess.run([\"ping\", \"-c\", \"1\", host])\n"},

    # ---- 路径遍历 ----
    {"name": "path_vuln.py", "type": "path", "vuln": True, "code":
        "def read(request):\n"
        "    name = request.args.get('f')\n"
        "    return open(\"/var/data/\" + name).read()\n"},
    {"name": "path_safe.py", "type": "path", "vuln": False, "code":
        "from werkzeug.utils import secure_filename\n"
        "def read(request):\n"
        "    name = secure_filename(request.args.get('f'))\n"
        "    return open(\"/var/data/\" + name).read()\n"},

    # ---- XSS（PHP echo）----
    {"name": "xss_vuln.php", "type": "xss", "vuln": True, "code":
        "<?php\n$name = $_GET['name'];\necho \"<div>\" . $name . \"</div>\";\n"},
    {"name": "xss_safe.php", "type": "xss", "vuln": False, "code":
        "<?php\n$name = $_GET['name'];\necho \"<div>\" . htmlspecialchars($name) . \"</div>\";\n"},

    # ---- 不安全反序列化 ----
    {"name": "deser_vuln.py", "type": "deserialize", "vuln": True, "code":
        "import pickle\n"
        "def load(request):\n"
        "    return pickle.loads(request.data)\n"},
    {"name": "deser_safe.py", "type": "deserialize", "vuln": False, "code":
        "import json\n"
        "def load(request):\n"
        "    return json.loads(request.data)\n"},

    # ---- 硬编码密钥 ----
    {"name": "secret_vuln.py", "type": "secret", "vuln": True, "code":
        "API_KEY = \"sk-live-abcdef1234567890\"\n"
        "def client():\n    return API_KEY\n"},
    {"name": "secret_safe.py", "type": "secret", "vuln": False, "code":
        "import os\n"
        "API_KEY = os.environ['API_KEY']\n"
        "def client():\n    return API_KEY\n"},

    # ---- 静态 SQL（无用户输入）：不应误报 ----
    {"name": "sqli_static_safe.py", "type": "sqli", "vuln": False, "code":
        "def init(cur):\n"
        "    cur.execute(\"CREATE TABLE IF NOT EXISTS users (id INT)\")\n"
        "    cur.execute(\"DELETE FROM users\")\n"},

    # ---- JS 命令注入 ----
    {"name": "cmdi_vuln.js", "type": "cmdi", "vuln": True, "code":
        "app.get('/p', (req, res) => {\n"
        "  child_process.exec('ls ' + req.query.dir);\n"
        "});\n"},

    # ---- 跨函数污点（窗口级追不到，考验 AST 跨函数分析）----
    {"name": "interproc_sqli_vuln.py", "type": "sqli", "vuln": True, "code":
        "def handler(request, cur):\n"
        "    uid = request.args.get('id')\n"
        "    return run_query(uid, cur)\n"
        "\n"
        "def run_query(x, cur):\n"
        "    return cur.execute('SELECT * FROM users WHERE id=' + x)\n"},
    {"name": "interproc_sqli_safe.py", "type": "sqli", "vuln": False, "code":
        "def handler(request, cur):\n"
        "    uid = request.args.get('id')\n"
        "    return run_query(uid, cur)\n"
        "\n"
        "def run_query(x, cur):\n"
        "    return cur.execute('SELECT * FROM users WHERE id=?', (x,))\n"},
    {"name": "interproc_cmdi_vuln.py", "type": "cmdi", "vuln": True, "code":
        "import os\n"
        "def handler(request):\n"
        "    host = request.args.get('host')\n"
        "    do_ping(host)\n"
        "\n"
        "def do_ping(h):\n"
        "    os.system('ping -c 1 ' + h)\n"},

    # ---- Java 函数级污点（源在顶、经中间变量拼接到底部 sink，考验 AST 污点）----
    {"name": "java_sqli_vuln.java", "type": "sqli", "vuln": True, "code":
        "public class T {\n"
        "  public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
        "    String param = request.getParameter(\"id\");\n"
        "    String sql = \"SELECT * FROM users WHERE id='\" + param + \"'\";\n"
        "    conn.createStatement().executeQuery(sql);\n"
        "  }\n}\n"},
    {"name": "java_sqli_safe.java", "type": "sqli", "vuln": False, "code":
        "public class T {\n"
        "  public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
        "    String param = request.getParameter(\"id\");\n"
        "    String bar = cond ? \"safe_constant\" : \"other_safe_constant\";\n"
        "    String sql = \"SELECT * FROM users WHERE id='\" + bar + \"'\";\n"
        "    conn.createStatement().executeQuery(sql);\n"
        "  }\n}\n"},
    {"name": "java_sqli_ternary_vuln.java", "type": "sqli", "vuln": True, "code":
        "public class T {\n"
        "  public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
        "    String param = request.getParameter(\"id\");\n"
        "    String bar = cond ? \"safe_constant\" : param;\n"
        "    String sql = \"SELECT * FROM users WHERE id='\" + bar + \"'\";\n"
        "    conn.createStatement().executeQuery(sql);\n"
        "  }\n}\n"},

    # ---- Java 弱加密 / 弱随机（字面量匹配，无需污点）----
    {"name": "java_crypto_vuln.java", "type": "weakcrypto", "vuln": True, "code":
        "class C { void f() { javax.crypto.Cipher.getInstance(\"DES/CBC/PKCS5Padding\"); } }\n"},
    {"name": "java_crypto_safe.java", "type": "weakcrypto", "vuln": False, "code":
        "class C { void f() { javax.crypto.Cipher.getInstance(\"AES/GCM/NoPadding\"); } }\n"},
    {"name": "java_rand_vuln.java", "type": "weakrand", "vuln": True, "code":
        "class R { int token() { return new java.util.Random().nextInt(); } }\n"},
    {"name": "java_rand_safe.java", "type": "weakrand", "vuln": False, "code":
        "class R { int f() { return new java.security.SecureRandom().nextInt(); } }\n"},

    # ---- 跨语言弱哈希（PHP / Go）----
    {"name": "php_md5_vuln.php", "type": "weakhash", "vuln": True, "code":
        "<?php\n$passwordHash = md5($password);\n"},
    {"name": "go_md5_vuln.go", "type": "weakhash", "vuln": True, "code":
        "package main\nimport \"crypto/md5\"\nfunc f() { passwordDigest := md5.New(); _ = passwordDigest }\n"},
    {"name": "go_md5_checksum_safe.go", "type": "weakhash", "vuln": False, "code":
        "package main\nimport \"crypto/md5\"\nfunc checksum() { fileChecksum := md5.New(); _ = fileChecksum }\n"},
]


def _scan_dir(scanner, cases: list[dict], *, min_confidence: float = 0.6) -> dict[str, set[str]]:
    """把 cases 写入临时目录，跑 scanner，返回 {filename: {归一化类型}}。

    只统计置信度 >= min_confidence 的 finding（低置信=待复核，不算"检出漏洞"）；
    无置信度字段的工具（如 semgrep）默认全部计入。
    """
    detected: dict[str, set[str]] = defaultdict(set)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for c in cases:
            (root / c["name"]).write_text(c["code"], encoding="utf-8")
        for f in scanner.run(root):
            conf = (getattr(f, "extra", {}) or {}).get("confidence")
            if conf is not None and conf < min_confidence:
                continue
            fname = Path(str(f.file)).name
            detected[fname].add(_norm_type(f.type))
    return detected


def _merge(a: dict[str, set[str]], b: dict[str, set[str]]) -> dict[str, set[str]]:
    """合并两个扫描器的检出（union），代表实际检测栈。"""
    out: dict[str, set[str]] = defaultdict(set)
    for d in (a, b):
        for k, v in d.items():
            out[k] |= v
    return out


def _metrics(cases: list[dict], detected: dict[str, set[str]]) -> dict:
    """按 ground-truth 标签算 TP/FP/FN/TN + precision/recall/F1（总体 + 分类型）。"""
    tp = fp = fn = tn = 0
    per_type: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    rows = []
    for c in cases:
        hit = c["type"] in detected.get(c["name"], set())
        pt = per_type[c["type"]]
        if c["vuln"] and hit:
            tp += 1; pt["tp"] += 1; outcome = "TP"
        elif c["vuln"] and not hit:
            fn += 1; pt["fn"] += 1; outcome = "FN(漏报)"
        elif not c["vuln"] and hit:
            fp += 1; pt["fp"] += 1; outcome = "FP(误报)"
        else:
            tn += 1; pt["tn"] += 1; outcome = "TN"
        rows.append((c["name"], c["type"], "vuln" if c["vuln"] else "safe", outcome))

    def pr(t, f, n):
        precision = t / (t + f) if (t + f) else 1.0
        recall = t / (t + n) if (t + n) else 1.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return precision, recall, f1

    precision, recall, f1 = pr(tp, fp, fn)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "total": len(cases), "rows": rows, "per_type": dict(per_type),
    }


def run_benchmark(scanner=None, *, min_confidence: float = 0.6) -> dict:
    """运行基准，返回内置 custom 污点扫描器（置信度阈值 min_confidence）的指标。"""
    scanner = scanner or CustomRuleScanner()
    detected = _scan_dir(scanner, CASES, min_confidence=min_confidence)
    return _metrics(CASES, detected)


def run_combined_benchmark(*, min_confidence: float = 0.6) -> dict:
    """评估实际检测栈：custom ∪ semgrep（semgrep 不可用时退化为 custom）。"""
    custom = _scan_dir(CustomRuleScanner(), CASES, min_confidence=min_confidence)
    sg = SemgrepScanner()
    if sg.available():
        detected = _merge(custom, _scan_dir(sg, CASES, min_confidence=min_confidence))
    else:
        detected = custom
    return _metrics(CASES, detected)


def _print_report(name: str, m: dict) -> None:
    print(f"\n===== {name} =====")
    print(f"样本数 {m['total']}  |  TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
    print(f"Precision={m['precision']}  Recall={m['recall']}  F1={m['f1']}")
    print("  逐样本:")
    for fname, typ, label, outcome in m["rows"]:
        flag = "" if outcome in ("TP", "TN") else "  <==="
        print(f"    [{outcome:9}] {typ:12} {label:5} {fname}{flag}")


if __name__ == "__main__":
    print("置信度阈值 min_confidence=0.6（低置信=待复核，不计入检出）")
    _print_report("内置 custom 污点扫描器", run_benchmark())

    sg = SemgrepScanner()
    if sg.available():
        _print_report("Semgrep（官方规则 auto + 项目规则）", _metrics(CASES, _scan_dir(sg, CASES)))
        _print_report("组合检测栈 custom ∪ semgrep（实际系统）", run_combined_benchmark())
    else:
        print("\n（semgrep 未安装，跳过其基准与组合评估）")
