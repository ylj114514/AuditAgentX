"""Fuzzing Harness 底层工具（借鉴 DeepAudit 的动态验证思路）。

提供两类能力：
1. extract_function：从项目源码中提取目标漏洞函数，供构建隔离 Harness。
2. run_harness：在沙箱（优先 Docker，回退受控本地子进程）执行 Python Harness，
   通过统一触发标记判断漏洞是否被动态触发。

安全约束：Harness 由提示词强制 mock 所有危险 sink，只在本地隔离环境短时运行，
绝不真实执行系统命令 / 删除文件 / 发起网络请求。
"""
from __future__ import annotations

import ast
import hmac
import json
import logging
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)

TRIGGER_MARKER = "AUDITAGENTX_VULN_TRIGGERED"
NO_TRIGGER_MARKER = "AUDITAGENTX_NO_TRIGGER"
# 新增：Harness 最后一行输出结构化结果，优先据此判定（无则退回 marker）
RESULT_JSON_MARKER = "AUDITAGENTX_RESULT_JSON="
# 框架侧「真实调用证明」：只有框架把真实目标函数包裹起来、在其被真正调用时打印的
# 随机 nonce 才算数。脚本自报的 target_function_called 一律忽略（避免自我感动）。
TARGET_INVOKED_MARKER = "AUDITAGENTX_TARGET_INVOKED="
# 脚手架里预留的占位符，只有 run_harness 在认证过的 scaffold 来源上才替换成本次随机 nonce。
NONCE_PLACEHOLDER = "__AUDITAGENTX_NONCE__"
_SCAFFOLD_CAPABILITY = secrets.token_urlsafe(32)

# 细化的执行级 verdict（run_harness 返回）
V_TARGET_CONFIRMED = "target_confirmed"        # 调用了项目真实目标函数 + 危险 sink 被攻击输入触发
V_MECHANISM_CONFIRMED = "mechanism_confirmed"  # 仅模板机理触发，不等价真实可利用（置信度封顶 0.75）
V_NOT_REPRODUCED = "not_reproduced"            # 成功执行但未触发 sink
V_INCONCLUSIVE = "inconclusive"               # 提取失败/依赖不足/生成失败等无法判断
V_SANDBOX_FAILED = "sandbox_failed"           # Docker/执行环境异常
V_UNSAFE_BLOCKED = "unsafe_harness_blocked"   # Harness 违反安全策略被阻止执行

LEVEL_TARGET = "target_specific"
LEVEL_ENTRYPOINT = "entrypoint_reproduced"
LEVEL_TEMPLATE = "template_mechanism"
LEVEL_UNATTESTED = "unattested_generated"
LEVEL_NONE = "none"


def scaffold_capability() -> str:
    """Return the process-local capability used for trusted backend scaffolds."""
    return _SCAFFOLD_CAPABILITY

# 多语言 Harness 执行运行时：本地解释器 / Docker 镜像 / 文件扩展名 / Docker 内联执行参数
_LANG_RUNTIMES = {
    "python": {"local": None, "image": "python:3.11-slim", "ext": "py", "inline": ["python", "-c"]},
    "javascript": {"local": "node", "image": "node:20-slim", "ext": "js", "inline": ["node", "-e"]},
    "php": {"local": "php", "image": "php:8.2-cli", "ext": "php", "inline": ["php", "-r"]},
}

# 语言/文件后缀 -> 归一化语言（未知一律回退 python，模板 Harness 均为 Python）
_LANG_ALIASES = {
    "py": "python", "python": "python", "python3": "python",
    "js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "javascript", "tsx": "javascript", "typescript": "javascript",
    "node": "javascript", "javascript": "javascript", "ecmascript": "javascript",
    "php": "php", "php5": "php", "php7": "php", "php8": "php", "phtml": "php",
}


def normalize_language(value: str | None) -> str:
    """把文件后缀 / 语言名归一化为受支持的 Harness 执行语言（默认 python）。"""
    return _LANG_ALIASES.get(str(value or "").strip().lower(), "python")


def is_target_harness_confirmed(harness: "dict | None") -> bool:
    """Canonical 判据：Harness 是否达到「入口级动态确认」。

    唯一权威定义，统一供 verify_agent / dynamic_analysis_agent / evidence_collector 共用，
    杜绝各处判据分叉。所有依赖字段都是框架侧独立事实，而非被验证对象自报：
      - verdict == V_TARGET_CONFIRMED：harness_verifier 已剔除全部 confirmed_blocker 后才保留；
      - dynamically_triggered：_VERDICT_EFFECT 中仅 target_confirmed 为 True；
      - function_extracted：确实从项目源码提取到了目标函数；
      - target_function_called：由框架随机 nonce 插桩证明「真实目标函数被调用」，忽略脚本自报；
      - verification_level == LEVEL_ENTRYPOINT：除函数触发外，还有真实入口到目标函数的可达性证明；
      - entrypoint_reachable：框架侧入口追踪明确成立。
    """
    h = harness or {}
    return bool(
        h.get("verdict") == V_TARGET_CONFIRMED
        and h.get("dynamically_triggered")
        and h.get("function_extracted")
        and h.get("target_function_called")
        and h.get("verification_level") == LEVEL_ENTRYPOINT
        and h.get("entrypoint_reachable")
    )


# ---------------------------------------------------------------------------
# 安全策略：静态扫描 Harness 代码，阻止真实危险行为（LLM 生成的代码尤其严格）
# ---------------------------------------------------------------------------

# 硬阻断：无论如何都不允许（真实网络 / 删文件 / 反射逃逸 / 外连），Harness 里没有正当理由出现
_HARD_BLOCK = {
    "python": [
        (r"\bsocket\.socket\s*\(", "real socket network access"),
        (r"\brequests\.(get|post|put|delete|head|patch|request)\s*\(", "real HTTP via requests"),
        (r"urllib\.request\.urlopen\s*\(|(?<![\w.])urlopen\s*\(", "real HTTP via urllib"),
        (r"\bhttp\.client|\bhttplib\b|\basyncio\b.*open_connection", "real network client"),
        (r"\b(shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir)\s*\(", "real file deletion"),
        (r"__subclasses__|__mro__\s*\[|__globals__|__builtins__", "python reflection sandbox escape"),
        (r"\bctypes\b|\bmultiprocessing\b|os\.fork\s*\(|\bpty\b", "process/native escape"),
        (r"open\s*\(\s*['\"][^'\"]*(\.ssh|/etc/shadow|id_rsa|/etc/passwd|\\\\Users\\\\)",
         "real read of sensitive path"),
    ],
    "javascript": [
        (r"\bchild_process\b|\.exec(Sync)?\s*\(|\.spawn\s*\(", "js child_process execution"),
        (r"require\s*\(\s*['\"](net|http|https|dgram|dns|tls)['\"]\s*\)", "js network module"),
        (r"(?<![\w.])fetch\s*\(|new\s+XMLHttpRequest", "js real HTTP"),
        (r"\bfs\.(unlink|rm|rmdir|rmSync|unlinkSync)\s*\(", "js file deletion"),
    ],
    "php": [
        (r"\b(shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(", "php real shell exec"),
        (r"(?<![\w])system\s*\(", "php system()"),
        (r"\b(unlink|rmdir)\s*\(", "php file deletion"),
        (r"\b(curl_exec|fsockopen|file_get_contents\s*\(\s*['\"]https?://)", "php real network"),
    ],
}

# mock 感知：危险 sink 只有被 mock（重新赋值/覆盖）后才允许出现；未 mock 的真实调用一律阻止。
# 每项 (调用正则, 展示名)；点号已转义，避免 os.system 误匹配 os_system 之类的 mock 名。
_MOCK_AWARE = {
    "python": [
        (r"os\.system", "os.system"),
        (r"subprocess\.(call|run|Popen|check_output)", "subprocess"),
        (r"(?:cPickle|pickle)\.loads", "pickle.loads"),
        (r"(?<![\w.])eval", "eval"),
        (r"(?<![\w.])exec", "exec"),
    ],
}


def validate_harness_safety(harness_code: str, language: str = "python",
                            source: str = "llm") -> dict:
    """静态审查 Harness 代码是否满足安全策略。

    返回 {allowed, blocked_reason, checks}。
    - 内置模板（source="template"）经过人工审阅、只做 mock，视为可信直接放行。
    - LLM 生成的 Harness（source="llm"）严格审查：禁止真实网络/删文件/反射逃逸/外连；
      危险 sink（os.system/subprocess/eval/pickle.loads…）只有被 mock 后才允许。
    """
    lang = normalize_language(language)
    code = harness_code or ""
    checks: list[str] = []
    if source == "template":
        return {"allowed": True, "blocked_reason": None,
                "checks": ["trusted built-in template (pre-vetted mock harness)"]}

    # 1) 硬阻断项
    for pattern, desc in _HARD_BLOCK.get(lang, []):
        if re.search(pattern, code, re.I):
            checks.append(f"BLOCK: {desc}")
            return {"allowed": False, "blocked_reason": desc, "checks": checks}
    checks.append("no hard-blocked network/file-delete/reflection patterns")

    # 2) mock 感知的危险 sink（仅 Python）：未被 mock 的真实调用 -> 阻止
    for pattern, display in _MOCK_AWARE.get(lang, []):
        if not re.search(pattern + r"\s*\(", code):
            continue
        # 是否被 mock：对同一 sink 的赋值（os.system = ... / subprocess.call = ...）或 def 同名覆盖
        mocked = (re.search(pattern + r"\s*=", code)
                  or (f"def {display.split('.')[-1]}" in code))
        if not mocked:
            checks.append(f"BLOCK: unmocked dangerous sink call: {display}")
            return {"allowed": False,
                    "blocked_reason": f"unmocked dangerous sink: {display}", "checks": checks}
    checks.append("dangerous sinks are mocked (or absent)")
    return {"allowed": True, "blocked_reason": None, "checks": checks}

# 各语言的函数定义起始模式
_FUNC_START = re.compile(
    r"^\s*(?:def |function |func |sub |public |private |protected |static |async def ).*",
    re.IGNORECASE,
)


def _blank_extract(file, line, reason) -> dict:
    return {"found": False, "file": file, "line": line, "function_code": "",
            "function_name": None, "class_name": None, "module_path": None,
            "imports": [], "decorators": [], "language": None,
            "extraction_method": None, "reason": reason}


def extract_function(code_root: Path | None, file: str | None, line: int | None,
                     *, max_lines: int = 80) -> dict:
    """提取 file:line 所在函数的源码与元信息。

    Python 用 AST 精确定位函数/类/装饰器/import；JS/PHP 用正则（精度有限，reason 里说明）。
    找不到时如实返回 found=False + 具体 reason，不假装成功。
    """
    if not code_root or not file or not line:
        return _blank_extract(file, line, "missing_code_root_or_location")

    target = (Path(code_root) / file).resolve()
    try:
        target.relative_to(Path(code_root).resolve())
    except ValueError:
        return _blank_extract(file, line, "file_outside_workspace")
    if not target.exists() or not target.is_file():
        return _blank_extract(file, line, "file_not_found")

    text = target.read_text(encoding="utf-8", errors="ignore")
    lang = normalize_language(target.suffix.lstrip("."))
    rel = str(Path(file).as_posix())

    if lang == "python":
        return _extract_python(text, rel, line)
    return _extract_regex(text, rel, line, lang, max_lines)


def _extract_python(text: str, rel: str, line: int) -> dict:
    """用 AST 提取 Python 目标函数/方法及其元信息。"""
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return _blank_extract(rel, line, f"python_parse_error: {e}")

    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            imports.extend(f"{mod}.{a.name}" if mod else a.name for a in node.names)

    # 找到包含目标行、且最内层的 FunctionDef
    best = None
    best_class = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            if start <= line <= end:
                if best is None or start >= best.lineno:  # 最内层（起始行更大）
                    best = node
    if best is None:
        return _blank_extract(rel, line, "no_enclosing_function_at_line")

    # 找它所属的类（若有）
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            cstart, cend = node.lineno, getattr(node, "end_lineno", node.lineno)
            if cstart <= best.lineno <= cend:
                best_class = node.name

    seg = ast.get_source_segment(text, best) or "\n".join(
        text.splitlines()[best.lineno - 1:getattr(best, "end_lineno", best.lineno)])
    decorators = [ast.get_source_segment(text, d) or "" for d in best.decorator_list]
    module_path = rel[:-3].replace("/", ".") if rel.endswith(".py") else rel.replace("/", ".")

    return {
        "found": True, "file": rel, "line": line,
        "start_line": best.lineno, "end_line": getattr(best, "end_lineno", best.lineno),
        "function_name": best.name, "class_name": best_class,
        "module_path": module_path, "function_code": seg,
        "imports": imports[:40], "decorators": [d for d in decorators if d],
        "language": "python", "reason": None,
    }


def _extract_regex(text: str, rel: str, line: int, lang: str, max_lines: int) -> dict:
    """JS/PHP 的保守函数提取。

    没有语言 AST 解析器时，宁可返回 ``found=False``，也不能把目标行附近任意
    片段伪装成函数。对可识别的函数头再做花括号边界匹配，结果仍显式标为
    ``regex_brace_limited``，调用方不得把它升级为入口级确认。
    """
    lines = text.splitlines()
    if not lines:
        return _blank_extract(rel, line, "empty_source_file")
    idx = max(0, min(line - 1, len(lines) - 1))

    # JS 同时覆盖 function foo()、async function foo()、const foo = () => {}、
    # class method() {}；PHP 覆盖 function foo()。这是识别函数边界的最低条件。
    if lang == "javascript":
        func_start = re.compile(
            r"^\s*(?:async\s+)?(?:function\s+[A-Za-z_$][\w$]*\s*\(|"
            r"(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=.*=>\s*\{|"
            r"(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{)"
        )
        name_re = re.compile(
            r"(?:function\s+|(?:const|let|var)\s+)([A-Za-z_$][\w$]*)|"
            r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\("
        )
    elif lang == "php":
        func_start = re.compile(r"^\s*(?:public|private|protected|static|final|abstract|\s)*function\s+&?\s*[A-Za-z_]\w*\s*\(", re.I)
        name_re = re.compile(r"function\s+&?\s*([A-Za-z_]\w*)", re.I)
    else:
        return _blank_extract(rel, line, f"unsupported_regex_language:{lang}")

    # 从目标行向上逐一考察候选函数头；只有目标行确实落在括号配对范围内才接受。
    for i in range(idx, max(-1, idx - max_lines), -1):
        if not func_start.match(lines[i]):
            continue
        end = _brace_function_end(lines, i, max_lines)
        if end is None or not (i <= idx < end):
            continue
        match = name_re.search(lines[i])
        groups = match.groups() if match else ()
        name = next((g for g in groups if g), None)
        return {
            "found": True, "file": rel, "line": line,
            "start_line": i + 1, "end_line": end,
            "function_name": name, "class_name": None,
            "module_path": rel, "function_code": "\n".join(lines[i:end]),
            "imports": [], "decorators": [], "language": lang,
            "extraction_method": "regex_brace_limited",
            "reason": "regex_extraction_limited_precision",
        }
    return _blank_extract(rel, line, "no_enclosing_recognized_function_at_line")


def _brace_function_end(lines: list[str], start: int, max_lines: int) -> int | None:
    """返回函数右花括号后的行号（0-based exclusive），无法可靠配对则返回 None。

    这是轻量保守解析：跳过单/双引号中的花括号和行尾注释；遇到模板字符串、
    block comment 等复杂结构时不猜测边界，最多截取 ``max_lines`` 范围。
    """
    depth = 0
    seen_open = False
    quote: str | None = None
    escaped = False
    end_limit = min(len(lines), start + max_lines)
    for line_index in range(start, end_limit):
        source = lines[line_index]
        pos = 0
        while pos < len(source):
            ch = source[pos]
            next_ch = source[pos + 1] if pos + 1 < len(source) else ""
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                pos += 1
                continue
            if ch in {"'", '"'}:
                quote = ch
                pos += 1
                continue
            if ch == "/" and next_ch == "/":
                break
            if ch == "#":  # PHP 单行注释
                break
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}" and seen_open:
                depth -= 1
                if depth == 0:
                    return line_index + 1
                if depth < 0:
                    return None
            pos += 1
    return None


def build_template_harness(vuln_type: str | None, code_snippet: str | None = None) -> str:
    """LLM 不可用时的兜底：按漏洞类型生成可运行的 mock-based Fuzzing Harness。

    这些 Harness 验证的是「该漏洞类型的可利用机理」（类型级），
    mock 掉危险 sink，喂恶意 payload，检测是否以危险方式触发。
    """
    t = (vuln_type or "").lower()
    # 注意匹配顺序：更具体的类型优先（如 "xpath" 含子串 "path"，必须先于 path 判断）
    if "command" in t or "rce" in t or "os command" in t:
        return _HARNESS_CMDI
    if "xpath" in t:
        return _HARNESS_XPATH
    if "ldap" in t:
        return _HARNESS_LDAP
    if "code injection" in t or "code exec" in t or "eval" in t:
        return _HARNESS_CODEI
    if "ssti" in t or "template" in t:
        return _HARNESS_SSTI
    if "sql" in t:
        return _HARNESS_SQLI
    if "path" in t or "traversal" in t or "lfi" in t:
        return _HARNESS_PATH
    if "deserial" in t or "pickle" in t:
        return _HARNESS_DESERIAL
    # 无类型模板：静态判断代码片段是否含危险 sink 模式
    snippet = (code_snippet or "").replace('"', '\\"')
    return (
        'snippet = "' + snippet[:200] + '"\n'
        'danger = ["os.system","subprocess","eval(","exec(","pickle.loads","+ request","_GET["]\n'
        'if any(d in snippet for d in danger):\n'
        '    print("AUDITAGENTX_VULN_TRIGGERED", "static sink pattern present")\n'
        'else:\n'
        '    print("AUDITAGENTX_NO_TRIGGER")\n'
    )


def _is_builtin_template_harness(code: str) -> bool:
    normalized = (code or "").strip()
    return normalized in {
        _HARNESS_CMDI.strip(), _HARNESS_SQLI.strip(), _HARNESS_PATH.strip(),
        _HARNESS_DESERIAL.strip(), _HARNESS_CODEI.strip(), _HARNESS_SSTI.strip(),
        _HARNESS_XPATH.strip(), _HARNESS_LDAP.strip(),
    }


_HARNESS_CMDI = '''executed = []
import os, subprocess
os.system = lambda c: (executed.append(str(c)), 0)[1]
subprocess.call = lambda *a, **k: (executed.append(str(a)), 0)[1]
def target(user_input):          # 通用命令注入模式：拼接进系统命令
    os.system("ping -c 1 " + user_input)
for p in ["127.0.0.1", "; id", "| whoami", "`id`", "&& ls -la"]:
    executed.clear()
    try: target(p)
    except Exception: pass
    danger = [c for c in executed if any(x in c for x in [";", "|", "`", "&&", "$("])]
    if danger:
        print("AUDITAGENTX_VULN_TRIGGERED", "command injection via", repr(p), "->", danger)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_SQLI = '''queries = []
class Cursor:
    def execute(self, q, params=None):
        queries.append((str(q), params))
def target(uid):                 # 通用 SQL 注入模式：字符串拼接查询
    Cursor().execute("SELECT * FROM users WHERE id=" + str(uid))
for p in ["1", "1' OR '1'='1", "1 UNION SELECT username,password FROM users", "1; DROP TABLE users"]:
    queries.clear()
    try: target(p)
    except Exception: pass
    q, params = queries[-1]
    if params is None and any(x in q.upper() for x in ["OR '1'='1", "UNION SELECT", "DROP TABLE"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "sql injection via", repr(p), "->", q)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_PATH = '''from io import StringIO
reads = []
def mock_open(path, *a, **k):
    reads.append(str(path)); return StringIO("")
def target(filename):            # 通用路径遍历模式：拼接进文件路径
    mock_open("/var/www/uploads/" + filename)
for p in ["report.txt", "../../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"]:
    reads.clear()
    try: target(p)
    except Exception: pass
    if any(".." in r or "%2f" in r.lower() for r in reads):
        print("AUDITAGENTX_VULN_TRIGGERED", "path traversal via", repr(p), "->", reads)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_DESERIAL = '''calls = []
import pickle
pickle.loads = lambda b: (calls.append(repr(b)[:60]), None)[1]
def target(data):                # 通用不安全反序列化模式
    pickle.loads(data)
target(b"cos\\nsystem\\n(S'id'\\ntR.")   # 恶意序列化占位（不真实执行）
if calls:
    print("AUDITAGENTX_VULN_TRIGGERED", "insecure deserialization: pickle.loads on untrusted data", calls)
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_CODEI = '''calls = []
def fake_eval(expr, *a, **k):    # mock：不真实 eval，只记录送入 eval 的内容
    calls.append(str(expr)); return None
def target(user_input):          # 代码注入：用户输入被送入 eval/exec
    fake_eval(user_input)
for p in ["1+1", "__import__('os').system('id')", "().__class__.__mro__[1].__subclasses__()", "globals()"]:
    calls.clear()
    try: target(p)
    except Exception: pass
    last = calls[-1] if calls else ""
    if any(x in last for x in ["__import__", "__class__", "subclasses", "os.system", "globals("]):
        print("AUDITAGENTX_VULN_TRIGGERED", "code injection: user input reaches eval ->", repr(last))
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_SSTI = '''rendered = []
def fake_render(tpl, **ctx):     # mock 模板引擎：记录被当作模板源编译的字符串
    rendered.append(str(tpl)); return str(tpl)
def target(name):                # SSTI：用户输入拼进模板源码本身
    fake_render("Hello " + name)
for p in ["World", "{{7*191}}", "${7*191}", "{{config.__class__}}", "#{7*7}", "<%= 7*7 %>"]:
    rendered.clear()
    try: target(p)
    except Exception: pass
    last = rendered[-1] if rendered else ""
    if any(x in last for x in ["{{", "${", "#{", "<%"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "SSTI: template expression compiled from user input ->", repr(p))
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_XPATH = '''queries = []
def fake_xpath(expr):            # mock XPath 求值：记录表达式
    queries.append(str(expr)); return []
def target(user):                # XPath 注入：用户输入拼进 XPath 表达式
    fake_xpath("//user[name/text()='" + user + "']")
for p in ["alice", "' or '1'='1", "'] | //password | a['", "' or 1=1 or ''='"]:
    queries.clear()
    try: target(p)
    except Exception: pass
    q = queries[-1] if queries else ""
    if any(x in q for x in ["' or '1'='1", "or 1=1", "| //"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "xpath injection via", repr(p), "->", q)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_LDAP = '''filters = []
def fake_search(f):              # mock LDAP 搜索：记录过滤器
    filters.append(str(f)); return []
def target(user):                # LDAP 注入：用户输入拼进搜索过滤器
    fake_search("(&(uid=" + user + ")(objectClass=person))")
for p in ["alice", "*", "*)(uid=*))(|(uid=*", "admin)(|(password=*)"]:
    filters.clear()
    try: target(p)
    except Exception: pass
    f = filters[-1] if filters else ""
    if any(x in f for x in ["*)(", ")(|", "uid=*)"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "ldap injection via", repr(p), "->", f)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''


def _parse_result_json(stdout: str) -> dict | None:
    """解析 Harness 打印的 AUDITAGENTX_RESULT_JSON={...}（取最后一处）。"""
    if RESULT_JSON_MARKER not in (stdout or ""):
        return None
    tail = stdout.rsplit(RESULT_JSON_MARKER, 1)[1]
    line = tail.splitlines()[0] if tail.splitlines() else tail
    try:
        obj = json.loads(line.strip())
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _base_result(language: str, source: str, backend: str) -> dict:
    """结构化结果骨架（保持旧字段兼容 + 新增结构化字段）。"""
    return {
        "executed": False, "triggered": False,
        "verdict": V_INCONCLUSIVE, "verification_level": LEVEL_NONE,
        "backend": backend, "language": language, "harness_source": source,
        "target_function_called": False, "sink_called": False,
        "entrypoint_reachable": False,
        "sink_name": None, "captured_argument": None, "payload": None,
        "trigger_detail": "", "stdout": "", "stderr": "", "reason": None,
        "attempt": 1, "safety": {"allowed": True, "blocked_reason": None, "checks": []},
    }


# ---------------------------------------------------------------------------
# 目标脚手架 Harness：内联真实函数 + mock 精确 sink + 真实调用（target_specific）
# 用 AST 得知「哪个参数流向哪个 sink」，从而可靠地构造调用真实函数的 harness。
# ---------------------------------------------------------------------------

_SCAFFOLD_PAYLOADS = {
    "sql": ["1' OR '1'='1", "1 UNION SELECT username,password FROM users"],
    "command": ["; id", "| whoami", "&& ls -la", "`id`"],
    "path": ["../../../../etc/passwd", "..%2f..%2fetc%2fpasswd"],
    "code": ["__import__('os').system('id')", "().__class__"],
    "template": ["{{7*191}}", "${7*191}"],
    "ldap": ["*)(uid=*))(|(uid=*"],
    "xpath": ["' or '1'='1"],
    "deserial": ["__AUDITAGENTX_PAYLOAD__"],
}


def _payload_group(vuln_type: str) -> str:
    t = (vuln_type or "").lower()
    if "sql" in t:
        return "sql"
    if "command" in t or "rce" in t or "os command" in t:
        return "command"
    if "path" in t or "traversal" in t or "lfi" in t:
        return "path"
    if "code" in t or "eval" in t:
        return "code"
    if "ssti" in t or "template" in t:
        return "template"
    if "ldap" in t:
        return "ldap"
    if "xpath" in t:
        return "xpath"
    if "deserial" in t or "pickle" in t:
        return "deserial"
    return ""


def build_target_scaffold_harness(func: dict, vuln_type: str) -> str | None:
    """内联真实目标函数 + mock 精确 sink + 真实调用，构造 target_specific harness。

    仅当能用 AST 确定「参数→sink」时才构造（否则返回 None，交由类型模板兜底）。
    只支持 Python（内联真实函数需同语言执行）。
    """
    from backend.scanners.interproc_taint import _sink_reaching_params  # 复用 AST 分析

    code = (func or {}).get("function_code")
    fname = (func or {}).get("function_name")
    if not code or not fname or normalize_language(func.get("language")) != "python":
        return None
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fname), None)
    if fn is None:
        return None

    reaching = _sink_reaching_params(fn)   # {param: (vuln_type, sink_name, line)}
    if not reaching:
        return None
    data_param, (_vt, sink_name, _line) = next(iter(reaching.items()))
    group = _payload_group(vuln_type or _vt)
    payloads = _SCAFFOLD_PAYLOADS.get(group)
    if not payloads:
        return None

    params = _params_of_py(fn)
    # sink 是「对象.方法」且对象是形参 -> 传 Dummy 记录器；否则模块级 sink 全局 mock
    sink_obj = None
    if "." in sink_name:
        prefix = sink_name.split(".", 1)[0]
        if prefix in params:
            sink_obj = prefix
    mock_setup = _scaffold_mock(sink_name, sink_obj)
    call_args = ", ".join(
        "_p" if p == data_param else ("_Dummy()" if p == sink_obj else "None") for p in params)

    import json as _json
    # 框架插桩：包裹真实目标函数，只有当它真正被调用时才打印框架 nonce（占位符，
    # 由 run_harness 在认证过的 scaffold 来源上替换成本次随机值）。脚本无法伪造该 nonce，
    # 因此 target_function_called 由框架据 nonce 独立判定，而非采信脚本自报字段。
    invoke_probe = TARGET_INVOKED_MARKER + NONCE_PLACEHOLDER
    return (
        "import json, os, subprocess\n"
        "_rec = []\n"
        + mock_setup +
        "\n# ==== 内联的项目真实目标函数 ====\n"
        + _dedent_code(code) +
        "\n# ==== 框架插桩：真实调用被包裹的目标函数时打印框架 nonce ====\n"
        f"_orig_target = globals().get({_json.dumps(fname)})\n"
        "def _target(*_a, **_k):\n"
        f"    print({_json.dumps(invoke_probe)})\n"
        "    return _orig_target(*_a, **_k)\n"
        f"_payloads = {_json.dumps(payloads)}\n"
        "_triggered = False; _cap = None; _pl = None\n"
        "for _p in _payloads:\n"
        "    _rec.clear()\n"
        "    try:\n"
        "        if callable(_orig_target):\n"
        f"            _target({call_args})\n"
        "    except Exception:\n"
        "        pass\n"
        "    for _r in _rec:\n"
        "        if str(_p) in str(_r):\n"
        "            _triggered = True; _cap = str(_r)[:200]; _pl = _p; break\n"
        "    if _triggered:\n"
        "        break\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({\n"
        "    'triggered': _triggered,\n"
        "    'sink_called': bool(_rec) or _triggered,\n"
        f"    'sink_name': {_json.dumps(sink_name)},\n"
        "    'captured_argument': _cap, 'payload': _pl,\n"
        "    'trigger_detail': ('真实目标函数把攻击 payload 送达 sink' if _triggered else '')}))\n"
        "print('AUDITAGENTX_VULN_TRIGGERED' if _triggered else 'AUDITAGENTX_NO_TRIGGER')\n"
    )


def build_route_testclient_harness(func: dict, vuln_type: str) -> str | None:
    """DeepAudit 式（借鉴非抄）：对【Web 路由 handler 型】漏洞，用框架 test-client
    在**进程内**调用真实路由——不用起整个服务、不碰端口/DB。

    执行模型（运行时自省，鲁棒）：
      1) import 真实模块；2) 在模块里找到 Flask/FastAPI app 实例；
      3) 从 app.url_map / app.routes 定位该 handler 的真实路由与方法；
      4) nonce 包裹真实 handler（含 flask view_functions），证明真实路由被真正调用；
      5) 全局打桩 os/subprocess 危险 sink（只记录不真跑）；
      6) test_client 用安全 marker 向真实路由发攻击请求，检测 marker 是否流到 sink。

    仅适用于「读取 request 输入的路由 handler + 命令注入类 sink」；否则返回 None，
    交由 import scaffold / 内联 / 模板兜底。真正安全边界是禁网只读一次性 Docker 沙箱。
    """
    if not isinstance(func, dict) or not func.get("found"):
        return None
    if normalize_language(func.get("language")) != "python":
        return None
    # test-client 需要 import 真实框架（flask/fastapi）——只有配置了预装框架的固定沙箱
    # 镜像才可靠可用；否则诚实回退（返回 None -> 内联/模板兜底），不产生"跑不起来"的假阴性。
    if not (getattr(settings, "harness_sandbox_image", "") or "").strip():
        return None
    code = func.get("function_code") or ""
    fname = func.get("function_name")
    module_path = (func.get("module_path") or "").strip()
    if not code or not fname or not module_path:
        return None
    # 必须是「读取 request 输入」的路由 handler（区别于工具函数 -> import scaffold）
    if "request" not in code:
        return None
    if module_path.endswith(".py"):
        module_path = module_path[:-3]
    module_path = module_path.replace("/", ".").replace("\\", ".").strip(".")
    if not module_path or not all(p.isidentifier() for p in module_path.split(".")):
        return None
    # 命令注入类 sink 才用本 harness（SQLi 等对象 sink 需真实 DB，交由别的路径）
    sink_name = "os.system"
    mcmd = re.search(r"(os\.system|os\.popen|subprocess\.\w+)", code)
    if mcmd:
        sink_name = mcmd.group(1)
    elif not re.search(r"os\.system|os\.popen|subprocess\.|commands\.", code):
        return None
    # 提取 request 参数名（拿不到就用常见默认，test-client 会逐个试）
    params = re.findall(r"request\.(?:args|form|values|json)\.get\(\s*['\"]([^'\"]+)['\"]", code)
    params += re.findall(r"request\.(?:args|form|values)\[\s*['\"]([^'\"]+)['\"]", code)
    seen: set = set()
    params = [p for p in params if not (p in seen or seen.add(p))]
    if not params:
        params = ["id", "host", "cmd", "q", "input", "file", "name", "path", "url", "data"]

    import json as _json
    invoke_probe = TARGET_INVOKED_MARKER + NONCE_PLACEHOLDER
    return (
        "import json, sys, importlib, os, subprocess, re as _re\n"
        "sys.path.insert(0, '/target')\n"
        "_rec = []\n"
        f"_marker = {_json.dumps('AAXROUTE_' + secrets.token_hex(6))}\n"
        f"_params = {_json.dumps(params)}\n"
        f"FUNC = {_json.dumps(fname)}\n"
        f"MOD = {_json.dumps(module_path)}\n"
        f"_nonce = {_json.dumps(invoke_probe)}\n"
        "_triggered=False; _cap=None; _imp_err=None; _route=None; _fw=None\n"
        "# 先用真实 exec/eval import 真实模块\n"
        "try:\n"
        "    _m = importlib.import_module(MOD)\n"
        "except Exception as _e:\n"
        "    _m = None; _imp_err = repr(_e)[:200]\n"
        "# import 后再打桩 os/subprocess（只记录不真跑；不碰框架内部 eval/exec）\n"
        "def _record(*a, **k):\n"
        "    try: _rec.append(str(a) + str(k))\n"
        "    except Exception: _rec.append('<arg>')\n"
        "    return ''\n"
        "class _FR:\n"
        "    def read(self,*a,**k): return ''\n"
        "    def close(self): pass\n"
        "os.system=_record\n"
        "os.popen=lambda *a,**k:(_rec.append(str(a)+str(k)),_FR())[1]\n"
        "subprocess.run=_record; subprocess.call=_record; subprocess.check_output=_record; subprocess.Popen=_record\n"
        "# 找 app 实例\n"
        "_app=None\n"
        "if _m:\n"
        "    for _n in dir(_m):\n"
        "        try: _o=getattr(_m,_n)\n"
        "        except Exception: continue\n"
        "        _cn=type(_o).__name__\n"
        "        if _cn=='Flask': _app=_o; _fw='flask'; break\n"
        "        if _cn=='FastAPI': _app=_o; _fw='fastapi'; break\n"
        "# nonce 包裹真实 handler（证明真实路由被真正调用）\n"
        "if _m and hasattr(_m, FUNC):\n"
        "    _orig=getattr(_m,FUNC)\n"
        "    def _wrap(*a,**k):\n"
        "        print(_nonce)\n"
        "        return _orig(*a,**k)\n"
        "    try: setattr(_m,FUNC,_wrap)\n"
        "    except Exception: pass\n"
        "    if _fw=='flask' and _app is not None:\n"
        "        for _ep,_vf in list(getattr(_app,'view_functions',{}).items()):\n"
        "            if getattr(_vf,'__name__','')==FUNC: _app.view_functions[_ep]=_wrap\n"
        "def _hit():\n"
        "    for _r in _rec:\n"
        "        if _marker in str(_r): return True\n"
        "    return False\n"
        "try:\n"
        "    if _fw=='flask' and _app is not None:\n"
        "        _c=_app.test_client()\n"
        "        for _rule in _app.url_map.iter_rules():\n"
        "            if _rule.endpoint.split('.')[-1]==FUNC: _route=str(_rule.rule); break\n"
        "        _rp=_re.sub(r'<[^>]+>','1',_route or '/')\n"
        "        for _p in _params:\n"
        "            _rec.clear()\n"
        "            try: _c.get(_rp, query_string={_p:_marker})\n"
        "            except Exception: pass\n"
        "            if not _hit():\n"
        "                try: _c.post(_rp, data={_p:_marker})\n"
        "                except Exception: pass\n"
        "            if _hit(): _triggered=True; _cap=[x for x in _rec if _marker in str(x)][0][:200]; break\n"
        "    elif _fw=='fastapi' and _app is not None:\n"
        "        from starlette.testclient import TestClient as _TC\n"
        "        _c=_TC(_app)\n"
        "        for _r in getattr(_app,'routes',[]):\n"
        "            if getattr(getattr(_r,'endpoint',None),'__name__','')==FUNC: _route=getattr(_r,'path',None); break\n"
        "        _rp=_re.sub(r'{[^}]+}','1',_route or '/')\n"
        "        for _p in _params:\n"
        "            _rec.clear()\n"
        "            try: _c.get(_rp, params={_p:_marker})\n"
        "            except Exception: pass\n"
        "            if _hit(): _triggered=True; _cap=[x for x in _rec if _marker in str(x)][0][:200]; break\n"
        "except Exception as _e:\n"
        "    if not _imp_err: _imp_err='route_probe_error: '+repr(_e)[:180]\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({\n"
        "  'triggered': _triggered, 'sink_called': bool(_rec) or _triggered,\n"
        f"  'sink_name': {_json.dumps(sink_name)}, 'captured_argument': _cap,\n"
        "  'payload': (_marker if _triggered else None), 'import_error': _imp_err,\n"
        "  'route': _route, 'framework': _fw,\n"
        "  'trigger_detail': ('真实路由 handler 经 test-client 被调用，用户输入送达 sink'\n"
        "      if _triggered else (_imp_err or '未命中 sink'))}))\n"
        "print('AUDITAGENTX_VULN_TRIGGERED' if _triggered else 'AUDITAGENTX_NO_TRIGGER')\n"
    )


def _params_of_py(fn) -> list[str]:
    a = fn.args
    names = [x.arg for x in list(a.args) + list(getattr(a, "kwonlyargs", []))]
    if a.vararg:
        names.append(a.vararg.arg)
    return names


def _scaffold_mock(sink_name: str, sink_obj: str | None) -> str:
    """生成把危险 sink 换成「只记录参数」的 mock 代码。"""
    if sink_obj:   # 对象方法 sink：Dummy 记录器
        method = sink_name.split(".", 1)[1]
        return (f"class _Dummy:\n"
                f"    def {method}(self, *a, **k):\n"
                f"        _rec.append(a[0] if a else (list(k.values())[0] if k else ''))\n"
                f"        return []\n"
                f"    def __getattr__(self, n):\n"
                f"        return lambda *a, **k: (_rec.append(a[0] if a else ''), [])[1]\n")
    # 模块级 / 内建 sink：全局覆盖为记录函数
    base = "_mock = lambda *a, **k: (_rec.append(a[0] if a else ''), None)[1]\n"
    if sink_name.startswith("os.system"):
        return base + "os.system = _mock\n"
    if sink_name.startswith("subprocess."):
        m = sink_name.split(".", 1)[1]
        return base + f"subprocess.{m} = _mock\n"
    if sink_name in ("eval", "exec", "open") or sink_name.endswith(".loads"):
        # eval/exec/open 内建，或 pickle.loads 等：用同名全局覆盖
        gname = sink_name.split(".")[-1]
        return base + f"{gname} = _mock\n"
    return base + f"{sink_name.split('.')[-1]} = _mock\n"


def build_import_scaffold_harness(func: dict, vuln_type: str) -> str | None:
    """DeepAudit 式：import 项目**真实模块**并调用真实函数（而非内联副本），
    配合 _run_in_docker 只读挂载的 /target 源码执行。

    适用范围：模块级函数（非类方法）+ 全局/内建 sink（os.system/os.popen/subprocess.*/
    eval/exec/open —— 命令注入/代码注入/路径遍历等）。方法级或对象方法 sink（如 SQLi 的
    cursor.execute）无法用全局打桩拦截、且需真实对象，返回 None 交由内联/模板兜底。

    安全：危险 sink 全局打桩为「只记录参数、绝不真实执行」；真正的安全边界是 Docker 沙箱
    （禁网/只读根/无 capability/nobody/一次性）。payload 用安全唯一 marker（不含会被安全
    校验器硬拦的 __subclasses__ 等），只为追踪「参数是否流到 sink」。框架 nonce 独立证明
    真实函数被真正调用。
    """
    from backend.scanners.interproc_taint import _sink_reaching_params

    if not isinstance(func, dict) or not func.get("found"):
        return None
    if normalize_language(func.get("language")) != "python" or func.get("class_name"):
        return None
    module_path = (func.get("module_path") or "").strip()
    fname = func.get("function_name")
    code = func.get("function_code")
    if not module_path or not fname or not code:
        return None
    if module_path.endswith(".py"):
        module_path = module_path[:-3]
    module_path = module_path.replace("/", ".").replace("\\", ".").strip(".")
    if not module_path or not all(p.isidentifier() for p in module_path.split(".")):
        return None
    try:
        fn = next((n for n in ast.walk(ast.parse(code))
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fname), None)
    except SyntaxError:
        return None
    if fn is None:
        return None
    reaching = _sink_reaching_params(fn)
    if not reaching:
        return None
    data_param, (_vt, sink_name, _line) = next(iter(reaching.items()))
    # 只处理全局/内建 sink（对象方法 sink 全局打桩拦不住）
    root = sink_name.split(".", 1)[0]
    if "." in sink_name and root not in ("os", "subprocess"):
        return None

    import json as _json
    params = _params_of_py(fn)
    marker = "AAXPROBE_" + secrets.token_hex(6)
    call_args = ", ".join("_p" if p == data_param else "None" for p in params)
    invoke_probe = TARGET_INVOKED_MARKER + NONCE_PLACEHOLDER
    return (
        "import json, sys, os, subprocess, builtins\n"
        "sys.path.insert(0, '/target')\n"
        "_rec = []\n"
        "def _record(*a, **k):\n"
        "    try: _rec.append(str(a) + str(k))\n"
        "    except Exception: _rec.append('<arg>')\n"
        "    return ''\n"
        "class _FR:\n"
        "    def read(self, *a, **k): return ''\n"
        "    def readlines(self, *a, **k): return []\n"
        "    def close(self): pass\n"
        f"_marker = {_json.dumps(marker)}\n"
        "_p = _marker\n"
        "_triggered = False; _cap = None; _imp_err = None\n"
        "# 关键顺序：先用真实 exec/eval import 模块（Python import 机制依赖 exec），再打桩 sink\n"
        "try:\n"
        f"    from {module_path} import {fname} as _real\n"
        "except Exception as _e:\n"
        "    _real = None; _imp_err = repr(_e)[:200]\n"
        "# import 完成后再全局打桩危险 sink：只记录送入参数，绝不真实执行\n"
        "os.system = _record\n"
        "os.popen = lambda *a, **k: (_rec.append(str(a) + str(k)), _FR())[1]\n"
        "subprocess.run = _record; subprocess.call = _record\n"
        "subprocess.check_output = _record; subprocess.Popen = _record\n"
        "builtins.eval = lambda s, *a, **k: (_rec.append(str(s)), None)[1]\n"
        "builtins.exec = lambda s, *a, **k: _rec.append(str(s))\n"
        "def _target(*a, **k):\n"
        f"    print({_json.dumps(invoke_probe)})\n"
        "    return _real(*a, **k)\n"
        "if callable(_real):\n"
        "    try:\n"
        f"        _target({call_args})\n"
        "    except Exception:\n"
        "        pass\n"
        "    for _r in _rec:\n"
        "        if _marker in str(_r):\n"
        "            _triggered = True; _cap = str(_r)[:200]; break\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({\n"
        "    'triggered': _triggered,\n"
        "    'sink_called': bool(_rec) or _triggered,\n"
        f"    'sink_name': {_json.dumps(sink_name)},\n"
        "    'captured_argument': _cap, 'payload': (_marker if _triggered else None),\n"
        "    'import_error': _imp_err,\n"
        "    'trigger_detail': ('真实模块函数把用户输入送达 sink（import 真实代码执行）'\n"
        "        if _triggered else (('import 失败: ' + _imp_err) if _imp_err else '未触达 sink'))}))\n"
        "print('AUDITAGENTX_VULN_TRIGGERED' if _triggered else 'AUDITAGENTX_NO_TRIGGER')\n"
    )


def _dedent_code(code: str) -> str:
    import textwrap
    return textwrap.dedent(code)


def run_harness(harness_code: str, *, timeout: int | None = None,
                language: str | None = None, source: str = "llm",
                require_docker: bool | None = None,
                scaffold_token: str | None = None,
                code_root: str | None = None,
                harness_kind: str | None = None) -> dict:
    """执行 Harness 并返回结构化结果 + 细化 verdict。

    安全策略（Docker-first）：
      - LLM 生成的 Harness（source="llm"）先过 validate_harness_safety，违规 -> unsafe_harness_blocked；
        且**必须 Docker 执行**，Docker 不可用 -> sandbox_failed（不回退本地跑 LLM 代码）。
      - 内置模板（source="template"）可信，Docker 不可用时允许本地回退。
    判定优先读 AUDITAGENTX_RESULT_JSON，无则退回 AUDITAGENTX_VULN_TRIGGERED marker。
    """
    timeout = timeout or int(getattr(settings, "harness_timeout", 8))
    if source == "scaffold" and not (
        scaffold_token
        and hmac.compare_digest(str(scaffold_token), _SCAFFOLD_CAPABILITY)
    ):
        logger.warning("拒绝未认证的 scaffold 来源，按普通 LLM Harness 降级处理")
        source = "llm"
    lang = normalize_language(language)
    if require_docker is None:
        # llm 与 scaffold（内联真实项目代码）都走 Docker-first；仅内置模板可本地
        require_docker = (source in ("llm", "scaffold")) and bool(
            getattr(settings, "harness_require_docker", True))

    res = _base_result(lang, source, "none")
    if not harness_code or not harness_code.strip():
        res["reason"] = "empty_harness"
        return res

    # 每次运行生成一个随机 nonce。只有认证过的 scaffold（框架自建、包裹真实目标函数）才会被
    # 注入该 nonce；其它来源的脚本无从得知它，因此永远无法伪造"真实目标函数被调用"的证明。
    nonce = secrets.token_hex(16)
    exec_code = harness_code
    if source == "scaffold":
        exec_code = harness_code.replace(NONCE_PLACEHOLDER, nonce)

    # 1) 安全审查（对原始代码审查即可；nonce 替换只影响打印内容）
    safety = validate_harness_safety(harness_code, lang, source)
    res["safety"] = safety
    if not safety["allowed"]:
        res["verdict"] = V_UNSAFE_BLOCKED
        res["reason"] = f"unsafe_harness_blocked: {safety['blocked_reason']}"
        logger.warning("Harness 被安全策略阻止执行: %s", safety["blocked_reason"])
        return res

    # 2) 内置可信模板：本地快速执行（模板只做 mock，无需 Docker 开销）
    if source == "template":
        local_out = _run_local(exec_code, timeout, lang, source)
        return _finalize(local_out, source, lang, local_out.get("backend", "local"), nonce, harness_kind)

    # 3) LLM/scaffold Harness：Docker-first（只要 Docker 引擎可用就用它，与 HTTP 动态验证同一判断）
    #    scaffold 挂载真实项目源码，import 真实模块；LLM 代码不挂载（不可信）。
    mount_root = code_root if source == "scaffold" else None
    docker_out = _run_in_docker(exec_code, timeout, lang, code_root=mount_root)
    if docker_out is not None:
        return _finalize(docker_out, source, lang, "docker", nonce, harness_kind)

    # Docker 不可用：LLM 代码与抽取自不可信项目的 scaffold 永不回退宿主机执行。
    # require_docker 参数只保留 API 兼容，不再能放宽这条安全边界。
    res["verdict"] = V_SANDBOX_FAILED
    res["reason"] = (
        "sandbox_failed: Docker 引擎不可用；LLM/scaffold Harness 禁止在宿主机执行。"
        "请启动 Docker，内置 template 仍可走本地预审模板路径。"
    )
    return res


def _finalize(exec_out: dict, source: str, language: str, backend: str,
              nonce: str = "", harness_kind: str | None = None) -> dict:
    """把底层执行输出（stdout/stderr）解析为结构化结果 + verdict + verification_level。

    关键：`target_function_called` 完全由框架侧证据（本次随机 nonce 是否被真实调用打印）
    判定，**忽略脚本自报的同名字段**——避免"被验证对象自报成功"式的自我感动。
    """
    res = _base_result(language, source, backend)
    res.update({k: exec_out.get(k, res.get(k)) for k in
                ("executed", "stdout", "stderr", "reason")})
    stdout = exec_out.get("stdout", "") or ""

    if not exec_out.get("executed"):
        # 未真正执行（解释器缺失/超时/错误）
        res["verdict"] = V_INCONCLUSIVE
        res["reason"] = exec_out.get("reason") or "not_executed"
        return res

    # 优先结构化 JSON（注意：不再从 JSON 读取 target_function_called，它是脚本自报，不可信）
    parsed = _parse_result_json(stdout)
    if parsed:
        res["triggered"] = bool(parsed.get("triggered"))
        res["sink_called"] = bool(parsed.get("sink_called", res["triggered"]))
        res["sink_name"] = parsed.get("sink_name")
        res["captured_argument"] = parsed.get("captured_argument")
        res["payload"] = parsed.get("payload")
        res["trigger_detail"] = str(parsed.get("trigger_detail") or "")[:300]
    else:
        # 退回旧 marker
        res["triggered"] = TRIGGER_MARKER in stdout
        res["sink_called"] = res["triggered"]
        if res["triggered"]:
            m = re.search(re.escape(TRIGGER_MARKER) + r"(.*)", stdout)
            res["trigger_detail"] = (m.group(1).strip() if m else "")[:300]

    # 框架侧独立证明「真实目标函数被调用」：仅当 scaffold 来源、且本次随机 nonce 真的被
    # 框架插桩打印出来才成立。脚本自报的 target_function_called 一律不采信。
    res["target_function_called"] = bool(
        source == "scaffold" and nonce and (TARGET_INVOKED_MARKER + nonce) in stdout
    )

    # 入口级可达性：仅当框架自建的 testclient_route 脚手架（经真实路由 dispatch 调真实
    # handler）+ 框架 nonce 证明真实调用 + sink 被触发，才成立。这不是脚本自报——
    # harness_kind 由框架侧决定，nonce/触发由框架独立观测。
    res["entrypoint_reachable"] = bool(
        source == "scaffold" and harness_kind == "testclient_route"
        and res["target_function_called"] and res["triggered"]
    )

    # verification_level：只有后端 scaffold 包裹真实函数、框架 nonce 证明其被真正调用，
    # 且危险 sink 被攻击 payload 触发，才算目标级；再叠加真实入口可达 -> 入口级。
    if source == "template":
        res["verification_level"] = LEVEL_TEMPLATE
    elif source == "scaffold" and res["target_function_called"] and res["triggered"]:
        res["verification_level"] = LEVEL_ENTRYPOINT if res["entrypoint_reachable"] else LEVEL_TARGET
    elif source == "llm" and res["triggered"]:
        res["verification_level"] = LEVEL_UNATTESTED
    else:
        res["verification_level"] = LEVEL_NONE

    # 执行级 verdict
    if not res["triggered"]:
        res["verdict"] = V_NOT_REPRODUCED
        res["reason"] = res["reason"] or "executed_but_sink_not_triggered"
    elif res["verification_level"] in (LEVEL_TARGET, LEVEL_ENTRYPOINT):
        res["verdict"] = V_TARGET_CONFIRMED
    else:
        res["verdict"] = V_MECHANISM_CONFIRMED
    return res


def _run_in_docker(harness_code: str, timeout: int, language: str,
                   code_root: str | None = None) -> dict | None:
    """Docker 沙箱执行（网络禁用 + 内存/CPU/超时限制 + 自动清理）；不可用返回 None。

    以「Docker 引擎是否真的可达」为准（复用 HTTP 动态验证同一套 get_docker_client），
    不再依赖 enable_sandbox 开关——只要装了 Docker 且引擎在跑，harness 就会用它。

    code_root 非空且为 Python 时，把项目源码**只读挂载**到 /target 并加入 PYTHONPATH，
    让 scaffold 能 `import` 项目真实模块（DeepAudit 式：跑真实代码而非内联副本）。
    配 settings.harness_sandbox_image 可用预装常见依赖的固定沙箱镜像。
    """
    try:
        from backend.verifier.app_runner import get_docker_client
        client = get_docker_client()
    except Exception as e:  # noqa: BLE001  docker SDK 缺失或引擎不可达
        logger.info("Docker 引擎不可用，harness 不走 Docker: %s", e)
        return None
    rt = _LANG_RUNTIMES.get(language, _LANG_RUNTIMES["python"])
    image = (getattr(settings, "harness_sandbox_image", "") or "").strip() or rt["image"]
    code = harness_code
    if language == "php":
        code = code.replace("<?php", "").replace("?>", "")
    run_kwargs = dict(
        image=image,
        command=rt["inline"] + [code],
        detach=True,
        network_disabled=True,          # 禁网
        mem_limit="512m",               # 内存上限（import 真实框架需更多）
        nano_cpus=1_000_000_000,        # CPU 上限（1 核）
        pids_limit=64,                  # 进程数上限，抑制 fork 炸弹
        read_only=True,                 # 根文件系统只读
        tmpfs={"/tmp": "size=32m"},     # 仅 /tmp 可写（受限）
        security_opt=["no-new-privileges"],
        cap_drop=["ALL"],
        user="65534:65534",
        remove=False,
    )
    # DeepAudit 式：只读挂载项目真实源码，让 scaffold import 真实模块（仅 Python）
    if code_root and language == "python":
        try:
            host_path = str(Path(code_root).resolve())
            if Path(host_path).exists():
                run_kwargs["volumes"] = {host_path: {"bind": "/target", "mode": "ro"}}
                run_kwargs["environment"] = {"PYTHONPATH": "/target",
                                             "PYTHONDONTWRITEBYTECODE": "1"}
        except Exception:  # noqa: BLE001  挂载失败不致命，退回无挂载执行
            pass
    container = None
    try:
        container = client.containers.run(**run_kwargs)
        container.wait(timeout=timeout)
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="ignore")
        return {"executed": True, "stdout": stdout[:4000], "stderr": stderr[:2000],
                "backend": "docker", "reason": None}
    except Exception as e:  # noqa: BLE001
        logger.warning("Docker harness 执行失败: %s", e)
        return None
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                pass


def _run_local(harness_code: str, timeout: int, language: str, source: str) -> dict:
    """受控本地子进程执行——仅供内置模板兜底（LLM 代码不会走到这里）。"""
    if not getattr(settings, "enable_local_harness", True):
        return {"executed": False, "backend": "none", "reason": "local_harness_disabled"}
    rt = _LANG_RUNTIMES.get(language, _LANG_RUNTIMES["python"])
    interpreter = sys.executable if language == "python" else shutil.which(rt["local"])
    if not interpreter:
        return {"executed": False, "backend": "none",
                "reason": f"interpreter_unavailable: {language}"}
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / f"harness.{rt['ext']}"
        script.write_text(harness_code, encoding="utf-8")
        try:
            proc = subprocess.run(
                [interpreter, str(script)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, cwd=tmp,
            )
            return {"executed": True, "stdout": (proc.stdout or "")[:4000],
                    "stderr": (proc.stderr or "")[:2000], "backend": "local", "reason": None}
        except subprocess.TimeoutExpired:
            return {"executed": True, "stdout": "", "stderr": "harness timed out",
                    "backend": "local", "reason": "timeout"}
        except Exception as e:  # noqa: BLE001
            return {"executed": False, "backend": "local", "reason": f"exec_error: {e}"}
