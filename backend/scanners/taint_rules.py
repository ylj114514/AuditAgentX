"""轻量污点分析规则库（source / sink / sanitizer 定义）。

污点分析核心思想（借鉴 Semgrep taint mode）：
  漏洞 = 用户可控输入(source) 经数据流到达危险函数(sink) 且中途未被净化(sanitizer)。

单行正则只看 sink，误报高；这里把 source/sink/sanitizer 分开定义，
供 taint_scanner 做「同函数/同窗口内 source→sink 可达性」判断，区分置信度。
"""
from __future__ import annotations

import re

# 用户可控输入来源（source）：多语言常见入口
SOURCE_PATTERNS = [
    re.compile(r"request\.(args|form|values|json|data|files|cookies|headers|GET|POST)", re.I),
    re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"),                 # PHP
    re.compile(r"\b(params|query|body)\s*[\[\.]", re.I),                        # Express/通用
    re.compile(r"req\.(query|body|params|headers|cookies)", re.I),             # Node
    re.compile(r"getParameter\s*\(|@RequestParam|@PathVariable", re.I),        # Java
    re.compile(r"\binput\s*\(", re.I),                                          # stdin
    re.compile(r"os\.environ|process\.env", re.I),                             # 环境变量（弱 source）
    re.compile(r"\bscanf\b|argv\[", re.I),                                      # C/命令行
]

# 净化器（sanitizer）：出现则大幅降低可利用性
SANITIZER_PATTERNS = [
    re.compile(r"(escape|sanitiz|quote|param|prepare|bind_param|placeholder)", re.I),
    re.compile(r"(int|float|str2int|parseInt|Number)\s*\(", re.I),             # 类型转换
    re.compile(r"(secure_filename|basename|realpath|normpath|abspath)", re.I),  # 路径净化
    re.compile(r"(htmlspecialchars|htmlentities|encodeURI|escapeHtml)", re.I),  # 输出编码
    re.compile(r"re\.escape|shlex\.quote", re.I),
    re.compile(r"allow\s*list|whitelist|is_valid|validate", re.I),
]

# (漏洞类型, 严重级, sink 正则, [是否需要 source 才成立])
# require_source=True：SQL/命令/路径/SSRF 等注入类必须有 source 才算高危
# require_source=False：硬编码密钥/不安全反序列化等本身即问题
TAINT_SINKS: list[tuple[str, str, re.Pattern, bool]] = [
    ("SQL Injection", "high", re.compile(
        r"(cursor\.execute|\.execute|\.query|db\.query|mysqli_query|->query|"
        r"executeQuery|createStatement)\s*\(", re.I), True),
    ("Command Injection", "high", re.compile(
        r"(os\.system|subprocess\.(call|run|Popen|check_output)|commands\.getoutput|"
        r"shell_exec|passthru|proc_open|popen|exec|eval|Runtime\.getRuntime\(\)\.exec|"
        r"child_process\.(exec|execSync|spawn))\s*\(", re.I), True),
    ("Path Traversal", "medium", re.compile(
        r"(open|file_get_contents|readfile|fopen|include|require|include_once|"
        r"require_once|fs\.readFile|Files\.read|new\s+File)\s*\(", re.I), True),
    ("SSRF", "medium", re.compile(
        r"(requests\.(get|post|put|delete)|urllib\.request\.urlopen|urlopen|"
        r"httpx\.(get|post)|axios\.(get|post)|fetch|curl_exec|file_get_contents|"
        r"HttpClient|URLConnection)\s*\(", re.I), True),
    ("Server-Side Template Injection", "high", re.compile(
        r"(render_template_string|Template\s*\(|env\.from_string|Twig|Handlebars\.compile|"
        r"\.render\s*\()", re.I), True),
    ("XSS", "medium", re.compile(
        r"(innerHTML|document\.write|render_template_string|\|\s*safe|"
        r"dangerouslySetInnerHTML|echo|print)\s*", re.I), True),
    ("Insecure Deserialization", "high", re.compile(
        r"(pickle\.loads|cPickle\.loads|yaml\.load\s*\((?!.*Loader)|unserialize|"
        r"ObjectInputStream|readObject|marshal\.loads|__reduce__)\s*", re.I), False),
    ("Hardcoded Secret", "high", re.compile(
        r"""(password|passwd|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)"""
        r"""\s*[=:]\s*['"][^'"]{6,}['"]""", re.I), False),
    ("Weak Cryptography", "low", re.compile(
        r"(md5|sha1|DES|RC4|ECB)\s*\(", re.I), False),
]

# 硬编码密钥的占位值（是则判为疑似误报）
PLACEHOLDER = re.compile(r"(your[-_]|example|dummy|test|placeholder|changeme|xxx+|<.*>|\{\{)", re.I)


# 动态构造痕迹：sink 处出现才说明可能有污点注入（拼接/格式化/插值）
INJECTION_MARKER = re.compile(
    r"""(\+|%[sd]?|\.format\s*\(|f['"]|`|\$\{|\{[a-zA-Z_]|\|\||\.\s*\+|"""   # 拼接/格式化/模板插值
    r"""%\s*\(|str\s*\(|\+\s*str|concat|\.join)""", re.I)


def has_source(text: str) -> bool:
    return any(p.search(text) for p in SOURCE_PATTERNS)


def has_sanitizer(text: str) -> bool:
    return any(p.search(text) for p in SANITIZER_PATTERNS)


def has_injection_marker(text: str) -> bool:
    """sink 行是否有动态构造痕迹（拼接/格式化）——静态字面量调用不算污点注入。"""
    return bool(INJECTION_MARKER.search(text))
