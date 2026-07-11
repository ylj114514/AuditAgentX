"""轻量污点分析规则库（source / sink / sanitizer 定义）。

污点分析核心思想（借鉴 Semgrep taint mode）：
  漏洞 = 用户可控输入(source) 经数据流到达危险函数(sink) 且中途未被净化(sanitizer)。

单行正则只看 sink，误报高；这里把 source/sink/sanitizer 分开定义，
供 custom scanner 做顺序和变量敏感的 source→sink 可达性判断。
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
    # 环境变量通常由部署者控制，不默认视为攻击者输入；否则配置 URL/命令会大量误报。
    re.compile(r"\b(scanf|fgets|gets)\b|argv\[", re.I),                         # C/命令行
    re.compile(r"r\.(URL\.Query|FormValue|PostFormValue|Form|Header\.Get)|"
               r"\bc\.(Query|Param|PostForm|DefaultQuery)\b|mux\.Vars|ps\.ByName", re.I),  # Go(net/http/gin/mux)
    re.compile(r"cookies\s*\[|request\.(parameters|env)\b|params\.require|params\.permit", re.I),  # Ruby(Rails 补充)
    re.compile(r"Request\.(QueryString|Form|Params|Cookies|Headers|Body|RawUrl|Files)|"
               r"Request\s*\[", re.I),                                          # C#/ASP.NET
    re.compile(r"req\.(query|get|content)\b|request\.query\b", re.I),           # Swift/Vapor
    re.compile(r"request\.url\.queryParameters|request\.readAsString|req\.params", re.I),  # Dart
    re.compile(r"web::(?:Query|Form)|HttpRequest\.query_string|axum::extract::Query|"
               r"rocket::form::Form", re.I),                                    # Rust Web
    re.compile(r"request\.(getQueryString|body)|conn\.params|get_req_header", re.I),  # Scala/Elixir
    re.compile(r"CGI\s*->\s*param|ngx\.var\.arg_|ngx\.req\.get_body_data", re.I),  # Perl/Lua
    re.compile(r"\binput\$[A-Za-z_]|\$Request\.(Query|Body|Headers|Params)", re.I),   # R/PowerShell
]

# 净化器（sanitizer）：出现则大幅降低可利用性
SANITIZER_PATTERNS = [
    # 注意：不用裸 "param"（会误伤 getParameter/@RequestParam 这类 source），改用 parameteriz*
    re.compile(r"(escape|sanitiz|quote|parameteriz|prepare|bind_param|placeholder)", re.I),
    re.compile(r"(int|float|str2int|parseInt|Number)\s*\(", re.I),             # 类型转换
    re.compile(r"(secure_filename|basename|realpath|normpath|abspath)", re.I),  # 路径净化
    re.compile(r"(htmlspecialchars|htmlentities|encodeURI|escapeHtml)", re.I),  # 输出编码
    re.compile(r"re\.escape|shlex\.quote", re.I),
    re.compile(r"allow\s*list|whitelist|is_valid|validate", re.I),
    re.compile(r"html\.EscapeString|template\.HTMLEscape|strconv\.(Atoi|Itoa|Parse)|"
               r"CGI\.escape|ERB::Util|Shellwords|\.to_i\b|\.to_f\b", re.I),      # Go/Ruby
]

# (漏洞类型, 严重级, sink 正则, [是否需要 source 才成立])
# require_source=True：SQL/命令/路径/SSRF 等注入类必须有 source 才算高危
# require_source=False：硬编码密钥、明确关闭安全校验等确定性配置问题
TAINT_SINKS: list[tuple[str, str, re.Pattern, bool]] = [
    ("SQL Injection", "high", re.compile(
        r"((cursor\.execute|\.execute|\.query|db\.query|mysqli_query|->query|"
        r"executeQuery|createStatement|"
        r"db\.(Query|Exec|QueryRow)|\.Raw|find_by_sql|\.where|"
        r"Execute(?:Reader|NonQuery|Scalar)|new\s+SqlCommand)\s*\(|"
        r"CommandText\s*=)", re.I), True),  # +Go(database/sql/gorm) +Ruby(ActiveRecord) +C#(ADO.NET)
    ("Command Injection", "high", re.compile(
        r"(os\.system|subprocess\.(call|run|Popen|check_output)|commands\.getoutput|"
        r"shell_exec|passthru|proc_open|popen|(?<![\w.])exec|Runtime\.getRuntime\(\)\.exec|"
        r"child_process\.(exec|execSync|spawn)|"
        r"exec\.Command(?:Context)?|Open3\.\w+|IO\.popen|Kernel\.system|\bsystem|%x|"
        r"Command::new|std::process::Command|Process\.run|Process\.start|Invoke-Expression)\s*\(", re.I), True),
    ("Code Injection", "critical", re.compile(
        r"((?<![\w.])eval|new\s+Function|vm\.runIn(?:This|New)Context|"
        r"ScriptEngine\.eval|GroovyShell\.evaluate|Code\.eval_string|loadstring)\s*\(", re.I), True),
    ("Path Traversal", "medium", re.compile(
        r"(open|file_get_contents|readfile|fopen|include|require|include_once|"
        r"require_once|fs\.readFile|Files\.read|new\s+File|"
        r"os\.(Open|ReadFile)|ioutil\.ReadFile|http\.ServeFile|File\.read|IO\.read|send_file)\s*\(", re.I), True),  # +Go +Ruby
    ("SSRF", "medium", re.compile(
        r"(requests\.(get|post|put|delete)|urllib\.request\.urlopen|urlopen|"
        r"httpx\.(get|post)|axios\.(get|post)|fetch|curl_exec|file_get_contents|"
        r"HttpClient|URLConnection|"
        r"http\.(Get|Post|Head|NewRequest)|net\.Dial|Net::HTTP\.\w+|"
        r"reqwest::(?:get|Client)|ureq::(?:get|post)|URLSession\.shared\.dataTask|"
        r"Invoke-WebRequest|Invoke-RestMethod)\s*\(", re.I), True),
    ("Server-Side Template Injection", "high", re.compile(
        r"(render_template_string|Template\s*\(|env\.from_string|Twig|Handlebars\.compile|"
        r"\.render\s*\(|ERB\.new|Liquid::Template\.parse)", re.I), True),  # +Ruby(ERB/Liquid)
    ("XSS", "medium", re.compile(
        # 注意：不用裸 print（会误伤 C printf / Java println / Python print，在 C/CLI 项目里
        # 把普通标准输出大量误报成 XSS）；echo 加词边界，只当 PHP/模板输出看待。
        r"(innerHTML|document\.write|render_template_string|\|\s*safe|"
        r"dangerouslySetInnerHTML|\becho\b|"
        r"\.html_safe|raw\s*\(|template\.HTML\s*\(|"
        r"res\.(?:send|write|end)\s*\(|"                                         # Node/Express 响应写出
        r"\bw\.Write\s*\(|fmt\.Fprint(?:f|ln)?\s*\(\s*w\b|"                       # Go http.ResponseWriter
        r"Response\.Write\s*\(|HttpContext[^;\n]*Response|<%=)\s*", re.I), True),  # C#/ASP.NET
    ("NoSQL Injection", "high", re.compile(
        r"(\.(?:find|findOne|find_one|aggregate|updateMany|deleteMany)\s*\(|"
        r"MongoCollection[^;\n]*\.(?:Find|Aggregate)\s*\()", re.I), True),
    ("LDAP Injection", "high", re.compile(
        r"(DirContext\.search|LdapTemplate\.search|ldap_search|\.search_s|LDAPConnection\.search)\s*\(", re.I), True),
    ("XPath Injection", "high", re.compile(
        r"(XPathExpression\.compile|XPath\.compile|xpath\.evaluate|selectNodes|selectSingleNode)\s*\(", re.I), True),
    ("Open Redirect", "medium", re.compile(
        r"((?<![\w.])redirect|res\.redirect|Response\.Redirect|HttpResponseRedirect|"
        r"RedirectResponse|redirect_to)\s*\(", re.I), True),
    ("Header Injection", "medium", re.compile(
        r"(setHeader|addHeader|res\.set|Response\.Headers\.Add|(?<![\w.])header)\s*\(", re.I), True),
    ("Log Injection", "low", re.compile(
        r"(logger?\.(?:info|warn|warning|error|debug|fatal)|logging\.(?:info|warning|error|debug)|"
        r"Log\.(?:d|i|w|e)|tracing::(?:info|warn|error))\s*[!(]", re.I), True),
    ("Regex Injection", "medium", re.compile(
        r"(re\.(?:compile|search|match)|new\s+RegExp|Pattern\.compile|Regex::new|Regex\s*\()", re.I), True),
    ("Insecure Deserialization", "high", re.compile(
        r"(pickle\.loads|cPickle\.loads|yaml\.load\s*\((?!.*Loader)|unserialize|"
        r"ObjectInputStream|readObject|marshal\.loads|__reduce__|"
        r"Marshal\.load\b|YAML\.load\b|Oj\.load|BinaryFormatter\.Deserialize|"
        r"ObjectInputStream\.readObject)\s*", re.I), True),
    ("Hardcoded Secret", "high", re.compile(
        r"""(password|passwd|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)"""
        r"""\s*[=:]\s*['"][^'"]{6,}['"]""", re.I), False),
    # 弱哈希（CWE-328）：Java MessageDigest/DigestUtils + PHP/JS/Python/Ruby 直接哈希函数
    ("Weak Hash", "medium", re.compile(
        r"""(MessageDigest\.getInstance\s*\(\s*"(?:MD2|MD4|MD5|SHA-?1)"|"""
        r"""DigestUtils\.(?:md5|sha1|getMd5|getSha1|md5Hex|sha1Hex)|"""
        r"""\bmd5\s*\(|\bsha1\s*\(|hashlib\.(?:md5|sha1)\s*\(|"""
        r"""crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]|"""
        r"""Digest::(?:MD5|SHA1)\b|md5\.New\s*\(|sha1\.New\s*\()""", re.I), False),
    # 弱加密算法（CWE-327）：Java Cipher/KeyGenerator 弱算法(DES/RC4/ECB) + 其它语言
    ("Weak Cryptography", "medium", re.compile(
        r"""((?:Cipher|KeyGenerator|SecretKeyFactory)\.getInstance\s*\(\s*"""
        r""""(?:DES|DESede|RC2|RC4|Blowfish|ARCFOUR)(?:[/"]|$)|"""              # Java 弱 cipher（前缀）
        r"""(?:Cipher|SecretKeyFactory)\.getInstance\s*\(\s*"[^"]*ECB[^"]*"|"""  # 任意含 ECB 模式
        r"""\bDES\b\s*\(|\bRC4\b\s*\(|mcrypt_encrypt|createCipheriv\s*\(\s*['"](?:des|rc4)|"""
        r"""crypto/des|crypto/rc4)""", re.I), False),
    # 不安全 Cookie（CWE-614）：显式关闭 Secure 标志，Cookie 可经明文 HTTP 泄露
    ("Insecure Cookie", "low", re.compile(
        r"""(setSecure\s*\(\s*false\s*\)|"""                                     # Java: cookie.setSecure(false)
        r"""SESSION_COOKIE_SECURE\s*[=:]\s*False|"""                             # Django/Flask 配置
        r"""cookie[^;\n]*secure\s*[:=]\s*false)""", re.I), False),               # JS/通用 secure:false
    # 弱随机（CWE-330）：安全敏感场景用非加密级 RNG；显式排除 SecureRandom
    ("Weak Randomness", "medium", re.compile(
        r"""(new\s+(?:java\.util\.)?Random\b|"""                                 # Java new Random()
        r"""\bMath\.random\s*\(|"""                                              # Java/JS Math.random()
        r"""\bmt_rand\s*\(|\brand\s*\(\s*\)|\bmt_srand\s*\(|"""                   # PHP
        r"""math/rand|\brandom\.(?:random|randint|randrange|choice)\s*\()""", re.I), False),
    ("TLS Certificate Validation Disabled", "high", re.compile(
        r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
        r"CERT_NONE|ServerCertificateValidationCallback\s*=\s*.*true", re.I), False),
    ("JWT Signature Verification Disabled", "critical", re.compile(
        r"verify_signature['\"]?\s*[:=]\s*False|algorithms?\s*[:=]\s*['\"]none['\"]|"
        r"verify\s*:\s*false[^\n]*jwt", re.I), False),
    ("Debug Mode Enabled", "low", re.compile(
        r"\bDEBUG\s*[=:]\s*(True|true|1)\b|app\.run\s*\([^\n]*debug\s*=\s*True", re.I), False),
    ("Permissive CORS", "low", re.compile(
        r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|"
        r"Access-Control-Allow-Origin\s*[:=]\s*['\"]\*", re.I), False),
]

# 硬编码密钥的占位值（是则判为疑似误报）
PLACEHOLDER = re.compile(r"(your[-_]|example|dummy|test|placeholder|changeme|xxx+|<.*>|\{\{)", re.I)


# 动态构造痕迹：sink 处出现才说明可能有污点注入（拼接/格式化/插值）
# 覆盖 Python(+/f-string/%/format) / PHP(. 拼接) / JS(模板 `${}`/+) / Java(+/String.format/concat)
INJECTION_MARKER = re.compile(
    r"""(\+|%[sd]?|\.format\s*\(|f['"]|`|\$\{|\{[a-zA-Z_]|\|\||\.\s*\+|"""   # 拼接/格式化/模板插值
    r"""%\s*\(|str\s*\(|\+\s*str|concat|\.join|"""
    r"""\.\s*\$|\$\w+\s*\.|['"]\s*\.\s*[\$'"A-Za-z_])""",                    # PHP 点号字符串拼接
    re.I)


def has_source(text: str) -> bool:
    return any(p.search(text) for p in SOURCE_PATTERNS)


def has_sanitizer(text: str) -> bool:
    return any(p.search(text) for p in SANITIZER_PATTERNS)


def has_injection_marker(text: str) -> bool:
    """sink 行是否有动态构造痕迹（拼接/格式化）——静态字面量调用不算污点注入。"""
    return bool(INJECTION_MARKER.search(text))
