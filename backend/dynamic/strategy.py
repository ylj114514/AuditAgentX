"""漏洞类型 → 动态验证策略映射（覆盖主流可动态验证漏洞）。

策略取值：
  http            : 适合对运行中的靶场发 HTTP 载荷验证
  harness         : 适合函数级 Fuzzing Harness 验证（无需靶场）
  both            : 两者都适用（优先 harness，有靶场再补 http）
  not_applicable  : 静态类漏洞，无运行时触发点，动态验证不适用（dynamic_not_applicable）

每条规则附：http_method / param_hint（HTTP 注入点候选）/ reason。
"""
from __future__ import annotations

HTTP = "http"
HARNESS = "harness"
BOTH = "both"
NOT_APPLICABLE = "not_applicable"

# 规则库：键为漏洞类型关键词（小写，子串匹配），值为策略描述
STRATEGY_RULES: dict[str, dict] = {
    # ---------------- 注入类 ----------------
    "sql injection": {"strategy": BOTH, "http_method": "GET",
                      "param_hint": ["id", "user", "search", "q", "order", "category"],
                      "reason": "可控参数拼入 SQL，可发注入载荷或函数级 mock 验证"},
    "nosql injection": {"strategy": BOTH, "http_method": "POST",
                        "param_hint": ["username", "query", "filter", "id"],
                        "reason": "NoSQL 查询拼接，可发对象注入载荷"},
    "ldap injection": {"strategy": HARNESS, "http_method": "GET",
                       "param_hint": ["user", "cn", "uid", "filter"],
                       "reason": "LDAP 过滤器拼接，函数级验证更稳"},
    "xpath injection": {"strategy": HARNESS, "http_method": "GET",
                        "param_hint": ["user", "name", "query"],
                        "reason": "XPath 表达式拼接"},
    "command injection": {"strategy": BOTH, "http_method": "GET",
                          "param_hint": ["host", "ip", "cmd", "target", "file", "domain"],
                          "reason": "参数拼入系统命令，harness mock 危险 sink 验证最可靠"},
    "code injection": {"strategy": HARNESS, "http_method": "POST",
                       "param_hint": ["code", "expr", "input", "data"],
                       "reason": "eval/exec 执行可控输入"},
    "ssti": {"strategy": BOTH, "http_method": "GET",
             "param_hint": ["name", "q", "input", "template", "msg"],
             "reason": "模板表达式注入，{{7*191}} 类载荷可 HTTP 或函数级验证"},
    "template injection": {"strategy": BOTH, "http_method": "GET",
                           "param_hint": ["name", "q", "template"],
                           "reason": "服务端模板注入"},
    # ---------------- 文件/路径类 ----------------
    "path traversal": {"strategy": BOTH, "http_method": "GET",
                       "param_hint": ["file", "path", "page", "template", "download", "name"],
                       "reason": "../ 目录穿越读取任意文件"},
    "lfi": {"strategy": BOTH, "http_method": "GET",
            "param_hint": ["file", "page", "include", "path"],
            "reason": "本地文件包含"},
    "rfi": {"strategy": HTTP, "http_method": "GET",
            "param_hint": ["file", "url", "page"],
            "reason": "远程文件包含（仅本地授权靶场）"},
    "arbitrary file upload": {"strategy": HTTP, "http_method": "POST",
                              "param_hint": ["file", "upload", "avatar", "attachment"],
                              "reason": "上传可执行脚本绕过校验"},
    "file upload": {"strategy": HTTP, "http_method": "POST",
                    "param_hint": ["file", "upload"],
                    "reason": "任意文件上传"},
    # ---------------- 请求伪造/重定向 ----------------
    "ssrf": {"strategy": HTTP, "http_method": "GET",
             "param_hint": ["url", "uri", "target", "callback", "webhook", "src", "image"],
             "reason": "诱导服务端请求任意地址（仅本地/云元数据探测）"},
    "open redirect": {"strategy": HTTP, "http_method": "GET",
                      "param_hint": ["url", "redirect", "next", "return", "returnUrl", "goto"],
                      "reason": "开放重定向到任意地址"},
    "crlf injection": {"strategy": HTTP, "http_method": "GET",
                       "param_hint": ["url", "redirect", "header"],
                       "reason": "CRLF 注入/响应拆分"},
    "host header injection": {"strategy": HTTP, "http_method": "GET",
                              "param_hint": ["host"],
                              "reason": "Host 头注入"},
    "cors misconfiguration": {"strategy": HTTP, "http_method": "GET",
                              "param_hint": ["origin"],
                              "reason": "CORS 配置不当"},
    # ---------------- XSS ----------------
    "xss": {"strategy": HTTP, "http_method": "GET",
            "param_hint": ["q", "search", "name", "comment", "message", "keyword"],
            "reason": "脚本注入，反射/存储型可 HTTP 验证"},
    "cross-site scripting": {"strategy": HTTP, "http_method": "GET",
                             "param_hint": ["q", "search", "name", "comment"],
                             "reason": "XSS"},
    # ---------------- 反序列化/XXE ----------------
    "insecure deserialization": {"strategy": HARNESS, "http_method": "POST",
                                 "param_hint": ["data", "obj", "payload", "session", "state"],
                                 "reason": "反序列化不可信数据，harness 触发 __reduce__ 验证"},
    "deserialization": {"strategy": HARNESS, "http_method": "POST",
                        "param_hint": ["data", "obj", "payload"],
                        "reason": "不安全反序列化"},
    "xxe": {"strategy": BOTH, "http_method": "POST",
            "param_hint": ["xml", "data", "body"],
            "reason": "XML 外部实体注入"},
    # ---------------- 访问控制 ----------------
    "idor": {"strategy": HTTP, "http_method": "GET",
             "param_hint": ["id", "uid", "user_id", "account", "order_id", "doc"],
             "reason": "越权访问对象，遍历 ID 验证"},
    "broken access control": {"strategy": HTTP, "http_method": "GET",
                              "param_hint": ["id", "role", "admin", "user"],
                              "reason": "访问控制缺陷"},
    "auth bypass": {"strategy": HTTP, "http_method": "POST",
                    "param_hint": ["user", "password", "token", "role"],
                    "reason": "认证绕过"},
    "mass assignment": {"strategy": HTTP, "http_method": "POST",
                        "param_hint": ["role", "is_admin", "id"],
                        "reason": "批量赋值污染"},
    # ---------------- 静态类：dynamic_not_applicable ----------------
    "hardcoded secret": {"strategy": NOT_APPLICABLE,
                         "reason": "静态类：源码硬编码密钥无运行时触发点，需人工核对密钥用途与影响面"},
    "hardcoded credential": {"strategy": NOT_APPLICABLE,
                             "reason": "静态类：硬编码凭证"},
    "secret": {"strategy": NOT_APPLICABLE, "reason": "静态类：敏感信息硬编码"},
    "weak crypto": {"strategy": NOT_APPLICABLE, "reason": "静态类：弱加密算法，配置层问题"},
    "weak hash": {"strategy": NOT_APPLICABLE, "reason": "静态类：弱哈希（MD5/SHA1）"},
    "insecure random": {"strategy": NOT_APPLICABLE, "reason": "静态类：不安全随机数"},
    "insecure configuration": {"strategy": NOT_APPLICABLE, "reason": "静态类：不安全配置"},
    "debug mode": {"strategy": NOT_APPLICABLE, "reason": "静态类：调试模式开启"},
    "sensitive data exposure": {"strategy": NOT_APPLICABLE, "reason": "静态类：敏感信息泄露"},
    "missing security header": {"strategy": NOT_APPLICABLE, "reason": "静态/被动类：缺失安全响应头"},
    "outdated dependency": {"strategy": NOT_APPLICABLE, "reason": "SCA 静态类：依赖已知漏洞（CVE）"},
    "cve": {"strategy": NOT_APPLICABLE, "reason": "SCA 静态类：依赖组件 CVE"},
}

# 别名归一（复用 exploit_templates 的思路）
_ALIASES = {
    "sqli": "sql injection", "rce": "command injection",
    "os command injection": "command injection", "command execution": "command injection",
    "directory traversal": "path traversal", "file inclusion": "lfi",
    "server-side request forgery": "ssrf", "server-side template injection": "ssti",
    "unsafe deserialization": "insecure deserialization",
    "broken object level authorization": "idor", "bola": "idor",
    "hardcoded password": "hardcoded credential",
}

# 默认策略（未匹配到规则时）：优先尝试 harness（函数级，无需靶场）
_DEFAULT = {"strategy": HARNESS, "http_method": "GET", "param_hint": ["id", "q", "input"],
            "reason": "未匹配专用规则，默认尝试函数级 Harness 验证"}


def resolve_strategy(vuln_type: str | None) -> dict:
    """按漏洞类型解析动态验证策略。返回 {strategy, http_method?, param_hint?, reason, matched}。"""
    if not vuln_type:
        return {**_DEFAULT, "matched": False, "vuln_type": vuln_type}
    key = vuln_type.strip().lower()
    if key in STRATEGY_RULES:
        return {**STRATEGY_RULES[key], "matched": True, "vuln_type": vuln_type}
    if key in _ALIASES:
        return {**STRATEGY_RULES[_ALIASES[key]], "matched": True, "vuln_type": vuln_type}
    for name, rule in STRATEGY_RULES.items():
        if name in key or key in name:
            return {**rule, "matched": True, "vuln_type": vuln_type}
    for alias, target in _ALIASES.items():
        if alias in key:
            return {**STRATEGY_RULES[target], "matched": True, "vuln_type": vuln_type}
    return {**_DEFAULT, "matched": False, "vuln_type": vuln_type}


def is_dynamic_applicable(vuln_type: str | None) -> bool:
    """该漏洞类型是否适合动态验证（False 即 dynamic_not_applicable）。"""
    return resolve_strategy(vuln_type)["strategy"] != NOT_APPLICABLE
