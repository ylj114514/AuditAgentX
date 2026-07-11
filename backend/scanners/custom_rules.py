"""自定义污点分析扫描器（离线兜底，升级自单行正则）。

升级点（借鉴 Semgrep taint mode）：
  旧版：单行匹配危险函数 -> 误报高（不管数据是否用户可控）。
  新版：source→sink 可达性分析 ——
    - 注入类 sink：按源码顺序追踪 source→变量赋值→实际 sink 参数，净化只对同一数据流生效。
    - 非注入类仅保留确定性模式；反序列化仍须证明不可信输入，弱哈希/随机须有安全上下文。

输出的 RawFinding.extra 携带污点证据：source_line / sanitized / confidence / taint_flow。
外部工具（Semgrep 等）缺失时，本扫描器保证离线也能给出「带数据流依据」的结果。
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from backend.scanners.base import (
    BaseScanner, RawFinding, plausible_secret_assignment, redact_secret_text,
)
from backend.repository.language_detector import scan_files
from backend.scanners import taint_rules as tr
from backend.scanners.interproc_taint import analyze_python_interproc
from backend.scanners.java_taint import analyze_java

logger = logging.getLogger(__name__)

# 赋值语句：同时捕获目标和表达式。兼容 PHP / Python / JS / Java / C# / Go / Ruby。
_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:const|let|var|final|val|var|auto|mut)\s+)?"
    r"(?:[A-Za-z_][\w<>\[\].,:?]*\s+)?"
    r"(\$?[A-Za-z_]\w*)\s*(?::=|=(?!=))\s*(.*)$"
)
# 标识符（含 PHP $ 前缀），用于从 sink 调用参数里提取传入的变量
_IDENT_RE = re.compile(r"\$?[A-Za-z_]\w*")

# 流敏感回溯上限；只看 sink 之前，并尽量截断到最近函数边界。
_FLOW_WINDOW = 80
_FUNCTION_BOUNDARY = re.compile(
    r"^\s*(?:async\s+)?(?:def|function|func|fn)\s+\w+|"
    r"^\s*(?:public|private|protected|internal|static|final|suspend|override)\b[^;{}]*\([^;{}]*\)\s*\{|"
    r"^\s*\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"
)
_SECURITY_CONTEXT = re.compile(
    r"password|passwd|credential|secret|token|session|auth|login|otp|nonce|csrf|"
    r"signature|signing|encrypt|decrypt|private.?key|api.?key|reset.?code|salt",
    re.I,
)

_THIRD_PARTY_ASSET_PARTS = {
    "third-party", "third_party", "vendor", "node_modules", "ueditor", "dplayer", "layui",
}


def _is_generated_or_third_party_asset(rel: str) -> bool:
    """Return True for generated/bundled frontend code that is not an editable source file."""
    normalized = str(rel or "").replace("\\", "/").lower()
    parts = {part for part in normalized.split("/") if part}
    name = normalized.rsplit("/", 1)[-1]
    return bool(parts & _THIRD_PARTY_ASSET_PARTS) or name.endswith((".min.js", ".bundle.js", ".map"))

_STRICT_PRIMARY_ARG_TYPES = {
    "SQL Injection", "NoSQL Injection", "LDAP Injection", "XPath Injection",
}

_DYNAMIC_HINTS = {
    "SQL Injection": "http_payload", "NoSQL Injection": "http_payload",
    "Command Injection": "harness_or_http", "Code Injection": "harness",
    "Path Traversal": "http_payload", "SSRF": "http_callback",
    "Server-Side Template Injection": "http_payload", "XSS": "browser_or_http",
    "Insecure Deserialization": "harness", "Open Redirect": "http_redirect",
    "LDAP Injection": "http_payload", "XPath Injection": "http_payload",
    "Regex Injection": "timing_probe", "Header Injection": "http_response",
}

_SINK_CALL_START = {
    "SQL Injection": re.compile(r"cursor\.execute|mysqli_query|executeQuery|db\.(?:Query|Exec)|\.execute|\.query|\.Raw", re.I),
    "Command Injection": re.compile(r"os\.system|subprocess\.|child_process\.|exec\.Command|shell_exec|passthru|proc_open|Kernel\.system", re.I),
    "Code Injection": re.compile(r"\beval\s*\(|new\s+Function|vm\.runIn|ScriptEngine\.eval", re.I),
    "Path Traversal": re.compile(r"\bopen\s*\(|file_get_contents|readfile|fopen|fs\.readFile|Files\.read|send_file", re.I),
    "SSRF": re.compile(r"requests\.|urlopen|httpx\.|axios\.|\bfetch\s*\(|curl_exec|http\.(?:Get|Post|Head)|Invoke-WebRequest", re.I),
    "XSS": re.compile(r"res\.(?:send|write|end)|Response\.Write|document\.write|render_template_string|raw\s*\(", re.I),
    "NoSQL Injection": re.compile(r"\.(?:find|findOne|find_one|aggregate|updateMany|deleteMany)\s*\(", re.I),
    "Open Redirect": re.compile(r"res\.redirect|Response\.Redirect|HttpResponseRedirect|RedirectResponse|\bredirect\s*\(", re.I),
    "Header Injection": re.compile(r"setHeader|addHeader|res\.set|Headers\.Add|\bheader\s*\(", re.I),
    "Log Injection": re.compile(r"logger?\.|logging\.|Log\.|tracing::", re.I),
    "Regex Injection": re.compile(r"re\.(?:compile|search|match)|new\s+RegExp|Pattern\.compile|Regex::new", re.I),
    "Insecure Deserialization": re.compile(r"pickle\.loads|yaml\.load|unserialize|Marshal\.load|BinaryFormatter\.Deserialize", re.I),
}


class CustomRuleScanner(BaseScanner):
    name = "custom"

    def available(self) -> bool:
        return True  # 纯 Python，永远可用

    def run(self, target: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        # 跨文件常量解析：先扫 .properties，得到「值为弱算法」的配置键（如 hashAlg1=MD5）。
        # 供后面识别 MessageDigest.getInstance(props.getProperty("hashAlg1")) 这类间接弱哈希/弱加密。
        weak_hash_keys, weak_crypto_keys = self._scan_weak_property_keys(target)
        for f in scan_files(target, max_files=getattr(self, "max_files", 20000)):
            rel = (f.relative_to(target).as_posix()
                   if target in f.parents or target == f.parent else f.name)
            if _is_generated_or_third_party_asset(rel):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines()
            suffix = f.suffix.lower()
            # Java 注入类污点由更精确的 AST 分析(java_taint)负责；正则窗口只保留非注入类
            # （弱加密/弱哈希/弱随机/密钥等字面量规则），避免粗糙窗口对 Java 引入 AST 已避免的误报。
            findings.extend(self._scan_file(rel, lines, skip_injection=(suffix == ".java")))
            # Python 文件额外做 AST 级跨函数（1-hop）污点分析，捕获窗口级追不到的跨函数链路
            if suffix == ".py":
                try:
                    findings.extend(analyze_python_interproc(rel, text))
                except Exception as e:  # noqa: BLE001  单文件分析失败不影响整体
                    logger.debug("跨函数污点分析失败 %s: %s", rel, e)
            # Java 文件做 AST 级函数内多跳污点分析（javalang），捕获正则窗口够不着的链路
            elif suffix == ".java":
                try:
                    findings.extend(analyze_java(rel, text))
                except Exception as e:  # noqa: BLE001
                    logger.debug("Java 污点分析失败 %s: %s", rel, e)
                if weak_hash_keys or weak_crypto_keys:
                    findings.extend(self._scan_indirect_weak_algo(
                        rel, lines, weak_hash_keys, weak_crypto_keys))
        return findings

    # 配置值里的弱哈希 / 弱加密算法
    _WEAK_HASH_VAL = re.compile(r"^\s*(MD2|MD4|MD5|SHA-?1)\b", re.I)
    _WEAK_CRYPTO_VAL = re.compile(r"\b(DES|DESede|RC2|RC4|Blowfish|ARCFOUR)\b|ECB", re.I)
    _GETPROP_RE = re.compile(r"""getProperty\s*\(\s*["']([^"']+)["']""")

    def _scan_weak_property_keys(self, target: Path) -> tuple[set[str], set[str]]:
        """扫 .properties 文件，返回 (值为弱哈希的键集合, 值为弱加密的键集合)。"""
        weak_hash: set[str] = set()
        weak_crypto: set[str] = set()
        if not target.is_dir():
            return weak_hash, weak_crypto
        for pf in target.rglob("*.properties"):
            try:
                for line in pf.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith(("#", "!")) or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key, val = key.strip(), val.strip()
                    if self._WEAK_HASH_VAL.match(val):
                        weak_hash.add(key)
                    elif self._WEAK_CRYPTO_VAL.search(val):
                        weak_crypto.add(key)
            except OSError:
                continue
        return weak_hash, weak_crypto

    def _scan_indirect_weak_algo(self, rel, lines, weak_hash_keys, weak_crypto_keys):
        """识别经 getProperty(弱算法键) 间接构造的弱哈希/弱加密（跨文件常量解析）。"""
        out: list[RawFinding] = []
        has_digest = any("MessageDigest" in ln for ln in lines)
        has_cipher = any(("Cipher" in ln or "KeyGenerator" in ln) for ln in lines)
        for idx, line in enumerate(lines, start=1):
            m = self._GETPROP_RE.search(line)
            if not m:
                continue
            key = m.group(1)
            if key in weak_hash_keys and has_digest:
                out.append(self._make(rel, idx, line, "Weak Hash", "medium",
                                      confidence=0.7, source_line=None, sanitized=False,
                                      note=f"MessageDigest 算法取自弱配置 {key}（跨文件常量解析）"))
            elif key in weak_crypto_keys and has_cipher:
                out.append(self._make(rel, idx, line, "Weak Cryptography", "medium",
                                      confidence=0.7, source_line=None, sanitized=False,
                                      note=f"Cipher 算法取自弱配置 {key}（跨文件常量解析）"))
        return out

    def _scan_file(self, rel: str, lines: list[str],
                   skip_injection: bool = False) -> list[RawFinding]:
        out: list[RawFinding] = []
        code_lines = _strip_comment_lines(lines)
        for idx, line in enumerate(code_lines, start=1):
            for vuln_type, base_sev, sink_re, require_source in tr.TAINT_SINKS:
                # skip_injection：注入类(require_source)交由更精确的 AST 污点分析处理
                if skip_injection and require_source:
                    continue
                if not sink_re.search(line):
                    continue
                finding = self._evaluate(rel, code_lines, idx, line, vuln_type,
                                         base_sev, require_source)
                if finding:
                    out.append(finding)
        return out

    def _evaluate(self, rel, lines, idx, line, vuln_type, base_sev, require_source):
        """对一个 sink 命中做污点评估，返回 RawFinding 或 None（判为噪音时）。"""
        if vuln_type == "XSS" and self._is_non_web_echo(rel, line):
            return None
        if (vuln_type == "Command Injection" and Path(rel).suffix.lower() == ".py"
                and re.search(r"^\s*(?:exec)\s*\(", line)):
            # Python exec 是代码执行，不是 OS 命令；由 Code Injection 规则单独归类。
            return None
        if vuln_type == "Command Injection" and self._safe_command_invocation(line):
            return None
        # 硬编码密钥：占位值直接跳过（降误报）
        if vuln_type == "Hardcoded Secret":
            plausible, _, _ = plausible_secret_assignment(line)
            if tr.PLACEHOLDER.search(line) or not plausible:
                return None

        # 非注入类：只把真正“存在即缺陷”的模式直接命中。弱哈希/弱随机必须结合
        # 安全上下文，否则常见 checksum、抽样、UI 随机数会制造大量误报。
        if not require_source:
            confidence = 0.7
            severity = base_sev
            if vuln_type in {"Weak Hash", "Weak Randomness"}:
                # 不能只看命中行，也不能“没有安全语境仍以低危上报”。取局部窗口确认
                # 是否涉及密码、会话、签名、令牌等安全用途；否则它只是 checksum/UI 随机。
                start = max(0, idx - 5)
                end = min(len(lines), idx + 4)
                security_window = "\n".join(lines[start:end])
                if not _SECURITY_CONTEXT.search(security_window):
                    return None
            return self._make(rel, idx, line, vuln_type, severity,
                              confidence=confidence, source_line=None, sanitized=False,
                              note="sink 本身即风险（非注入类）")

        flow = self._trace_flow(lines, idx, line, vuln_type)
        if not flow["tainted"]:
            # source-less 动态字符串不是注入漏洞。以前仍生成 low finding，会持续污染
            # LLM/验证候选池；现在直接抑制。
            return None
        if flow["sanitized"]:
            return None
        if vuln_type in _STRICT_PRIMARY_ARG_TYPES and not flow["primary_tainted"]:
            # 参数化 SQL 的第二参数可以是污点；只有查询/表达式主参数被污染才成立。
            return None

        source_line = flow["source_line"]
        confidence = 0.9 if source_line == idx else 0.82
        return self._make(rel, idx, line, vuln_type, base_sev,
                          confidence=confidence, source_line=source_line,
                          sanitized=False, note="user input (source) → dangerous sink，无有效净化")

    @classmethod
    def _trace_flow(cls, lines: list[str], idx: int, sink_line: str,
                    vuln_type: str) -> dict:
        """流敏感的轻量 source→assignment→sink 追踪。

        关键约束：只看 sink 之前；source/sanitizer 必须落在 sink 实际引用变量的数据
        依赖上。它不是完整编译器，但比“窗口里出现过某个词就算”更难被对抗样本欺骗。
        """
        start = cls._scope_start(lines, idx)
        tainted: dict[str, int] = {}
        sanitized: set[str] = set()
        dynamic: set[str] = set()
        for off in range(start, idx - 1):
            m = _ASSIGN_RE.match(lines[off])
            if not m:
                continue
            target, expr = m.group(1), m.group(2)
            refs = set(_IDENT_RE.findall(expr))
            deps = refs & set(tainted)
            if tr.has_sanitizer(expr):
                tainted.pop(target, None)
                sanitized.add(target)
                dynamic.discard(target)
                continue
            if tr.has_source(expr):
                tainted[target] = off + 1
                sanitized.discard(target)
            elif deps:
                tainted[target] = min(tainted[name] for name in deps)
                sanitized.discard(target)
            else:
                tainted.pop(target, None)
                sanitized.discard(target)
            if tr.has_injection_marker(expr) or any(name in dynamic for name in deps):
                dynamic.add(target)
            else:
                dynamic.discard(target)

        primary = cls._data_argument(sink_line, vuln_type)
        sink_vars = set(_IDENT_RE.findall(primary))
        direct_source = tr.has_source(primary)
        direct_sanitized = tr.has_sanitizer(primary)
        reaching = sink_vars & set(tainted)
        sanitized_reaching = sink_vars & sanitized
        source_line = idx if direct_source else (
            min((tainted[name] for name in reaching), default=None)
        )

        primary_tainted = (
            (tr.has_source(primary) and not tr.has_sanitizer(primary))
            or bool(reaching)
        )
        return {
            "tainted": (direct_source and not direct_sanitized) or bool(reaching),
            "sanitized": direct_sanitized or (not reaching and bool(sanitized_reaching)),
            "source_line": source_line,
            "primary_tainted": primary_tainted,
            "dynamic": tr.has_injection_marker(sink_line) or bool(reaching & dynamic),
        }

    @staticmethod
    def _scope_start(lines: list[str], idx: int) -> int:
        lower = max(0, idx - 1 - _FLOW_WINDOW)
        for off in range(idx - 2, lower - 1, -1):
            if _FUNCTION_BOUNDARY.search(lines[off]):
                return off
        return lower

    @staticmethod
    def _arguments(line: str) -> list[str]:
        """轻量拆分调用参数，保留字符串和嵌套括号。"""
        if "(" not in line:
            return [line]
        text = line.split("(", 1)[1]
        quote = None
        depth = 0
        escaped = False
        out: list[str] = []
        args: list[str] = []
        for char in text:
            if escaped:
                out.append(char); escaped = False; continue
            if char == "\\" and quote:
                out.append(char); escaped = True; continue
            if quote:
                out.append(char)
                if char == quote:
                    quote = None
                continue
            if char in "'\"`":
                quote = char; out.append(char)
            elif char in "([{":
                depth += 1; out.append(char)
            elif char in ")]}" and depth:
                depth -= 1; out.append(char)
            elif char == "," and depth == 0:
                args.append("".join(out)); out = []
            elif char == ")" and depth == 0:
                break
            else:
                out.append(char)
        if out:
            args.append("".join(out))
        return args or [line]

    @classmethod
    def _data_argument(cls, line: str, vuln_type: str = "") -> str:
        """返回真正承载危险数据的参数，避免把 SQL bind/body/mode 当成 sink 输入。"""
        if vuln_type == "XSS" and re.search(
                r"\becho\b|innerHTML|<%=|\|\s*safe|dangerouslySetInnerHTML", line, re.I):
            return line
        if vuln_type == "SQL Injection" and re.search(r"CommandText\s*=", line, re.I):
            return line.split("=", 1)[1]
        candidate = line
        start = _SINK_CALL_START.get(vuln_type)
        match = start.search(line) if start else None
        if match:
            candidate = line[match.start():]
        args = cls._arguments(candidate)
        lowered = candidate.lower()
        if ("mysqli_query" in lowered or "mysqli_real_query" in lowered) and len(args) > 1:
            return args[1]
        if "pg_query" in lowered and len(args) > 1:
            return args[1]
        if vuln_type == "Command Injection" and re.search(
                r"exec\.Command|Command::new|Process\.(?:run|start)", line, re.I):
            return ",".join(args)
        return args[0]

    @staticmethod
    def _safe_command_invocation(line: str) -> bool:
        """识别不经 shell 的 argv 调用，避免把普通参数传递误报成命令注入。"""
        lowered = line.lower()
        if re.search(r"subprocess\.(?:run|call|popen)\s*\(\s*\[", line, re.I):
            return "shell=true" not in lowered.replace(" ", "")
        if "exec.command" in lowered:
            # Go exec.Command 只有显式进入 shell -c / cmd /c 时按命令注入处理。
            return not bool(re.search(
                r"exec\.Command(?:Context)?\s*\([^\n]*(?:['\"](?:sh|bash|zsh|cmd|powershell)['\"])"
                r"[^\n]*(?:['\"](?:-c|/c|command)['\"])", line, re.I))
        if "child_process.spawn" in lowered:
            return "shell" not in lowered or "shell: false" in lowered
        return False

    @staticmethod
    def _is_non_web_echo(rel: str, line: str) -> bool:
        suffix = Path(rel).suffix.lower()
        if suffix in {".php", ".phtml", ".html", ".htm", ".jsx", ".tsx", ".vue", ".erb"}:
            return False
        lowered = line.lower()
        return any(token in lowered for token in ("echo ", "printf(", "logger ", "cat "))

    @staticmethod
    def _make(rel, idx, line, vuln_type, sev, *, confidence, source_line,
              sanitized, note) -> RawFinding:
        taint_flow = []
        if source_line is not None:
            taint_flow.append({"stage": "source", "file": rel, "line": source_line})
        taint_flow.append({"stage": "sink", "file": rel, "line": idx})
        snippet = line.strip()[:200]
        if vuln_type == "Hardcoded Secret":
            snippet = redact_secret_text(snippet)
        return RawFinding(
            type=vuln_type, file=rel, line=idx, severity=sev, source="custom-taint",
            code_snippet=snippet,
            message=f"污点分析: {vuln_type} —— {note}",
            rule_id=f"taint-{vuln_type.lower().replace(' ', '-')}",
            extra={
                "confidence": confidence,
                "source_line": source_line,
                "sanitized": sanitized,
                "taint_flow": taint_flow,
                "analysis": "taint",
                "dynamic_verification": _DYNAMIC_HINTS.get(vuln_type),
            },
        )


def _strip_comment_lines(lines: list[str]) -> list[str]:
    """Blank comment text while preserving line numbers for findings."""
    cleaned: list[str] = []
    in_block = False
    for original in lines:
        line = original
        output = ""
        cursor = 0
        while cursor < len(line):
            if in_block:
                end = line.find("*/", cursor)
                if end < 0:
                    cursor = len(line)
                    break
                in_block = False
                cursor = end + 2
                continue
            start = line.find("/*", cursor)
            if start < 0:
                output += line[cursor:]
                break
            output += line[cursor:start]
            in_block = True
            cursor = start + 2
        stripped = output.lstrip()
        if stripped.startswith(("//", "#", "*", "<!--")):
            output = ""
        cleaned.append(output)
    return cleaned
