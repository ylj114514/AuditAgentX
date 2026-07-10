# -*- coding: utf-8 -*-
"""Java 函数级污点分析（AST 级，基于 javalang）。

补足正则「窗口级」污点追不到的 Java Web 典型链路：用户输入(source) 经多跳变量传播
（含 String 拼接、集合 add、for-each、类型转换）到达危险 sink，且中途未被净化。

为什么需要：OWASP BenchmarkJava 的用例把 source 放文件顶部、sink 放底部（常 >15 行），
且刻意经中间变量传播：
    param = request.getHeader(..)          // source
    ...
    String sql = "SELECT ... '" + param + "'";   // 拼接
    statement.executeQuery(sql);                  // sink（跨多行、跨变量）
其安全用例则用 `bar = cond ? "常量" : param` 三元打断污点——本模块据此做「污点断链」判定，
从而区分真漏洞与安全用例（而非见 sink 就报）。

覆盖类别：SQL 注入 / 命令注入 / 路径遍历 / XSS / Trust Boundary / LDAP 注入 / XPath 注入。
javalang 缺失或解析失败时优雅返回 []（不影响其它扫描器）。
"""
from __future__ import annotations

import logging

from backend.scanners.base import RawFinding

logger = logging.getLogger(__name__)

try:
    import javalang
    from javalang import tree as jt
    _AVAILABLE = True
except Exception:  # noqa: BLE001  javalang 未安装
    _AVAILABLE = False


# 用户可控输入来源（HttpServletRequest 及衍生）
SOURCE_MEMBERS = {
    "getParameter", "getParameterValues", "getParameterMap", "getParameterNames",
    "getHeader", "getHeaders", "getHeaderNames", "getQueryString",
    "getCookies", "getInputStream", "getReader", "getPathInfo", "getPathTranslated",
    "getRequestURI", "getRequestURL",
}
# 从已污染对象取值的传播型取值方法（仅当 qualifier 已污染才算）。
# 刻意【不含】集合的 get：安全用例惯用 put(污点)/add(污点) 后再 get(另一个安全键/下标)，
# 精确索引/键追踪超出轻量污点能力，纳入 get 会把这些安全用例误报（见 java_taint 校准）。
PROPAGATE_MEMBERS = {"getValue", "nextElement", "next", "toString", "trim",
                     "substring", "toLowerCase", "toUpperCase", "getBytes", "toCharArray"}

# 净化 / 编码方法：出现即视为该数据流被净化（断链）
SANITIZER_MEMBERS = {
    "encodeForHTML", "encodeForHTMLAttribute", "encodeForJavaScript", "encodeForCSS",
    "encodeForURL", "encodeForLDAP", "encodeForDN", "encodeForXPath", "encodeForXML",
    "encodeForXMLAttribute", "encodeForSQL", "encodeForOS", "encodeForBase64",
    "escapeHtml", "escapeHtml4", "escapeHtml3", "escapeEcmaScript", "escapeXml",
    "escapeXml10", "escapeXml11", "escapeSql", "escapeJava", "htmlEscape",
    "stripXSS", "cleanXSS", "filter",
}

# 各类 sink 的方法名 / 构造类型
SQL_MEMBERS = {"execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
               "prepareStatement", "prepareCall", "addBatch", "nativeSQL", "createQuery",
               "createNativeQuery", "createSQLQuery"}
CMD_MEMBERS = {"exec", "command"}
LDAP_MEMBERS = {"search"}
XPATH_MEMBERS = {"evaluate", "compile"}
TRUSTBOUND_MEMBERS = {"setAttribute", "putValue"}
PRINT_MEMBERS = {"print", "println", "write", "format", "printf", "append", "getOutputStream"}
PATH_TYPES = {"File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
              "RandomAccessFile", "PrintWriter"}
PATH_MEMBERS = {"newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter",
                "readAllBytes", "readAllLines", "readString", "copy", "getResourceAsStream"}
CMD_TYPES = {"ProcessBuilder"}
# 集合/构造器上的写入方法：参数被污染则容器被污染
CONTAINER_WRITE = {"add", "addAll", "put", "push", "offer", "set", "append", "insert"}


def available() -> bool:
    return _AVAILABLE


def _type_leaf(type_node) -> str:
    """把 ReferenceType 链（java.io.FileInputStream）取叶子名（FileInputStream）。"""
    name = getattr(type_node, "name", "") or ""
    sub = getattr(type_node, "sub_type", None)
    while sub is not None:
        name = getattr(sub, "name", name) or name
        sub = getattr(sub, "sub_type", None)
    return name


def _pos_line(node) -> int:
    """尽力取节点行号：自身 position 优先，否则在子树里找第一个有 position 的节点。"""
    pos = getattr(node, "position", None)
    if pos is not None:
        return pos.line
    try:
        for _, child in node.filter(jt.Node):
            cpos = getattr(child, "position", None)
            if cpos is not None:
                return cpos.line
    except Exception:  # noqa: BLE001
        pass
    return 0


def _qual_root(qualifier) -> str | None:
    if not qualifier:
        return None
    return str(qualifier).split(".")[0]


class _MethodTaint:
    """单个方法内的污点分析：计算污点变量集合 + 检出 sink。"""

    def __init__(self, method) -> None:
        self.method = method
        self.tainted: set[str] = set()
        # 「源容器」：直接来自 source 的集合/数组/枚举（如 request.getParameterMap()）。
        # 其整体用户可控，任意 get()/索引取值都视为污点——区别于本地容器
        # （安全用例惯用 put(污点) 后 get(另一个安全键)，故本地容器的 get 不传播）。
        self.source_containers: set[str] = set()

    # ---- 表达式是否被污染 ----
    def expr_tainted(self, node) -> bool:
        if node is None:
            return False
        if isinstance(node, jt.Literal):
            return False
        if isinstance(node, jt.MemberReference):
            root = _qual_root(node.qualifier)
            return node.member in self.tainted or (root in self.tainted if root else False)
        if isinstance(node, jt.MethodInvocation):
            members = [node.member] + [getattr(s, "member", None) for s in (node.selectors or [])]
            if any(m in SANITIZER_MEMBERS for m in members):
                return False                                   # 被编码/净化 -> 断链
            if any(m in SOURCE_MEMBERS for m in members):
                return True                                    # 直接取用户输入
            root = _qual_root(node.qualifier)
            if root and root in self.source_containers:
                return True                                    # 源容器任意取值均为污点
            if root and root in self.tainted and node.member in PROPAGATE_MEMBERS:
                return True                                    # 污染对象取值传播
            if any(self.expr_tainted(a) for a in (node.arguments or [])):
                return True                                    # 透传（如 URLDecoder.decode(param)）
            for s in node.selectors or []:
                if isinstance(s, jt.MethodInvocation) and any(
                        self.expr_tainted(a) for a in (s.arguments or [])):
                    return True
            return False
        if isinstance(node, jt.BinaryOperation):
            return self.expr_tainted(node.operandl) or self.expr_tainted(node.operandr)
        if isinstance(node, jt.TernaryExpression):
            # 任一可达分支带污点，表达式结果就可能带污点。旧逻辑只要一支是常量
            # 就整体断链，会漏掉 `flag ? "safe" : attackerInput`。
            return self.expr_tainted(node.if_true) or self.expr_tainted(node.if_false)
        if isinstance(node, jt.Cast):
            return self.expr_tainted(node.expression)
        if isinstance(node, jt.ClassCreator):
            return any(self.expr_tainted(a) for a in (node.arguments or []))
        if isinstance(node, jt.ArraySelector):
            return self.expr_tainted(getattr(node, "index", None))
        # 兜底：遍历直接子节点
        try:
            for _, child in node.filter(jt.Node):
                if child is node:
                    continue
                if isinstance(child, (jt.MemberReference, jt.MethodInvocation,
                                      jt.BinaryOperation)) and self.expr_tainted(child):
                    return True
        except Exception:  # noqa: BLE001
            pass
        return False

    def _add(self, name) -> bool:
        """加入污点集合。返回是否有变化。"""
        if name and name not in self.tainted:
            self.tainted.add(name)
            return True
        return False

    @staticmethod
    def _is_direct_source(expr) -> bool:
        """表达式整体是否为一次直接的 source 调用（如 request.getParameterMap()）。"""
        node = expr
        if isinstance(node, jt.Cast):
            node = node.expression
        if isinstance(node, jt.MethodInvocation):
            members = [node.member] + [getattr(s, "member", None) for s in (node.selectors or [])]
            return any(mm in SOURCE_MEMBERS for mm in members)
        return False

    def _collect_source_containers(self) -> None:
        m = self.method
        for _, decl in m.filter(jt.LocalVariableDeclaration):
            for d in decl.declarators:
                if self._is_direct_source(d.initializer):
                    self.source_containers.add(d.name)
        for _, asg in m.filter(jt.Assignment):
            tgt = asg.expressionl
            if isinstance(tgt, jt.MemberReference) and self._is_direct_source(asg.value):
                self.source_containers.add(tgt.member)

    # ---- 计算污点变量集合（不动点）----
    def compute_tainted(self) -> None:
        self._collect_source_containers()
        self.tainted |= self.source_containers
        m = self.method
        changed = True
        while changed:
            changed = False
            for _, decl in m.filter(jt.LocalVariableDeclaration):
                for d in decl.declarators:
                    if d.initializer is not None and self.expr_tainted(d.initializer):
                        changed |= self._add(d.name)
            for _, asg in m.filter(jt.Assignment):
                tgt = asg.expressionl
                name = getattr(tgt, "member", None) if isinstance(tgt, jt.MemberReference) else None
                if name and self.expr_tainted(asg.value):
                    changed |= self._add(name)
            for _, ctrl in m.filter(jt.EnhancedForControl):
                if self.expr_tainted(ctrl.iterable):
                    var = getattr(ctrl, "var", None)
                    for d in getattr(var, "declarators", []) or []:
                        changed |= self._add(d.name)
            for _, mi in m.filter(jt.MethodInvocation):
                if mi.member in CONTAINER_WRITE and mi.qualifier:
                    root = _qual_root(mi.qualifier)
                    if root and any(self.expr_tainted(a) for a in (mi.arguments or [])):
                        changed |= self._add(root)

    # ---- 检出 sink ----
    def find_sinks(self):
        results = []  # (vuln_type, severity, line, sink_desc)
        m = self.method
        for _, mi in m.filter(jt.MethodInvocation):
            member = mi.member
            args_tainted = any(self.expr_tainted(a) for a in (mi.arguments or []))
            if member in SQL_MEMBERS and args_tainted:
                results.append(("SQL Injection", "high", _pos_line(mi), member))
            elif member in CMD_MEMBERS and args_tainted:
                results.append(("Command Injection", "high", _pos_line(mi), member))
            elif member in LDAP_MEMBERS and args_tainted:
                results.append(("LDAP Injection", "high", _pos_line(mi), member))
            elif member in XPATH_MEMBERS and args_tainted:
                results.append(("XPath Injection", "high", _pos_line(mi), member))
            elif member in TRUSTBOUND_MEMBERS and args_tainted:
                results.append(("Trust Boundary Violation", "medium", _pos_line(mi), member))
            # XSS：response.getWriter().print/println/write/format(污点)
            if member == "getWriter":
                for s in mi.selectors or []:
                    if isinstance(s, jt.MethodInvocation) and s.member in PRINT_MEMBERS \
                            and any(self.expr_tainted(a) for a in (s.arguments or [])):
                        results.append(("XSS", "medium", _pos_line(mi), f"getWriter().{s.member}"))
        for _, cc in m.filter(jt.ClassCreator):
            leaf = _type_leaf(cc.type)
            if not any(self.expr_tainted(a) for a in (cc.arguments or [])):
                continue
            if leaf in PATH_TYPES:
                results.append(("Path Traversal", "medium", _pos_line(cc), f"new {leaf}"))
            elif leaf in CMD_TYPES:
                results.append(("Command Injection", "high", _pos_line(cc), f"new {leaf}"))
        return results


def analyze_java(rel: str, text: str) -> list[RawFinding]:
    """对单个 Java 文件做函数级污点分析，返回带数据流依据的 finding。"""
    if not _AVAILABLE:
        return []
    try:
        tree = javalang.parse.parse(text)
    except Exception:  # noqa: BLE001  语法/编码问题
        return []

    findings: list[RawFinding] = []
    seen: set[tuple] = set()
    for _, method in tree.filter(jt.MethodDeclaration):
        analyzer = _MethodTaint(method)
        analyzer.compute_tainted()
        if not analyzer.tainted:
            continue
        for vuln_type, sev, line, sink_desc in analyzer.find_sinks():
            key = (rel, vuln_type, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(RawFinding(
                type=vuln_type, file=rel, line=line or 0, severity=sev,
                source="custom-java-taint",
                code_snippet=sink_desc,
                message=(f"Java 函数级污点: 用户输入经方法 {method.name}() 内多跳传播到达 "
                         f"{sink_desc}（无有效净化）"),
                rule_id=f"java-taint-{vuln_type.lower().replace(' ', '-')}",
                extra={
                    "confidence": 0.8,
                    "analysis": "java-taint",
                    "method": method.name,
                    "sink": sink_desc,
                    "taint_flow": [
                        {"stage": "source", "detail": f"user input in {method.name}()"},
                        {"stage": "sink", "file": rel, "line": line, "detail": sink_desc},
                    ],
                },
            ))
    return findings
