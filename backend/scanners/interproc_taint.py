# -*- coding: utf-8 -*-
"""文件内跨函数污点分析（AST 级，1-hop inter-procedural）。

补足窗口级/单函数污点追不到的链路：
    用户输入(source) → 传给另一个函数的参数 → 该函数内部把该参数拼进危险 sink。

例（现有窗口级会漏）：
    def handler(request):
        uid = request.args.get('id')     # source
        run_query(uid)                   # 跨函数传参
    def run_query(x):
        cur.execute("SELECT * FROM u WHERE id=" + x)   # sink，x 是被污染的参数

仅对 Python 用 AST 精确分析；其它语言仍由正则污点扫描器覆盖。作为 custom 扫描器的补充 pass，
产出带 analysis="interproc-taint" 的独立 finding。
"""
from __future__ import annotations

import ast
import re

from backend.scanners.base import RawFinding
from backend.scanners import taint_rules as tr


def _call_name(node: ast.Call) -> str | None:
    try:
        return ast.unparse(node.func)
    except Exception:  # noqa: BLE001
        return None


def _match_sink(node: ast.Call) -> tuple[str, str] | None:
    """调用是否命中「注入类」危险 sink；命中返回 (vuln_type, sink_name)。"""
    name = _call_name(node)
    if not name:
        return None
    probe = name + "("
    for vuln_type, _sev, rx, require_source in tr.TAINT_SINKS:
        if require_source and rx.search(probe):
            return vuln_type, name
    return None


def _params_of(fn: ast.AST) -> list[str]:
    args = getattr(fn, "args", None)
    if not args:
        return []
    names = [a.arg for a in list(args.args) + list(getattr(args, "kwonlyargs", []))]
    if args.vararg:
        names.append(args.vararg.arg)
    return names


def _sink_reaching_params(fn: ast.AST) -> dict[str, tuple[str, str, int]]:
    """函数内：哪些【形参】被以拼接/格式化方式送进危险 sink（参数化调用不算，避免误报）。"""
    params = set(_params_of(fn))
    reaching: dict[str, tuple[str, str, int]] = {}
    if not params:
        return reaching
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        sink = _match_sink(node)
        if not sink:
            continue
        for arg in node.args:
            try:
                src = ast.unparse(arg)
            except Exception:  # noqa: BLE001
                continue
            if not tr.has_injection_marker(src):     # 必须是拼接/格式化上下文
                continue
            for p in params:
                if re.search(r"\b" + re.escape(p) + r"\b", src):
                    reaching[p] = (sink[0], sink[1], node.lineno)
    return reaching


def _tainted_vars(fn: ast.AST) -> set[str]:
    """函数内：被用户输入(source)污染的局部变量（含经其它污染变量传播，取不动点）。"""
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)]
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for a in assigns:
            try:
                src = ast.unparse(a.value)
            except Exception:  # noqa: BLE001
                continue
            if tr.has_source(src) or any(
                    re.search(r"\b" + re.escape(t) + r"\b", src) for t in tainted):
                for tgt in a.targets:
                    if isinstance(tgt, ast.Name) and tgt.id not in tainted:
                        tainted.add(tgt.id)
                        changed = True
    return tainted


def _arg_is_tainted(arg: ast.AST, tainted: set[str]) -> bool:
    if isinstance(arg, ast.Name) and arg.id in tainted:
        return True
    try:
        return tr.has_source(ast.unparse(arg))
    except Exception:  # noqa: BLE001
        return False


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return ""


def analyze_python_interproc(rel: str, text: str) -> list[RawFinding]:
    """对单个 Python 文件做 1-hop 跨函数污点分析，返回跨函数漏洞 finding。"""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    funcs = {n.name: n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if len(funcs) < 2:
        return []

    sink_params = {name: _sink_reaching_params(fn) for name, fn in funcs.items()}
    callee_params = {name: _params_of(fn) for name, fn in funcs.items()}

    findings: list[RawFinding] = []
    seen: set[tuple] = set()
    for caller, fn in funcs.items():
        tainted = _tainted_vars(fn)
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            callee = node.func.id
            reaching = sink_params.get(callee)
            if not reaching or callee == caller:
                continue
            cparams = callee_params.get(callee, [])
            for i, arg in enumerate(node.args):
                pname = cparams[i] if i < len(cparams) else None
                if pname not in reaching:
                    continue
                if not _arg_is_tainted(arg, tainted):
                    continue
                vuln_type, sink_name, sink_line = reaching[pname]
                key = (rel, node.lineno, callee, pname)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(RawFinding(
                    type=vuln_type, file=rel, line=node.lineno, severity="high",
                    source="custom-interproc",
                    code_snippet=_safe_unparse(node)[:200],
                    message=(f"跨函数污点: 用户输入经 {caller}() 传入 {callee}() 的参数 "
                             f"'{pname}'，在 {callee}() 内到达 {sink_name}"),
                    rule_id=f"interproc-{vuln_type.lower().replace(' ', '-')}",
                    extra={
                        "confidence": 0.8,
                        "analysis": "interproc-taint",
                        "caller": caller, "callee": callee, "param": pname,
                        "sink": sink_name, "sink_line": sink_line,
                        "taint_flow": [
                            {"stage": "source", "file": rel, "detail": f"user input in {caller}()"},
                            {"stage": "cross_function_call", "file": rel, "line": node.lineno,
                             "detail": f"{caller}() -> {callee}('{pname}')"},
                            {"stage": "sink", "file": rel, "line": sink_line, "detail": sink_name},
                        ],
                    },
                ))
    return findings
