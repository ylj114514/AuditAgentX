"""跨文件符号解析（Vulnhuntr 式调用链补全的底层能力）。

给定一个符号名（函数/类/变量），在项目源码里找到它的定义并返回源码，
让审计智能体能从"命中点"递归向其他文件索要上下文，拼出 用户输入→sink 的完整调用链。

实现：Python 用标准库 ast 精确解析；其他语言用正则兜底。不引入第三方依赖，离线可用。
"""
from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}
SRC_EXT = {".py", ".js", ".ts", ".php", ".java", ".go", ".rb"}


@lru_cache(maxsize=64)
def _index_python_defs(root_str: str) -> tuple:
    """扫描项目所有 .py，建立 {符号名: [(file, start_line, end_line)]} 索引。"""
    root = Path(root_str)
    index: dict[str, list[tuple[str, int, int]]] = {}
    for f in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        try:
            source = f.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        rel = f.relative_to(root).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                end = getattr(node, "end_lineno", node.lineno + 1)
                index.setdefault(node.name, []).append((rel, node.lineno, end))
    # dict 不可哈希，返回可缓存的 items 元组
    return tuple((name, tuple(locs)) for name, locs in index.items())


def _get_index(root: Path) -> dict[str, list[tuple[str, int, int]]]:
    return {name: list(locs) for name, locs in _index_python_defs(str(root.resolve()))}


def resolve_symbol(code_root: Path | None, symbol: str, *,
                   max_defs: int = 3, max_lines: int = 60) -> dict:
    """在项目中查找符号定义，返回其源码。

    Returns
    -------
    {found, symbol, definitions: [{file, start_line, end_line, code}], count}
    """
    result = {"found": False, "symbol": symbol, "definitions": [], "count": 0}
    if not code_root or not symbol or not Path(code_root).exists():
        return result
    root = Path(code_root)
    symbol = symbol.strip()

    # 1) Python ast 精确索引
    index = _get_index(root)
    locs = index.get(symbol, [])

    # 2) 其他语言 / ast 未命中：正则兜底跨文件搜定义
    if not locs:
        locs = _regex_search_defs(root, symbol, max_defs)

    for rel, start, end in locs[:max_defs]:
        fp = root / rel
        try:
            lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        s = max(0, start - 1)
        e = min(len(lines), min(end, start + max_lines))
        result["definitions"].append({
            "file": rel, "start_line": start, "end_line": e,
            "code": "\n".join(lines[s:e]),
        })
    result["count"] = len(result["definitions"])
    result["found"] = result["count"] > 0
    return result


def _regex_search_defs(root: Path, symbol: str, limit: int) -> list[tuple[str, int, int]]:
    """跨文件正则搜函数/类/方法定义（多语言兜底）。"""
    sym = re.escape(symbol)
    patterns = [
        re.compile(rf"\b(?:def|function|func|class|sub)\s+{sym}\b"),   # py/js/go/php/java
        re.compile(rf"\b{sym}\s*(?:=|:)\s*(?:function|async|\()"),      # js 赋值式
        re.compile(rf"(?:public|private|protected|static).*\b{sym}\s*\("),  # java/php 方法
    ]
    found: list[tuple[str, int, int]] = []
    scanned = 0
    for f in root.rglob("*"):
        if len(found) >= limit or scanned > 4000:
            break
        if f.is_dir() or any(part in SKIP_DIRS for part in f.parts):
            continue
        if f.suffix.lower() not in SRC_EXT:
            continue
        scanned += 1
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        rel = f.relative_to(root).as_posix()
        for i, line in enumerate(lines, start=1):
            if any(p.search(line) for p in patterns):
                found.append((rel, i, i + 40))
                break
    return found


def extract_referenced_symbols(code_snippet: str, *, limit: int = 12) -> list[str]:
    """从代码片段提取被调用/引用的符号名（函数调用、类实例化），供递归补全。"""
    if not code_snippet:
        return []
    # 匹配 name( 形式的调用；过滤语言关键字与常见内置
    calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(", code_snippet)
    stop = {"if", "for", "while", "return", "print", "len", "str", "int", "dict",
            "list", "set", "range", "super", "isinstance", "open", "format",
            "function", "def", "class", "switch", "catch", "require", "import"}
    seen: list[str] = []
    for c in calls:
        if c not in stop and c not in seen:
            seen.append(c)
        if len(seen) >= limit:
            break
    return seen
