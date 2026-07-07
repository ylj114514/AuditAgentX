"""自动提取项目路由 / 端点（用于动态验证时确定攻击面）。

多框架规则：Flask / FastAPI / Django / Express / Spring / PHP。
返回端点路径列表及其方法，供 DynamicVerifier 定向发包。
"""
from __future__ import annotations

import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}
SRC_EXT = {".py", ".js", ".ts", ".java", ".php", ".rb", ".go"}

# (框架, 方法提取组?, 正则)
_ROUTE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Flask / Blueprint: @app.route("/path", methods=["GET","POST"])
    ("flask", re.compile(r"""@\w+\.route\(\s*['"]([^'"]+)['"]""")),
    # FastAPI / APIRouter: @app.get("/path")  @router.post("/x")
    ("fastapi", re.compile(r"""@\w+\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""", re.I)),
    # Express: app.get("/path")  router.post('/x')
    ("express", re.compile(r"""\b\w+\.(get|post|put|delete|patch|all)\(\s*['"]([^'"]+)['"]""", re.I)),
    # Django urls: path("x/", ...)  re_path(r"^x$", ...)  url(r"...")
    ("django", re.compile(r"""(?:path|re_path|url)\(\s*r?['"]([^'"]+)['"]""")),
    # Spring: @RequestMapping/@GetMapping("/path")
    ("spring", re.compile(r"""@(?:Request|Get|Post|Put|Delete|Patch)Mapping\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]""")),
    # PHP 常见路由: $router->get('/path', ...)  Route::get('/path')
    ("php", re.compile(r"""(?:->|::)\s*(get|post|put|delete|any)\(\s*['"]([^'"]+)['"]""", re.I)),
]

# 通用兜底：源码里出现的疑似路径字面量
_PATH_LITERAL = re.compile(r"""['"](/[A-Za-z0-9_\-/{}:.]{1,60})['"]""")


def extract_endpoints(code_root: Path | None, *, max_files: int = 4000,
                      max_endpoints: int = 80) -> dict:
    """返回 {endpoints: [{path, methods, framework, file}], count, frameworks}。"""
    result = {"endpoints": [], "count": 0, "frameworks": []}
    if not code_root or not Path(code_root).exists():
        return result
    root = Path(code_root)

    seen: set[str] = set()
    endpoints: list[dict] = []
    frameworks: set[str] = set()
    scanned = 0

    for f in root.rglob("*"):
        if scanned >= max_files or len(endpoints) >= max_endpoints:
            break
        if f.is_dir() or any(part in SKIP_DIRS for part in f.parts):
            continue
        if f.suffix.lower() not in SRC_EXT:
            continue
        scanned += 1
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = f.relative_to(root).as_posix()

        for fw, pattern in _ROUTE_PATTERNS:
            for m in pattern.finditer(text):
                groups = m.groups()
                if len(groups) == 2:  # 含方法
                    method, path = groups[0].upper(), groups[1]
                else:
                    method, path = "GET", groups[0]
                path = _normalize(path)
                if not path or path in seen:
                    continue
                seen.add(path)
                frameworks.add(fw)
                endpoints.append({"path": path, "methods": [method],
                                  "framework": fw, "file": rel})
                if len(endpoints) >= max_endpoints:
                    break

    result["endpoints"] = endpoints
    result["count"] = len(endpoints)
    result["frameworks"] = sorted(frameworks)
    return result


def _normalize(path: str) -> str | None:
    """规整路由路径：Django 正则转普通、去锚点、保证以 / 开头。"""
    if not path:
        return None
    path = path.strip()
    path = path.lstrip("^").rstrip("$")
    if not path.startswith("/"):
        path = "/" + path
    # Django 命名组 (?P<id>...) / FastAPI {id} 归一为占位
    path = re.sub(r"\(\?P<\w+>[^)]*\)", "1", path)
    path = re.sub(r"\{[^}]+\}", "1", path)
    path = re.sub(r"<[^>]+>", "1", path)      # Flask <int:id>
    path = re.sub(r":[A-Za-z_]+", "1", path)  # Express :id
    if len(path) > 80 or " " in path:
        return None
    return path


def candidate_endpoints(code_root: Path | None) -> list[str]:
    """便捷函数：返回去重的路径列表，供动态验证兜底使用。"""
    data = extract_endpoints(code_root)
    paths = [e["path"] for e in data["endpoints"]]
    # 附加常见兜底端点
    for p in ("/", "/user", "/search", "/login", "/api", "/admin", "/download"):
        if p not in paths:
            paths.append(p)
    return paths
