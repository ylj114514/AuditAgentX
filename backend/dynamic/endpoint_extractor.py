"""自动提取项目路由 / 端点（用于动态验证时确定攻击面）。

多框架规则：Flask / FastAPI / Django / Express / Spring / PHP。
返回端点路径列表及其方法，供 DynamicVerifier 定向发包。
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}
SRC_EXT = {".py", ".js", ".ts", ".java", ".php", ".rb", ".go"}

# (框架, 方法提取组?, 正则)
_ROUTE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Flask / Blueprint: @app.route("/path", methods=["GET","POST"])
    ("flask", re.compile(r"""@\w+\.route\(\s*['"]([^'"]+)['"]""")),
    # FastAPI / APIRouter: @app.get("/path")  @router.post("/x")
    ("fastapi", re.compile(r"""@(?:app|router|api)\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""", re.I)),
    # Express: app.get("/path")  router.post('/x')
    ("express", re.compile(r"""\b(?:app|router|server|api)\.(get|post|put|delete|patch|all)\(\s*['"]([^'"]+)['"]""", re.I)),
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

    seen: dict[str, dict] = {}
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
        request_params = _extract_request_params(text)

        for fw, pattern in _ROUTE_PATTERNS:
            for m in pattern.finditer(text):
                groups = m.groups()
                if len(groups) == 2:  # 含方法
                    method, path = groups[0].upper(), groups[1]
                else:
                    method, path = "GET", groups[0]
                path = _normalize(path)
                if not path:
                    continue
                methods = _route_methods(fw, text[m.start():m.end() + 300], method)
                endpoint_params = _params_near_route(text, m.end(), request_params)
                if path in seen:
                    existing = seen[path]
                    existing["methods"] = sorted(set(existing["methods"] + methods))
                    existing["params"] = _merge_params(existing.get("params", []), endpoint_params)
                    continue
                frameworks.add(fw)
                endpoint = {
                    "path": path,
                    "methods": methods,
                    "framework": fw,
                    "file": rel,
                    "params": endpoint_params,
                    "source": "static_route",
                }
                seen[path] = endpoint
                endpoints.append(endpoint)
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


def candidate_attack_surfaces(code_root: Path | None) -> list[dict]:
    """返回可直接用于运行时验证的结构化攻击面。

    与旧的 ``candidate_endpoints`` 相比，保留路由方法、源码参数位置和来源文件，
    避免对每个端点盲试一大组通用参数。没有静态路由时仍提供少量、明确标记为
    heuristic 的兜底入口；兜底入口本身永远不能作为漏洞证据。
    """
    data = extract_endpoints(code_root)
    surfaces = [dict(item) for item in data["endpoints"]]
    # 已有源码路由时，优先只测这些入口；把通用 /search、/api 等猜测混入会浪费预算，
    # 还可能把同一个注入参数错投到无关接口。运行时 HTML/OpenAPI 发现会另行补充。
    if surfaces:
        return surfaces
    present = {item["path"] for item in surfaces}
    for path in ("/", "/login", "/search", "/api", "/download"):
        if path not in present:
            surfaces.append({
                "path": path,
                "methods": ["GET"],
                "params": [],
                "framework": "unknown",
                "file": "",
                "source": "heuristic",
            })
    return surfaces


def discover_live_surfaces(base_url: str, *, timeout: float = 3.0,
                           max_surfaces: int = 80) -> list[dict]:
    """从运行中的本地靶场发现 OpenAPI 路由、HTML 表单和同源链接。

    这是 DeepAudit ``sandbox_http`` 思路的收敛版：网络发现只针对已通过
    ``target_guard`` 的本地授权目标，不跟随重定向，也不把“请求成功”当漏洞成功。
    """
    import httpx
    from backend.dynamic.target_guard import validate_dynamic_base_url

    safe_base = validate_dynamic_base_url(base_url).rstrip("/") + "/"
    found: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(surface: dict) -> None:
        path = _same_origin_path(safe_base, str(surface.get("path") or "/"))
        if not path:
            return
        methods = [str(m).upper() for m in (surface.get("methods") or ["GET"])]
        params = surface.get("params") or []
        key = (path, ",".join(methods), json.dumps(params, sort_keys=True, ensure_ascii=False))
        if key in seen or len(found) >= max_surfaces:
            return
        seen.add(key)
        found.append({**surface, "path": path, "methods": methods, "source": surface.get("source") or "live"})

    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        for spec_path in ("/openapi.json", "/swagger.json", "/api/openapi.json"):
            try:
                response = client.get(safe_base.rstrip("/") + spec_path)
                if response.status_code >= 400:
                    continue
                spec = response.json()
            except Exception:  # noqa: BLE001 - live discovery is best effort
                continue
            for raw_path, operations in (spec.get("paths") or {}).items():
                if not isinstance(operations, dict):
                    continue
                for method, operation in operations.items():
                    if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                        continue
                    operation = operation if isinstance(operation, dict) else {}
                    params = []
                    for p in operation.get("parameters") or []:
                        if isinstance(p, dict) and p.get("name"):
                            params.append({"name": str(p["name"]), "location": str(p.get("in") or "query")})
                    schema = (((operation.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema") or {}
                    for name in (schema.get("properties") or {}):
                        params.append({"name": str(name), "location": "json"})
                    add({"path": raw_path, "methods": [method], "params": _merge_params([], params),
                         "framework": "openapi", "file": "", "source": "live_openapi"})

        try:
            home = client.get(safe_base)
            parser = _SurfaceHTMLParser(safe_base)
            parser.feed(home.text if home.status_code < 500 else "")
            for surface in parser.surfaces:
                add(surface)
        except Exception:  # noqa: BLE001
            pass
    return found


def merge_attack_surfaces(*groups: list[dict] | None) -> list[dict]:
    """按 path/method 合并静态与运行时攻击面，运行时参数优先补强静态结果。"""
    merged: dict[tuple[str, str], dict] = {}
    for group in groups:
        for item in group or []:
            path = _normalize(str(item.get("path") or ""))
            if not path:
                continue
            for method in item.get("methods") or ["GET"]:
                key = (path, str(method).upper())
                if key not in merged:
                    merged[key] = {**item, "path": path, "methods": [key[1]],
                                   "params": list(item.get("params") or [])}
                else:
                    merged[key]["params"] = _merge_params(
                        merged[key].get("params", []), item.get("params") or [])
                    if str(item.get("source", "")).startswith("live"):
                        merged[key]["source"] = item.get("source")
    return list(merged.values())


def _route_methods(framework: str, snippet: str, default: str) -> list[str]:
    if framework == "flask":
        match = re.search(r"methods\s*=\s*\[([^]]+)\]", snippet, re.I)
        if match:
            values = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", match.group(1), re.I)
            if values:
                return sorted({value.upper() for value in values})
    return [str(default or "GET").upper()]


_PARAM_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("query", re.compile(r"request\.(?:args|GET)\s*(?:\.get\(\s*|\[\s*)['\"]([\w-]+)['\"]", re.I)),
    ("form", re.compile(r"request\.(?:form|POST|values)\s*(?:\.get\(\s*|\[\s*)['\"]([\w-]+)['\"]", re.I)),
    ("json", re.compile(r"(?:request\.(?:json)|request\.get_json\(\))\s*(?:\.get\(\s*|\[\s*)['\"]([\w-]+)['\"]", re.I)),
    ("query", re.compile(r"req\.query(?:\.([A-Za-z_$][\w$-]*)|\[['\"]([\w-]+)['\"]\])", re.I)),
    ("json", re.compile(r"req\.body(?:\.([A-Za-z_$][\w$-]*)|\[['\"]([\w-]+)['\"]\])", re.I)),
    ("path", re.compile(r"req\.params(?:\.([A-Za-z_$][\w$-]*)|\[['\"]([\w-]+)['\"]\])", re.I)),
    ("query", re.compile(r"\$_GET\s*\[\s*['\"]([\w-]+)['\"]\s*\]", re.I)),
    ("form", re.compile(r"\$_POST\s*\[\s*['\"]([\w-]+)['\"]\s*\]", re.I)),
    ("query", re.compile(r"@RequestParam(?:\([^)]*?(?:value|name)?\s*=\s*)?['\"]([\w-]+)['\"]", re.I)),
]


def _extract_request_params(text: str) -> list[dict]:
    params: list[dict] = []
    for location, pattern in _PARAM_PATTERNS:
        for match in pattern.finditer(text):
            name = next((group for group in match.groups() if group), "")
            if name:
                params.append({"name": name, "location": location})
    return _merge_params([], params)


def _params_near_route(text: str, start: int, fallback: list[dict]) -> list[dict]:
    """提取当前路由处理函数附近的参数，降低跨端点参数笛卡尔积。"""
    tail = text[start:]
    boundary = re.search(r"\n\s*@(?:\w+\.)?(?:route|get|post|put|delete|patch)\(", tail, re.I)
    segment = tail[:boundary.start()] if boundary else tail[:8000]
    return _extract_request_params(segment) or list(fallback)


def _merge_params(left: list[dict], right: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in [*left, *right]:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        normalized = {"name": str(item["name"]), "location": str(item.get("location") or "query")}
        key = (normalized["name"], normalized["location"])
        if key not in seen:
            seen.add(key)
            out.append(normalized)
    return out


def _same_origin_path(base_url: str, raw: str) -> str | None:
    absolute = urljoin(base_url, raw)
    base = urlparse(base_url)
    parsed = urlparse(absolute)
    if (parsed.scheme, parsed.hostname, parsed.port) != (base.scheme, base.hostname, base.port):
        return None
    return _normalize(parsed.path or "/")


class _SurfaceHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.surfaces: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(k).lower(): str(v or "") for k, v in attrs}
        if tag.lower() == "form":
            self._form = {
                "path": values.get("action") or "/",
                "methods": [(values.get("method") or "GET").upper()],
                "params": [], "framework": "html", "file": "", "source": "live_form",
            }
        elif tag.lower() in {"input", "textarea", "select"} and self._form is not None:
            name = values.get("name")
            if name:
                location = "query" if self._form["methods"] == ["GET"] else "form"
                self._form["params"].append({"name": name, "location": location})
        elif tag.lower() == "a" and values.get("href"):
            path = _same_origin_path(self.base_url, values["href"])
            if path:
                self.surfaces.append({"path": path, "methods": ["GET"], "params": [],
                                      "framework": "html", "file": "", "source": "live_link"})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self._form["path"] = _same_origin_path(self.base_url, self._form["path"]) or "/"
            self._form["params"] = _merge_params([], self._form["params"])
            self.surfaces.append(self._form)
            self._form = None
