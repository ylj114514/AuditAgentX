"""自动提取项目路由 / 端点（用于动态验证时确定攻击面）。

多框架规则：Flask / FastAPI / Django / Express / Spring / PHP。
返回端点路径列表及其方法，供 DynamicVerifier 定向发包。
"""
from __future__ import annotations

import ast
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

    # An operation is identified by path *and method*. Merging GET/POST parameters
    # into one endpoint causes JSON/form parameters to be sent to unrelated GET routes.
    seen: dict[tuple[str, str], dict] = {}
    endpoints: list[dict] = []
    frameworks: set[str] = set()
    sources: list[tuple[Path, str, str]] = []
    for f in root.rglob("*"):
        if len(sources) >= max_files:
            break
        if f.is_dir() or any(part in SKIP_DIRS for part in f.parts):
            continue
        if f.suffix.lower() not in SRC_EXT:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        sources.append((f, text, f.relative_to(root).as_posix()))

    express_mounts = _express_mounts(root, sources)
    flask_routes = _flask_routes(sources)
    flask_route_starts = {
        (rel, offset) for rel, routes in flask_routes.items()
        for _path, _methods, start, _params in routes
        for offset in (start, start + 1)  # Express regex begins after the decorator's @.
    }

    def add_route(fw: str, raw_path: str, methods: list[str], f: Path, text: str, rel: str,
                  start: int, params: list[dict] | None = None) -> None:
        if len(endpoints) >= max_endpoints:
            return
        path = _normalize(raw_path)
        if not path:
            return
        endpoint_params = _merge_params(params if params is not None else _params_near_route(text, start),
                                       _route_path_parameters(raw_path))
        for route_method in methods:
            key = (path, route_method)
            if key in seen:
                seen[key]["params"] = _merge_params(seen[key].get("params", []), endpoint_params)
                continue
            frameworks.add(fw)
            endpoint = {
                "path": path, "raw_path": raw_path, "methods": [route_method],
                "framework": fw, "file": rel,
                "line": text.count("\n", 0, start) + 1,
                "params": endpoint_params, "source": "static_route",
            }
            seen[key] = endpoint
            endpoints.append(endpoint)
            if len(endpoints) >= max_endpoints:
                return

    for f, text, rel in sources:
        for raw_path, methods, start, params in flask_routes.get(rel, []):
            add_route("flask", raw_path, methods, f, text, rel, start, params)

        for fw, raw_path, methods, start, params in _framework_routes(
                text, rel, express_mounts):
            if fw in {"express", "fastapi"} and (rel, start) in flask_route_starts:
                continue
            add_route(fw, raw_path, methods, f, text, rel, start, params)

        for fw, pattern in _ROUTE_PATTERNS:
            if fw in {"flask", "express", "fastapi", "spring"}:
                continue
            for m in pattern.finditer(text):
                groups = m.groups()
                if len(groups) == 2:  # 含方法
                    method, path = groups[0].upper(), groups[1]
                else:
                    method, path = "GET", groups[0]
                methods = _route_methods(fw, text[m.start():m.end() + 300], method)
                add_route(fw, path, methods, f, text, rel, m.start(),
                          _params_near_route(text, m.end()))

    # Connexion / OpenAPI-first 项目可能没有任何 @app.route；路由与 operationId
    # 全部声明在 openapi*.yml/json 中。静态读取规范并映射回处理函数源码。
    for endpoint in _extract_openapi_endpoints(root, max_endpoints=max_endpoints - len(endpoints)):
        duplicate = next((
            item for item in endpoints
            if item.get("path") == endpoint.get("path")
            and item.get("methods") == endpoint.get("methods")
        ), None)
        if duplicate:
            duplicate["params"] = _merge_params(duplicate.get("params", []), endpoint.get("params", []))
            continue
        endpoints.append(endpoint)
        frameworks.add("openapi")
        if len(endpoints) >= max_endpoints:
            break

    result["endpoints"] = endpoints
    result["count"] = len(endpoints)
    result["frameworks"] = sorted(frameworks)
    return result


_FLASK_ROUTE_METHODS = {"get", "post", "put", "delete", "patch"}


def _flask_routes(sources: list[tuple[Path, str, str]]) -> dict[str, list[tuple]]:
    """Extract Flask application and Blueprint routes with static registration prefixes.

    A Blueprint decorator does not create a reachable route until an application
    registers that exact local Blueprint object.  Resolve only literal local
    imports and literal ``url_prefix`` values; unknown registration forms remain
    unextracted rather than producing a guessed URL.
    """
    parsed: dict[str, ast.Module] = {}
    module_files: dict[str, str] = {}
    source_texts: dict[str, str] = {}
    for _path, text, rel in sources:
        if not rel.endswith(".py"):
            continue
        try:
            parsed[rel] = ast.parse(text)
        except SyntaxError:
            continue
        module_files[_python_module_name(rel)] = rel
        source_texts[rel] = text

    blueprints: dict[tuple[str, str], str] = {}
    applications: dict[str, set[str]] = {}
    imports: dict[str, dict[str, tuple[str, str]]] = {}
    for rel, tree in parsed.items():
        applications[rel] = set()
        imports[rel] = _python_imports(tree, rel, module_files)
        flask_factories = _flask_factory_names(tree)
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            target_names = _assignment_names(node)
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            factory = _call_symbol(value.func)
            if factory in flask_factories["Flask"]:
                applications[rel].update(target_names)
            elif factory in flask_factories["Blueprint"]:
                prefix = _literal_keyword(value, "url_prefix") or ""
                for name in target_names:
                    blueprints[(rel, name)] = prefix

    mounts: dict[tuple[str, str], list[str]] = {}
    for rel, tree in parsed.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "register_blueprint" or not isinstance(node.func.value, ast.Name):
                continue
            if node.func.value.id not in applications.get(rel, set()) or not node.args:
                continue
            blueprint = node.args[0]
            if not isinstance(blueprint, ast.Name):
                continue
            owner = imports[rel].get(blueprint.id, (rel, blueprint.id))
            if owner not in blueprints:
                continue
            # Flask's explicit registration prefix overrides Blueprint.url_prefix.
            prefix = _literal_keyword(node, "url_prefix")
            mounts.setdefault(owner, []).append(
                blueprints[owner] if prefix is None else prefix,
            )

    output: dict[str, list[tuple]] = {}
    for rel, tree in parsed.items():
        text = source_texts[rel]
        lines = _line_offsets(text)
        route_owners = {name: [""] for name in applications.get(rel, set())}
        for (owner_rel, owner_name), _prefix in blueprints.items():
            if owner_rel == rel and (owner_rel, owner_name) in mounts:
                route_owners[owner_name] = mounts[(owner_rel, owner_name)]
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                route = _flask_decorator_route(decorator, route_owners)
                if route is None:
                    continue
                owner, path, methods = route
                start = lines[max(0, decorator.lineno - 1)]
                params = _params_near_route(text, start)
                for prefix in route_owners[owner]:
                    output.setdefault(rel, []).append((
                        _join_paths(prefix, path), methods, start, params,
                    ))
    return output


def _flask_factory_names(tree: ast.Module) -> dict[str, set[str]]:
    names = {"Flask": {"Flask"}, "Blueprint": {"Blueprint"}}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.module != "flask":
            continue
        for alias in node.names:
            if alias.name in names:
                names[alias.name].add(alias.asname or alias.name)
    return names


def _call_symbol(value: ast.expr) -> str | None:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute) and value.attr in {"Flask", "Blueprint"}:
        return value.attr
    return None


def _flask_decorator_route(decorator: ast.expr, owners: dict[str, list[str]]) -> tuple[str, str, list[str]] | None:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return None
    if not isinstance(decorator.func.value, ast.Name) or decorator.func.value.id not in owners:
        return None
    if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
        return None
    path = decorator.args[0].value
    if not isinstance(path, str):
        return None
    method = decorator.func.attr.lower()
    if method == "route":
        methods = _literal_methods(decorator) or ["GET"]
    elif method in _FLASK_ROUTE_METHODS:
        methods = [method.upper()]
    else:
        return None
    return decorator.func.value.id, path, methods


def _assignment_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return {target.id for target in targets if isinstance(target, ast.Name)}


def _literal_keyword(node: ast.Call, name: str) -> str | None:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
    return None


def _literal_methods(node: ast.Call) -> list[str]:
    for keyword in node.keywords:
        if keyword.arg != "methods" or not isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            continue
        methods = [item.value.upper() for item in keyword.value.elts
                   if isinstance(item, ast.Constant) and isinstance(item.value, str)]
        if methods:
            return sorted(set(methods))
    return []


def _python_module_name(rel: str) -> str:
    path = rel[:-3].replace("/", ".")
    return path.rsplit(".__init__", 1)[0] if path.endswith(".__init__") else path


def _python_imports(tree: ast.Module, rel: str, module_files: dict[str, str]) -> dict[str, tuple[str, str]]:
    imports: dict[str, tuple[str, str]] = {}
    package = _python_module_name(rel).split(".")[:-1]
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        base = node.module.split(".") if node.module else []
        if node.level:
            base = package[:max(0, len(package) - node.level + 1)] + base
        target = module_files.get(".".join(base))
        if not target:
            continue
        for alias in node.names:
            imports[alias.asname or alias.name] = (target, alias.name)
    return imports


def _line_offsets(text: str) -> list[int]:
    offsets = [0]
    for match in re.finditer("\\n", text):
        offsets.append(match.end())
    return offsets


_EXPRESS_ROUTE = re.compile(
    r"""\b(?P<router>[A-Za-z_$][\w$]*)\.(?P<method>get|post|put|delete|patch|all)\(\s*['\"](?P<path>[^'\"]+)['\"]""",
    re.I,
)
_EXPRESS_ROUTE_CHAIN = re.compile(
    r"""\b(?P<router>[A-Za-z_$][\w$]*)\.route\(\s*['\"](?P<path>[^'\"]+)['\"]\s*\)""",
    re.I,
)
_EXPRESS_CHAIN_METHOD = re.compile(r"\.\s*(get|post|put|delete|patch|all)\s*\(", re.I)
_FASTAPI_ROUTE = re.compile(
    r"""@(?P<router>[A-Za-z_]\w*)\.(?P<method>get|post|put|delete|patch)\(\s*['\"](?P<path>[^'\"]+)['\"]""",
    re.I,
)
_FASTAPI_PREFIX = re.compile(
    r"""\b(?P<router>[A-Za-z_]\w*)\s*=\s*(?:APIRouter|FastAPI)\([^)]*?\bprefix\s*=\s*['\"](?P<prefix>[^'\"]+)['\"]""",
    re.I | re.S,
)
_SPRING_CLASS = re.compile(
    r"""@RequestMapping\(\s*(?:value\s*=\s*)?['\"](?P<prefix>[^'\"]+)['\"]\s*\)\s*(?:public\s+)?(?:class|interface)\s+\w+[^\{]*\{""",
    re.I,
)
_SPRING_METHOD = re.compile(
    r"""@(?P<method>Get|Post|Put|Delete|Patch)Mapping\(\s*(?:value\s*=\s*)?['\"](?P<path>[^'\"]+)['\"]\s*\)""",
    re.I,
)


def _framework_routes(text: str, rel: str, mounts: dict[tuple[str, str], list[str]]) -> list[tuple]:
    """Extract framework-native routes before generic patterns can lose their scope."""
    routes: list[tuple] = []
    prefixes = {match.group("router"): match.group("prefix") for match in _FASTAPI_PREFIX.finditer(text)}
    for match in _FASTAPI_ROUTE.finditer(text):
        raw_path = _join_paths(prefixes.get(match.group("router"), ""), match.group("path"))
        routes.append(("fastapi", raw_path, [match.group("method").upper()], match.start(),
                       _fastapi_parameters(text, match.end(), raw_path)))

    express_routers = _express_router_names(text)
    for match in _EXPRESS_ROUTE.finditer(text):
        if match.group("router") not in express_routers:
            continue
        for prefix in _mounted_prefixes(rel, match.group("router"), mounts):
            raw_path = _join_paths(prefix, match.group("path"))
            routes.append(("express", raw_path, [match.group("method").upper()], match.start(),
                           _params_near_route(text, match.end())))
    for match in _EXPRESS_ROUTE_CHAIN.finditer(text):
        if match.group("router") not in express_routers:
            continue
        chain_end = text.find(";", match.end())
        chain = text[match.end():chain_end if chain_end >= 0 else match.end() + 8000]
        if not re.match(r"\s*\.", chain):
            continue
        chain_methods = list(_EXPRESS_CHAIN_METHOD.finditer(chain))
        for index, method_match in enumerate(chain_methods):
            handler_start = match.end() + method_match.end()
            handler_end = (match.end() + chain_methods[index + 1].start()
                           if index + 1 < len(chain_methods) else
                           (chain_end if chain_end >= 0 else handler_start + 8000))
            params = _extract_request_params(text[handler_start:handler_end])
            for prefix in _mounted_prefixes(rel, match.group("router"), mounts):
                raw_path = _join_paths(prefix, match.group("path"))
                routes.append(("express", raw_path, [method_match.group(1).upper()], match.start(), params))

    for class_match in _SPRING_CLASS.finditer(text):
        class_end = _matching_brace(text, text.find("{", class_match.start()))
        class_body_end = class_end if class_end is not None else len(text)
        for method_match in _SPRING_METHOD.finditer(text, class_match.end(), class_body_end):
            raw_path = _join_paths(class_match.group("prefix"), method_match.group("path"))
            routes.append(("spring", raw_path, [method_match.group("method").upper()], method_match.start(),
                           _spring_parameters(text, method_match.end())))
    return routes


def _express_router_names(text: str) -> set[str]:
    """Return only identifiers with source evidence that they are Express routers."""
    names = {"app", "router", "server", "api"}
    pattern = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:express\s*\.\s*)?(?:Router|router)\s*\(",
        re.I,
    )
    names.update(match.group(1) for match in pattern.finditer(text))
    names.update(match.group(1) for match in re.finditer(
        r"\b([A-Za-z_$][\w$]*)\s*=\s*express\s*\(", text,
    ))
    return names


def _express_mounts(root: Path, sources: list[tuple[Path, str, str]]) -> dict[tuple[str, str], list[str]]:
    """Map an Express ``app.use(prefix, router)`` to the router's source file.

    Only an explicit local import/require can cross a file boundary.  Matching a
    bare variable name in every JS file would make unrelated routers authorize
    one another.
    """
    known = {rel for _path, _text, rel in sources}
    mounts: dict[tuple[str, str], list[str]] = {}
    for path, text, rel in sources:
        if path.suffix.lower() not in {".js", ".ts"}:
            continue
        imports: dict[str, str] = {}
        for match in re.finditer(r"""\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)""", text):
            target = _resolve_js_module(path, match.group(2), root, known)
            if target:
                imports[match.group(1)] = target
        for match in re.finditer(r"""\bimport\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]""", text):
            target = _resolve_js_module(path, match.group(2), root, known)
            if target:
                imports[match.group(1)] = target
        for match in re.finditer(r"""\b\w+\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_$][\w$]*)\s*\)""", text):
            prefix, router = match.groups()
            target = imports.get(router)
            key = (target, "*") if target else (rel, router)
            mounts.setdefault(key, []).append(prefix)
    return mounts


def _resolve_js_module(path: Path, module: str, root: Path, known: set[str]) -> str | None:
    if not module.startswith("."):
        return None
    base = (path.parent / module).resolve()
    for candidate in (base.with_suffix(".js"), base.with_suffix(".ts"), base / "index.js", base / "index.ts"):
        try:
            rel = candidate.relative_to(root).as_posix()
        except ValueError:
            continue
        if rel in known:
            return rel
    return None


def _mounted_prefixes(rel: str, router: str, mounts: dict[tuple[str, str], list[str]]) -> list[str]:
    return mounts.get((rel, router)) or mounts.get((rel, "*")) or [""]


def _fastapi_parameters(text: str, start: int, raw_path: str) -> list[dict]:
    match = re.search(r"(?:async\s+)?def\s+\w+\s*\((.*?)\)\s*:", text[start:], re.S)
    if not match:
        return _route_path_parameters(raw_path)
    params: list[dict] = []
    for item in re.finditer(r"\b([A-Za-z_]\w*)\s*:\s*[^,=\n]+(?:\s*=\s*([^,\n]+))?", match.group(1)):
        name, default = item.group(1), item.group(2) or ""
        marker = default.lower()
        location = ("path" if "path(" in marker or any(p["name"] == name for p in _route_path_parameters(raw_path)) else
                    "query" if "query(" in marker or not default else
                    "json" if "body(" in marker else
                    "form" if "form(" in marker else "query")
        params.append({"name": name, "location": location, "required": "..." in default})
    return _merge_params(params, _route_path_parameters(raw_path))


def _spring_parameters(text: str, start: int) -> list[dict]:
    declaration = re.search(r"\b\w+[\w<>?\s]*\s+\w+\s*\(", text[start:], re.S)
    if not declaration:
        return []
    open_paren = start + declaration.end() - 1
    close_paren = _matching_paren(text, open_paren)
    if close_paren is None:
        return []
    signature = text[open_paren + 1:close_paren]
    params: list[dict] = []
    for annotation, location in (("PathVariable", "path"), ("RequestParam", "query"), ("RequestBody", "json")):
        explicit = re.compile(rf"@{annotation}\s*\(\s*(?:value\s*=\s*|name\s*=\s*)?['\"]([^'\"]+)['\"]\s*\)\s+(?:final\s+)?[\w<>?]+\s+(\w+)")
        plain = re.compile(rf"@{annotation}\s+(?:final\s+)?[\w<>?]+\s+(\w+)")
        for match in explicit.finditer(signature):
            params.append({"name": match.group(1), "location": location, "required": location == "path"})
        for match in plain.finditer(signature):
            params.append({"name": match.group(1), "location": location, "required": location == "path"})
    return _merge_params([], params)


def _join_paths(prefix: str, path: str) -> str:
    return "/" + "/".join(part.strip("/") for part in (prefix, path) if part.strip("/"))


def _matching_brace(text: str, start: int) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}" and depth:
            depth -= 1
            if depth == 0:
                return index
    return None


def _matching_paren(text: str, start: int) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")" and depth:
            depth -= 1
            if depth == 0:
                return index
    return None


def _extract_openapi_endpoints(root: Path, *, max_endpoints: int) -> list[dict]:
    if max_endpoints <= 0:
        return []
    specs = [
        path for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".yaml", ".yml", ".json"}
        and any(token in path.name.lower() for token in ("openapi", "swagger"))
        and not any(part in SKIP_DIRS for part in path.parts)
    ]
    out: list[dict] = []
    for spec_path in sorted(specs)[:12]:
        try:
            raw = spec_path.read_text(encoding="utf-8", errors="ignore")
            if spec_path.suffix.lower() == ".json":
                spec = json.loads(raw)
            else:
                import yaml
                spec = yaml.safe_load(raw)
        except Exception:  # noqa: BLE001 - malformed specs are skipped, never executed
            continue
        if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
            continue
        spec_controller = spec.get("x-openapi-router-controller")
        for raw_path, path_item in spec["paths"].items():
            if not isinstance(path_item, dict):
                continue
            shared_params = path_item.get("parameters") or []
            for method, operation in path_item.items():
                if str(method).upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                operation = operation if isinstance(operation, dict) else {}
                params = _openapi_parameters(shared_params, operation)
                operation_id = _qualified_operation_id(
                    operation.get("operationId"),
                    operation.get("x-openapi-router-controller")
                    or path_item.get("x-openapi-router-controller")
                    or spec_controller,
                )
                source_file, source_line = _operation_source(root, operation_id)
                out.append({
                    "path": _normalize(str(raw_path)) or "/",
                    "raw_path": str(raw_path),
                    "methods": [str(method).upper()],
                    "framework": "openapi",
                    "file": source_file or _relative_posix(root, spec_path),
                    "line": source_line,
                    "params": params,
                    "operation_id": operation_id,
                    "summary": str(operation.get("summary") or ""),
                    "description": str(operation.get("description") or ""),
                    "tags": [str(value) for value in (operation.get("tags") or [])],
                    "response_fields": _openapi_response_fields(operation),
                    "source": "static_openapi",
                })
                if len(out) >= max_endpoints:
                    return out
    return out


def _openapi_parameters(shared: list, operation: dict) -> list[dict]:
    params: list[dict] = []
    for item in [*(shared or []), *(operation.get("parameters") or [])]:
        if isinstance(item, dict) and item.get("name"):
            schema = item.get("schema") or {}
            params.append({
                "name": str(item["name"]), "location": str(item.get("in") or "query"),
                "required": bool(item.get("required")) or item.get("in") == "path",
                "type": schema.get("type"), "enum": schema.get("enum") or [],
                "default": schema.get("default", item.get("example", schema.get("example"))),
            })
    content = ((operation.get("requestBody") or {}).get("content") or {})
    for media_type, media in content.items():
        schema = (media or {}).get("schema") or {}
        media_lower = str(media_type).lower()
        location = ("json" if "json" in media_lower else
                    "multipart" if "multipart" in media_lower else "form")
        required = set(schema.get("required") or [])
        for name, prop in (schema.get("properties") or {}).items():
            prop = prop if isinstance(prop, dict) else {}
            params.append({
                "name": str(name), "location": location, "required": name in required,
                "type": prop.get("type"), "enum": prop.get("enum") or [],
                "default": prop.get("default", prop.get("example")),
            })
    return _merge_params([], params)


def _openapi_response_fields(operation: dict) -> list[str]:
    """提取 2xx JSON 响应的顶层对象字段，供业务逻辑 oracle 规划使用。"""
    fields: set[str] = set()
    for status, response in (operation.get("responses") or {}).items():
        if not str(status).startswith("2") or not isinstance(response, dict):
            continue
        for media_type, media in (response.get("content") or {}).items():
            if "json" not in str(media_type).lower() or not isinstance(media, dict):
                continue
            schema = media.get("schema") or {}
            if schema.get("type") == "array":
                schema = schema.get("items") or {}
            for name in (schema.get("properties") or {}):
                fields.add(str(name))
    return sorted(fields)


_OPERATION_ID = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")


def _qualified_operation_id(operation_id: object, controller: object) -> str:
    """Return the exact dotted handler reference declared by OpenAPI/Connexion.

    Connexion permits an operation-local function name when
    ``x-openapi-router-controller`` supplies its module.  A fully-qualified
    ``operationId`` remains authoritative, including when a controller is also
    present.  No filesystem search is used: malformed or ambiguous references
    stay unresolved.
    """
    raw_operation = str(operation_id or "").strip().replace(":", ".")
    if _OPERATION_ID.fullmatch(raw_operation):
        return raw_operation
    raw_controller = str(controller or "").strip()
    if not raw_operation or not re.fullmatch(r"[A-Za-z_]\w*", raw_operation):
        return raw_operation
    if not _OPERATION_ID.fullmatch(raw_controller):
        return raw_operation
    return f"{raw_controller}.{raw_operation}"


def _operation_source(root: Path, operation_id: str) -> tuple[str, int | None]:
    if not _OPERATION_ID.fullmatch(operation_id):
        return "", None
    module, function = operation_id.rsplit(".", 1)
    source = root.joinpath(*module.split(".")).with_suffix(".py")
    if not source.is_file():
        return "", None
    text = source.read_text(encoding="utf-8", errors="ignore")
    match = re.search(rf"^[ \t]*(?:async[ \t]+)?def[ \t]+{re.escape(function)}[ \t]*\(", text, re.M)
    line = text.count("\n", 0, match.start()) + 1 if match else None
    return _relative_posix(root, source), line


def _relative_posix(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _normalize(path: str) -> str | None:
    """规整路由路径：Django 正则转普通、去锚点、保证以 / 开头。"""
    if not path:
        return None
    path = path.strip()
    # Route declarations must be project-relative.  Treating an absolute or
    # protocol-relative URL as a path would turn source text into a request
    # capability after later normalization.
    if path.startswith("//") or "://" in path or path.startswith(("?", "#")):
        return None
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


def _route_path_parameters(raw_path: str) -> list[dict]:
    """Recover path variables before normalization replaces them with safe controls."""
    names = re.findall(r"\{([^}/]+)\}|<(?:[^:>]+:)?([^>]+)>|:([A-Za-z_]\w*)|\(\?P<(\w+)>", raw_path)
    return [
        {"name": next(name for name in match if name), "location": "path", "required": True,
         "type": "integer" if "int:" in raw_path else "string"}
        for match in names
        if any(match)
    ]


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
    # Flask 常见别名写法：content = request.json / request.get_json();
    # 后续 content['search'] 或 content.get('search')。只看 request.json 直连表达式会漏掉
    # 真实开源项目 VFA 的 /search JSON 注入点。
    aliases = re.findall(
        r"\b([A-Za-z_]\w*)\s*=\s*request\.(?:json|get_json\(\))",
        text,
        re.I,
    )
    for alias in aliases:
        pattern = re.compile(
            rf"\b{re.escape(alias)}\s*(?:\.get\(\s*|\[\s*)['\"]([\w-]+)['\"]",
            re.I,
        )
        for match in pattern.finditer(text):
            params.append({"name": match.group(1), "location": "json"})
    return _merge_params([], params)


def _params_near_route(text: str, start: int) -> list[dict]:
    """提取当前路由处理函数附近的参数，降低跨端点参数笛卡尔积。"""
    tail = text[start:]
    boundary = re.search(
        r"\n\s*(?:@(?:\w+\.)?(?:route|get|post|put|delete|patch)\(|"
        r"\w+\.(?:route|get|post|put|delete|patch|all)\s*\()", tail, re.I,
    )
    segment = tail[:boundary.start()] if boundary else tail[:8000]
    # Do not fall back to parameters extracted from the complete file: a route
    # with no proven request read has no proven injection parameter.
    return _extract_request_params(segment)


def _merge_params(left: list[dict], right: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in [*left, *right]:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        normalized = {**item, "name": str(item["name"]),
                      "location": str(item.get("location") or "query")}
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
