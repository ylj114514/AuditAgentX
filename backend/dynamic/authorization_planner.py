"""从结构化攻击面确定性规划 BOLA/IDOR 多身份验证工作流。

规划器只为一次性本地沙箱生成会改变目标状态的注册/创建请求。它不调用 LLM，
也不执行任何请求；真正的证据裁决仍由 DynamicVerifier 完成。
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import quote


def plan_authorization_workflow(finding: dict, surfaces: list[dict] | None, *,
                                disposable: bool, seed: str = "",
                                include_initializer: bool = True) -> dict | None:
    """返回可执行的授权工作流；攻击面不唯一或目标非一次性时返回 None。"""
    vuln_type = str(finding.get("type") or "").lower()
    if not any(token in vuln_type for token in ("idor", "bola", "object level authorization")):
        return None
    if not disposable:
        return None

    items = [item for item in (surfaces or []) if isinstance(item, dict)]
    register = _unique(items, method="POST", path_tokens=("register",),
                       required_params={"username", "password", "email"})
    login = _unique(items, method="POST", path_tokens=("login",),
                    required_params={"username", "password"})
    create, read = _resource_pair(items)
    if not all((register, login, create, read)):
        return None

    create_names = _param_names(create, locations={"json", "form", "body"})
    secret_field = _single_named(create_names, ("secret", "private", "content"))
    path_param = _path_parameter(read)
    resource_field = _resource_field(create_names, path_param, create.get("path"))
    response_fields = {str(value) for value in (read.get("response_fields") or [])}
    owner_field = _single_named(response_fields, ("owner", "created_by", "user"))
    response_secret = _single_named(response_fields, ("secret", "private", "content"))
    if not all((secret_field, path_param, resource_field, owner_field, response_secret)):
        return None

    suffix = hashlib.sha256(
        f"{seed}|{finding.get('finding_id') or finding.get('id') or finding.get('file')}".encode()
    ).hexdigest()[:8]
    owner = f"aax_owner_{suffix}"
    attacker = f"aax_attacker_{suffix}"
    owner_password = f"Aax-{suffix}-Owner!"
    attacker_password = f"Aax-{suffix}-Attacker!"
    resource_value = f"aax-private-{suffix}"
    sentinel = f"AAX_BOLA_SENTINEL_{suffix.upper()}"
    item_path = _fill_path(str(read.get("raw_path") or read.get("path") or ""),
                           path_param, resource_value)
    if not item_path:
        return None

    steps: list[dict] = []
    initializer = plan_disposable_initializer(items) if include_initializer else None
    if initializer:
        steps.append({
            "name": "initialize_disposable_target",
            "path": initializer["path"],
            "method": "GET",
            "role": "initialize",
        })
    steps.extend([
        _identity_step(register, owner, owner_password, f"{owner}@example.invalid", "register_owner"),
        _identity_step(register, attacker, attacker_password,
                       f"{attacker}@example.invalid", "register_attacker"),
        _login_step(login, owner, owner_password, "owner_token", "login_owner"),
        _login_step(login, attacker, attacker_password, "attacker_token", "login_attacker"),
        {
            "name": "create_owner_resource",
            "path": str(create.get("path")),
            "method": "POST",
            "transport": _body_transport(create),
            "headers": {"Authorization": "Bearer ${owner_token}"},
            "values": {resource_field: resource_value, secret_field: sentinel},
            "role": "owner_create",
        },
        {
            "name": "owner_control",
            "path": item_path,
            "method": "GET",
            "headers": {"Authorization": "Bearer ${owner_token}"},
            "role": "owner_control",
        },
        {
            "name": "cross_identity_read",
            "path": item_path,
            "method": "GET",
            "headers": {"Authorization": "Bearer ${attacker_token}"},
            "role": "authorization_attack",
        },
    ])
    return {
        "planner": "openapi_bola_v1",
        "steps": steps,
        "oracle": {
            "owner_identity": owner,
            "attacker_identity": attacker,
            "owner_json_field": owner_field,
            "secret_json_field": response_secret,
            "secret_value": sentinel,
        },
        "source_surfaces": {
            "register": _surface_ref(register),
            "login": _surface_ref(login),
            "create": _surface_ref(create),
            "read": _surface_ref(read),
        },
    }


def plan_disposable_initializer(surfaces: list[dict] | None) -> dict | None:
    """Return one auditable DB initializer for an isolated local target only.

    The caller must independently establish that the target is disposable. This
    helper merely recognizes a single, explicitly labelled OpenAPI/route
    operation; it never reads or executes arbitrary README/setup commands.
    """
    items = [item for item in (surfaces or []) if isinstance(item, dict)]
    initializer = _initializer(items)
    if not initializer:
        return None
    return {
        "name": "initialize_disposable_target",
        "path": str(initializer["path"]),
        "method": "GET",
        "transport": "query",
        "values": {},
        "role": "initialize",
    }


def _unique(items: list[dict], *, method: str, path_tokens: tuple[str, ...],
            required_params: set[str] | None = None) -> dict | None:
    candidates = []
    for item in items:
        methods = {str(value).upper() for value in (item.get("methods") or [])}
        path = str(item.get("path") or "").lower()
        if method not in methods or not all(token in path for token in path_tokens):
            continue
        if required_params and not required_params <= _param_names(item):
            continue
        candidates.append(item)
    return candidates[0] if len(candidates) == 1 else None


def _resource_pair(items: list[dict]) -> tuple[dict | None, dict | None]:
    pairs: list[tuple[dict, dict]] = []
    posts = [item for item in items if "POST" in {
        str(value).upper() for value in (item.get("methods") or [])}]
    gets = [item for item in items if "GET" in {
        str(value).upper() for value in (item.get("methods") or [])} and _path_parameter(item)]
    for create in posts:
        base = str(create.get("path") or "").rstrip("/")
        if not base or any(token in base.lower() for token in ("login", "register")):
            continue
        for read in gets:
            raw = str(read.get("raw_path") or read.get("path") or "")
            if raw.startswith(base + "/{"):
                pairs.append((create, read))
    return pairs[0] if len(pairs) == 1 else (None, None)


def _param_names(item: dict, locations: set[str] | None = None) -> set[str]:
    return {
        str(param.get("name"))
        for param in (item.get("params") or [])
        if isinstance(param, dict) and param.get("name")
        and (locations is None or str(param.get("location") or "").lower() in locations)
    }


def _path_parameter(item: dict) -> str:
    names = [
        str(param.get("name")) for param in (item.get("params") or [])
        if isinstance(param, dict) and str(param.get("location") or "").lower() == "path"
    ]
    return names[0] if len(names) == 1 else ""


def _single_named(names: set[str], tokens: tuple[str, ...]) -> str:
    matches = sorted(name for name in names if any(token in name.lower() for token in tokens))
    return matches[0] if len(matches) == 1 else ""


def _resource_field(names: set[str], path_param: str, collection_path: str | None) -> str:
    singular = str(collection_path or "").rstrip("/").rsplit("/", 1)[-1].rstrip("s")
    candidates = sorted(
        name for name in names
        if not re.search(r"secret|private|content|password|token", name, re.I)
        and (path_param.lower() in name.lower() or (singular and singular in name.lower()))
    )
    if len(candidates) == 1:
        return candidates[0]
    preferred = [name for name in candidates if re.search(r"title|name|id$", name, re.I)]
    return preferred[0] if len(preferred) == 1 else ""


def _body_transport(item: dict) -> str:
    locations = {
        str(param.get("location") or "").lower()
        for param in (item.get("params") or []) if isinstance(param, dict)
    }
    return "json" if "json" in locations else "form"


def _identity_step(surface: dict, username: str, password: str, email: str,
                   name: str) -> dict:
    return {
        "name": name,
        "path": str(surface.get("path")),
        "method": "POST",
        "transport": _body_transport(surface),
        "values": {"username": username, "password": password, "email": email},
        "role": "setup",
    }


def _login_step(surface: dict, username: str, password: str, token_name: str,
                name: str) -> dict:
    return {
        "name": name,
        "path": str(surface.get("path")),
        "method": "POST",
        "transport": _body_transport(surface),
        "values": {"username": username, "password": password},
        "capture_json_candidates": {
            token_name: ["auth_token", "access_token", "token"],
        },
        "role": "setup",
    }


def _initializer(items: list[dict]) -> dict | None:
    candidates = [
        item for item in items
        if _is_server_extracted_initializer(item)
        and (
            "db-init" in {str(value).lower() for value in (item.get("tags") or [])}
            or re.search(r"/(?:create|init|reset)[_-]?db$", str(item.get("path") or ""), re.I)
        )
    ]
    return candidates[0] if len(candidates) == 1 else None


def _is_server_extracted_initializer(item: dict) -> bool:
    """Accept only a source-extracted, parameterless GET DB initializer.

    An initializer resets application state, so a guessed live/OpenAPI route or a
    generic state-changing endpoint is never enough.  The pipeline supplies this
    helper only with its freshly extracted source inventory after it has started
    an AuditAgentX-owned disposable Docker sandbox.
    """
    methods = {str(value).upper() for value in (item.get("methods") or [])}
    try:
        line = int(item.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    return bool(
        methods == {"GET"}
        and not (item.get("params") or [])
        and str(item.get("source") or "") in {"static_route", "static_openapi"}
        and str(item.get("file") or "").strip()
        and line > 0
        and str(item.get("path") or "").startswith("/")
        and not str(item.get("path") or "").startswith("//")
    )


def _fill_path(path: str, parameter: str, value: str) -> str:
    if not path.startswith("/") or path.startswith("//"):
        return ""
    rendered, count = re.subn(
        rf"\{{{re.escape(parameter)}\}}", quote(value, safe=""), path, count=1)
    return rendered if count == 1 else ""


def _surface_ref(item: dict) -> dict:
    return {
        "path": item.get("path"),
        "methods": item.get("methods") or [],
        "file": item.get("file"),
        "line": item.get("line"),
        "operation_id": item.get("operation_id"),
    }
