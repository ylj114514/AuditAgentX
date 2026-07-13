"""Fail-closed, local-only disposable form-auth bootstrap for dynamic verification."""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import secrets
import re
from urllib.parse import urljoin, urlparse

from backend.dynamic.source_route_binding import is_server_bound_surface
from backend.dynamic.target_guard import is_loopback_base_url


_AUTH_PATHS = {
    "registration": re.compile(r"(?:^|/)(?:register|registration|signup|sign-up|sign_up)(?:/|$)", re.I),
    "login": re.compile(r"(?:^|/)(?:login|log-in|signin|sign-in)(?:/|$)", re.I),
}
_USERNAME_FIELDS = {"username", "user", "user_name", "login"}
_EMAIL_FIELDS = {"email", "email_address"}
_PASSWORD_FIELDS = {"password", "passwd", "pass", "user_password"}
_CONFIRM_FIELDS = {
    "password_confirm", "password_confirmation", "confirm_password", "password_confirmed",
    "verify", "verify_password", "password_verify", "repeat_password", "retype_password",
}
_PROFILE_FIELDS = {"firstname", "first_name", "given_name", "lastname", "last_name", "family_name"}
_CSRF_FIELD = "_csrf"
_ALLOWED_INPUT_TYPES = {"", "text", "email", "password"}


@dataclass
class AuthSetupRecord:
    record: object
    stage: str
    kind: str
    field_names: list[str] = field(default_factory=list)
    csrf_field: str = ""


@dataclass
class AuthBootstrapResult:
    authenticated: bool = False
    reason: str = "authentication_required"
    records: list[AuthSetupRecord] = field(default_factory=list)


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {str(key).lower(): (value or "") for key, value in attrs}
        if tag.lower() == "form":
            if self.current is not None:
                self.current["invalid"] = True
                return
            self.current = {"method": values.get("method", "get").lower(),
                            "action": values.get("action", ""), "fields": [], "invalid": False}
            return
        if self.current is None:
            return
        lower = tag.lower()
        if lower in {"textarea", "select"}:
            self.current["invalid"] = True
            return
        if lower != "input":
            return
        name = values.get("name", "").strip()
        input_type = values.get("type", "").strip().lower()
        if not name and input_type in {"submit", "button", "reset"}:
            return
        if input_type == "hidden":
            # The only hidden value this narrow bootstrap understands is the
            # conventional same-form _csrf token.  A non-empty value is used
            # only in memory and never retained in evidence.  Some applications
            # render a conventional but empty _csrf input without enforcing CSRF;
            # retain that known field shape so it can be omitted from submission.
            # Any other hidden field remains fail-closed.
            if name.lower() != _CSRF_FIELD:
                self.current["invalid"] = True
                return
            self.current["fields"].append({"name": name, "type": input_type,
                                           "value": values["value"]})
            return
        if not name or input_type not in _ALLOWED_INPUT_TYPES:
            self.current["invalid"] = True
            return
        self.current["fields"].append({"name": name, "type": input_type, "value": ""})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


def is_local_auth_redirect(base_url: str, record) -> bool:
    """Only a local 30x Location that names a login route can trigger bootstrap."""
    status = getattr(record, "status_code", None) or getattr(record, "status", None)
    location = str(getattr(record, "redirect_location", "") or "")
    if status not in {301, 302, 303, 307, 308} or not location or not is_loopback_base_url(base_url):
        return False
    resolved = urljoin(base_url.rstrip("/") + "/", location)
    if not _same_origin(base_url, resolved):
        return False
    return bool(_AUTH_PATHS["login"].search(urlparse(resolved).path or ""))


def bootstrap_disposable_form_auth(base_url: str, endpoints: list[dict], probe) -> AuthBootstrapResult:
    """Register and log in a random disposable user using only bound local forms.

    Discovery, actions, form fields, and submission methods are deliberately
    constrained.  Any uncertainty is an authentication-required result, never an
    optimistic request to a guessed endpoint.
    """
    if not is_loopback_base_url(base_url):
        return AuthBootstrapResult(reason="authentication_required")
    routes = _discover_routes(endpoints)
    if routes is None:
        return AuthBootstrapResult(reason="authentication_required")
    register = routes.get("registration")
    login = routes.get("login")
    if register is None or login is None:
        return AuthBootstrapResult(reason="authentication_required")

    credentials = {
        "username": "aax_" + secrets.token_hex(8),
        "email": "aax_" + secrets.token_hex(8) + "@example.invalid",
        # Keep the random disposable password below conservative form limits
        # (NodeGoat accepts at most 20 characters) while retaining upper/lower,
        # digit, and punctuation for common password-policy compatibility.
        "password": "Aax!" + secrets.token_hex(6),
    }
    result = AuthBootstrapResult()
    for kind, route in (("registration", register), ("login", login)):
        fetched = probe.send_values(base_url, route["path"], {}, method="GET", transport="query",
                                    role="setup")
        result.records.append(AuthSetupRecord(fetched, "form_fetch", kind))
        if getattr(fetched, "error", "") or not (200 <= int(getattr(fetched, "status_code", 0) or 0) < 300):
            return result
        form = _safe_form(_form_response_body(fetched), base_url, route, kind)
        if form is None:
            return result
        values = _credential_values(form["fields"], credentials, kind)
        if values is None:
            return result
        submitted = probe.send_values(base_url, form["path"], values, method="POST", transport="form",
                                      role="setup")
        result.records.append(AuthSetupRecord(
            submitted, "form_submit", kind,
            sorted(name for name in values if name.lower() != _CSRF_FIELD),
            form.get("csrf_field", ""),
        ))
        status = getattr(submitted, "status_code", None)
        if getattr(submitted, "error", "") or status is None or not (200 <= int(status) < 400):
            return result
    result.authenticated = True
    result.reason = ""
    return result


def _discover_routes(endpoints: list[dict]) -> dict[str, dict] | None:
    found: dict[str, dict[str, set[str]]] = {"registration": {}, "login": {}}
    for surface in endpoints or []:
        if not is_server_bound_surface(surface):
            continue
        path = str(surface.get("path") or "")
        methods = {str(method).upper() for method in (surface.get("methods") or [])}
        if not path.startswith("/") or path.startswith("//") or not methods <= {"GET", "POST"}:
            continue
        for kind, pattern in _AUTH_PATHS.items():
            if pattern.search(path):
                found[kind].setdefault(path, set()).update(methods)
    if any(len(items) != 1 for items in found.values()):
        return None
    routes = {kind: {"path": next(iter(items)), "methods": next(iter(items.values()))}
              for kind, items in found.items()}
    if any(not {"GET", "POST"} <= route["methods"] for route in routes.values()):
        return None
    return routes


def is_auth_bootstrap_surface(surface: object) -> bool:
    """Whether a freshly extracted source route can join the auth-only inventory."""
    if not isinstance(surface, dict):
        return False
    path = str(surface.get("path") or "")
    methods = {str(method).upper() for method in (surface.get("methods") or [])}
    return bool(
        path.startswith("/") and not path.startswith("//")
        and methods and methods <= {"GET", "POST"}
        and any(pattern.search(path) for pattern in _AUTH_PATHS.values())
    )


def _form_response_body(record) -> str:
    """Use the bounded setup-only body without making raw HTML public evidence."""
    return str(getattr(record, "setup_response_body", "") or getattr(record, "response_excerpt", "") or "")


def _safe_form(html: str, base_url: str, route: dict, kind: str) -> dict | None:
    parser = _FormParser()
    try:
        parser.feed(str(html or ""))
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML is not safe to automate
        return None
    if parser.current is not None or len(parser.forms) != 1:
        return None
    form = parser.forms[0]
    if form["invalid"] or form["method"] != "post":
        return None
    action = urljoin(base_url.rstrip("/") + route["path"], form["action"] or route["path"])
    parsed_action = urlparse(action)
    if (not _same_origin(base_url, action) or parsed_action.path != route["path"]
            or parsed_action.query or parsed_action.fragment):
        return None
    fields = form["fields"]
    names = [str(field["name"]).lower() for field in fields]
    csrf_fields = [field for field in fields if str(field["name"]).lower() == _CSRF_FIELD]
    if len(names) != len(set(names)) or len(csrf_fields) > 1:
        return None
    if csrf_fields and str(csrf_fields[0].get("type") or "").lower() != "hidden":
        return None
    if any(("csrf" in name or "token" in name or "nonce" in name) and name != _CSRF_FIELD
           for name in names):
        return None
    allowed = _USERNAME_FIELDS | _EMAIL_FIELDS | _PASSWORD_FIELDS | _CONFIRM_FIELDS | _PROFILE_FIELDS | {_CSRF_FIELD}
    if not fields or any(name not in allowed for name in names):
        return None
    if not any(name in _PASSWORD_FIELDS for name in names):
        return None
    if not any(name in _USERNAME_FIELDS | _EMAIL_FIELDS for name in names):
        return None
    if kind == "login" and any(name in _CONFIRM_FIELDS | _PROFILE_FIELDS for name in names):
        return None
    return {
        "path": urlparse(action).path,
        "fields": fields,
        # Empty conventional fields are deliberately omitted from the live POST.
        # A target that truly enforces CSRF will reject that POST and remain
        # authentication_required; no dynamic verdict is promoted.
        "csrf_field": (
            str(csrf_fields[0]["name"])
            if csrf_fields and str(csrf_fields[0].get("value") or "").strip()
            else ""
        ),
    }


def _credential_values(fields: list[dict], credentials: dict[str, str], kind: str) -> dict[str, str] | None:
    values: dict[str, str] = {}
    for field in fields:
        raw_name = str(field["name"])
        name = raw_name.lower()
        if name in _USERNAME_FIELDS:
            values[raw_name] = credentials["username"]
        elif name in _EMAIL_FIELDS:
            values[raw_name] = credentials["email"]
        elif name in _PASSWORD_FIELDS or (kind == "registration" and name in _CONFIRM_FIELDS):
            values[raw_name] = credentials["password"]
        elif name in _PROFILE_FIELDS:
            values[raw_name] = "Audit" if "first" in name or "given" in name else "Agent"
        elif name == _CSRF_FIELD:
            value = str(field.get("value") or "")
            if value:
                values[raw_name] = value
        else:
            return None
    return values


def _same_origin(base_url: str, candidate: str) -> bool:
    try:
        base, other = urlparse(base_url), urlparse(candidate)
        return (
            base.scheme == other.scheme
            and (base.hostname or "").lower() == (other.hostname or "").lower()
            and base.port == other.port
        )
    except ValueError:
        return False
