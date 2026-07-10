"""Safety checks for dynamic verification targets."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from backend.config import settings


def validate_dynamic_base_url(base_url: str | None) -> str:
    """Validate that dynamic HTTP verification targets an authorized local URL by default."""
    raw = str(base_url or "").strip()
    if not raw:
        raise ValueError("dynamic base_url is empty")
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("dynamic base_url must be http(s) with a host")
    if settings.allow_external_dynamic_targets:
        return raw
    if _is_allowed_local_host(parsed.hostname):
        return raw
    raise ValueError(
        "external dynamic targets are disabled; use localhost/127.0.0.1 or set allow_external_dynamic_targets=True"
    )


def _is_allowed_local_host(hostname: str) -> bool:
    host = hostname.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for info in infos:
        address = info[4][0]
        try:
            if not ipaddress.ip_address(address).is_loopback:
                return False
        except ValueError:
            return False
    return bool(infos)
