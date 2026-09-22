"""URL validation at the untrusted metadata / CSP boundary."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def origin_of(url: str) -> str:
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
        return ""
    try:
        p = urlsplit(url)
        if p.scheme not in {"http", "https", "ws", "wss"} or not p.hostname:
            return ""
        if p.username is not None or p.password is not None:
            return ""
        host = p.hostname
        if ":" in host:
            host = f"[{ipaddress.IPv6Address(host).compressed}]"
        else:
            host = host.encode("idna").decode("ascii").lower()
            # Never let permissive URL parsing turn authority data into CSP syntax.
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.rstrip(".").split(".")
            ):
                return ""
        port = p.port
        default = 443 if p.scheme in {"https", "wss"} else 80
        suffix = f":{port}" if port is not None and port != default else ""
        return f"{p.scheme}://{host}{suffix}"
    except (ValueError, UnicodeError):
        return ""


def canonical_url(url: str) -> str:
    origin = origin_of(url)
    if not origin or not origin.startswith(("http://", "https://")):
        raise ValueError("Expected an HTTP(S) URL without credentials or whitespace")
    p = urlsplit(url)
    o = urlsplit(origin)
    return urlunsplit((o.scheme, o.netloc, p.path or "/", p.query, ""))
