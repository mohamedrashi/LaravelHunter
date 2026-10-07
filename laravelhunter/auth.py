from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

FORBIDDEN_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "proxy-connection",
}


@dataclass
class AuthContext:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    source: str | None = None

    @property
    def loaded(self) -> bool:
        return bool(self.headers or self.cookies)

    @property
    def header_names(self) -> list[str]:
        return sorted(self.headers)

    @property
    def cookie_names(self) -> list[str]:
        return sorted(self.cookies)


def _parse_cookie_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for chunk in value.split(";"):
        item = chunk.strip()
        if not item or "=" not in item:
            continue
        name, val = item.split("=", 1)
        name = name.strip()
        if name:
            cookies[name] = val.strip()
    return cookies


def load_auth_file(path: Path) -> AuthContext:
    """Load request headers/cookies without persisting secret values in reports.

    File format is one `Header-Name: value` per line. Blank lines and `#` comments
    are ignored. `Cookie:` is parsed into the client's cookie jar. Hop-by-hop and
    request-framing headers are rejected.
    """
    text = path.read_text(encoding="utf-8")
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Invalid auth-file line {lineno}: expected 'Header: value'")
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            raise ValueError(f"Invalid auth-file line {lineno}: empty header name/value")
        lower = name.lower()
        if lower in FORBIDDEN_HEADERS:
            raise ValueError(f"Header '{name}' is not allowed in auth files")
        if lower == "cookie":
            cookies.update(_parse_cookie_header(value))
        else:
            headers[name] = value

    return AuthContext(headers=headers, cookies=cookies, source=str(path))
