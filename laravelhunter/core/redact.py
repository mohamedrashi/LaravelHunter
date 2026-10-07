from __future__ import annotations
import re
from laravelhunter.models import HttpSnapshot

SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "authorization", "proxy-authorization"}

_META_CSRF = re.compile(r'(<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\'])[^"\']+(["\'])', re.I)
_DATA_CSRF = re.compile(r'(data-csrf=["\'])[^"\']+(["\'])', re.I)
_HIDDEN_TOKEN = re.compile(r'(<input[^>]+name=["\']_token["\'][^>]+value=["\'])[^"\']+(["\'])', re.I)


def _cookie_names_from_set_cookie(value: str) -> list[str]:
    # Best-effort extraction only; the report never needs cookie values.
    names = re.findall(r'(?:^|,\s*)([A-Za-z0-9_.-]+)=', value)
    return sorted(set(names))


def redact_body(body: str) -> str:
    body = _META_CSRF.sub(r'\1<redacted>\2', body)
    body = _DATA_CSRF.sub(r'\1<redacted>\2', body)
    body = _HIDDEN_TOKEN.sub(r'\1<redacted>\2', body)
    return body


def sanitize_snapshot(snapshot: HttpSnapshot) -> HttpSnapshot:
    headers = dict(snapshot.headers)
    if "set-cookie" in headers:
        names = _cookie_names_from_set_cookie(headers["set-cookie"])
        suffix = f" cookie-names={','.join(names)}" if names else ""
        headers["set-cookie"] = f"<redacted;{suffix.strip()}>" if suffix else "<redacted>"

    for header in SENSITIVE_RESPONSE_HEADERS - {"set-cookie"}:
        if header in headers:
            headers[header] = "<redacted>"

    cookies = {name: "<redacted>" for name in snapshot.cookies}

    return snapshot.model_copy(update={
        "headers": headers,
        "cookies": cookies,
        "body_sample": redact_body(snapshot.body_sample),
    })
