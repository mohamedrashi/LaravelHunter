from __future__ import annotations
from urllib.parse import urlparse


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be a valid HTTP/HTTPS URL")
    return target.rstrip("/")
