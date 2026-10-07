from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlparse, urlunparse

from laravelhunter.core.http import SafeHttpClient
from laravelhunter.edge.detect import detect_edge
from laravelhunter.models import Evidence, FeatureSurface, HttpSnapshot, RouteSurface

STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".webm", ".mp3",
}
UNSAFE_PATH_WORDS = {
    "logout", "signout", "sign-out", "delete", "destroy", "remove", "revoke", "disable", "terminate",
    "unsubscribe", "confirm-delete", "impersonate",
}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value)


def _origin(url: str) -> tuple[str, str]:
    p = urlparse(url)
    return p.scheme.lower(), p.netloc.lower()


def _canonical_resource_key(url: str) -> tuple[str, str, str]:
    """Canonical server-resource identity for bounded discovery.

    Query-string variants are treated as the same page resource so table filters,
    pagination, and sort links do not inflate route/page counts or trigger repeated GETs.
    Paths remain case-sensitive.
    """
    p = urlparse(url)
    path = p.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return p.scheme.lower(), p.netloc.lower(), path


def _normalize_candidate(base_url: str, raw: str, origin: tuple[str, str]) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    absolute = urljoin(base_url, raw)
    p = urlparse(absolute)
    if p.scheme.lower() not in {"http", "https"} or _origin(absolute) != origin:
        return None
    path = p.path or "/"
    lower_path = path.lower()
    if any(lower_path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return None
    segments = {seg for seg in lower_path.split("/") if seg}
    if segments & UNSAFE_PATH_WORDS:
        return None
    # Fragments do not change the server resource. Preserve existing query strings but never invent/mutate them.
    return urlunparse((p.scheme, p.netloc, path, "", p.query, ""))


def extract_same_origin_links(snapshot: HttpSnapshot, root_origin: tuple[str, str]) -> list[str]:
    parser = _LinkParser()
    try:
        parser.feed(snapshot.body_sample)
    except Exception:
        return []
    found: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in parser.hrefs:
        candidate = _normalize_candidate(snapshot.url, raw, root_origin)
        if candidate:
            key = _canonical_resource_key(candidate)
            if key not in seen:
                seen.add(key)
                found.append(candidate)
    return found


def _route_kind(url: str, body: str = "") -> str:
    path = urlparse(url).path.lower()
    text = f"{path}\n{body[:12000].lower()}"
    if re.search(r"/(?:admin|panel)(?:/|$)", path):
        return "admin-panel"
    if re.search(r"/(?:login|signin|sign-in)(?:/|$)", path):
        return "auth-login"
    if re.search(r"/(?:register|signup|sign-up)(?:/|$)", path):
        return "auth-registration"
    if re.search(r"(?:forgot[-_/]?password|password/(?:reset|email)|reset[-_/]?password)", text):
        return "password-reset"
    if re.search(r"/(?:api)(?:/|$)", path):
        return "api"
    if re.search(r"/(?:download|storage|uploads?|files?)(?:/|$)", path):
        return "file-surface"
    return "page"


def _extract_non_get_surfaces(snapshot: HttpSnapshot) -> list[RouteSurface]:
    body = snapshot.body_sample
    routes: list[RouteSurface] = []
    seen: set[tuple[str, str]] = set()

    patterns = [
        (r'data-update-uri=["\']([^"\']+)["\']', "livewire-update"),
        (r'data-module-url=["\']([^"\']+)["\']', "livewire-module"),
    ]
    for regex, kind in patterns:
        for match in re.finditer(regex, body, re.I):
            url = urljoin(snapshot.url, match.group(1))
            key = (url, kind)
            if key in seen:
                continue
            seen.add(key)
            routes.append(RouteSurface(
                url=url,
                path=urlparse(url).path or "/",
                kind=kind,
                source="html-marker",
                status_code=None,
                fetched=False,
                evidence=[Evidence(source="discovery", detail=f"{kind} endpoint exposed in HTML", weight=80)],
            ))
    return routes


def summarize_features(routes: list[RouteSurface], snapshots: list[HttpSnapshot]) -> list[FeatureSurface]:
    features: dict[str, list[Evidence]] = {}

    def add(name: str, detail: str, weight: int) -> None:
        features.setdefault(name, []).append(Evidence(source="discovery", detail=detail, weight=weight))

    for route in routes:
        mapping = {
            "admin-panel": ("Filament/Admin panel surface", 70),
            "auth-login": ("Authentication login surface", 60),
            "auth-registration": ("Registration surface", 55),
            "password-reset": ("Password reset / outbound mail surface", 65),
            "api": ("API surface", 45),
            "file-surface": ("File/download surface", 45),
            "livewire-update": ("Livewire update endpoint", 90),
            "livewire-module": ("Livewire module endpoint", 70),
        }
        if route.kind in mapping:
            name, weight = mapping[route.kind]
            add(name, f"Observed route: {route.path}", weight)

    for snap in snapshots:
        body = snap.body_sample.lower()
        if "signature=" in body and "expires=" in body:
            add("Signed URL surface", f"Signed URL parameters observed in {urlparse(snap.url).path or '/'}", 75)
        if "wire:snapshot" in body or "data-update-uri=" in body:
            add("Livewire runtime surface", f"Livewire runtime markers observed in {urlparse(snap.url).path or '/'}", 80)
        if "filament" in body:
            add("Filament runtime surface", f"Filament markers observed in {urlparse(snap.url).path or '/'}", 75)

    result: list[FeatureSurface] = []
    for name, evidence in sorted(features.items()):
        score = min(100, sum(e.weight for e in evidence))
        result.append(FeatureSurface(name=name, observed=True, confidence=score, evidence=evidence[:8]))
    return result


async def discover_routes(http: SafeHttpClient, home: HttpSnapshot, max_pages: int = 8) -> tuple[list[RouteSurface], list[HttpSnapshot], list[dict]]:
    """Conservative same-origin GET discovery.

    Only follows anchor links already present in fetched HTML. It never submits forms,
    never invents parameters, never calls non-GET endpoints, and skips action-like paths.
    """
    if max_pages <= 0:
        return _extract_non_get_surfaces(home), [], []

    root_origin = _origin(home.url)
    queue = deque(extract_same_origin_links(home, root_origin))
    visited: set[tuple[str, str, str]] = {_canonical_resource_key(home.url)}
    routes: list[RouteSurface] = [
        RouteSurface(
            url=home.url,
            path=urlparse(home.url).path or "/",
            kind=_route_kind(home.url, home.body_sample),
            source="entry",
            status_code=home.status_code,
            fetched=True,
            evidence=[Evidence(source="discovery", detail="Final entry page", weight=100)],
        ),
        *_extract_non_get_surfaces(home),
    ]
    snapshots: list[HttpSnapshot] = []
    diagnostics: list[dict] = []

    while queue and len(snapshots) < max_pages:
        url = queue.popleft()
        request_key = _canonical_resource_key(url)
        if request_key in visited:
            continue
        visited.add(request_key)
        try:
            snap = await http.get(url)
        except Exception as exc:
            diagnostics.append({"url": url, "status": "error", "detail": type(exc).__name__})
            continue

        if _origin(snap.url) != root_origin:
            diagnostics.append({"url": url, "status_code": snap.status_code, "result": "cross-origin-redirect-skipped"})
            continue

        edge = detect_edge(snap)
        snapshots.append(snap)
        routes.append(RouteSurface(
            url=snap.url,
            path=urlparse(snap.url).path or "/",
            kind=_route_kind(snap.url, snap.body_sample),
            source="anchor-crawl",
            status_code=snap.status_code,
            fetched=True,
            evidence=[Evidence(source="discovery", detail=f"Same-origin anchor followed with GET ({snap.status_code})", weight=60)],
        ))
        routes.extend(_extract_non_get_surfaces(snap))
        result = "fetched"
        if edge.protected_response:
            result = "edge-protected-stop"
        diagnostics.append({
            "url": url,
            "status_code": snap.status_code,
            "final_url": snap.url,
            "result": result,
            "edge_provider": edge.provider,
            "edge_policy": edge.recommended_policy,
        })

        # Respect edge controls. A challenge, explicit rate-limit, or provider-backed
        # protected response ends bounded discovery instead of attempting evasion.
        if edge.protected_response:
            break

        queued_keys = {_canonical_resource_key(item) for item in queue}
        for candidate in extract_same_origin_links(snap, root_origin):
            candidate_key = _canonical_resource_key(candidate)
            if candidate_key not in visited and candidate_key not in queued_keys:
                queue.append(candidate)
                queued_keys.add(candidate_key)

    # Stable deduplication by canonical resource + kind. Merge evidence when the
    # same path was observed through multiple query-string variants or links.
    deduped: list[RouteSurface] = []
    by_key: dict[tuple[tuple[str, str, str], str], RouteSurface] = {}
    for route in routes:
        key = (_canonical_resource_key(route.url), route.kind)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = route
            deduped.append(route)
            continue
        existing.evidence = [*existing.evidence, *[e for e in route.evidence if e.detail not in {x.detail for x in existing.evidence}]]
        existing.fetched = existing.fetched or route.fetched
        if existing.status_code is None and route.status_code is not None:
            existing.status_code = route.status_code
    return deduped, snapshots, diagnostics
