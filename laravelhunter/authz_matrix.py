from __future__ import annotations

from urllib.parse import urljoin, urlparse

from laravelhunter.auth import AuthContext
from laravelhunter.core.http import SafeHttpClient
from laravelhunter.filament.analyzer import analyze_filament_pages
from laravelhunter.models import (
    AuthorizationMatrixReport,
    AuthorizationMatrixRow,
    AuthorizationRoleSummary,
    Evidence,
    FilamentPageSurface,
    HttpSnapshot,
    ScanReport,
)


def _action_set(page: FilamentPageSurface | None) -> set[str]:
    if page is None:
        return set()
    return set(page.page_actions) | set(page.table_actions) | set(page.bulk_actions) | set(page.submit_actions)


def _page_map(report: ScanReport) -> dict[str, FilamentPageSurface]:
    return {p.path: p for p in report.filament_pages}


def _role_summary(label: str, report: ScanReport) -> AuthorizationRoleSummary:
    pages = report.filament_pages
    return AuthorizationRoleSummary(
        label=label,
        auth_state=(report.metadata.get("auth") or {}).get("state", "unknown"),
        final_url=report.final_url,
        reachable_pages=sum(1 for p in pages if p.access_state == "reachable"),
        denied_pages=sum(1 for p in pages if p.access_state == "denied"),
        filament_pages=len(pages),
        application_actions=sum(len(_action_set(p)) for p in pages),
        authorization_surfaces=sum(len(p.authorization_surfaces) for p in pages),
    )


def _identity(a: FilamentPageSurface | None, b: FilamentPageSurface | None) -> tuple[str | None, str | None]:
    page = a or b
    if page is None:
        return None, None
    resource = ", ".join(page.resource_classes[:2]) or None
    identity_parts = [*page.page_classes[:1], *page.page_types[:1]]
    identity = " / ".join(identity_parts) or None
    return resource, identity


def build_authorization_matrix(
    target: str,
    report_a: ScanReport,
    report_b: ScanReport,
    label_a: str,
    label_b: str,
) -> AuthorizationMatrixReport:
    """Compare two read-only authenticated inventories.

    This function does not execute actions and does not infer which role *should*
    be more privileged. Differences are review signals, not vulnerability findings.
    """
    a_map = _page_map(report_a)
    b_map = _page_map(report_b)
    all_paths = sorted(set(a_map) | set(b_map))
    rows: list[AuthorizationMatrixRow] = []
    priority_order = {"high": 0, "medium": 1, "normal": 2}

    for path in all_paths:
        a = a_map.get(path)
        b = b_map.get(path)
        a_actions = sorted(_action_set(a))
        b_actions = sorted(_action_set(b))
        a_authz = sorted(set(a.authorization_surfaces if a else []))
        b_authz = sorted(set(b.authorization_surfaces if b else []))
        only_a_actions = sorted(set(a_actions) - set(b_actions))
        only_b_actions = sorted(set(b_actions) - set(a_actions))
        only_a_authz = sorted(set(a_authz) - set(b_authz))
        only_b_authz = sorted(set(b_authz) - set(a_authz))

        a_access = a.access_state if a else "not-observed"
        b_access = b.access_state if b else "not-observed"
        access_diff = (a_access, a.status_code if a else None) != (b_access, b.status_code if b else None)
        action_diff = bool(only_a_actions or only_b_actions)
        authz_diff = bool(only_a_authz or only_b_authz)

        priority_candidates = [p.review_priority for p in (a, b) if p]
        priority = min(priority_candidates, key=lambda x: priority_order.get(x, 9)) if priority_candidates else "normal"
        resource, page_identity = _identity(a, b)

        notes: list[str] = []
        if access_diff:
            notes.append("Access state differs between supplied sessions")
        if action_diff:
            notes.append("Visible application-action surface differs")
        if authz_diff:
            notes.append("Authorization-review surface differs")
        if not notes:
            notes.append("No observed authorization-surface difference")

        rows.append(AuthorizationMatrixRow(
            path=path,
            priority=priority,
            resource=resource,
            page_identity=page_identity,
            a_status=a.status_code if a else None,
            a_access=a_access,
            b_status=b.status_code if b else None,
            b_access=b_access,
            a_actions=a_actions,
            b_actions=b_actions,
            only_a_actions=only_a_actions,
            only_b_actions=only_b_actions,
            a_authz_surfaces=a_authz,
            b_authz_surfaces=b_authz,
            only_a_authz_surfaces=only_a_authz,
            only_b_authz_surfaces=only_b_authz,
            access_diff=access_diff,
            action_diff=action_diff,
            authz_diff=authz_diff,
            notes=notes,
        ))

    rows.sort(key=lambda r: (0 if (r.access_diff or r.action_diff or r.authz_diff) else 1, priority_order.get(r.priority, 9), r.path))
    changed = sum(1 for r in rows if r.access_diff or r.action_diff or r.authz_diff)
    access_changed = sum(1 for r in rows if r.access_diff)
    action_changed = sum(1 for r in rows if r.action_diff)
    authz_changed = sum(1 for r in rows if r.authz_diff)

    return AuthorizationMatrixReport(
        target=target,
        role_a=_role_summary(label_a, report_a),
        role_b=_role_summary(label_b, report_b),
        rows=rows,
        metadata={
            "version": "0.9.0",
            "comparison_scope": "read-only visibility/access comparison",
            "paths_compared": len(rows),
            "paths_with_differences": changed,
            "access_differences": access_changed,
            "action_differences": action_changed,
            "authz_surface_differences": authz_changed,
            "actions_executed": 0,
            "forms_submitted": 0,
            "secrets_recorded": False,
        },
    )


def _canonical_path(url_or_path: str) -> str:
    p = urlparse(url_or_path)
    path = p.path if p.scheme else url_or_path.split("?", 1)[0]
    path = path or "/"
    return path.rstrip("/") or "/"


def _generic_surface(requested_path: str, snap: HttpSnapshot, peer: FilamentPageSurface | None = None) -> FilamentPageSurface:
    final_path = _canonical_path(snap.url)
    if final_path != requested_path:
        access = "redirect"
    elif 200 <= snap.status_code < 300:
        access = "reachable"
    elif snap.status_code in {401, 403}:
        access = "denied"
    elif snap.status_code == 404:
        access = "not-found"
    elif 300 <= snap.status_code < 400:
        access = "redirect"
    else:
        access = "other"
    return FilamentPageSurface(
        url=snap.url,
        path=requested_path,
        status_code=snap.status_code,
        access_state=access,
        review_priority=peer.review_priority if peer else "normal",
        priority_reasons=list(peer.priority_reasons) if peer else [],
        resource_classes=list(peer.resource_classes) if peer else [],
        page_classes=list(peer.page_classes) if peer else [],
        page_types=list(peer.page_types) if peer else [],
        evidence=[Evidence(source="auth-matrix-cross-check", detail=f"Read-only GET cross-check for {requested_path}; final path {final_path}", weight=70)],
    )


async def cross_check_union_paths(
    target: str,
    report: ScanReport,
    peer_report: ScanReport,
    auth: AuthContext,
    timeout: float = 10.0,
    max_redirects: int = 5,
) -> int:
    """GET only the peer-observed Filament paths missing from this report.

    Paths are never invented: every requested path was already observed by one of
    the two supplied sessions. No forms or application actions are executed.
    """
    own = {p.path: p for p in report.filament_pages}
    peer = {p.path: p for p in peer_report.filament_pages}
    missing = [path for path in sorted(peer) if path not in own]
    if not missing:
        return 0

    http = SafeHttpClient(timeout=timeout, max_redirects=max_redirects, auth_headers=auth.headers, auth_cookies=auth.cookies)
    checked = 0
    try:
        for path in missing:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                snap = await http.get(url)
            except Exception:
                continue
            checked += 1
            final_path = _canonical_path(snap.url)
            if final_path == path:
                parsed = analyze_filament_pages([snap])
                if parsed:
                    surface = parsed[0]
                    surface.path = path
                    # Preserve the peer's triage identity if this response is a generic
                    # denied/not-found page without useful Filament identity.
                    if not surface.resource_classes and peer[path].resource_classes:
                        surface.resource_classes = list(peer[path].resource_classes)
                    if not surface.page_classes and peer[path].page_classes:
                        surface.page_classes = list(peer[path].page_classes)
                    if surface.review_priority == "normal" and peer[path].review_priority != "normal":
                        surface.review_priority = peer[path].review_priority
                        surface.priority_reasons = list(peer[path].priority_reasons)
                else:
                    surface = _generic_surface(path, snap, peer[path])
            else:
                surface = _generic_surface(path, snap, peer[path])
            report.filament_pages.append(surface)
            own[path] = surface
    finally:
        await http.close()
    report.filament_pages.sort(key=lambda p: p.path)
    return checked
