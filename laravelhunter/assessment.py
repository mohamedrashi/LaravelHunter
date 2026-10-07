from __future__ import annotations
import re
from urllib.parse import urlparse

from laravelhunter.models import ScanReport, HttpSnapshot

LOGIN_PATH_RE = re.compile(r"/(?:admin/)?(?:login|signin|sign-in)(?:/|$)", re.I)
LOGIN_BODY_RE = re.compile(r"type=[\"']password[\"']|wire:submit=[\"']authenticate[\"']", re.I)


def infer_auth_state(auth_loaded: bool, home: HttpSnapshot) -> str:
    if not auth_loaded:
        return "not-provided"
    path = urlparse(home.url).path or "/"
    if LOGIN_PATH_RE.search(path) and LOGIN_BODY_RE.search(home.body_sample):
        return "likely-unauthenticated"
    return "possibly-authenticated"


def coverage_summary(report: ScanReport) -> dict[str, int | str | bool]:
    return {
        "entry_pages": len(report.snapshots),
        "route_surfaces": len(report.routes),
        "feature_surfaces": len(report.features),
        "filament_pages": len(report.filament_pages),
        "high_interest_filament_pages": sum(1 for p in report.filament_pages if p.review_priority == "high"),
        "medium_interest_filament_pages": sum(1 for p in report.filament_pages if p.review_priority == "medium"),
        "resource_correlated_pages": sum(1 for p in report.filament_pages if p.resource_classes or p.page_classes),
        "authorization_surfaces": sum(len(p.authorization_surfaces) for p in report.filament_pages),
        "ui_state_actions": sum(len(p.ui_state_actions) for p in report.filament_pages),
        "exact_version_resolved": bool(report.framework_version.version and report.framework_version.exact),
        "advisories_evaluated": sum(1 for a in report.advisories if a.status != "not-evaluated"),
        "advisories_with_runtime_evidence": sum(1 for a in report.advisories if a.runtime_confidence > 0),
    }
