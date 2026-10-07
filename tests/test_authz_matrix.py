from laravelhunter.authz_matrix import build_authorization_matrix
from laravelhunter.models import (
    ComponentResult, EdgeResult, FilamentPageSurface, FingerprintResult,
    ScanReport, VersionResult
)


def _report(pages, state="possibly-authenticated"):
    return ScanReport(
        target="https://example.test",
        final_url="https://example.test/admin",
        fingerprint=FingerprintResult(detected=True, confidence=100),
        framework_version=VersionResult(),
        components=[ComponentResult(name="Filament", detected=True, confidence=100)],
        edge=EdgeResult(), findings=[], filament_pages=pages, snapshots=[],
        metadata={"auth": {"state": state}},
    )


def page(path, status=200, access="reachable", actions=None, authz=None, priority="normal"):
    actions = actions or []
    return FilamentPageSurface(
        url="https://example.test" + path, path=path, status_code=status,
        access_state=access, review_priority=priority,
        page_actions=actions, actions=actions,
        authorization_surfaces=authz or [],
    )


def test_matrix_detects_access_difference():
    a = _report([page("/admin/users")])
    b = _report([page("/admin/users", 403, "denied")])
    m = build_authorization_matrix("https://example.test", a, b, "admin", "viewer")
    assert m.rows[0].access_diff is True
    assert m.metadata["access_differences"] == 1


def test_matrix_detects_action_visibility_difference_without_finding():
    a = _report([page("/admin/users", actions=["create", "delete"], authz=["page-action:create"])])
    b = _report([page("/admin/users", actions=["create"], authz=["page-action:create"])])
    m = build_authorization_matrix("https://example.test", a, b, "admin", "editor")
    row = m.rows[0]
    assert row.only_a_actions == ["delete"]
    assert row.action_diff is True
    assert m.metadata["actions_executed"] == 0


def test_matrix_marks_missing_page_as_not_observed():
    a = _report([page("/admin/roles", priority="high")])
    b = _report([])
    m = build_authorization_matrix("https://example.test", a, b, "admin", "viewer")
    row = m.rows[0]
    assert row.b_access == "not-observed"
    assert row.priority == "high"


def test_matrix_no_difference():
    p1 = page("/admin/accounts", actions=["syncFromSynapse"])
    p2 = page("/admin/accounts", actions=["syncFromSynapse"])
    m = build_authorization_matrix("https://example.test", _report([p1]), _report([p2]), "a", "b")
    assert m.metadata["paths_with_differences"] == 0
    assert m.rows[0].notes == ["No observed authorization-surface difference"]


def test_matrix_summary_does_not_record_secrets():
    a = _report([page("/admin/users")])
    b = _report([page("/admin/users")])
    m = build_authorization_matrix("https://example.test", a, b, "admin", "viewer")
    assert m.metadata["secrets_recorded"] is False
    assert m.metadata["forms_submitted"] == 0
