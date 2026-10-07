from pathlib import Path
import tempfile
import pytest

from laravelhunter.auth import load_auth_file
from laravelhunter.assessment import infer_auth_state, coverage_summary
from laravelhunter.models import HttpSnapshot, FingerprintResult, VersionResult, EdgeResult, ScanReport


def snap(url: str, body: str = ""):
    return HttpSnapshot(url=url, status_code=200, headers={}, cookies={}, body_sample=body, elapsed_ms=1)


def test_load_auth_file_parses_cookie_and_headers():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "auth.txt"
        p.write_text("Cookie: session=abc; XSRF-TOKEN=xyz\nAuthorization: Bearer token\nX-Test: yes\n", encoding="utf-8")
        ctx = load_auth_file(p)
        assert ctx.cookies == {"session": "abc", "XSRF-TOKEN": "xyz"}
        assert ctx.headers["Authorization"] == "Bearer token"
        assert "Cookie" not in ctx.headers
        assert ctx.loaded is True


def test_load_auth_file_rejects_host_header():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "auth.txt"
        p.write_text("Host: evil.test\n", encoding="utf-8")
        with pytest.raises(ValueError):
            load_auth_file(p)


def test_auth_state_login_form_is_likely_unauthenticated():
    home = snap("https://example.test/admin/login", '<input type="password" wire:submit="authenticate">')
    assert infer_auth_state(True, home) == "likely-unauthenticated"
    assert infer_auth_state(False, home) == "not-provided"


def test_coverage_summary_counts():
    report = ScanReport(
        target="https://example.test",
        final_url="https://example.test",
        fingerprint=FingerprintResult(detected=True, confidence=100),
        framework_version=VersionResult(),
        components=[],
        edge=EdgeResult(),
        findings=[],
        advisories=[],
        runtime_prerequisites=[],
        routes=[],
        features=[],
        snapshots=[snap("https://example.test")],
        metadata={},
    )
    c = coverage_summary(report)
    assert c["entry_pages"] == 1
    assert c["exact_version_resolved"] is False
