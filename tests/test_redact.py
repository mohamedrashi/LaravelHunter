from laravelhunter.core.redact import sanitize_snapshot
from laravelhunter.models import HttpSnapshot


def test_report_redacts_cookie_and_csrf_values():
    s = HttpSnapshot(
        url="https://example.test",
        status_code=200,
        headers={"set-cookie": "XSRF-TOKEN=secret; Path=/, app-session=verysecret; HttpOnly"},
        cookies={"XSRF-TOKEN": "secret", "app-session": "verysecret"},
        body_sample='<meta name="csrf-token" content="topsecret"><script data-csrf="secret2"></script>',
        elapsed_ms=1,
    )
    clean = sanitize_snapshot(s)
    blob = clean.model_dump_json()
    assert "verysecret" not in blob
    assert "topsecret" not in blob
    assert "secret2" not in blob
    assert "<redacted>" in blob
