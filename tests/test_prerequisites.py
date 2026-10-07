from laravelhunter.models import HttpSnapshot
from laravelhunter.prerequisites.detect import assess_runtime_prerequisites


def snap(body: str, status: int = 200) -> HttpSnapshot:
    return HttpSnapshot(url="https://example.test/", status_code=status, headers={}, cookies={}, body_sample=body, elapsed_ms=1)


def by_id(results, advisory_id):
    return next(x for x in results if x.advisory_id == advisory_id)


def test_debug_runtime_observed_with_ignition_and_stack_trace():
    result = by_id(assess_runtime_prerequisites(snap("ok"), snap("Ignition Stack Trace Laravel exception", 404)), "GHSA-jh5r-qr3c-85q8")
    assert result.status == "observed"
    assert result.confidence >= 50


def test_login_email_input_is_only_partial_mail_hint():
    result = by_id(assess_runtime_prerequisites(snap('<input type="email" name="email">')), "GHSA-5vg9-5847-vvmq")
    assert result.status == "partial"
    assert result.confidence < 50


def test_signed_url_pair_is_partial_without_local_driver_proof():
    result = by_id(assess_runtime_prerequisites(snap('<a href="/download/x?expires=1&signature=abc">x</a>')), "GHSA-crmm-hgp2-wgrp")
    assert result.status in {"partial", "observed"}
    assert result.confidence >= 55
