from pathlib import Path

from laravelhunter.advisories.engine import assess_advisories, load_advisories
from laravelhunter.models import VersionResult

DATA = Path(__file__).resolve().parents[1] / "laravelhunter" / "data" / "advisories"


def test_unresolved_version_is_never_called_affected():
    results = assess_advisories(VersionResult(), load_advisories(DATA))
    assert results
    assert all(a.status == "not-evaluated" for a in results)


def test_affected_12_59_matches_recent_advisories():
    version = VersionResult(version="12.59.0", exact=True, confidence=100, source="test")
    results = {a.advisory_id: a for a in assess_advisories(version, load_advisories(DATA))}
    assert results["GHSA-5vg9-5847-vvmq"].status == "affected-version"
    assert results["GHSA-crmm-hgp2-wgrp"].status == "affected-version"
    assert results["GHSA-jh5r-qr3c-85q8"].status == "affected-version"


def test_patched_12_69_not_affected_by_loaded_advisories():
    version = VersionResult(version="12.69.0", exact=True, confidence=100, source="test")
    results = assess_advisories(version, load_advisories(DATA))
    assert all(a.status == "not-affected-version" for a in results)
