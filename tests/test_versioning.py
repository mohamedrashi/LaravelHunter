import json
from laravelhunter.models import HttpSnapshot
from laravelhunter.versioning.resolver import parse_composer_lock, parse_installed_json, parse_composer_json_constraint, enrich_with_component_constraints


def snap(body: str):
    return HttpSnapshot(url="https://example.test/composer.lock", status_code=200, headers={}, cookies={}, body_sample=body, elapsed_ms=1)


def test_parse_composer_lock_exact_framework_version():
    body = json.dumps({"packages": [{"name": "laravel/framework", "version": "v12.69.0"}]})
    assert parse_composer_lock(snap(body)) == "12.69.0"


def test_parse_installed_json_exact_framework_version():
    body = json.dumps({"packages": [{"name": "laravel/framework", "version": "v13.30.0"}]})
    assert parse_installed_json(snap(body)) == "13.30.0"


def test_parse_composer_json_constraint():
    body = json.dumps({"require": {"laravel/framework": "^12.0"}})
    assert parse_composer_json_constraint(snap(body)) == "^12.0"


def test_filament_5_adds_compatibility_hint_without_exact_version():
    from laravelhunter.models import VersionResult, ComponentResult
    current = VersionResult()
    components = [ComponentResult(name="Filament", detected=True, confidence=100, version_hint="5.0.0.0", evidence=[])]
    result = enrich_with_component_constraints(current, components)
    assert result.exact is False
    assert result.version is None
    assert result.candidate_majors == [11, 12, 13]
    assert result.confidence >= 55
