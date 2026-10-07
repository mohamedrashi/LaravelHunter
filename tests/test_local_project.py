import json
from pathlib import Path

from laravelhunter.versioning.resolver import resolve_local_project, normalize_filament_asset_version


def test_filament_asset_version_normalization():
    assert normalize_filament_asset_version("5.10.0.0") == "5.10.0"
    assert normalize_filament_asset_version("5.10.0") == "5.10.0"


def test_resolve_local_project(tmp_path: Path):
    lock = {
        "packages": [
            {"name": "laravel/framework", "version": "v13.35.0"},
            {"name": "filament/filament", "version": "v5.10.0"},
            {"name": "livewire/livewire", "version": "v4.4.7"},
        ]
    }
    (tmp_path / "composer.lock").write_text(json.dumps(lock))
    result, versions, diagnostics = resolve_local_project(tmp_path)
    assert result.exact is True
    assert result.version == "13.35.0"
    assert result.source == "local composer.lock"
    assert versions["filament/filament"] == "5.10.0"
    assert versions["livewire/livewire"] == "4.4.7"
    assert diagnostics


def test_local_project_missing_lock(tmp_path: Path):
    try:
        resolve_local_project(tmp_path)
    except FileNotFoundError as exc:
        assert "composer.lock" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")
