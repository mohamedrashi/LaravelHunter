from __future__ import annotations
import json
import re
from pathlib import Path
from urllib.parse import urljoin

from laravelhunter.models import ComponentResult, Evidence, FingerprintResult, HttpSnapshot, VersionResult

EXACT_VERSION_RE = re.compile(r"(?:Laravel(?: Framework)?(?: v|/)?|laravel/framework[^0-9]{0,20})(v?\d+\.\d+(?:\.\d+)?)", re.I)
PHP_VERSION_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I)


def _clean_version(value: str) -> str:
    return value.strip().lstrip("vV")


def normalize_filament_asset_version(value: str) -> str:
    """Normalize Filament asset cache versions to package-like semver hints.

    Filament asset URLs can expose values such as 5.10.0.0 even when the
    installed package version is 5.10.0. The fourth zero is an asset/build
    suffix, not a SemVer patch component.
    """
    cleaned = _clean_version(value)
    parts = cleaned.split(".")
    if len(parts) == 4 and parts[-1] == "0" and all(part.isdigit() for part in parts):
        return ".".join(parts[:3])
    return cleaned


def resolve_passive(snapshot: HttpSnapshot, fingerprint: FingerprintResult) -> VersionResult:
    evidence: list[Evidence] = []
    if fingerprint.version:
        version = _clean_version(fingerprint.version)
        evidence.append(Evidence(source="fingerprint", detail=f"Explicit Laravel version marker: {version}", weight=95))
        return VersionResult(version=version, exact=True, confidence=95, source="response-marker", evidence=evidence)

    match = EXACT_VERSION_RE.search(snapshot.body_sample)
    if match:
        version = _clean_version(match.group(1))
        evidence.append(Evidence(source="body", detail=f"Explicit Laravel framework version found: {version}", weight=95))
        return VersionResult(version=version, exact=True, confidence=95, source="response-marker", evidence=evidence)

    return VersionResult(version=None, exact=False, confidence=0, source="unresolved", evidence=[])


def enrich_with_component_constraints(current: VersionResult, components: list[ComponentResult]) -> VersionResult:
    """Add compatibility hints without pretending they are an installed framework version.

    These constraints are intentionally never used for advisory range matching. They only
    narrow the likely Laravel family when a strongly identified component has documented
    framework compatibility.
    """
    if current.exact:
        return current

    constraints = list(current.constraints)
    majors = list(current.candidate_majors)
    evidence = list(current.evidence)
    confidence = current.confidence
    source = current.source

    filament = next((c for c in components if c.name.lower() == "filament" and c.detected), None)
    if filament and filament.version_hint:
        m = re.match(r"(\d+)", filament.version_hint)
        if m and int(m.group(1)) == 5:
            constraint = "Filament 5 compatibility: Laravel 11.28+ / 12.x / 13.x"
            if constraint not in constraints:
                constraints.append(constraint)
            for major in (11, 12, 13):
                if major not in majors:
                    majors.append(major)
            evidence.append(Evidence(
                source="component-compatibility",
                detail="Filament 5 detected; its 5.x support package allows illuminate/contracts ^11.28|^12.0|^13.0",
                weight=55,
            ))
            confidence = max(confidence, 55)
            source = "component-compatibility"

    return VersionResult(
        version=current.version,
        exact=current.exact,
        confidence=confidence,
        source=source,
        constraints=constraints,
        candidate_majors=sorted(majors),
        evidence=evidence,
    )


def detect_php_version(snapshot: HttpSnapshot) -> str | None:
    value = snapshot.headers.get("x-powered-by", "")
    match = PHP_VERSION_RE.search(value)
    return match.group(1) if match else None


def parse_composer_lock(snapshot: HttpSnapshot) -> str | None:
    if snapshot.status_code != 200:
        return None
    try:
        data = json.loads(snapshot.body_sample)
    except (json.JSONDecodeError, TypeError):
        return None
    packages = []
    if isinstance(data, dict):
        packages.extend(data.get("packages") or [])
        packages.extend(data.get("packages-dev") or [])
    for package in packages:
        if isinstance(package, dict) and package.get("name") == "laravel/framework":
            version = package.get("version")
            if isinstance(version, str) and re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?", version.strip()):
                return _clean_version(version)
    return None


def parse_installed_json(snapshot: HttpSnapshot) -> str | None:
    if snapshot.status_code != 200:
        return None
    try:
        data = json.loads(snapshot.body_sample)
    except (json.JSONDecodeError, TypeError):
        return None

    packages = []
    if isinstance(data, dict):
        packages = data.get("packages") or []
    elif isinstance(data, list):
        for block in data:
            if isinstance(block, dict):
                packages.extend(block.get("packages") or [])
    for package in packages:
        if isinstance(package, dict) and package.get("name") == "laravel/framework":
            version = package.get("version") or package.get("pretty_version")
            if isinstance(version, str) and re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?", version.strip()):
                return _clean_version(version)
    return None


def parse_composer_json_constraint(snapshot: HttpSnapshot) -> str | None:
    if snapshot.status_code != 200:
        return None
    try:
        data = json.loads(snapshot.body_sample)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    require = data.get("require")
    if not isinstance(require, dict):
        return None
    value = require.get("laravel/framework")
    if isinstance(value, str) and 0 < len(value.strip()) <= 100:
        return value.strip()
    return None


def composer_probe_urls(target: str) -> list[tuple[str, str]]:
    base = target if target.endswith("/") else target + "/"
    return [
        ("composer.lock", urljoin(base, "composer.lock")),
        ("vendor/composer/installed.json", urljoin(base, "vendor/composer/installed.json")),
        ("composer.json", urljoin(base, "composer.json")),
    ]


LOCAL_PACKAGE_MAP = {
    "laravel/framework": "Laravel",
    "filament/filament": "Filament",
    "livewire/livewire": "Livewire",
    "laravel/sanctum": "Sanctum",
    "laravel/telescope": "Telescope",
    "laravel/horizon": "Horizon",
}


def _local_lock_packages(data: object) -> list[dict]:
    packages: list[dict] = []
    if isinstance(data, dict):
        for key in ("packages", "packages-dev"):
            value = data.get(key) or []
            if isinstance(value, list):
                packages.extend(item for item in value if isinstance(item, dict))
    return packages


def resolve_local_project(project_path: Path) -> tuple[VersionResult, dict[str, str], list[str]]:
    """Resolve exact package versions from a local Composer project.

    This mode is intended for owned labs/source trees. It never exposes file
    contents in reports; only package names/versions and diagnostic filenames
    are returned.
    """
    root = project_path.expanduser().resolve()
    diagnostics: list[str] = []
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Project path does not exist or is not a directory: {root}")

    lock_path = root / "composer.lock"
    if not lock_path.exists():
        raise FileNotFoundError(f"composer.lock not found under project path: {root}")

    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid composer.lock JSON: {lock_path}") from exc

    versions: dict[str, str] = {}
    for package in _local_lock_packages(data):
        name = package.get("name")
        version = package.get("version") or package.get("pretty_version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        cleaned = _clean_version(version)
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", cleaned):
            versions[name] = cleaned

    laravel_version = versions.get("laravel/framework")
    diagnostics.append("composer.lock parsed locally")
    if not laravel_version:
        return VersionResult(
            version=None,
            exact=False,
            confidence=0,
            source="local-composer-lock-unresolved",
            evidence=[Evidence(source="local-project", detail="composer.lock parsed but laravel/framework was not found", weight=0)],
        ), versions, diagnostics

    result = VersionResult(
        version=laravel_version,
        exact=True,
        confidence=100,
        source="local composer.lock",
        evidence=[Evidence(source="local-project", detail=f"Exact laravel/framework version parsed from local composer.lock: {laravel_version}", weight=100)],
    )
    return result, versions, diagnostics
