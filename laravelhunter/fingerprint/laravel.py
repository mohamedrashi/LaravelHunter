from __future__ import annotations
import re
from laravelhunter.models import Evidence, FingerprintResult, HttpSnapshot, ComponentResult
from laravelhunter.versioning.resolver import normalize_filament_asset_version

VERSION_PATTERNS = [
    re.compile(r"Laravel(?: Framework)?(?: v|/)?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"laravel/framework[^0-9]{0,20}(\d+\.\d+(?:\.\d+)?)", re.I),
]

FILAMENT_NAMESPACE_RE = re.compile(r'wire:name=["\'][^"\']*(?:App\\\\Filament|Filament\\\\)', re.I)
FILAMENT_ASSET_RE = re.compile(r'/(?:js|css|fonts)/filament/', re.I)
LIVEWIRE_ASSET_RE = re.compile(r'/livewire(?:[-/]|\.)', re.I)
CSRF_META_RE = re.compile(r'<meta[^>]+name=["\']csrf-token["\']', re.I)
FILAMENT_VERSION_RE = re.compile(r'/filament/(?:filament|support|actions|notifications|schemas|tables)/[^\"\']+[?&]v=(\d+(?:\.\d+){1,3})', re.I)


def _cap(value: int) -> int:
    return max(0, min(100, value))


def detect_laravel(snapshot: HttpSnapshot, components: list[ComponentResult] | None = None) -> FingerprintResult:
    """Detect Laravel using direct signals plus correlated ecosystem evidence.

    The score intentionally favors multiple independent signals over one weak banner.
    Strong Filament/Livewire evidence is correlated because those components are part of
    the Laravel ecosystem, while generic PHP/XSRF signals remain low-weight.
    """
    evidence: list[Evidence] = []
    score = 0
    headers = snapshot.headers
    cookies = {k.lower(): v for k, v in snapshot.cookies.items()}
    body = snapshot.body_sample
    body_lower = body.lower()

    if "laravel_session" in cookies:
        score += 55
        evidence.append(Evidence(source="cookie", detail="Default laravel_session cookie present", weight=55))

    if "xsrf-token" in cookies:
        score += 12
        evidence.append(Evidence(source="cookie", detail="XSRF-TOKEN cookie present", weight=12))

    # Laravel apps frequently customize the session cookie name. This is only a weak
    # signal by itself, and is useful mainly when correlated with XSRF/Filament/Livewire.
    custom_session = next((name for name in cookies if name.endswith("-session") or name.endswith("_session")), None)
    if custom_session and custom_session != "laravel_session":
        score += 8
        evidence.append(Evidence(source="cookie", detail=f"Application session cookie present: {custom_session}", weight=8))

    if "laravel" in headers.get("set-cookie", "").lower():
        score += 25
        evidence.append(Evidence(source="header", detail="Set-Cookie contains Laravel marker", weight=25))

    # Direct response markers.
    if "laravel" in body_lower:
        score += 12
        evidence.append(Evidence(source="body", detail="Body contains 'laravel' marker", weight=12))

    if "whoops" in body_lower:
        score += 5
        evidence.append(Evidence(source="body", detail="Body contains Whoops-style error marker", weight=5))

    if CSRF_META_RE.search(body):
        score += 8
        evidence.append(Evidence(source="body", detail="CSRF meta token marker present", weight=8))

    if FILAMENT_NAMESPACE_RE.search(body):
        score += 45
        evidence.append(Evidence(source="body", detail="Filament PHP component namespace exposed in wire:name", weight=45))

    if FILAMENT_ASSET_RE.search(body):
        score += 35
        evidence.append(Evidence(source="body", detail="Filament asset path detected", weight=35))

    if "wire:snapshot" in body_lower:
        score += 15
        evidence.append(Evidence(source="body", detail="Livewire wire:snapshot directive detected", weight=15))

    if "wire:id" in body_lower:
        score += 8
        evidence.append(Evidence(source="body", detail="Livewire wire:id directive detected", weight=8))

    if LIVEWIRE_ASSET_RE.search(body):
        score += 10
        evidence.append(Evidence(source="body", detail="Livewire asset/update path detected", weight=10))

    # Correlate separately-detected components. This prevents a response with very
    # strong Filament/Livewire evidence from being mislabeled as non-Laravel merely
    # because the default laravel_session cookie was renamed.
    if components:
        by_name = {c.name.lower(): c for c in components}
        filament = by_name.get("filament")
        livewire = by_name.get("livewire")

        if filament and filament.detected and filament.confidence >= 80:
            score += 35
            evidence.append(Evidence(
                source="correlation",
                detail=f"Strong Filament detection correlated with Laravel ({filament.confidence}% component confidence)",
                weight=35,
            ))

        if livewire and livewire.detected and livewire.confidence >= 80:
            score += 20
            evidence.append(Evidence(
                source="correlation",
                detail=f"Strong Livewire detection correlated with Laravel ({livewire.confidence}% component confidence)",
                weight=20,
            ))

    version = None
    for pattern in VERSION_PATTERNS:
        match = pattern.search(body)
        if match:
            version = match.group(1)
            score += 15
            evidence.append(Evidence(source="body", detail=f"Explicit Laravel version exposed: {version}", weight=15))
            break

    confidence = _cap(score)
    return FingerprintResult(detected=confidence >= 50, confidence=confidence, version=version, evidence=evidence)


def detect_components(snapshot: HttpSnapshot) -> list[ComponentResult]:
    body = snapshot.body_sample.lower()
    headers = snapshot.headers
    results: list[ComponentResult] = []

    definitions = {
        "Livewire": [
            ("livewire", 60, "HTML/asset marker contains livewire"),
            ("wire:id", 30, "wire:id directive found"),
            ("wire:snapshot", 30, "wire:snapshot directive found"),
            ("wire:name", 10, "wire:name component directive found"),
        ],
        "Filament": [
            ("filament", 70, "HTML/asset marker contains filament"),
            ("fi-body", 25, "Filament CSS class marker found"),
            ("app\\\\filament\\\\", 20, "Application Filament PHP namespace found"),
        ],
        "Telescope": [
            ("laravel telescope", 70, "Laravel Telescope marker found"),
            ("telescope-toolbar", 40, "Telescope toolbar marker found"),
        ],
        "Horizon": [
            ("laravel horizon", 70, "Laravel Horizon marker found"),
            ("horizon", 20, "Horizon marker found"),
        ],
        "Sanctum": [
            ("sanctum", 45, "Sanctum marker found"),
        ],
    }

    combined = body + "\n" + "\n".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for name, markers in definitions.items():
        score = 0
        evidence: list[Evidence] = []
        for marker, weight, detail in markers:
            if marker in combined:
                score += weight
                evidence.append(Evidence(source="response", detail=detail, weight=weight))
        version_hint = None
        if name == "Filament":
            version_match = FILAMENT_VERSION_RE.search(snapshot.body_sample)
            if version_match:
                version_hint = normalize_filament_asset_version(version_match.group(1))
                evidence.append(Evidence(source="asset", detail=f"Filament asset version hint: {version_hint}", weight=10))
        results.append(ComponentResult(name=name, detected=score >= 40, confidence=_cap(score), version_hint=version_hint, evidence=evidence))
    return results
