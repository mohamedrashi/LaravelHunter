from __future__ import annotations
from pathlib import Path
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
import yaml

from laravelhunter.models import AdvisoryAssessment, RuntimePrerequisiteResult, VersionResult

SEVERITIES = {"info", "low", "medium", "high", "critical"}


def load_advisories(path: Path) -> list[dict]:
    advisories: list[dict] = []
    if not path.exists():
        return advisories
    for file in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            advisories.append(data)
    return advisories


def _version_matches(version: str, ranges: list[str]) -> bool:
    try:
        parsed = Version(version.lstrip("vV"))
    except InvalidVersion:
        return False
    for raw in ranges:
        try:
            if parsed in SpecifierSet(raw):
                return True
        except InvalidSpecifier:
            continue
    return False


def assess_advisories(version: VersionResult, advisories: list[dict], runtime: list[RuntimePrerequisiteResult] | None = None) -> list[AdvisoryAssessment]:
    results: list[AdvisoryAssessment] = []
    runtime_by_id = {r.advisory_id: r for r in (runtime or [])}
    for item in advisories:
        severity = str(item.get("severity", "info")).lower()
        if severity not in SEVERITIES:
            severity = "info"
        affected = [str(v) for v in item.get("affected", [])]
        patched = [str(v) for v in item.get("patched", [])]

        if not version.version or not version.exact:
            status = "not-evaluated"
            confidence = 0
            reason = "Exact Laravel version is unresolved; affected-range matching was intentionally not performed."
        elif _version_matches(version.version, affected):
            status = "affected-version"
            confidence = min(95, max(75, version.confidence))
            reason = f"Laravel {version.version} falls inside a published affected version range. Runtime prerequisites still require validation."
        else:
            status = "not-affected-version"
            confidence = min(95, max(70, version.confidence))
            reason = f"Laravel {version.version} does not fall inside the published affected version ranges."

        advisory_id = str(item.get("id", "GHSA-UNKNOWN"))
        runtime_result = runtime_by_id.get(advisory_id)
        results.append(AdvisoryAssessment(
            advisory_id=advisory_id,
            cve=item.get("cve"),
            title=str(item.get("title", "Untitled advisory")),
            severity=severity,
            package=str(item.get("package", "laravel/framework")),
            status=status,
            confidence=confidence,
            reason=reason,
            affected_ranges=affected,
            patched_versions=patched,
            prerequisites=[str(v) for v in item.get("prerequisites", [])],
            references=[str(v) for v in item.get("references", [])],
            runtime_status=runtime_result.status if runtime_result else "not-tested",
            runtime_confidence=runtime_result.confidence if runtime_result else 0,
            runtime_summary=runtime_result.summary if runtime_result else "Runtime prerequisites were not tested.",
            runtime_evidence=[e.detail for e in runtime_result.evidence] if runtime_result else [],
        ))
    return results
