from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse

from laravelhunter.advisories.engine import assess_advisories, load_advisories
from laravelhunter.auth import AuthContext
from laravelhunter.assessment import infer_auth_state, coverage_summary
from laravelhunter.core.http import SafeHttpClient
from laravelhunter.core.redact import sanitize_snapshot
from laravelhunter.core.target import normalize_target
from laravelhunter.discovery import discover_routes, summarize_features
from laravelhunter.edge.detect import detect_edge
from laravelhunter.fingerprint.laravel import detect_components, detect_laravel
from laravelhunter.filament.analyzer import analyze_filament_pages
from laravelhunter.models import Evidence, Finding, ScanReport, VersionResult
from laravelhunter.rules.engine import evaluate_rules, load_rules
from laravelhunter.prerequisites.detect import assess_runtime_prerequisites, debug_probe_url
from laravelhunter.versioning.resolver import (
    composer_probe_urls,
    detect_php_version,
    parse_composer_lock,
    parse_installed_json,
    parse_composer_json_constraint,
    resolve_passive,
    enrich_with_component_constraints,
    resolve_local_project,
)


def _same_path(requested: str, final_url: str) -> bool:
    return urlparse(requested).path.rstrip("/") == urlparse(final_url).path.rstrip("/")


async def _safe_active_version_resolution(http: SafeHttpClient, target: str, current: VersionResult) -> tuple[VersionResult, list[str], list[dict]]:
    if current.exact:
        return current, [], []

    exposures: list[str] = []
    diagnostics: list[dict] = []
    best = current

    for label, url in composer_probe_urls(target):
        try:
            snapshot = await http.get(url)
        except Exception as exc:
            diagnostics.append({"probe": label, "status": "error", "detail": type(exc).__name__})
            continue

        same_path = _same_path(url, snapshot.url)
        probe_edge = detect_edge(snapshot)
        probe_result = "readable" if snapshot.status_code == 200 and same_path else "not-usable"
        if probe_edge.protected_response:
            probe_result = "edge-protected-stop"
        diagnostics.append({
            "probe": label,
            "status_code": snapshot.status_code,
            "same_path": same_path,
            "result": probe_result,
            "edge_provider": probe_edge.provider,
        })
        if probe_edge.protected_response:
            break
        if snapshot.status_code != 200 or not same_path:
            continue

        if label == "composer.lock":
            version = parse_composer_lock(snapshot)
            constraint = None
        elif label == "vendor/composer/installed.json":
            version = parse_installed_json(snapshot)
            constraint = None
        else:
            version = None
            constraint = parse_composer_json_constraint(snapshot)

        if version:
            exposures.append(label)
            return VersionResult(
                version=version,
                exact=True,
                confidence=100,
                source=label,
                constraints=best.constraints,
                candidate_majors=best.candidate_majors,
                evidence=[*best.evidence, Evidence(source="safe-active", detail=f"Exact laravel/framework version parsed from public {label}: {version}", weight=100)],
            ), exposures, diagnostics

        if constraint:
            exposures.append(label)
            constraints = list(best.constraints)
            hint = f"composer.json requires laravel/framework {constraint}"
            if hint not in constraints:
                constraints.append(hint)
            best = VersionResult(
                version=None,
                exact=False,
                confidence=max(best.confidence, 70),
                source="composer.json-constraint",
                constraints=constraints,
                candidate_majors=best.candidate_majors,
                evidence=[*best.evidence, Evidence(source="safe-active", detail=hint, weight=70)],
            )

    return best, exposures, diagnostics


async def scan(
    target: str,
    timeout: float = 10.0,
    max_redirects: int = 5,
    rules_dir: Path | None = None,
    advisories_dir: Path | None = None,
    safe_active: bool = False,
    max_discovery_pages: int = 8,
    auth: AuthContext | None = None,
    project_path: Path | None = None,
) -> ScanReport:
    target = normalize_target(target)
    auth = auth or AuthContext()
    http = SafeHttpClient(timeout=timeout, max_redirects=max_redirects, auth_headers=auth.headers, auth_cookies=auth.cookies)
    try:
        home = await http.get(target)
        edge = detect_edge(home)

        # Edge-aware policy: identify protective infrastructure and adapt by
        # slowing read-only assessment. Challenge/rate-limit responses suppress
        # active probing entirely. LaravelHunter never attempts WAF/Cloudflare evasion.
        edge_delay_ms = 750 if edge.waf_detected else 0
        if edge_delay_ms:
            http.set_min_delay_ms(edge_delay_ms)
        edge_active_suppressed = bool(edge.challenge_detected or edge.rate_limited or edge.protected_response)

        components = detect_components(home)
        fingerprint = detect_laravel(home, components=components)
        framework_version = resolve_passive(home, fingerprint)
        framework_version = enrich_with_component_constraints(framework_version, components)
        local_package_versions: dict[str, str] = {}
        local_project_diagnostics: list[str] = []
        if project_path is not None:
            local_version, local_package_versions, local_project_diagnostics = resolve_local_project(project_path)
            if local_version.exact:
                framework_version = local_version
            package_to_component = {
                "filament/filament": "Filament",
                "livewire/livewire": "Livewire",
                "laravel/sanctum": "Sanctum",
                "laravel/telescope": "Telescope",
                "laravel/horizon": "Horizon",
            }
            by_name = {component.name: component for component in components}
            for package, component_name in package_to_component.items():
                version = local_package_versions.get(package)
                component = by_name.get(component_name)
                if version and component is not None:
                    component.version_hint = version
                    component.detected = True
                    component.confidence = 100
                    component.evidence.append(Evidence(source="local-project", detail=f"{package} {version} present in local composer.lock", weight=100))
        manifest_exposures: list[str] = []
        version_probe_diagnostics: list[dict] = []
        debug_probe = None
        runtime_probe_diagnostics: list[dict] = []
        routes = []
        discovered_snapshots = []
        discovery_diagnostics: list[dict] = []

        if safe_active and fingerprint.detected and not edge_active_suppressed:
            framework_version, manifest_exposures, version_probe_diagnostics = await _safe_active_version_resolution(http, target, framework_version)
            probe_edge_stop = any(item.get("result") == "edge-protected-stop" for item in version_probe_diagnostics)
            if probe_edge_stop:
                edge_active_suppressed = True
                runtime_probe_diagnostics.append({"probe": "edge-policy", "status": "suppressed", "detail": "protection-triggered-during-version-probe"})
                discovery_diagnostics.append({"url": home.url, "status_code": home.status_code, "result": "edge-active-suppressed-after-probe", "edge_provider": edge.provider})
            else:
                try:
                    probe_url = debug_probe_url(target)
                    debug_probe = await http.get(probe_url)
                    debug_edge = detect_edge(debug_probe)
                    runtime_probe_diagnostics.append({
                        "probe": "debug-404",
                        "status_code": debug_probe.status_code,
                        "final_url": debug_probe.url,
                        "result": "edge-protected-stop" if debug_edge.protected_response else "response-inspected",
                        "edge_provider": debug_edge.provider,
                    })
                    if debug_edge.protected_response:
                        edge_active_suppressed = True
                except Exception as exc:
                    runtime_probe_diagnostics.append({"probe": "debug-404", "status": "error", "detail": type(exc).__name__})

                if not edge_active_suppressed:
                    routes, discovered_snapshots, discovery_diagnostics = await discover_routes(http, home, max_pages=max_discovery_pages)
                else:
                    discovery_diagnostics.append({"url": home.url, "status_code": home.status_code, "result": "edge-active-suppressed-after-runtime-probe", "edge_provider": edge.provider})
        elif safe_active and edge_active_suppressed:
            reason = "challenge" if edge.challenge_detected else "rate-limit" if edge.rate_limited else "protected-response"
            version_probe_diagnostics.append({"probe": "edge-policy", "status": "suppressed", "detail": reason})
            runtime_probe_diagnostics.append({"probe": "edge-policy", "status": "suppressed", "detail": reason})
            discovery_diagnostics.append({"url": home.url, "status_code": home.status_code, "result": "edge-active-suppressed", "edge_provider": edge.provider})

        all_snapshots = [home, *discovered_snapshots]
        runtime_prerequisites = assess_runtime_prerequisites(home, debug_probe, discovered_snapshots)
        features = summarize_features(routes, all_snapshots) if routes else []
        filament_pages = analyze_filament_pages(all_snapshots)
    finally:
        await http.close()

    if framework_version.version and framework_version.exact:
        fingerprint.version = framework_version.version

    php_version = detect_php_version(home)

    report = ScanReport(
        target=target,
        final_url=home.url,
        fingerprint=fingerprint,
        framework_version=framework_version,
        components=components,
        edge=edge,
        findings=[],
        advisories=[],
        runtime_prerequisites=runtime_prerequisites,
        routes=routes,
        features=features,
        filament_pages=filament_pages,
        snapshots=[sanitize_snapshot(home), *[sanitize_snapshot(s) for s in discovered_snapshots]],
        metadata={
            "mode": "safe-active" if safe_active else "safe-passive",
            "version": "0.9.0",
            "secrets_redacted": True,
            "php_version": php_version,
            "edge_policy": {
                "provider": edge.provider,
                "confidence": edge.confidence,
                "policy": edge.recommended_policy,
                "request_delay_ms": edge_delay_ms,
                "active_suppressed": edge_active_suppressed,
                "reason": "edge-protection-observed" if edge_active_suppressed else "provider-detected" if edge.waf_detected else "none",
            },
            "manifest_exposures": manifest_exposures,
            "version_probe_diagnostics": version_probe_diagnostics,
            "runtime_probe_diagnostics": runtime_probe_diagnostics,
            "discovery_diagnostics": discovery_diagnostics,
            "max_discovery_pages": max_discovery_pages if safe_active else 0,
            "local_project": {
                "enabled": project_path is not None,
                "source": "composer.lock" if project_path is not None else None,
                "package_versions": {
                    key: value for key, value in local_package_versions.items()
                    if key in {"laravel/framework", "filament/filament", "livewire/livewire", "laravel/sanctum", "laravel/telescope", "laravel/horizon"}
                },
                "diagnostics": local_project_diagnostics,
            },
            "auth": {
                "loaded": auth.loaded,
                "state": infer_auth_state(auth.loaded, home),
                "cookie_names": auth.cookie_names,
                "header_names": auth.header_names,
            },
        },
    )

    if rules_dir is None:
        rules_dir = Path(__file__).resolve().parent / "data" / "rules"
    report.findings = evaluate_rules(report, load_rules(rules_dir))

    if manifest_exposures:
        report.findings.append(Finding(
            rule_id="LH-LOW-010",
            title="Public dependency manifest exposed",
            severity="low",
            status="observed",
            confidence=100,
            description="A Composer dependency manifest was publicly readable and exposed Laravel dependency information.",
            evidence=[f"Publicly readable: {item}" for item in manifest_exposures],
            recommendation="Do not serve Composer dependency manifests from the public web root. Restrict them at the web server and deployment layer.",
            references=[],
        ))

    if advisories_dir is None:
        advisories_dir = Path(__file__).resolve().parent / "data" / "advisories"
    report.advisories = assess_advisories(framework_version, load_advisories(advisories_dir), runtime_prerequisites)

    for advisory in report.advisories:
        if advisory.status == "affected-version":
            report.findings.append(Finding(
                rule_id=f"LH-ADV-{advisory.advisory_id}",
                title=f"Affected framework version: {advisory.title}",
                severity=advisory.severity,
                status="potential",
                confidence=advisory.confidence,
                description="The detected Laravel version is within a published affected range. Runtime prerequisite evidence is reported separately and does not by itself prove exploitability.",
                evidence=[
                    f"Laravel version={framework_version.version}",
                    f"Affected ranges={', '.join(advisory.affected_ranges)}",
                    *[f"Prerequisite: {p}" for p in advisory.prerequisites],
                    f"Runtime prerequisite status={advisory.runtime_status} ({advisory.runtime_confidence}%)",
                    *[f"Runtime evidence: {e}" for e in advisory.runtime_evidence],
                ],
                recommendation=f"Review the advisory prerequisites and upgrade to a patched release ({', '.join(advisory.patched_versions)}).",
                references=advisory.references,
            ))

    report.metadata["coverage"] = coverage_summary(report)
    return report
