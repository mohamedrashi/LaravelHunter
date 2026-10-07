from __future__ import annotations
from pathlib import Path
from laravelhunter.models import ScanReport

ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _framework_label(detected: bool, confidence: int) -> str:
    if detected and confidence >= 90:
        return "Detected — high confidence"
    if detected:
        return "Detected — moderate confidence"
    if confidence >= 30:
        return "Possible / not confirmed"
    return "Not confirmed"


def write_json(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_markdown(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# LaravelHunter Security Assessment",
        "",
        f"**Target:** `{report.target}`  ",
        f"**Final URL:** `{report.final_url}`  ",
        f"**Mode:** `{report.metadata.get('mode', 'unknown')}`  ",
        "",
        "## Assessment Context",
        "",
    ]
    auth_meta = report.metadata.get("auth") or {}
    lines += [
        f"- Authentication context supplied: **{bool(auth_meta.get('loaded'))}**",
        f"- Authentication state: **{auth_meta.get('state', 'not-provided')}**",
    ]
    if auth_meta.get("loaded"):
        lines.append("- Imported cookie names: " + (", ".join(f"`{x}`" for x in auth_meta.get("cookie_names", [])) or "none"))
        lines.append("- Imported header names: " + (", ".join(f"`{x}`" for x in auth_meta.get("header_names", [])) or "none"))
        lines.append("- Secret values are intentionally omitted from the report.")
    coverage = report.metadata.get("coverage") or {}
    if coverage:
        lines += [
            "",
            "### Assessment Coverage",
            "",
            f"- Saved pages: **{coverage.get('entry_pages', 0)}**",
            f"- Route surfaces: **{coverage.get('route_surfaces', 0)}**",
            f"- Feature surfaces: **{coverage.get('feature_surfaces', 0)}**",
            f"- Filament pages inventoried: **{coverage.get('filament_pages', 0)}**",
            f"- High-interest Filament pages: **{coverage.get('high_interest_filament_pages', 0)}**",
            f"- Medium-interest Filament pages: **{coverage.get('medium_interest_filament_pages', 0)}**",
            f"- Authorization review surfaces: **{coverage.get('authorization_surfaces', 0)}**",
            f"- UI/state-only action markers: **{coverage.get('ui_state_actions', 0)}**",
            f"- Exact Laravel version resolved: **{bool(coverage.get('exact_version_resolved'))}**",
            f"- Advisories with version evaluation: **{coverage.get('advisories_evaluated', 0)}**",
            f"- Advisories with runtime evidence: **{coverage.get('advisories_with_runtime_evidence', 0)}**",
        ]
    lines += ["", "## Fingerprint", ""]

    lines += [
        f"- Laravel status: **{_framework_label(report.fingerprint.detected, report.fingerprint.confidence)}**",
        f"- Confidence: **{report.fingerprint.confidence}%**",
        "",
        "### Fingerprint Evidence",
        "",
    ]
    if report.fingerprint.evidence:
        for e in sorted(report.fingerprint.evidence, key=lambda x: x.weight, reverse=True):
            lines.append(f"- {e.detail} (+{e.weight})")
    else:
        lines.append("- No framework-specific evidence recorded")

    lines += ["", "## Framework Version", ""]
    if report.framework_version.version:
        lines += [
            f"- Laravel version: **{report.framework_version.version}**",
            f"- Exact version: **{report.framework_version.exact}**",
            f"- Confidence: **{report.framework_version.confidence}%**",
            f"- Source: **{report.framework_version.source}**",
        ]
        for e in report.framework_version.evidence:
            lines.append(f"- Evidence: {e.detail}")
    else:
        lines.append("- Laravel version: **Unresolved**")
        if report.framework_version.constraints:
            lines.append("- Version constraints / compatibility hints:")
            lines.extend(f"  - {item}" for item in report.framework_version.constraints)
        if report.framework_version.candidate_majors:
            lines.append("- Candidate Laravel majors: **" + ", ".join(map(str, report.framework_version.candidate_majors)) + "**")
        if report.framework_version.evidence:
            lines.append("- Version-hint evidence:")
            lines.extend(f"  - {e.detail}" for e in report.framework_version.evidence)
        lines.append("- Advisory range matching is not performed without an exact installed version.")

    diagnostics = report.metadata.get("version_probe_diagnostics") or []
    if diagnostics:
        lines += ["", "### Version Probe Diagnostics", ""]
        for item in diagnostics:
            status = item.get("status_code", item.get("status", "unknown"))
            result = item.get("result", item.get("detail", ""))
            lines.append(f"- `{item.get('probe')}`: {status} — {result}")

    local_meta = report.metadata.get("local_project") or {}
    if local_meta.get("enabled"):
        lines += ["", "### Local Project Versions", ""]
        lines.append("Owned local project mode is enabled. Only package names/versions are recorded; Composer file contents are not copied into the report.")
        for package, version in (local_meta.get("package_versions") or {}).items():
            lines.append(f"- `{package}`: **{version}**")

    php_version = report.metadata.get("php_version")
    if php_version:
        lines.append(f"- PHP header version: **{php_version}**")

    lines += ["", "## Components", ""]
    for c in report.components:
        suffix = f" — version hint `{c.version_hint}`" if c.version_hint else ""
        lines.append(f"- {c.name}: **{'Detected' if c.detected else 'Not confirmed'}** ({c.confidence}%){suffix}")

    lines += ["", "## Safe Route Discovery", ""]
    if not report.routes:
        lines.append("No route discovery performed (passive mode) or no routes were observed.")
    else:
        lines.append("| Kind | Path | HTTP | Source |")
        lines.append("|---|---|---:|---|")
        for r in report.routes[:50]:
            lines.append(f"| {r.kind} | `{r.path}` | {r.status_code if r.status_code is not None else '—'} | {r.source} |")

    lines += ["", "## Observed Feature Surfaces", ""]
    if not report.features:
        lines.append("No additional feature surfaces recorded.")
    else:
        for feature in report.features:
            lines.append(f"- **{feature.name}** ({feature.confidence}%)")
            for e in feature.evidence[:8]:
                lines.append(f"  - {e.detail}")

    lines += ["", "## Authenticated Filament Inventory", ""]
    if not report.filament_pages:
        lines.append("No Filament page inventory was produced from the fetched pages.")
    else:
        lines.append("Review priority is a triage label only; it is **not** a vulnerability severity.")
        lines.append("")
        lines.append("| Priority | Path | HTTP | Access | Resource / Page | Actions | Authz surfaces | Fields |")
        lines.append("|---|---|---:|---|---|---:|---:|---:|")
        priority_order = {"high": 0, "medium": 1, "normal": 2}
        for page in sorted(report.filament_pages, key=lambda p: (priority_order.get(p.review_priority, 9), p.path))[:60]:
            identity = " / ".join((page.resource_classes + page.page_classes)[:2]) or "—"
            lines.append(f"| {page.review_priority.upper()} | `{page.path}` | {page.status_code} | {page.access_state} | `{identity}` | {len(page.actions)} | {len(page.authorization_surfaces)} | {len(page.fields)} |")

        lines += ["", "### Filament Page Details", ""]
        for page in sorted(report.filament_pages, key=lambda p: (priority_order.get(p.review_priority, 9), p.path))[:40]:
            lines += [
                f"#### `{page.path}`",
                "",
                f"- Access state: **{page.access_state}** (`HTTP {page.status_code}`)",
                f"- Review priority: **{page.review_priority}**",
            ]
            if page.priority_reasons:
                lines.append("- Priority reasons: " + "; ".join(page.priority_reasons))
            if page.resource_classes:
                lines.append("- Resource class(es): " + ", ".join(f"`{x}`" for x in page.resource_classes[:10]))
            if page.page_classes:
                lines.append("- Page class(es): " + ", ".join(f"`{x}`" for x in page.page_classes[:10]))
            if page.page_types:
                lines.append("- Inferred page type(s): **" + ", ".join(page.page_types) + "**")
            if page.component_names:
                lines.append("- Livewire/Filament components:")
                lines.extend(f"  - `{x}`" for x in page.component_names[:15])
            if page.page_actions:
                lines.append("- Page actions (observed, not executed): " + ", ".join(f"`{x}`" for x in page.page_actions[:20]))
            if page.table_actions:
                lines.append("- Table record actions (observed, not executed): " + ", ".join(f"`{x}`" for x in page.table_actions[:20]))
            if page.bulk_actions:
                lines.append("- Bulk actions (observed, not executed): " + ", ".join(f"`{x}`" for x in page.bulk_actions[:20]))
            if page.submit_actions:
                lines.append("- Form submit actions (observed, not submitted): " + ", ".join(f"`{x}`" for x in page.submit_actions[:20]))
            if page.ui_state_actions:
                lines.append("- UI/state-only methods (not counted as application actions): " + ", ".join(f"`{x}`" for x in page.ui_state_actions[:20]))
            if page.authorization_surfaces:
                lines.append("- Authorization review surfaces (not findings):")
                lines.extend(f"  - `{x}`" for x in page.authorization_surfaces[:30])
            if page.form_fields:
                lines.append("- Form/application fields:")
                lines.extend(f"  - `{x}`" for x in page.form_fields[:30])
            if page.table_state_fields:
                lines.append("- Table state/filter fields:")
                lines.extend(f"  - `{x}`" for x in page.table_state_fields[:20])
            elif page.fields:
                lines.append("- Visible field/model markers:")
                lines.extend(f"  - `{x}`" for x in page.fields[:30])
            if page.forms:
                lines.append("- Form markers (not submitted): " + ", ".join(f"`{x}`" for x in page.forms[:10]))
            lines.append("")

        lines += ["### Access-Control Surface Map", "", "This map describes only the supplied session. A reachable page is not, by itself, evidence of broken authorization.", "", "| Path | HTTP | State | Review priority |", "|---|---:|---|---|"]
        for page in sorted(report.filament_pages, key=lambda p: p.path)[:80]:
            lines.append(f"| `{page.path}` | {page.status_code} | {page.access_state} | {page.review_priority} |")

    discovery_diagnostics = report.metadata.get("discovery_diagnostics") or []
    if discovery_diagnostics:
        lines += ["", "### Discovery Diagnostics", ""]
        for item in discovery_diagnostics[:50]:
            status = item.get("status_code", item.get("status", "unknown"))
            result = item.get("result", item.get("detail", ""))
            lines.append(f"- `{item.get('url')}`: {status} — {result}")

    edge_meta = report.metadata.get("edge_policy") or {}
    lines += [
        "",
        "## Edge Security",
        "",
        f"- Cloudflare: **{report.edge.cloudflare}**",
        f"- WAF detected: **{report.edge.waf_detected}**",
        f"- Edge provider: **{report.edge.provider or 'unresolved'}**",
        f"- Provider confidence: **{report.edge.confidence}%**",
        f"- Challenge detected: **{report.edge.challenge_detected}**",
        f"- Rate limited: **{report.edge.rate_limited}**",
        f"- Protected response observed: **{report.edge.protected_response}**",
        f"- Edge-aware policy: **{edge_meta.get('policy', report.edge.recommended_policy)}**",
        f"- Minimum request pacing: **{edge_meta.get('request_delay_ms', 0)} ms**",
        f"- Active probes suppressed: **{bool(edge_meta.get('active_suppressed'))}**",
        "",
        "LaravelHunter does not attempt WAF or CDN evasion. Edge-aware mode slows read-only requests and stops active discovery when challenge, rate-limit, or provider-backed blocking is observed.",
        "",
        "## Advisory Correlation",
        "",
    ]

    if not report.advisories:
        lines.append("No advisory data loaded.")
    else:
        for a in sorted(report.advisories, key=lambda a: ORDER.get(a.severity, 0), reverse=True):
            identifier = f"{a.cve} / {a.advisory_id}" if a.cve else a.advisory_id
            lines += [
                f"### [{a.severity.upper()}] {a.title}",
                "",
                f"- Advisory: `{identifier}`",
                f"- Status: **{a.status}**",
                f"- Version confidence: **{a.confidence}%**",
                f"- Reason: {a.reason}",
                f"- Runtime prerequisite status: **{a.runtime_status}** ({a.runtime_confidence}%)",
                f"- Runtime summary: {a.runtime_summary}",
                f"- Affected ranges: `{', '.join(a.affected_ranges)}`",
                f"- Patched versions: `{', '.join(a.patched_versions)}`",
            ]
            if a.prerequisites:
                lines.append("- Published prerequisites:")
                lines.extend(f"  - {p}" for p in a.prerequisites)
            if a.runtime_evidence:
                lines.append("- Runtime evidence:")
                lines.extend(f"  - {e}" for e in a.runtime_evidence)
            lines.append("")

    runtime_diagnostics = report.metadata.get("runtime_probe_diagnostics") or []
    if runtime_diagnostics:
        lines += ["## Runtime Probe Diagnostics", ""]
        for item in runtime_diagnostics:
            status = item.get("status_code", item.get("status", "unknown"))
            result = item.get("result", item.get("detail", ""))
            lines.append(f"- `{item.get('probe')}`: {status} — {result}")
        lines.append("")

    lines += ["## Findings", ""]
    findings = sorted(report.findings, key=lambda f: ORDER.get(f.severity, 0), reverse=True)
    if not findings:
        lines.append("No rule-based findings in this scan.")
    for f in findings:
        lines += [
            f"### [{f.severity.upper()}] {f.title}",
            "",
            f"- Rule: `{f.rule_id}`",
            f"- Status: **{f.status}**",
            f"- Confidence: **{f.confidence}%**",
            "",
            f.description,
            "",
            "**Evidence**",
        ]
        lines += [f"- {e}" for e in f.evidence] or ["- No additional evidence recorded"]
        lines += ["", "**Recommendation**", "", f.recommendation, ""]
        if f.references:
            lines += ["**References**", ""] + [f"- {r}" for r in f.references] + [""]

    lines += [
        "## Notes",
        "",
        "LaravelHunter v0.9.0 is passive by default. `--safe-active` performs read-only dependency/version checks, one harmless non-existent-path debug response check, and a bounded same-origin GET crawl of links already exposed by the application.",
        "Safe discovery never submits forms, never sends POST/PUT/PATCH/DELETE requests, never invents query parameters, and skips action-like paths such as logout/delete/destroy.",
        "Version status and runtime-prerequisite status are intentionally separate. Neither one alone is proof of exploitability.",
        "Sensitive cookie and CSRF token values are redacted from saved reports by default. Imported authentication secret values are never written to reports; only cookie/header names are recorded.",
        "Edge-aware behavior is defensive: provider/challenge/rate-limit signals cause pacing or suppression of active probes. No WAF/Cloudflare bypass or evasion payloads are generated.",
        "The Filament resource/action correlation is passive: resource/page identities, application actions, UI/state-only methods, authorization-review surfaces, and form fields are parsed from already-fetched HTML and are never executed or submitted. UI/state-only methods are excluded from application-action and authorization counts. Authorization-review surfaces are triage hints, not vulnerability findings.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_auth_matrix_json(report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_auth_matrix_markdown(report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# LaravelHunter Authorization Matrix",
        "",
        f"**Target:** `{report.target}`  ",
        f"**Mode:** `{report.mode}`  ",
        "",
        "This report compares read-only page/action visibility between two supplied authenticated sessions. Differences are review signals, not vulnerability findings.",
        "",
        "## Role Summaries",
        "",
        "| Role | Auth state | Final URL | Reachable pages | Denied pages | Filament pages | Actions | Authz surfaces |",
        "|---|---|---|---:|---:|---:|---:|---:|",
        f"| {report.role_a.label} | {report.role_a.auth_state} | `{report.role_a.final_url}` | {report.role_a.reachable_pages} | {report.role_a.denied_pages} | {report.role_a.filament_pages} | {report.role_a.application_actions} | {report.role_a.authorization_surfaces} |",
        f"| {report.role_b.label} | {report.role_b.auth_state} | `{report.role_b.final_url}` | {report.role_b.reachable_pages} | {report.role_b.denied_pages} | {report.role_b.filament_pages} | {report.role_b.application_actions} | {report.role_b.authorization_surfaces} |",
        "",
        "## Difference Summary",
        "",
        f"- Paths compared: **{report.metadata.get('paths_compared', 0)}**",
        f"- Paths with any difference: **{report.metadata.get('paths_with_differences', 0)}**",
        f"- Access differences: **{report.metadata.get('access_differences', 0)}**",
        f"- Action-visibility differences: **{report.metadata.get('action_differences', 0)}**",
        f"- Authorization-surface differences: **{report.metadata.get('authz_surface_differences', 0)}**",
        f"- Actions executed: **{report.metadata.get('actions_executed', 0)}**",
        f"- Forms submitted: **{report.metadata.get('forms_submitted', 0)}**",
        "",
        "## Matrix",
        "",
        f"| Priority | Path | {report.role_a.label} access | {report.role_b.label} access | {report.role_a.label}-only actions | {report.role_b.label}-only actions | Difference |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report.rows[:120]:
        a_access = f"{row.a_access} ({row.a_status if row.a_status is not None else '—'})"
        b_access = f"{row.b_access} ({row.b_status if row.b_status is not None else '—'})"
        a_only = ", ".join(f"`{x}`" for x in row.only_a_actions[:10]) or "—"
        b_only = ", ".join(f"`{x}`" for x in row.only_b_actions[:10]) or "—"
        flags = []
        if row.access_diff: flags.append("access")
        if row.action_diff: flags.append("actions")
        if row.authz_diff: flags.append("authz")
        lines.append(f"| {row.priority.upper()} | `{row.path}` | {a_access} | {b_access} | {a_only} | {b_only} | {', '.join(flags) or 'none'} |")

    lines += ["", "## Detailed Differences", ""]
    changed = [r for r in report.rows if r.access_diff or r.action_diff or r.authz_diff]
    if not changed:
        lines.append("No observed differences between the supplied sessions.")
    for row in changed[:80]:
        lines += [f"### `{row.path}`", "", f"- Priority: **{row.priority}**"]
        if row.resource:
            lines.append(f"- Resource: `{row.resource}`")
        if row.page_identity:
            lines.append(f"- Page identity: `{row.page_identity}`")
        lines.append(f"- {report.role_a.label} access: **{row.a_access}** (`{row.a_status}`)")
        lines.append(f"- {report.role_b.label} access: **{row.b_access}** (`{row.b_status}`)")
        if row.only_a_actions:
            lines.append(f"- Actions visible only to {report.role_a.label}: " + ", ".join(f"`{x}`" for x in row.only_a_actions))
        if row.only_b_actions:
            lines.append(f"- Actions visible only to {report.role_b.label}: " + ", ".join(f"`{x}`" for x in row.only_b_actions))
        if row.only_a_authz_surfaces:
            lines.append(f"- Authz review surfaces only in {report.role_a.label}: " + ", ".join(f"`{x}`" for x in row.only_a_authz_surfaces))
        if row.only_b_authz_surfaces:
            lines.append(f"- Authz review surfaces only in {report.role_b.label}: " + ", ".join(f"`{x}`" for x in row.only_b_authz_surfaces))
        lines.append("- Interpretation: compare this observed difference against the application's intended role/permission model before treating it as a security issue.")
        lines.append("")

    lines += [
        "## Notes",
        "",
        "- The matrix performs two independent safe-active, same-origin, GET-only assessments using the supplied sessions.",
        "- It does not click or execute Filament/Livewire actions, submit forms, mutate records, brute-force authentication, or infer a privilege ordering between the two role labels.",
        "- Imported cookie/header values are not written to this report.",
        "- A visible or reachable surface is not evidence of broken access control by itself; compare against expected authorization policy.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
