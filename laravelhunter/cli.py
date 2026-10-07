from __future__ import annotations
import asyncio
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from laravelhunter import __version__
from laravelhunter.report.render import write_json, write_markdown, write_auth_matrix_json, write_auth_matrix_markdown
from laravelhunter.scanner import scan
from laravelhunter.auth import load_auth_file
from laravelhunter.authz_matrix import build_authorization_matrix, cross_check_union_paths
from laravelhunter.waf_lab import run_waf_lab, write_waf_lab_reports

app = typer.Typer(help="LaravelHunter - safe Laravel security assessment engine")
console = Console()


def _framework_label(detected: bool, confidence: int) -> str:
    if detected and confidence >= 90:
        return "YES — HIGH CONFIDENCE"
    if detected:
        return "YES — MODERATE CONFIDENCE"
    if confidence >= 30:
        return "POSSIBLE — NOT CONFIRMED"
    return "NOT CONFIRMED"


@app.callback()
def main():
    """LaravelHunter command line interface."""
    pass


@app.command("scan")
def scan_cmd(
    target: str = typer.Argument(..., help="Target URL or hostname"),
    out: Path = typer.Option(Path("reports/latest"), "--out", "-o", help="Output directory"),
    timeout: float = typer.Option(10.0, help="HTTP timeout in seconds"),
    max_redirects: int = typer.Option(5, help="Maximum redirects"),
    safe_active: bool = typer.Option(False, "--safe-active", help="Allow a small set of read-only version/runtime/discovery probes"),
    max_discovery_pages: int = typer.Option(8, "--max-discovery-pages", min=0, max=25, help="Maximum same-origin linked pages fetched in safe-active mode"),
    auth_file: Path | None = typer.Option(None, "--auth-file", help="Read-only session headers/cookies file. Values are never written to reports."),
    project_path: Path | None = typer.Option(None, "--project-path", help="Owned local Laravel project path. Reads composer.lock locally for exact package versions."),
):
    """Run a safe Laravel assessment. Passive by default."""
    try:
        auth = load_auth_file(auth_file) if auth_file else None
        report = asyncio.run(scan(
            target,
            timeout=timeout,
            max_redirects=max_redirects,
            safe_active=safe_active,
            max_discovery_pages=max_discovery_pages,
            auth=auth,
            project_path=project_path,
        ))
    except Exception as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]LaravelHunter v{__version__}[/bold cyan]")
    console.print(f"Target: {report.target}")
    console.print(f"Final URL: {report.final_url}")
    console.print(f"Laravel: {_framework_label(report.fingerprint.detected, report.fingerprint.confidence)} ({report.fingerprint.confidence}%)")

    if report.framework_version.version:
        exact = "exact" if report.framework_version.exact else "hint"
        console.print(f"Laravel version: {report.framework_version.version} ({exact}, {report.framework_version.confidence}%)")
        console.print(f"Version source: {report.framework_version.source}")
    else:
        console.print("Laravel version: unresolved")
        if report.framework_version.constraints:
            console.print("Version constraints:")
            for item in report.framework_version.constraints:
                console.print(f"  - {item}")
        if report.framework_version.candidate_majors:
            console.print("Candidate Laravel majors: " + ", ".join(map(str, report.framework_version.candidate_majors)))

    local_meta = report.metadata.get("local_project") or {}
    if local_meta.get("enabled"):
        console.print("Local project mode: ENABLED (composer.lock)")
        package_versions = local_meta.get("package_versions") or {}
        for package in ("laravel/framework", "filament/filament", "livewire/livewire", "laravel/sanctum", "laravel/telescope", "laravel/horizon"):
            if package in package_versions:
                console.print(f"  {package}: {package_versions[package]}")

    php_version = report.metadata.get("php_version")
    if php_version:
        console.print(f"PHP: {php_version}")
    console.print(f"Cloudflare: {'YES' if report.edge.cloudflare else 'NO'}")
    console.print(f"WAF: {'YES' if report.edge.waf_detected else 'NOT DETECTED'}")
    if report.edge.provider:
        console.print(f"Edge provider: {report.edge.provider} ({report.edge.confidence}%)")
    edge_meta = report.metadata.get("edge_policy") or {}
    console.print(f"Edge-aware policy: {edge_meta.get('policy', report.edge.recommended_policy)}")
    if edge_meta.get("request_delay_ms"):
        console.print(f"Request pacing: {edge_meta.get('request_delay_ms')} ms minimum delay")
    if edge_meta.get("active_suppressed"):
        console.print("[yellow]Active probes suppressed:[/yellow] protective edge response observed")
    console.print(f"Mode: {report.metadata.get('mode')}")
    auth_meta = report.metadata.get("auth") or {}
    if auth_meta.get("loaded"):
        console.print(f"Auth context: LOADED — {auth_meta.get('state')} (cookies: {len(auth_meta.get('cookie_names', []))}, headers: {len(auth_meta.get('header_names', []))})")

    coverage = report.metadata.get("coverage") or {}
    if coverage:
        ctable = Table(title="Assessment Coverage")
        ctable.add_column("Metric")
        ctable.add_column("Value", justify="right")
        for label, key in [
            ("Saved pages", "entry_pages"),
            ("Route surfaces", "route_surfaces"),
            ("Feature surfaces", "feature_surfaces"),
            ("Filament pages inventoried", "filament_pages"),
            ("High-interest Filament pages", "high_interest_filament_pages"),
            ("Medium-interest Filament pages", "medium_interest_filament_pages"),
            ("Resource/page-correlated pages", "resource_correlated_pages"),
            ("Authorization review surfaces", "authorization_surfaces"),
            ("UI/state-only action markers", "ui_state_actions"),
            ("Advisories evaluated", "advisories_evaluated"),
            ("Advisories with runtime evidence", "advisories_with_runtime_evidence"),
        ]:
            ctable.add_row(label, str(coverage.get(key, 0)))
        ctable.add_row("Exact Laravel version", "yes" if coverage.get("exact_version_resolved") else "no")
        console.print(ctable)

    table = Table(title="Components")
    table.add_column("Component")
    table.add_column("Detected")
    table.add_column("Version hint")
    table.add_column("Confidence", justify="right")
    for c in report.components:
        table.add_row(c.name, "yes" if c.detected else "no", c.version_hint or "—", f"{c.confidence}%")
    console.print(table)

    if report.routes:
        rtable = Table(title="Safe Route Discovery")
        rtable.add_column("Kind")
        rtable.add_column("Path")
        rtable.add_column("HTTP", justify="right")
        rtable.add_column("Source")
        for r in report.routes[:25]:
            rtable.add_row(r.kind, r.path, str(r.status_code) if r.status_code is not None else "—", r.source)
        console.print(rtable)

    if report.features:
        fstable = Table(title="Observed Feature Surfaces")
        fstable.add_column("Feature")
        fstable.add_column("Confidence", justify="right")
        for feature in report.features:
            fstable.add_row(feature.name, f"{feature.confidence}%")
        console.print(fstable)

    if report.filament_pages:
        ptable = Table(title="Authenticated Filament Page Inventory")
        ptable.add_column("Priority")
        ptable.add_column("Path")
        ptable.add_column("Access")
        ptable.add_column("Identity")
        ptable.add_column("Actions", justify="right")
        ptable.add_column("Authz", justify="right")
        ptable.add_column("Fields", justify="right")
        priority_order = {"high": 0, "medium": 1, "normal": 2}
        for page in sorted(report.filament_pages, key=lambda p: (priority_order.get(p.review_priority, 9), p.path))[:30]:
            ptable.add_row(
                page.review_priority.upper(),
                page.path,
                f"{page.access_state} ({page.status_code})",
                ", ".join((page.resource_classes + page.page_classes)[:2]) or "—",
                str(len(page.actions)),
                str(len(page.authorization_surfaces)),
                str(len(page.fields)),
            )
        console.print(ptable)

        cormap = Table(title="Filament Resource & Action Correlation")
        cormap.add_column("Path")
        cormap.add_column("Resource")
        cormap.add_column("Page / Type")
        cormap.add_column("Page")
        cormap.add_column("Table")
        cormap.add_column("Bulk")
        cormap.add_column("Submit")
        cormap.add_column("UI state")
        cormap.add_column("Authz", justify="right")
        ranked = sorted(report.filament_pages, key=lambda p: (priority_order.get(p.review_priority, 9), p.path))[:30]
        for page in ranked:
            cormap.add_row(
                page.path,
                ", ".join(page.resource_classes[:2]) or "—",
                (", ".join(page.page_classes[:1]) + (f" [{','.join(page.page_types)}]" if page.page_types else "")) or "—",
                ", ".join(page.page_actions[:3]) or "—",
                ", ".join(page.table_actions[:3]) or "—",
                ", ".join(page.bulk_actions[:3]) or "—",
                ", ".join(page.submit_actions[:3]) or "—",
                ", ".join(page.ui_state_actions[:3]) or "—",
                str(len(page.authorization_surfaces)),
            )
        console.print(cormap)

        amap = Table(title="Access-Control Surface Map (Current Session Only)")
        amap.add_column("Path")
        amap.add_column("HTTP", justify="right")
        amap.add_column("State")
        amap.add_column("Review priority")
        for page in sorted(report.filament_pages, key=lambda p: p.path)[:40]:
            amap.add_row(page.path, str(page.status_code), page.access_state, page.review_priority)
        console.print(amap)

    if report.advisories:
        atable = Table(title="Laravel Advisory Correlation")
        atable.add_column("Severity")
        atable.add_column("Advisory")
        atable.add_column("Version status")
        atable.add_column("Runtime")
        for a in report.advisories:
            atable.add_row(a.severity.upper(), a.cve or a.advisory_id, a.status, f"{a.runtime_status} ({a.runtime_confidence}%)")
        console.print(atable)

    if report.findings:
        ftable = Table(title="Findings")
        ftable.add_column("Severity")
        ftable.add_column("Rule")
        ftable.add_column("Finding")
        ftable.add_column("Confidence", justify="right")
        for f in report.findings:
            ftable.add_row(f.severity.upper(), f.rule_id, f.title, f"{f.confidence}%")
        console.print(ftable)

    out.mkdir(parents=True, exist_ok=True)
    write_json(report, out / "report.json")
    write_markdown(report, out / "report.md")
    console.print(f"\nReports written to: [bold]{out}[/bold]")


@app.command("auth-matrix")
def auth_matrix_cmd(
    target: str = typer.Argument(..., help="Target URL or hostname"),
    auth_a: Path = typer.Option(..., "--auth-a", help="First authorized session file"),
    auth_b: Path = typer.Option(..., "--auth-b", help="Second authorized session file"),
    label_a: str = typer.Option("role-a", "--label-a", help="Display label for first session"),
    label_b: str = typer.Option("role-b", "--label-b", help="Display label for second session"),
    out: Path = typer.Option(Path("reports/auth-matrix"), "--out", "-o", help="Output directory"),
    timeout: float = typer.Option(10.0, help="HTTP timeout in seconds"),
    max_redirects: int = typer.Option(5, help="Maximum redirects"),
    max_discovery_pages: int = typer.Option(20, "--max-discovery-pages", min=1, max=25, help="Maximum same-origin linked pages per session"),
):
    """Compare two authorized sessions using read-only Filament/Laravel visibility."""
    try:
        ctx_a = load_auth_file(auth_a)
        ctx_b = load_auth_file(auth_b)
        report_a = asyncio.run(scan(target, timeout=timeout, max_redirects=max_redirects, safe_active=True, max_discovery_pages=max_discovery_pages, auth=ctx_a))
        report_b = asyncio.run(scan(target, timeout=timeout, max_redirects=max_redirects, safe_active=True, max_discovery_pages=max_discovery_pages, auth=ctx_b))
        cross_a = asyncio.run(cross_check_union_paths(target, report_a, report_b, ctx_a, timeout=timeout, max_redirects=max_redirects))
        cross_b = asyncio.run(cross_check_union_paths(target, report_b, report_a, ctx_b, timeout=timeout, max_redirects=max_redirects))
        matrix = build_authorization_matrix(target, report_a, report_b, label_a, label_b)
        matrix.metadata["cross_checked_paths_a"] = cross_a
        matrix.metadata["cross_checked_paths_b"] = cross_b
    except Exception as exc:
        console.print(f"[red]Authorization matrix failed:[/red] {exc}")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]LaravelHunter v{__version__} — Authorization Matrix[/bold cyan]")
    console.print(f"Target: {matrix.target}")
    console.print(f"{matrix.role_a.label}: {matrix.role_a.auth_state} — {matrix.role_a.reachable_pages} reachable Filament pages")
    console.print(f"{matrix.role_b.label}: {matrix.role_b.auth_state} — {matrix.role_b.reachable_pages} reachable Filament pages")

    summary = Table(title="Authorization Matrix Summary")
    summary.add_column("Metric")
    summary.add_column("Value", justify="right")
    for label, key in [
        ("Paths compared", "paths_compared"),
        ("Paths with differences", "paths_with_differences"),
        ("Access differences", "access_differences"),
        ("Action differences", "action_differences"),
        ("Authz-surface differences", "authz_surface_differences"),
    ]:
        summary.add_row(label, str(matrix.metadata.get(key, 0)))
    summary.add_row("Actions executed", str(matrix.metadata.get("actions_executed", 0)))
    console.print(summary)

    table = Table(title="Multi-Role Authorization Matrix")
    table.add_column("Priority")
    table.add_column("Path")
    table.add_column(matrix.role_a.label)
    table.add_column(matrix.role_b.label)
    table.add_column(f"Only {matrix.role_a.label}")
    table.add_column(f"Only {matrix.role_b.label}")
    table.add_column("Diff")
    for row in matrix.rows[:40]:
        flags = []
        if row.access_diff: flags.append("access")
        if row.action_diff: flags.append("actions")
        if row.authz_diff: flags.append("authz")
        table.add_row(
            row.priority.upper(),
            row.path,
            f"{row.a_access} ({row.a_status if row.a_status is not None else '—'})",
            f"{row.b_access} ({row.b_status if row.b_status is not None else '—'})",
            ", ".join(row.only_a_actions[:3]) or "—",
            ", ".join(row.only_b_actions[:3]) or "—",
            ",".join(flags) or "none",
        )
    console.print(table)
    console.print("[yellow]Note:[/yellow] Differences are review signals only; LaravelHunter does not infer which role should have more privilege and executes no actions.")

    out.mkdir(parents=True, exist_ok=True)
    write_auth_matrix_json(matrix, out / "matrix.json")
    write_auth_matrix_markdown(matrix, out / "matrix.md")
    console.print(f"\nMatrix reports written to: [bold]{out}[/bold]")


@app.command("waf-lab")
def waf_lab_cmd(
    target: str = typer.Argument(..., help="Private/loopback laboratory URL only"),
    out: Path = typer.Option(Path("reports/waf-lab"), "--out", "-o", help="Output directory"),
    timeout: float = typer.Option(10.0, help="HTTP timeout in seconds"),
):
    """Run benign GET-only differential WAF normalization checks on private labs."""
    try:
        report = asyncio.run(run_waf_lab(target, timeout=timeout))
    except Exception as exc:
        console.print(f"[red]WAF lab failed:[/red] {exc}")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]LaravelHunter v{__version__} — WAF Lab Differential[/bold cyan]")
    console.print(f"Target: {report.target}")
    console.print("Scope guard: PRIVATE LAB ONLY")
    console.print(f"Requests sent: {report.metadata.get('requests_sent', 0)} — GET only")
    console.print("Exploit payloads: 0")

    table = Table(title="Benign Differential Observations")
    table.add_column("Variant")
    table.add_column("HTTP", justify="right")
    table.add_column("Edge")
    table.add_column("Protected")
    table.add_column("Challenge")
    table.add_column("Body hash")
    for obs in report.observations:
        table.add_row(
            obs.name,
            str(obs.status_code),
            obs.edge_provider or "—",
            "yes" if obs.protected_response else "no",
            "yes" if obs.challenge_detected else "no",
            obs.body_sha256_16,
        )
    console.print(table)

    if report.control_divergences:
        console.print("[yellow]Edge-control divergences:[/yellow]")
        for item in report.control_divergences:
            console.print(f"  - {item}")
    else:
        console.print("Edge-control divergences: none observed")

    if report.application_divergences:
        console.print("[cyan]Application/normalization divergences:[/cyan]")
        for item in report.application_divergences[:10]:
            console.print(f"  - {item}")

    write_waf_lab_reports(report, out)
    console.print(f"\nWAF lab reports written to: [bold]{out}[/bold]")
