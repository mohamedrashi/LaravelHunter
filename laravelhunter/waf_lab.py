from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from laravelhunter.edge.detect import detect_edge
from laravelhunter.models import HttpSnapshot

SAFE_HEADERS = {
    "User-Agent": "LaravelHunter/0.9.1 (authorized-private-lab)",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
}


@dataclass
class WafLabObservation:
    name: str
    request_url: str
    status_code: int
    final_url: str
    elapsed_ms: int
    body_bytes: int
    body_sha256_16: str
    edge_provider: str | None
    edge_confidence: int
    protected_response: bool
    challenge_detected: bool
    rate_limited: bool


@dataclass
class WafLabReport:
    target: str
    scope_guard: str
    observations: list[WafLabObservation]
    control_divergences: list[str]
    application_divergences: list[str]
    metadata: dict


def _allowed_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def assert_private_lab_target(target: str) -> None:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("waf-lab requires an http(s) URL with a hostname")

    host = parsed.hostname
    try:
        if _allowed_ip(host):
            return
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"Could not resolve lab target: {host}") from exc

    resolved = sorted({item[4][0] for item in infos})
    if not resolved or any(not _allowed_ip(addr) for addr in resolved):
        raise ValueError("waf-lab refuses public Internet targets; use loopback or RFC1918/private lab addresses only")


def _with_query(target: str, items: list[tuple[str, str]]) -> str:
    parsed = urlparse(target)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode([*existing, *items], doseq=True)
    return urlunparse(parsed._replace(query=query))


def build_benign_variants(target: str) -> list[tuple[str, str, dict[str, str]]]:
    # Intentionally non-exploitative. Values are inert labels used only to
    # compare edge/application normalization behavior inside private labs.
    return [
        ("baseline", target, {}),
        ("query-simple", _with_query(target, [("lh_probe", "alpha")]), {}),
        ("query-space-plus", _with_query(target, [("lh_probe", "hello world")]), {}),
        ("query-duplicate-benign", _with_query(target, [("lh_probe", "alpha"), ("lh_probe", "alpha")]), {}),
        ("header-benign-lower", target, {"X-LH-Probe": "alpha"}),
        ("header-benign-upper", target, {"X-LH-Probe": "ALPHA"}),
    ]


def _snapshot_from_response(response: httpx.Response, elapsed_ms: int) -> HttpSnapshot:
    text = response.text[:200_000]
    return HttpSnapshot(
        url=str(response.url),
        status_code=response.status_code,
        headers={k.lower(): v for k, v in response.headers.items()},
        cookies={k: v for k, v in response.cookies.items()},
        body_sample=text,
        elapsed_ms=elapsed_ms,
    )


def _classify(report: WafLabReport) -> None:
    if not report.observations:
        return
    base = report.observations[0]
    for obs in report.observations[1:]:
        if (
            obs.protected_response != base.protected_response
            or obs.challenge_detected != base.challenge_detected
            or obs.rate_limited != base.rate_limited
            or (obs.edge_provider or "") != (base.edge_provider or "")
        ):
            report.control_divergences.append(
                f"{obs.name}: edge-control behavior differs from baseline "
                f"(status {base.status_code}->{obs.status_code}, protected {base.protected_response}->{obs.protected_response})"
            )
        elif obs.status_code != base.status_code:
            report.application_divergences.append(
                f"{obs.name}: HTTP status differs from baseline ({base.status_code}->{obs.status_code}) without a new edge-protection marker"
            )
        elif obs.body_sha256_16 != base.body_sha256_16:
            report.application_divergences.append(
                f"{obs.name}: response body fingerprint differs from baseline; review application-side normalization/reflection"
            )


async def run_waf_lab(target: str, timeout: float = 10.0) -> WafLabReport:
    assert_private_lab_target(target)
    observations: list[WafLabObservation] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=SAFE_HEADERS, verify=True) as client:
        for name, url, headers in build_benign_variants(target):
            import time
            started = time.perf_counter()
            response = await client.get(url, headers=headers)
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            snap = _snapshot_from_response(response, elapsed_ms)
            edge = detect_edge(snap)
            body_bytes = len(response.content)
            body_hash = hashlib.sha256(response.content).hexdigest()[:16]
            observations.append(WafLabObservation(
                name=name,
                request_url=url,
                status_code=response.status_code,
                final_url=str(response.url),
                elapsed_ms=elapsed_ms,
                body_bytes=body_bytes,
                body_sha256_16=body_hash,
                edge_provider=edge.provider,
                edge_confidence=edge.confidence,
                protected_response=edge.protected_response,
                challenge_detected=edge.challenge_detected,
                rate_limited=edge.rate_limited,
            ))

    report = WafLabReport(
        target=target,
        scope_guard="private-lab-only",
        observations=observations,
        control_divergences=[],
        application_divergences=[],
        metadata={
            "mode": "benign-differential-testing",
            "requests_sent": len(observations),
            "state_changing_requests": 0,
            "exploit_payloads": 0,
            "public_targets_allowed": False,
        },
    )
    _classify(report)
    return report


def write_waf_lab_reports(report: WafLabReport, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    data = asdict(report)
    (out / "waf-lab.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    lines = [
        "# LaravelHunter WAF Lab Differential Report",
        "",
        f"- Target: `{report.target}`",
        f"- Scope guard: `{report.scope_guard}`",
        f"- Requests sent: `{report.metadata['requests_sent']}`",
        "- State-changing requests: `0`",
        "- Exploit payloads: `0`",
        "",
        "## Observations",
        "",
        "| Variant | HTTP | Edge | Protected | Challenge | Rate limited | Body hash |",
        "|---|---:|---|---|---|---|---|",
    ]
    for o in report.observations:
        lines.append(
            f"| {o.name} | {o.status_code} | {o.edge_provider or '—'} | {str(o.protected_response).lower()} | "
            f"{str(o.challenge_detected).lower()} | {str(o.rate_limited).lower()} | `{o.body_sha256_16}` |"
        )
    lines += ["", "## Edge-control divergences", ""]
    if report.control_divergences:
        lines += [f"- {x}" for x in report.control_divergences]
    else:
        lines.append("- None observed.")
    lines += ["", "## Application/normalization divergences", ""]
    if report.application_divergences:
        lines += [f"- {x}" for x in report.application_divergences]
    else:
        lines.append("- None observed.")
    lines += [
        "",
        "## Safety boundary",
        "",
        "This command is intentionally restricted to loopback/private laboratory targets and uses benign GET-only variants. "
        "It does not attempt WAF evasion, exploit execution, challenge solving, origin discovery, or public-target bypass.",
    ]
    (out / "waf-lab.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
