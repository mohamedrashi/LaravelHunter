from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse

from laravelhunter.models import Evidence, HttpSnapshot, RuntimePrerequisiteResult

DEBUG_MARKERS = [
    (re.compile(r"ignition", re.I), 35, "Ignition debug-page marker observed"),
    (re.compile(r"whoops", re.I), 25, "Whoops debug-page marker observed"),
    (re.compile(r"stack\s*trace|stacktrace", re.I), 20, "Stack-trace marker observed"),
    (re.compile(r"exception[-_ ](?:message|trace)|class=\"exception", re.I), 20, "Exception-detail marker observed"),
    (re.compile(r"laravel[^<]{0,40}(?:exception|debug)", re.I), 20, "Laravel debug/exception marker observed"),
]

MAIL_FLOW_MARKERS = [
    (re.compile(r"forgot[-_/ ]?password|password/(?:reset|email)|reset[-_/ ]?password", re.I), 35, "Password-reset/mail flow marker observed"),
    (re.compile(r"verify[-_/ ]?email|email[-_/ ]?verification", re.I), 30, "Email-verification flow marker observed"),
    (re.compile(r"contact[-_/ ]?(?:us|form)?", re.I), 15, "Contact-flow marker observed"),
]

SIGNED_URL_RE = re.compile(r"(?:[?&](?:signature|expires)=)[^\s\"'<>]+", re.I)
SIGNED_PAIR_RE = re.compile(r"(?=[^\"']*[?&]signature=)(?=[^\"']*[?&]expires=)", re.I)
LOCAL_STORAGE_HINT_RE = re.compile(r"/(?:storage|uploads|files|download)/", re.I)


def debug_probe_url(target: str) -> str:
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    return urljoin(root, "__laravelhunter_probe_not_found_7d9e3f__")


def _debug_evidence(snapshot: HttpSnapshot | None) -> list[Evidence]:
    if snapshot is None:
        return []
    body = snapshot.body_sample
    evidence: list[Evidence] = []
    for regex, weight, detail in DEBUG_MARKERS:
        if regex.search(body):
            evidence.append(Evidence(source="runtime", detail=detail, weight=weight))
    return evidence


def _mail_evidence(snapshot: HttpSnapshot) -> list[Evidence]:
    body = snapshot.body_sample
    evidence: list[Evidence] = []
    for regex, weight, detail in MAIL_FLOW_MARKERS:
        if regex.search(body):
            evidence.append(Evidence(source="runtime", detail=f"{detail} on {urlparse(snapshot.url).path or '/'}", weight=weight))
    if re.search(r"<input[^>]+type=[\"']email[\"']", body, re.I):
        evidence.append(Evidence(source="runtime", detail=f"Email input field observed on {urlparse(snapshot.url).path or '/'} (weak mail-flow hint only)", weight=5))
    return evidence


def _signed_url_evidence(snapshot: HttpSnapshot) -> list[Evidence]:
    body = snapshot.body_sample
    evidence: list[Evidence] = []
    if SIGNED_PAIR_RE.search(body) or ("signature=" in body.lower() and "expires=" in body.lower()):
        evidence.append(Evidence(source="runtime", detail=f"URL containing both signature and expires parameters observed on {urlparse(snapshot.url).path or '/'}", weight=55))
    elif SIGNED_URL_RE.search(body):
        evidence.append(Evidence(source="runtime", detail=f"Signed/expiring URL parameter marker observed on {urlparse(snapshot.url).path or '/'}", weight=25))
    if LOCAL_STORAGE_HINT_RE.search(body):
        evidence.append(Evidence(source="runtime", detail=f"Local/public file path marker observed on {urlparse(snapshot.url).path or '/'}", weight=10))
    return evidence


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    result: list[Evidence] = []
    seen: set[str] = set()
    for item in evidence:
        if item.detail not in seen:
            seen.add(item.detail)
            result.append(item)
    return result


def assess_runtime_prerequisites(home: HttpSnapshot, debug_probe: HttpSnapshot | None = None, observed_pages: list[HttpSnapshot] | None = None) -> list[RuntimePrerequisiteResult]:
    pages = [home, *(observed_pages or [])]
    results: list[RuntimePrerequisiteResult] = []

    debug_evidence = _dedupe([*_debug_evidence(home), *_debug_evidence(debug_probe)])
    debug_score = min(100, sum(e.weight for e in debug_evidence))
    results.append(RuntimePrerequisiteResult(
        advisory_id="GHSA-jh5r-qr3c-85q8",
        status="observed" if debug_score >= 50 else ("partial" if debug_score > 0 else "not-observed"),
        confidence=debug_score,
        summary="APP_DEBUG/debug-page behavior appears exposed." if debug_score >= 50 else "No strong APP_DEBUG/debug-page evidence observed.",
        evidence=debug_evidence,
    ))

    mail_evidence = _dedupe([e for page in pages for e in _mail_evidence(page)])
    mail_score = min(100, sum(e.weight for e in mail_evidence))
    results.append(RuntimePrerequisiteResult(
        advisory_id="GHSA-5vg9-5847-vvmq",
        status="observed" if mail_score >= 50 else ("partial" if mail_score > 0 else "not-observed"),
        confidence=mail_score,
        summary="A user-controlled outbound-email flow may be present." if mail_score >= 50 else "No strong outbound-mail flow evidence observed from discovered pages.",
        evidence=mail_evidence[:12],
    ))

    signed_evidence = _dedupe([e for page in pages for e in _signed_url_evidence(page)])
    signed_score = min(100, sum(e.weight for e in signed_evidence))
    results.append(RuntimePrerequisiteResult(
        advisory_id="GHSA-crmm-hgp2-wgrp",
        status="observed" if signed_score >= 60 else ("partial" if signed_score > 0 else "not-observed"),
        confidence=signed_score,
        summary="Signed/temporary URL behavior is visible in discovered responses." if signed_score >= 60 else "No strong temporary signed-URL evidence observed from discovered pages.",
        evidence=signed_evidence[:12],
    ))

    return results
