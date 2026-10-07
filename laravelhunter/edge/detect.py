from __future__ import annotations

from laravelhunter.models import EdgeResult, Evidence, HttpSnapshot

# Detection only. These markers are used to identify edge providers and decide
# whether LaravelHunter should slow down or stop active discovery. They are not
# used to evade, spoof, or bypass protective controls.
PROVIDER_HEADER_MARKERS = {
    "cf-ray": ("Cloudflare", "Cloudflare ray header", 35),
    "cf-cache-status": ("Cloudflare", "Cloudflare cache header", 25),
    "x-sucuri-id": ("Sucuri", "Sucuri header", 40),
    "x-sucuri-cache": ("Sucuri", "Sucuri cache header", 30),
    "x-akamai-transformed": ("Akamai", "Akamai transform header", 40),
    "akamai-grn": ("Akamai", "Akamai request marker", 35),
    "x-iinfo": ("Imperva", "Imperva Incapsula header", 40),
    "x-cdn": ("Generic CDN/WAF", "CDN/WAF header", 20),
}

BODY_PROVIDER_MARKERS = {
    "cloudflare": ["attention required! | cloudflare", "cf-chl-", "cloudflare ray id"],
    "sucuri": ["sucuri website firewall", "access denied - sucuri website firewall"],
    "imperva": ["incapsula incident id", "powered by imperva"],
}

CHALLENGE_MARKERS = [
    "cf-chl-",
    "just a moment...",
    "checking your browser",
    "attention required! | cloudflare",
    "verify you are human",
    "captcha",
]


def _choose_provider(scores: dict[str, int]) -> tuple[str | None, int]:
    if not scores:
        return None, 0
    provider, score = max(scores.items(), key=lambda item: item[1])
    return provider, min(100, score)


def detect_edge(snapshot: HttpSnapshot) -> EdgeResult:
    headers = snapshot.headers
    body = snapshot.body_sample.lower()
    evidence: list[Evidence] = []
    provider_scores: dict[str, int] = {}
    cloudflare = False
    waf = False
    challenge = False
    rate_limited = snapshot.status_code == 429

    for header, (provider, label, weight) in PROVIDER_HEADER_MARKERS.items():
        if header in headers:
            waf = True
            provider_scores[provider] = provider_scores.get(provider, 0) + weight
            evidence.append(Evidence(source="header", detail=label, weight=weight))
            if provider == "Cloudflare":
                cloudflare = True

    server = headers.get("server", "").lower()
    if "cloudflare" in server:
        cloudflare = True
        waf = True
        provider_scores["Cloudflare"] = provider_scores.get("Cloudflare", 0) + 55
        evidence.append(Evidence(source="header", detail="Server header indicates Cloudflare", weight=55))
    elif "sucuri" in server:
        waf = True
        provider_scores["Sucuri"] = provider_scores.get("Sucuri", 0) + 45
        evidence.append(Evidence(source="header", detail="Server header indicates Sucuri", weight=45))

    for provider_key, markers in BODY_PROVIDER_MARKERS.items():
        if any(marker in body for marker in markers):
            provider = {"cloudflare": "Cloudflare", "sucuri": "Sucuri", "imperva": "Imperva"}[provider_key]
            waf = True
            provider_scores[provider] = provider_scores.get(provider, 0) + 40
            evidence.append(Evidence(source="body", detail=f"{provider} protection marker observed", weight=40))
            if provider == "Cloudflare":
                cloudflare = True

    if any(marker in body for marker in CHALLENGE_MARKERS):
        challenge = True
        waf = True
        evidence.append(Evidence(source="body", detail="Challenge/interstitial page detected", weight=45))

    protected_status = snapshot.status_code in {403, 406, 409, 429, 503}
    protected_response = bool(challenge or rate_limited or (protected_status and waf))

    if protected_status and waf:
        evidence.append(Evidence(source="status", detail=f"Edge protection response status {snapshot.status_code}", weight=15))

    provider, confidence = _choose_provider(provider_scores)
    if waf and confidence == 0:
        confidence = 40

    if challenge or rate_limited:
        policy = "stop-active"
    elif waf:
        policy = "paced-read-only"
    else:
        policy = "normal"

    return EdgeResult(
        cloudflare=cloudflare,
        waf_detected=waf,
        rate_limited=rate_limited,
        challenge_detected=challenge,
        provider=provider,
        confidence=confidence,
        protected_response=protected_response,
        recommended_policy=policy,
        evidence=evidence,
    )
