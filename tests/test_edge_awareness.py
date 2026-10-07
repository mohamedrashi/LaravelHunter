import asyncio

from laravelhunter.discovery import discover_routes
from laravelhunter.edge.detect import detect_edge
from laravelhunter.models import HttpSnapshot


def snap(url="https://example.test/", body="", headers=None, status=200):
    return HttpSnapshot(
        url=url,
        status_code=status,
        headers=headers or {},
        cookies={},
        body_sample=body,
        elapsed_ms=1,
    )


def test_cloudflare_provider_and_paced_policy_on_normal_response():
    edge = detect_edge(snap(headers={"server": "cloudflare", "cf-ray": "abc"}, status=200))
    assert edge.cloudflare is True
    assert edge.waf_detected is True
    assert edge.provider == "Cloudflare"
    assert edge.confidence >= 50
    assert edge.recommended_policy == "paced-read-only"
    assert edge.protected_response is False


def test_cloudflare_challenge_stops_active_policy():
    edge = detect_edge(snap(
        body="<html><title>Just a moment...</title><div>cf-chl-test</div></html>",
        headers={"server": "cloudflare", "cf-ray": "abc"},
        status=403,
    ))
    assert edge.challenge_detected is True
    assert edge.protected_response is True
    assert edge.recommended_policy == "stop-active"


def test_plain_403_is_not_assumed_to_be_waf_block():
    edge = detect_edge(snap(status=403))
    assert edge.waf_detected is False
    assert edge.protected_response is False
    assert edge.recommended_policy == "normal"


class EdgeFakeHttp:
    async def get(self, url):
        pages = {
            "https://example.test/first": snap(
                "https://example.test/first",
                '<title>Just a moment...</title><div>cf-chl-demo</div><a href="/second">Second</a>',
                headers={"server": "cloudflare", "cf-ray": "abc"},
                status=403,
            ),
            "https://example.test/second": snap("https://example.test/second", "ok"),
        }
        return pages[url]


def test_discovery_stops_after_protected_edge_response():
    home = snap("https://example.test/", '<a href="/first">First</a><a href="/second">Second</a>')
    routes, pages, diagnostics = asyncio.run(discover_routes(EdgeFakeHttp(), home, max_pages=5))
    assert len(pages) == 1
    assert pages[0].url.endswith("/first")
    assert any(item.get("result") == "edge-protected-stop" for item in diagnostics)
