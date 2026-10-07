from __future__ import annotations
import asyncio
import time
from urllib.parse import urljoin, urlparse

import httpx

from laravelhunter.models import HttpSnapshot

DEFAULT_HEADERS = {
    "User-Agent": "LaravelHunter/0.9.1 (+authorized-security-assessment)",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
}
REDIRECT_CODES = {301, 302, 303, 307, 308}


def _origin(url: str) -> tuple[str, str]:
    p = urlparse(url)
    return p.scheme.lower(), p.netloc.lower()


class SafeHttpClient:
    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 5,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
        min_delay_ms: int = 0,
    ):
        self.max_redirects = max_redirects
        self.min_delay_ms = max(0, int(min_delay_ms))
        self._last_request_at: float | None = None
        self.auth_headers = dict(auth_headers or {})
        self.auth_enabled = bool(self.auth_headers or auth_cookies)
        self.client = httpx.AsyncClient(
            timeout=timeout,
            headers=DEFAULT_HEADERS,
            follow_redirects=False,
            verify=True,
            cookies=auth_cookies or {},
        )

    async def close(self):
        await self.client.aclose()

    def set_min_delay_ms(self, value: int) -> None:
        self.min_delay_ms = max(0, int(value))

    async def _pace(self) -> None:
        if self.min_delay_ms <= 0 or self._last_request_at is None:
            return
        elapsed_ms = (time.perf_counter() - self._last_request_at) * 1000
        remaining_ms = self.min_delay_ms - elapsed_ms
        if remaining_ms > 0:
            await asyncio.sleep(remaining_ms / 1000)

    async def get(self, url: str) -> HttpSnapshot:
        started = time.perf_counter()
        current = url
        request_origin = _origin(url)
        response: httpx.Response | None = None

        for _ in range(self.max_redirects + 1):
            # Imported credentials are only attached while requests remain on the
            # origin the caller asked us to fetch. Cross-origin redirects are not
            # followed when an auth context is loaded.
            headers = self.auth_headers if (not self.auth_enabled or _origin(current) == request_origin) else {}
            await self._pace()
            response = await self.client.get(current, headers=headers)
            self._last_request_at = time.perf_counter()
            if response.status_code not in REDIRECT_CODES or not response.headers.get("location"):
                break

            nxt = urljoin(str(response.url), response.headers["location"])
            if self.auth_enabled and _origin(nxt) != request_origin:
                break
            current = nxt
        else:
            raise httpx.TooManyRedirects(f"Exceeded {self.max_redirects} redirects", request=None)

        assert response is not None
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        body = response.text[:200_000]
        return HttpSnapshot(
            url=str(response.url),
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            cookies={k: v for k, v in response.cookies.items()},
            body_sample=body,
            elapsed_ms=elapsed_ms,
        )
